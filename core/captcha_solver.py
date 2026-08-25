# 验证码识别器（D3 阶段）
#
# 功能：探测若依验证码接口，下载验证码图片，OCR 识别验证码文本。
#
# 支持的 OCR 后端（按优先级）：
#   1. ddddocr（纯 Python，自带模型，无需 tessdata）—— 首选
#   2. pytesseract（需 tesseract 可执行 + tessdata）—— 备选
#
# 若依验证码接口：
#   - RuoYi 4.x:  /captcha/captchaImage（SysCaptchaController，返回 image/jpeg）
#   - RuoYi 4.x 旧版: /captcha/image（部分版本路径不同）
#   - RuoYi 5.x:  /code?captchaType=math（前后端分离，返回 base64 JSON）
#
# 验证码类型：
#   - math: 算术验证码（如 "3+5=?@8"，识别算式结果 8）
#   - char: 字符验证码（如 "aB3x"，直接识别）
import base64
import io
import re

from common.logger import get_logger
from core.http import join_url

logger = get_logger(__name__)

# 验证码接口候选路径（按若依版本兼容性排序）
CAPTCHA_PATHS = [
    "/captcha/captchaImage",  # RuoYi 4.x 标准（SysCaptchaController）
    "/captcha/image",  # 部分旧版/定制版
    "/code",  # RuoYi 5.x（前后端分离）
]


class CaptchaSolver:
    """验证码识别器

    用法：
        solver = CaptchaSolver(target, session)
        has_captcha, code = solver.solve()
        if has_captcha and code:
            # 用 code 作为 validateCode 参数登录
            chain.login(captcha_code=code)
    """

    def __init__(self, target, session, captcha_type="auto"):
        """初始化验证码识别器

        Args:
            target: 目标站点根 URL
            session: SessionManager 实例
            captcha_type: auto / math / char（auto 先按算术求值，非算式回退原文）
        """
        self.target = target
        self.session = session
        self.captcha_type = captcha_type  # auto / math / char
        self._ocr_backend = None
        self._captcha_path = None

    def _init_ocr_backend(self):
        """初始化 OCR 后端，返回后端名称或 None"""
        if self._ocr_backend is not None:
            return self._ocr_backend
        # 1. 优先 ddddocr
        try:
            import ddddocr

            self._ocr = ddddocr.DdddOcr(show_ad=False)
            self._ocr_backend = "ddddocr"
            return self._ocr_backend
        except Exception:
            logger.debug("ddddocr 后端加载失败", exc_info=True)
        # 2. 备选 pytesseract
        try:
            import pytesseract
            from PIL import Image

            self._pytesseract = pytesseract
            self._PIL = Image
            self._ocr_backend = "pytesseract"
            return self._ocr_backend
        except Exception:
            logger.debug("pytesseract 后端加载失败", exc_info=True)
        return None

    def detect_captcha(self):
        """探测验证码接口是否存在

        按候选路径顺序请求，找到第一个返回图片的路径。

        Returns:
            (has_captcha: bool, captcha_path: str)
            has_captcha=True, captcha_path='/captcha/captchaImage'：存在验证码
            has_captcha=False, captcha_path=''：无验证码
        """
        for path in CAPTCHA_PATHS:
            try:
                resp = self.session.get(join_url(self.target, path))
                ct = (resp.headers.get("Content-Type", "") or "").lower()
                code = getattr(resp, "status_code", 0)
                # 验证码接口返回 image/* 类型
                if code == 200 and ("image" in ct or "jpeg" in ct or "png" in ct):
                    self._captcha_path = path
                    return True, path
                # RuoYi 5.x 返回 JSON（base64 图片）
                if code == 200 and "json" in ct:
                    try:
                        body = resp.json()
                        if "img" in body or "image" in body or "data" in body:
                            self._captcha_path = path
                            return True, path
                    except (ValueError, TypeError):
                        logger.debug("验证码接口 JSON 响应解析失败", exc_info=True)
            except Exception:
                continue
        return False, ""

    def _download_image(self):
        """下载验证码图片，返回 (image_bytes: bytes, is_base64_json: bool)"""
        if not self._captcha_path:
            has, path = self.detect_captcha()
            if not has:
                return b"", False
        try:
            resp = self.session.get(join_url(self.target, self._captcha_path))
            ct = (resp.headers.get("Content-Type", "") or "").lower()
            if "json" in ct:
                # RuoYi 5.x base64 JSON
                body = resp.json()
                b64 = body.get("img") or body.get("image") or body.get("data") or ""
                if b64:
                    # 去 data:image/...;base64, 前缀
                    if "," in b64 and b64.startswith("data:"):
                        b64 = b64.split(",", 1)[1]
                    return base64.b64decode(b64), True
                return b"", True
            # 直接返回图片字节
            return resp.content or b"", False
        except Exception:
            return b"", False

    def _ocr_recognize(self, image_bytes):
        """用 OCR 后端识别图片，返回识别文本"""
        backend = self._init_ocr_backend()
        if not backend:
            return ""
        if backend == "ddddocr":
            try:
                return self._ocr.classification(image_bytes)
            except Exception:
                return ""
        if backend == "pytesseract":
            try:
                img = self._PIL.open(io.BytesIO(image_bytes))
                # 数字+字母模式（验证码常见）
                return self._pytesseract.image_to_string(
                    img, config="--psm 7 -c tessedit_char_whitelist=0123456789+-*=abcdefgABCDEFG"
                ).strip()
            except Exception:
                return ""
        return ""

    def _eval_math_captcha(self, text):
        """算术验证码求值（如 '3+5=?' → '8'）"""
        if not text:
            return ""
        # 提取算式部分（去掉 =? 或 = 等）
        m = re.search(r"(\d+)\s*([+\-*/])\s*(\d+)", text)
        if not m:
            return text  # 非算术，直接返回原文
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        try:
            if op == "+":
                return str(a + b)
            if op == "-":
                return str(a - b)
            if op == "*":
                return str(a * b)
            if op == "/":
                # 验证码算式为整数除法；b==0 是 OCR 误识别，直接给 "0" 防御
                return str(a // b) if b != 0 else "0"
        except Exception:
            logger.debug("算术验证码求值失败", exc_info=True)
        return text

    def solve(self):
        """探测并识别验证码

        Returns:
            (has_captcha: bool, code: str)
            has_captcha=False：无验证码接口
            has_captcha=True, code=''：有验证码但识别失败（OCR 不可用或图片异常）
            has_captcha=True, code='8'：识别成功
        """
        has, path = self.detect_captcha()
        if not has:
            return False, ""
        # 下载验证码图片
        image_bytes, is_json = self._download_image()
        if not image_bytes:
            # 有接口但图片为空（如真实若依靶场 kaptcha 配置问题）
            return True, ""
        # OCR 识别
        text = self._ocr_recognize(image_bytes)
        if not text:
            return True, ""
        # 算术验证码求值
        if self.captcha_type in ("auto", "math"):
            result = self._eval_math_captcha(text)
            return True, result
        return True, text

    @property
    def backend_name(self):
        """当前 OCR 后端名称（供调试/证据用）"""
        return self._init_ocr_backend() or "none"
