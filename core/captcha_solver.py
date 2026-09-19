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
from typing import Any, Optional, Tuple

from common.logger import get_logger
from core.http import join_url

logger = get_logger(__name__)

# OCR 引擎进程级缓存（见 _init_ocr_backend 的说明）：
#   ddddocr 后端 → DdddOcr 实例；pytesseract 后端 → (pytesseract, PIL.Image) 元组
_OCR_ENGINE: Any = None
_OCR_BACKEND: Optional[str] = None
_OCR_PROBED = False

# 验证码接口候选路径（按若依版本兼容性排序）
#
# ⚠ RuoYi 4.x 的 SysCaptchaController 有隐藏前提：**必须带 type 参数**。
#   其源码形如：
#       if ("math".equals(type)) { ... } else if ("char".equals(type)) { ... }
#       // 没有 else 分支
#       ImageIO.write(bi, "jpg", out);
#   type 缺失时 BufferedImage 保持 null，ImageIO.write 抛异常并被 catch 静默吞掉，
#   于是返回 **HTTP 200 + Content-Type: image/jpeg + 0 字节**。
#   2026-09-17 实测：不带参数 0 字节；?type=char 3071 字节；?type=math 2818 字节。
#
# 之所以优先 type=char：controller 会把「渲染出来的文本」存入 session
# （math 分支存入的是算式**结果**）——所以请求 char 时 OCR 结果可直接当 validateCode 用，
# 无需本地做算术求值，稳定性和准确率都更高。
CAPTCHA_PATHS = [
    "/captcha/captchaImage?type=char",  # RuoYi 4.x 标准（推荐：session 存的就是渲染文本）
    "/captcha/captchaImage?type=math",  # 算术验证码（需本地求值，见 _normalize_code）
    "/captcha/captchaImage",  # 兜底：无参（部分定制版仍可用）
    "/captcha/image",  # 部分旧版/定制版
    "/code",  # RuoYi 5.x（前后端分离，返回 base64 JSON）
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

    def __init__(self, target: str, session: Any, captcha_type: str = "auto") -> None:
        """初始化验证码识别器

        Args:
            target: 目标站点根 URL
            session: SessionManager 实例
            captcha_type: auto / math / char（auto 先按算术求值，非算式回退原文）
        """
        self.target = target
        self.session = session
        self.captcha_type = captcha_type  # auto / math / char
        self._ocr_backend: Optional[str] = None
        self._captcha_path: Optional[str] = None

    def _init_ocr_backend(self) -> Optional[str]:
        """初始化 OCR 后端，返回后端名称或 None

        引擎缓存在进程级（模块全局）而非实例级：登录爆破对每个口令新建一个
        CaptchaSolver（默认字典 1052 条），实例级缓存等于每个口令重新加载一次
        DdddOcr 模型——实测默认 -u 扫描因此白等 100 秒以上。引擎本身无状态，
        进程内复用安全（并发首次加载最多重复构造一次，无副作用）。
        """
        global _OCR_ENGINE, _OCR_BACKEND, _OCR_PROBED

        if _OCR_PROBED:
            self._ocr_backend = _OCR_BACKEND
            if _OCR_BACKEND == "ddddocr":
                self._ocr = _OCR_ENGINE
            elif _OCR_BACKEND == "pytesseract":
                self._pytesseract, self._PIL = _OCR_ENGINE
            return _OCR_BACKEND

        _OCR_PROBED = True
        # 1. 优先 ddddocr
        try:
            import ddddocr

            _OCR_ENGINE = ddddocr.DdddOcr(show_ad=False)
            _OCR_BACKEND = "ddddocr"
            self._ocr = _OCR_ENGINE
            self._ocr_backend = _OCR_BACKEND
            return self._ocr_backend
        except Exception:
            logger.debug("ddddocr 后端加载失败", exc_info=True)
        # 2. 备选 pytesseract
        try:
            import pytesseract
            from PIL import Image

            _OCR_ENGINE = (pytesseract, Image)
            _OCR_BACKEND = "pytesseract"
            self._pytesseract, self._PIL = _OCR_ENGINE
            self._ocr_backend = _OCR_BACKEND
            return self._ocr_backend
        except Exception:
            logger.debug("pytesseract 后端加载失败", exc_info=True)
        # 两个后端都不可用：记录已探测，避免每次识别都重试 import
        _OCR_BACKEND = None
        return None

    def detect_captcha(self) -> Tuple[bool, str]:
        """探测验证码接口是否存在

        按候选路径顺序请求，**优先返回能拿到非空图片的路径**。

        历史缺陷（2026-09-17 多版本矩阵实测发现）：原实现遇到第一个
        `200 + image/*` 就返回，不检查响应体是否为空。而 RuoYi 4.x 的无参路径
        `/captcha/captchaImage` 恰好返回 200 + image/jpeg + **0 字节**
        （controller 缺 type 参数时 BufferedImage 为 null，ImageIO.write 抛异常被吞），
        于是探测在第一个候选上「成功」，后面的 `?type=char` 永远得不到尝试机会，
        调用方随后在 OCR 阶段失败并上报「接口存在但识别失败」——真实原因被掩盖。

        现策略：空图片只记为候选（endpoint 确实存在），继续找可用图片；
        若所有候选都拿不到图，再返回该候选（语义仍是「有验证码，但解不了」）。

        Returns:
            (has_captcha: bool, captcha_path: str)
            has_captcha=True, captcha_path 为可用路径：存在验证码且能取到图
            has_captcha=True, captcha_path 为空图路径：接口存在但拿不到图（调用方应报 LOGIN_CAPTCHA）
            has_captcha=False, captcha_path=''：无验证码
        """
        empty_fallback = ""
        for path in CAPTCHA_PATHS:
            try:
                resp = self.session.get(join_url(self.target, path))
                ct = (resp.headers.get("Content-Type", "") or "").lower()
                code = getattr(resp, "status_code", 0)
                # 验证码接口返回 image/* 类型
                if code == 200 and ("image" in ct or "jpeg" in ct or "png" in ct):
                    if not (resp.content or b""):
                        # 200 + image/* 但响应体为空：接口存在却给不出图。
                        # 记为兜底候选并继续尝试其他路径（不要在这里就「成功」返回）。
                        if not empty_fallback:
                            empty_fallback = path
                        logger.debug("验证码接口 %s 返回空图片，继续尝试下一候选", path)
                        continue
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
        if empty_fallback:
            # 所有候选都拿不到图，但确实存在验证码接口：仍判「存在」，
            # 由调用方按「验证码不可解」处理（LOGIN_CAPTCHA），而不是误判为无验证码。
            self._captcha_path = empty_fallback
            return True, empty_fallback
        return False, ""

    def _download_image(self) -> Tuple[bytes, bool]:
        """下载验证码图片，返回 (image_bytes: bytes, is_base64_json: bool)"""
        if not self._captcha_path:
            has, path = self.detect_captcha()
            if not has:
                return b"", False
        try:
            resp = self.session.get(join_url(self.target, self._captcha_path or ""))
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

    def _ocr_recognize(self, image_bytes: bytes) -> str:
        """用 OCR 后端识别图片，返回识别文本"""
        backend = self._init_ocr_backend()
        if not backend:
            return ""
        if backend == "ddddocr":
            try:
                return str(self._ocr.classification(image_bytes))
            except Exception:
                return ""
        if backend == "pytesseract":
            try:
                img = self._PIL.open(io.BytesIO(image_bytes))
                # 数字+字母模式（验证码常见）
                return str(
                    self._pytesseract.image_to_string(
                        img, config="--psm 7 -c tessedit_char_whitelist=0123456789+-*=abcdefgABCDEFG"
                    )
                ).strip()
            except Exception:
                return ""
        return ""

    def _eval_math_captcha(self, text: str) -> str:
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

    def solve(self) -> Tuple[bool, str]:
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
    def backend_name(self) -> str:
        """当前 OCR 后端名称（供调试/证据用）"""
        return self._init_ocr_backend() or "none"
