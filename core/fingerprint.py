# 指纹识别接口 + RuoyiFingerprint（多特征交叉判定，标准库 hashlib，无第三方依赖）
import hashlib
import re

from core.models import FingerprintResult


class Fingerprint:
    """指纹识别抽象接口（阶段二新增 CMS 实现此接口即可，引擎零改动）"""

    def detect(self, target, session) -> FingerprintResult:
        """识别目标 CMS，返回 FingerprintResult（cms 空串表示未识别）"""
        raise NotImplementedError


class RuoyiFingerprint(Fingerprint):
    """若依指纹识别：多特征交叉判定

    特征来源（开发方案 §三 Step 3）：
    - favicon hash（标准库 hashlib.md5，避免第三方依赖）
    - 特征路径 /prod-api/（若依前后端分离版 API 前缀）
    - 验证码接口 /captcha/image（若依标准验证码图片接口）
    - 登录页特征（HTML 含 RuoYi / 若依管理系统）
    - 响应头 / 标题

    置信度计算：强特征 0.5/个，弱特征 0.2/个，上限 1.0。
    至少命中一个强特征才高置信判定为 ruoyi；仅弱特征则低置信标记供人工复核。
    """

    # 已知若依 favicon md5（采集后填入；当前为空，favicon 仅作弱特征加分）
    FAVICON_HASHES = set()

    # 强特征路径（命中任一且响应符合预期，强烈指向 ruoyi）
    STRONG_PATHS = [
        '/prod-api/',        # 若依前后端分离版 API 前缀
        '/captcha/image',    # 若依验证码图片接口
        '/getInfo',          # 若依登录后用户信息接口
    ]

    # 登录页强特征关键字（HTML / 标题含其一即强特征）
    LOGIN_KEYWORDS = ['RuoYi', '若依管理系统', '若依管理']

    # 弱特征关键字（标题/响应体含其一即弱特征）
    WEAK_KEYWORDS = ['若依', 'ruoyi', 'RuoYi']

    def detect(self, target, session) -> FingerprintResult:
        matched = []
        strong_hits = 0
        weak_hits = 0

        # 1. 主页特征：GET 根路径，检查标题与响应体关键字
        try:
            resp = session.get(target)
            text = resp.text or ''
            title_m = re.findall(r'<title>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
            title = title_m[0] if title_m else ''
            # 登录页强关键字（命中任一即 +1 强特征）
            for kw in self.LOGIN_KEYWORDS:
                if kw in text or kw in title:
                    strong_hits += 1
                    matched.append(f'login:{kw}')
                    break
            # 弱关键字（命中任一即 +1 弱特征，与强关键字不重复计数）
            for kw in self.WEAK_KEYWORDS:
                if kw in text or kw in title:
                    weak_hits += 1
                    matched.append(f'keyword:{kw}')
                    break
        except Exception:
            pass

        # 2. 特征路径探测
        for path in self.STRONG_PATHS:
            # target 以 / 结尾，path 以 / 开头，去掉 path 的 / 避免双斜杠
            url = target + path.lstrip('/')
            try:
                r = session.get(url)
                ct = (r.headers.get('Content-Type') or '').lower()
                body = r.text or ''
                if r.status_code == 200:
                    if 'json' in ct and ('code' in body or 'msg' in body):
                        # /prod-api/、/getInfo 返回若依标准 JSON
                        strong_hits += 1
                        matched.append(f'path:{path}(json,{r.status_code})')
                    elif 'image' in ct:
                        # /captcha/image 返回图片
                        strong_hits += 1
                        matched.append(f'path:{path}(image,{r.status_code})')
            except Exception:
                continue

        # 3. favicon hash（标准库 hashlib.md5）
        try:
            fav = session.get(target + 'favicon.ico')
            if fav.status_code == 200 and len(fav.content) > 0:
                h = hashlib.md5(fav.content).hexdigest()
                if h in self.FAVICON_HASHES:
                    strong_hits += 1
                    matched.append(f'favicon:{h}')
                else:
                    # 拿到 favicon 但不在已知列表：弱特征加分（记录前 8 位便于后续采集）
                    weak_hits += 1
                    matched.append(f'favicon:unknown:{h[:8]}')
        except Exception:
            pass

        # 置信度计算
        confidence = min(1.0, strong_hits * 0.5 + weak_hits * 0.2)

        # 判定：至少一个强特征 → 高置信 ruoyi；仅弱特征 → 低置信 ruoyi（供人工复核）；无特征 → 未识别
        if strong_hits > 0:
            return FingerprintResult(
                cms='ruoyi', version='', confidence=confidence, matched=matched)
        if weak_hits > 0:
            return FingerprintResult(
                cms='ruoyi', version='', confidence=confidence, matched=matched)
        return FingerprintResult(cms='', version='', confidence=0.0, matched=matched)
