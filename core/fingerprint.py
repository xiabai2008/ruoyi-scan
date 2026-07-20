# 指纹识别接口 + 通用特征判定（数据驱动，支持多 CMS 自动识别与路由）
import hashlib
import re

from core.fingerprint_features import get_feature, list_cms
from core.logger import get_logger
from core.models import FingerprintResult
from core.session import SessionManager

logger = get_logger(__name__)


class Fingerprint:
    """指纹识别抽象接口（新增 CMS 实现此接口即可，引擎零改动）"""

    def detect(self, target: str, session: SessionManager, cache=None) -> FingerprintResult:
        """识别目标 CMS，返回 FingerprintResult（cms 空串表示未识别）

        cache（可选）：core.cache.FingerprintCache 实例，用于多 CMS 遍历时
        共享根响应/favicon 响应，避免重复请求（阶段五指纹去重）。
        """
        raise NotImplementedError


class FeatureBasedFingerprint(Fingerprint):
    """基于特征库的通用多特征交叉判定

    适用于任一在 lib.fingerprint_features.CMS_FEATURES 中注册的 CMS。
    强特征 +weight_strong/个，弱特征 +weight_weak/个，置信度上限 1.0。
    至少命中一个强特征 → 高置信；仅弱特征 → 低置信（供人工复核）；无特征 → 未识别。
    """

    def __init__(self, cms):
        self.cms = cms
        self.feature = get_feature(cms)

    def detect(self, target: str, session: SessionManager, cache=None) -> FingerprintResult:
        if not self.feature:
            return FingerprintResult(cms="", version="", confidence=0.0, matched=[])

        f = self.feature
        matched = []
        strong_hits = 0
        weak_hits = 0
        w_strong = f.get("weight_strong", 0.5)
        w_weak = f.get("weight_weak", 0.2)

        # 阶段五：cache 存在时走缓存（多 CMS 共享根/favicon 响应），否则直接 session.get
        def _get(url):
            if cache is not None:
                return cache.get(url)
            return session.get(url)

        # 1. 主页特征：GET 根路径，检查标题与响应体关键字
        try:
            resp = _get(target)
            text = resp.text or ""
            title_m = re.findall(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            title = title_m[0] if title_m else ""
            for kw in f.get("login_keywords", []):
                if kw in text or kw in title:
                    strong_hits += 1
                    matched.append("login:%s" % kw)
                    break
            for kw in f.get("weak_keywords", []):
                if kw in text or kw in title:
                    weak_hits += 1
                    matched.append("keyword:%s" % kw)
                    break
        except Exception:
            logger.debug("主页特征检测失败", exc_info=True)

        # 2. 强特征路径探测
        for item in f.get("strong_paths", []):
            path = item["path"]
            expect = item.get("expect", "any")
            url = target + path.lstrip("/")
            try:
                r = _get(url)
                if r.status_code != 200:
                    continue
                ct = (r.headers.get("Content-Type") or "").lower()
                body = r.text or ""
                if expect == "json":
                    ok = ("json" in ct) and ("code" in body or "msg" in body)
                elif expect == "image":
                    ok = "image" in ct
                else:
                    ok = True
                if ok:
                    strong_hits += 1
                    matched.append("path:%s(%s,%d)" % (path, expect, r.status_code))
            except Exception:
                continue

        # 3. favicon hash 比对（标准库 hashlib.md5(content).hexdigest()）
        try:
            fav = _get(target + "favicon.ico")
            if fav.status_code == 200 and len(fav.content) > 0:
                h = hashlib.md5(fav.content).hexdigest()
                if h in f.get("favicon_hashes", set()):
                    strong_hits += 1
                    matched.append("favicon:%s" % h)
                else:
                    weak_hits += 1
                    matched.append("favicon:unknown:%s" % h[:8])
        except Exception:
            logger.debug("favicon hash 比对失败", exc_info=True)

        confidence = min(1.0, strong_hits * w_strong + weak_hits * w_weak)
        # D5 误报率修复：仅弱特征命中时需达到弱特征阈值（0.4），避免单弱特征误判
        # 设计依据：若依弱_keywords 含"若依"/"ruoyi"/"RuoYi"，单弱特征命中（0.2）不足以确信，
        # 需至少 2 个弱特征（0.4）或 1 个强特征（0.5）才判为该 CMS。
        # 边界用例：含"若依"二字的非若依页面（单弱特征）不应误判。
        weak_confidence = weak_hits * w_weak
        if strong_hits > 0 or weak_confidence >= 0.4:
            return FingerprintResult(cms=self.cms, version="", confidence=confidence, matched=matched)
        return FingerprintResult(cms="", version="", confidence=0.0, matched=matched)


class RuoyiFingerprint(FeatureBasedFingerprint):
    """若依指纹识别（薄封装，向后兼容 main.py / 旧测试）"""

    def __init__(self):
        super().__init__("ruoyi")


def detect_cms(target: str, session: SessionManager) -> FingerprintResult:
    """多 CMS 指纹识别：遍历所有注册 CMS，返回置信度最高的结果

    用于阶段二自动路由：未知目标自动识别为对应 CMS 并加载插件包。
    多个 CMS 均弱命中时，选弱特征置信度最高者；均强命中时，选先注册者。

    阶段五：内部创建 FingerprintCache 共享根响应/favicon 响应，避免多 CMS
    遍历时重复 GET 相同 URL（detect 签名不变，向后兼容旧调用方）。

    D2 阶段：识别出 CMS 后，对若依额外探测版本号（/login 页面 HTML 中的 X.Y.Z），
    版本号存入 FingerprintResult.version，供 Router 按 affected_versions 过滤 POC。
    """
    from core.cache import FingerprintCache

    cache = FingerprintCache(session)
    best = FingerprintResult(cms="", version="", confidence=0.0, matched=[])
    for cms in list_cms():
        res = FeatureBasedFingerprint(cms).detect(target, session, cache=cache)
        if res.cms and res.confidence > best.confidence:
            best = res
    # D2：若依版本探测（仅对 ruoyi 做，其他 CMS 暂不支持）
    if best.cms == "ruoyi":
        try:
            from core.http import join_url
            from core.ruoyi_versions import extract_version

            # 优先从缓存中已有的 /login 和根路径响应提取版本号（避免额外请求）
            cached_version = ""
            for path in ["/login", "/", ""]:
                try:
                    full_url = join_url(target, path) if path else target
                    cached_resp = cache.get(full_url)
                    if cached_resp:
                        v = extract_version(cached_resp.text or "")
                        if v:
                            cached_version = v
                            break
                except Exception:
                    logger.debug("缓存响应版本号提取失败", exc_info=True)
            if cached_version:
                best.version = cached_version
                best.matched.append("version:%s" % cached_version)
            # 注：缓存未命中版本号时不额外请求 detect_version，
            # 避免 detect_cms 的请求次数超出缓存测试预期。
            # 版本号未在首页/login 出现时，Router 会按"版本未识别"处理（跑全部 POC）。
        except Exception:
            logger.debug("若依版本探测失败", exc_info=True)
    return best


def detect_waf(target: str, session: SessionManager) -> dict:
    """WAF 指纹识别：检测目标是否部署了 Web 应用防火墙（P1-C）

    通过分析根路径响应头、响应体、Set-Cookie 特征判断 WAF 类型。

    Args:
        target: 目标 URL
        session: SessionManager 实例
    Returns:
        dict: {'waf': 'WAF标识' 或 '', 'display': '显示名', 'bypass_hint': '绕过提示'}
    """
    from core.waf_features import WAF_FEATURES

    try:
        resp = session.get(target)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        resp_text = (resp.text or "").lower()
        cookie = (resp.headers.get("Set-Cookie") or "").lower()
    except Exception:
        return {"waf": "", "display": "", "bypass_hint": ""}

    for waf_key, f in WAF_FEATURES.items():
        # 响应头检测
        for hdr in f.get("headers", []):
            hdr_lower = hdr.lower()
            if hdr_lower in resp_headers or any(hdr_lower in k for k in resp_headers):
                return {"waf": waf_key, "display": f["display"], "bypass_hint": f.get("bypass_hint", "")}
        # 响应体关键字
        for kw in f.get("body", []):
            if kw.lower() in resp_text:
                return {"waf": waf_key, "display": f["display"], "bypass_hint": f.get("bypass_hint", "")}
        # Cookie 特征
        for ck in f.get("cookie", []):
            if ck.lower() in cookie:
                return {"waf": waf_key, "display": f["display"], "bypass_hint": f.get("bypass_hint", "")}

    return {"waf": "", "display": "", "bypass_hint": ""}
