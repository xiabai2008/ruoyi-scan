# 指纹识别接口 + 通用特征判定（数据驱动，支持多 CMS 自动识别与路由）
import hashlib
import re
from typing import Any, Dict

from common.logger import get_logger
from common.models import FingerprintResult
from core.fingerprint_features import get_feature, get_variant_feature, list_cms, list_variants
from core.session import SessionManager

logger = get_logger(__name__)


class Fingerprint:
    """指纹识别抽象接口（新增 CMS 实现此接口即可，引擎零改动）"""

    def detect(self, target: str, session: SessionManager, cache: Any = None) -> FingerprintResult:
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

    def __init__(self, cms: str) -> None:
        self.cms = cms
        self.feature = get_feature(cms)

    def detect(self, target: str, session: SessionManager, cache: Any = None) -> FingerprintResult:
        """按特征库做多特征交叉判定：主页关键字 + 强特征路径 + favicon hash

        Args:
            target: 目标 URL（以 / 结尾）
            session: SessionManager 实例
            cache: 可选 FingerprintCache（多 CMS 遍历时共享根/favicon 响应）

        Returns:
            FingerprintResult；特征不足时 cms 为空串（不误判），matched 给出命中依据
        """
        if not self.feature:
            return FingerprintResult(cms="", version="", confidence=0.0, matched=[])

        f = self.feature
        matched = []
        strong_hits = 0
        weak_hits = 0
        root_body = ""  # 根路径响应体，供软404检测（catch-all 站点对任意路径返回相同内容）
        root_ok = False  # 根路径是否取到响应：取不到时无法比对，见软404判定
        w_strong = f.get("weight_strong", 0.5)
        w_weak = f.get("weight_weak", 0.2)

        # 阶段五：cache 存在时走缓存（多 CMS 共享根/favicon 响应），否则直接 session.get
        def _get(url: str) -> Any:
            if cache is not None:
                return cache.get(url)
            return session.get(url)

        # 1. 主页特征：GET 根路径，检查标题与响应体关键字
        try:
            resp = _get(target)
            text = resp.text or ""
            root_body = text
            root_ok = True
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
            # target 已归一化以 / 结尾，去特征路径前导斜杠避免拼出双斜杠
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
                    # expect="any"：状态码 200 只是必要条件，还需排除"软404/通配200"——
                    # 对任意路径返回与根路径完全相同内容的站点（SPA 前端兜底、静态站
                    # catch-all、部分 CDN/WAF）并非有效强特征；否则会把非若依站点
                    # （wordpress/django/nginx 等）误判为若依变体。
                    # 根路径取到响应时即做比对（含同为空的兜底页）；根路径获取失败
                    # 时没有基线可用，维持原判定（无法比对不等于命中）
                    ok = True
                    if root_ok and body == root_body:
                        ok = False
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
                    # 非匹配 favicon 不构成任何特征：几乎每个站点都返回 favicon.ico，
                    # 若计为弱特征，配合单个弱关键字就能凑到 0.4 阈值，D5 误报防护失效
                    logger.debug("favicon 未命中特征库: %s", h[:8])
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

    def __init__(self) -> None:
        super().__init__("ruoyi")


def detect_variant(target: str, session: SessionManager, cache: Any = None) -> str:
    """E1：若依变体细分识别（仅在主 CMS=ruoyi 确认后调用）

    遍历 VARIANT_FEATURES 注册的变体：
      1. strong_paths 命中 >=1（复用 expect 语义，走 cache 避免重复请求）
      2. negative_paths 全部未命中（404/非 200 才算排除成立）
    多个变体命中时取强特征命中数最多者；全部未命中返回 ''（通用版）。

    Args:
        target: 目标 URL
        session: SessionManager 实例
        cache: 可选 FingerprintCache（多 CMS 遍历时共享响应）

    Returns:
        变体标识字符串（如 'ruoyi-vue3'），未识别返回 ''
    """

    def _get(url: str) -> Any:
        if cache is not None:
            return cache.get(url)
        return session.get(url)

    def _expect_ok(r: Any, expect: str) -> bool:
        """复用主指纹的 expect 语义：json/image/any"""
        if r.status_code != 200:
            return False
        ct = (r.headers.get("Content-Type") or "").lower()
        body = r.text or ""
        if expect == "json":
            return ("json" in ct) and ("code" in body or "msg" in body)
        if expect == "image":
            return "image" in ct
        return True

    best_variant = ""
    best_hits = 0
    # 软404/通配 200 基线：根路径响应体。cache 场景下根路径已被指纹探测抓取，
    # 此处只是缓存读取（不会新增请求）；直接调用时仅多 1 次基线请求。
    root_ok = False
    root_body = ""
    try:
        root_resp = _get(target)
        if root_resp is not None and getattr(root_resp, "status_code", 0) == 200:
            root_ok = True
            root_body = root_resp.text or ""
    except Exception:
        logger.debug("变体识别根路径基线获取失败", exc_info=True)

    for variant in list_variants():
        f = get_variant_feature(variant)
        if not f:
            continue
        hits = 0
        # 负向特征：任一命中（200 且符合 expect 语义）→ 排除该变体。
        # 复用 _expect_ok，并对与根路径同内容的响应做通配 200 防护：
        # catch-all/SPA/CDN 站点对任意路径返回 200（甚至同一页面），
        # 若直接按 200 排除会把真实变体也一并排除（detect_variant 恒返回 ''）
        excluded = False
        for item in f.get("negative_paths", []):
            try:
                r = _get(target + item["path"].lstrip("/"))
                if not _expect_ok(r, item.get("expect", "any")):
                    continue
                if root_ok and (r.text or "") == root_body:
                    continue  # 与根路径同内容 → 通配 200，不作为排除依据
                excluded = True
                break
            except Exception:
                continue
        if excluded:
            continue
        # 正向强特征路径
        for item in f.get("strong_paths", []):
            try:
                r = _get(target + item["path"].lstrip("/"))
                if _expect_ok(r, item.get("expect", "any")):
                    hits += 1
            except Exception:
                continue
        if hits > 0 and hits > best_hits:
            best_hits = hits
            best_variant = variant
    return best_variant


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
        # E1：变体细分识别（复用 cache，不增加额外请求数之外的请求）
        try:
            variant = detect_variant(target, session, cache=cache)
            if variant:
                best.variant = variant
                best.matched.append("variant:%s" % variant)
        except Exception:
            logger.debug("若依变体识别失败", exc_info=True)
        try:
            from core.http import join_url
            from core.ruoyi_versions import extract_version

            # 版本号来源：/login（页脚/JS 变量最常见位置）优先，缓存未命中时会显式
            # 探测一次（1 次 GET）；根路径改用缓存 peek（各 CMS 指纹探测必已抓取），
            # 不再用 cache.get 触发重复请求，也去掉与根 URL 等价的 "" 重复项
            cached_version = ""
            try:
                login_resp = cache.get(join_url(target, "/login"))
                if login_resp:
                    cached_version = extract_version(login_resp.text or "")
            except Exception:
                logger.debug("/login 版本号提取失败", exc_info=True)
            if not cached_version and target in set(cache.keys()):
                try:
                    root_resp = cache.get(target)
                    if root_resp:
                        cached_version = extract_version(root_resp.text or "")
                except Exception:
                    logger.debug("根路径缓存版本号提取失败", exc_info=True)
            if cached_version:
                best.version = cached_version
                best.matched.append("version:%s" % cached_version)
            # 注：缓存未命中版本号时不再调用 detect_version 额外请求
            # （detect_cms 仅新增 /login 一次探测，根路径复用缓存）。
            # 版本号未在登录页/根路径出现时，Router 会按"版本未识别"处理（跑全部 POC）。
        except Exception:
            logger.debug("若依版本探测失败", exc_info=True)
    return best


def detect_waf(target: str, session: SessionManager) -> Dict[str, Any]:
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
