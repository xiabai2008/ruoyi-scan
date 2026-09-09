# G1：认证后深度扫描 —— 登录态接口资产盘点 + 越权矩阵
#
# 定位（ROADMAP G1 认证后深度扫描）：
#   现有插件以未授权检测为主；--logic-scan 的越权检测需要手动提供端点文件。
#   本模块补上自动化闭环：用高权会话盘点登录态可达接口，再对每个资产做
#   匿名重放（未授权访问）与低权重放（垂直越权）双维判定。
#
# 流程：
#   1. 端点发现：若依管理端点字典（含 /prod-api 前缀变体）+ 登录态页面链接/
#      fetch 调用提取 + 可选浅层爬虫（use_crawler）
#   2. 资产盘点：高权会话逐个 GET，200 记入资产清单（401/403 不入清单）
#   3. 越权矩阵：对每个资产
#      a. 匿名会话重放 → 200+业务数据 → CONFIRMED 未授权访问（LogicVuln）
#      b. 低权会话重放 → 200+非拒绝 → CONFIRMED 垂直越权（LogicVuln）
#   4. 输出：(资产清单 List[SurfaceAsset], 漏洞 List[LogicVuln])
#      资产清单可 JSON 落盘（--surface-output），漏洞并入统一报告管线
#
# 三态纪律（与全局一致）：
#   CONFIRMED  匿名/低权 200 且响应为业务数据（排除登录页/拒绝语义）
#   SAFE       明确拒绝：HTTP 401/403，或 HTTP 200 但业务码 401/403 / 拒绝关键字
#   UNKNOWN    网络异常（绝不判 SAFE）
#
# 注意：RuoYi 未授权访问常返回 HTTP 200 + JSON code:401，判定必须同时看
# HTTP 状态码与业务语义，不能只看状态码。
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from common.logger import get_logger
from core.http import join_url
from lib.logic_scan import LogicVuln

logger = get_logger(__name__)

# ============================================================
# 数据模型
# ============================================================


@dataclass
class SurfaceAsset:
    """登录态接口资产（盘点结果）"""

    url: str
    method: str = "GET"
    source: str = "dict"  # dict=端点字典 / page=页面提取 / crawl=爬虫
    admin_code: int = 0  # 高权会话响应码
    admin_size: int = 0
    anon_code: Optional[int] = None  # 匿名重放响应码（None=未探测/异常）
    low_code: Optional[int] = None  # 低权重放响应码（None=未配置低权账号）
    verdict: str = ""  # confirmed/safe/unknown（越权矩阵综合判定，空=未判定）

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "source": self.source,
            "admin_code": self.admin_code,
            "admin_size": self.admin_size,
            "anon_code": self.anon_code,
            "low_code": self.low_code,
            "verdict": self.verdict,
        }


# ============================================================
# 端点字典
# ============================================================

# 若依管理端点字典（GET 类，登录态可达；覆盖单体/Plus/Cloud 常见管理接口）
RUOYI_ADMIN_ENDPOINTS = [
    "/system/user/list",
    "/system/role/list",
    "/system/menu/list",
    "/system/dept/list",
    "/system/post/list",
    "/system/config/list",
    "/system/notice/list",
    "/system/dict/data/list",
    "/monitor/operlog/list",
    "/monitor/logininfor/list",
    "/monitor/online/list",
    "/monitor/job/list",
    "/tool/gen/list",
]

# 自动生成前端代理前缀变体（RuoYi-Vue/Plus 前端经 /prod-api 反代后端）
_ENDPOINT_PREFIXES = ["", "/prod-api"]

# 静态资源/无需盘点的路径后缀（登录态盘点过滤）
_STATIC_SUFFIXES = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)

# 匿名/低权重放判定为"拒绝"的关键字（响应体，小写匹配）
DENY_KEYWORDS = [
    "请先登录",
    "unauthorized",
    "权限不足",
    "无权限",
    "forbidden",
    "禁止访问",
    "没有权限",
    "认证失败",
    "未授权",
]

# HTTP 200 但业务码 401/403（RuoYi AjaxResult 风格）→ 同样视为拒绝
_DENY_BODY_PATTERN = re.compile(r'"code"\s*:\s*40[13]')

# 页面内 API 路径提取（fetch/axios 调用与链接），限制为管理类路径形态
_PAGE_PATH_PATTERN = re.compile(r"[\"'`](/[a-zA-Z][a-zA-Z0-9_/\-]{3,60})[\"'`]")


def _looks_denied(status_code: int, body: str) -> bool:
    """判定响应是否为'明确拒绝'（HTTP 状态码 + 业务语义双重判定）"""
    if status_code in (401, 403):
        return True
    body_lower = (body or "").lower()
    if _DENY_BODY_PATTERN.search(body or ""):
        return True
    return any(kw in body_lower for kw in DENY_KEYWORDS)


def _candidate_paths(variant: str = "") -> List[str]:
    """生成字典候选路径（按变体加前缀，全部去重保序）"""
    prefixes = [""]
    if variant in (
        "",
        "ruoyi",
        "ruoyi-vue",
        "ruoyi-vue3",
        "ruoyi-app",
        "ruoyi-plus",
        "ruoyi-cloud",
        "ruoyi-cloud-plus",
    ):
        # /prod-api 前缀对所有前后端分离变体成立
        prefixes.append("/prod-api")
    paths: List[str] = []
    for ep in RUOYI_ADMIN_ENDPOINTS:
        for p in prefixes:
            paths.append(p + ep)
    return paths


def _extract_paths_from_page(text: str) -> List[str]:
    """从登录态页面 HTML/JS 提取候选 API 路径（管理类形态过滤）"""
    found: List[str] = []
    for m in _PAGE_PATH_PATTERN.finditer(text or ""):
        p = m.group(1)
        low = p.lower()
        if low.endswith(_STATIC_SUFFIXES):
            continue
        # 管理类路径形态：≥2 段且含 list/detail/info/export 等关键词，或 /system /monitor 前缀
        segs = [s for s in p.split("/") if s]
        if len(segs) < 2:
            continue
        if segs[0] in ("system", "monitor", "tool", "prod-api") or any(
            kw in low for kw in ("list", "detail", "info", "export", "page")
        ):
            found.append(p)
    return found


class AuthSurfaceScanner:
    """认证后深度扫描器：登录态接口资产盘点 + 越权矩阵

    用法：
        scanner = AuthSurfaceScanner(target, admin_session, low_session=None)
        assets, vulns = scanner.run()
    """

    def __init__(
        self,
        target: str,
        admin_session,
        low_session=None,
        use_crawler: bool = False,
        max_crawl_pages: int = 10,
    ):
        """初始化扫描器

        Args:
            target: 目标站点根 URL（已归一化）
            admin_session: 高权（管理员）SessionManager，登录态由调用方准备
            low_session: 低权普通用户 SessionManager（可选，缺省跳过垂直越权维度）
            use_crawler: 是否叠加浅层爬虫端点发现（默认 False，字典+页面提取已够）
            max_crawl_pages: 爬虫最大页面数
        """
        self.target = target
        self.admin_session = admin_session
        self.low_session = low_session
        self.use_crawler = use_crawler
        self.max_crawl_pages = max_crawl_pages

    # ── 端点发现 ──

    def discover(self, variant: str = "") -> List[Tuple[str, str]]:
        """候选端点发现：(path, source) 列表，字典 + 页面提取 + 可选爬虫，去重保序

        Args:
            variant: 若依变体标识（影响前缀生成，可选）
        """
        candidates: List[Tuple[str, str]] = []
        seen = set()

        def _add(path: str, source: str):
            if path.endswith(_STATIC_SUFFIXES):
                return
            if path in seen:
                return
            seen.add(path)
            candidates.append((path, source))

        # 1. 端点字典（含 /prod-api 变体）
        for p in _candidate_paths(variant):
            _add(p, "dict")

        # 2. 登录态页面提取（首页 + 常见入口页）
        for page in ("/", "/index", "/prod-api/", "/system/user"):
            try:
                resp = self.admin_session.get(join_url(self.target, page))
                if getattr(resp, "status_code", 0) == 200:
                    for p in _extract_paths_from_page(resp.text or ""):
                        _add(p, "page")
            except Exception:
                logger.debug("页面端点提取失败: %s", page, exc_info=True)

        # 3. 可选深扫爬虫（登录态会话）：HTML 链接 + JS 端点提取
        #    RuoYi-Vue/Plus 为 SPA，管理 API 路径多藏于 JS 包中（/system/user/list 等），
        #    纯 HTML 爬取覆盖不足——用 crawl_with_js_urls 抓 JS 文件后经 JSExtractor 提取。
        if self.use_crawler:
            try:
                from lib.crawler import Crawler
                from lib.js_extractor import JSExtractor

                crawler = Crawler(max_depth=1, max_pages=self.max_crawl_pages)
                crawled = crawler.crawl_with_js_urls(self.target + "/", self.admin_session)
                for u in crawled.get("all", []):
                    path = u.split("://", 1)[-1].split("/", 1)
                    if len(path) == 2 and path[1]:
                        _add("/" + path[1].split("?")[0], "crawl")
                # JS 端点提取（登录态会话下载 JS 包，SPA API 路径主要来源）
                js_urls = [join_url(self.target, js) if js.startswith("/") else js for js in crawled.get("js", [])]
                for ep in JSExtractor(min_path_segments=2).extract_from_urls(js_urls, self.admin_session):
                    p = ep.url
                    if p.startswith("http"):
                        path_part = p.split("://", 1)[-1].split("/", 1)
                        p = "/" + path_part[1] if len(path_part) == 2 and path_part[1] else ""
                    if p and p.startswith("/"):
                        _add(p.split("?")[0], "js")
            except Exception:
                logger.debug("爬虫/JS 端点发现失败（忽略，不影响字典路径）", exc_info=True)

        return candidates

    # ── 资产盘点 ──

    def inventory(self, candidates: List[Tuple[str, str]]) -> List[SurfaceAsset]:
        """高权会话盘点：逐个 GET，200 记入资产（401/403/异常不入清单）"""
        assets: List[SurfaceAsset] = []
        for path, source in candidates:
            url = join_url(self.target, path)
            try:
                resp = self.admin_session.get(url)
            except Exception:
                logger.debug("盘点请求失败: %s", url, exc_info=True)
                continue
            code = getattr(resp, "status_code", 0)
            if code != 200:
                continue
            body = resp.text or ""
            # HTTP 200 但业务 401/403（未真正登录可达）→ 不入资产
            if _looks_denied(code, body):
                continue
            assets.append(
                SurfaceAsset(
                    url=url,
                    source=source,
                    admin_code=code,
                    admin_size=len(body),
                )
            )
        return assets

    # ── 越权矩阵 ──

    def _anon_session(self):
        """构造干净匿名会话（无任何凭证头/cookie）"""
        from core.session import SessionManager

        return SessionManager()

    def authz_matrix(self, assets: List[SurfaceAsset]) -> Tuple[List[SurfaceAsset], List[LogicVuln]]:
        """越权矩阵：匿名重放（未授权访问）+ 低权重放（垂直越权）

        Returns:
            (更新 verdict 后的资产清单, 漏洞列表)
        """
        vulns: List[LogicVuln] = []
        anon = self._anon_session()

        for asset in assets:
            verdicts = []
            # 1. 匿名重放 → 未授权访问
            try:
                resp = anon.get(asset.url)
                code = getattr(resp, "status_code", 0)
                body = resp.text or ""
                asset.anon_code = code
                if _looks_denied(code, body):
                    verdicts.append("safe")
                elif code == 200 and len(body) > 0:
                    verdicts.append("confirmed")
                    vulns.append(
                        LogicVuln(
                            vuln_type="unauthorized_access",
                            name=f"未授权访问 - {asset.url}",
                            severity="high",
                            url=asset.url,
                            method="GET",
                            evidence=f"匿名请求返回 200，响应大小 {len(body)}B（高权盘点该接口登录态可达）",
                            fix="接口增加鉴权过滤器，未认证请求返回 401",
                            fix_detail=(
                                "【代码修复】Spring Security 配置该路径 authenticated()，"
                                "或自定义 Filter 校验 Token\n"
                                "【合规】OWASP A01:2021 / 等保 2.0 8.1.4"
                            ),
                            reproduce=f'curl -i "{asset.url}"\n# 预期：401（实际返回 200 + 业务数据）',
                            description="接口未做任何认证校验，匿名用户可直接读取业务数据",
                        )
                    )
                else:
                    verdicts.append("unknown")
            except Exception:
                logger.debug("匿名重放失败: %s", asset.url, exc_info=True)
                asset.anon_code = None
                verdicts.append("unknown")

            # 2. 低权重放 → 垂直越权（配置了低权账号时）
            if self.low_session is not None:
                try:
                    resp = self.low_session.get(asset.url)
                    code = getattr(resp, "status_code", 0)
                    body = resp.text or ""
                    asset.low_code = code
                    if _looks_denied(code, body):
                        verdicts.append("safe")
                    elif code == 200 and len(body) > 0:
                        verdicts.append("confirmed")
                        vulns.append(
                            LogicVuln(
                                vuln_type="privilege_escalation",
                                name=f"垂直越权 - 低权用户可访问管理接口 {asset.url}",
                                severity="high",
                                url=asset.url,
                                method="GET",
                                evidence=f"低权用户请求管理接口返回 200，响应大小 {len(body)}B（无拒绝语义）",
                                fix="实施基于角色的访问控制（RBAC），接口层校验用户角色",
                                fix_detail=(
                                    "【代码修复】Spring Security @PreAuthorize(\"@ss.hasRole('admin')\")\n"
                                    "【权限框架】Sa-Token 注解 @SaCheckRole / Shiro @RequiresRoles\n"
                                    "【合规】OWASP A01:2021 / 等保 2.0 8.1.4"
                                ),
                                reproduce=(
                                    f"# 1. 低权账号登录\n"
                                    f'curl -d "username=user&password=pass" "{join_url(self.target, "/login")}"\n\n'
                                    f"# 2. 携带低权凭证访问管理接口\n"
                                    f'curl -H "Authorization: Bearer <user-token>" "{asset.url}"\n\n'
                                    f"# 预期：403（实际返回 200 + 管理数据）"
                                ),
                                description="低权用户通过认证后可访问应仅限管理员访问的接口（RBAC 缺失）",
                            )
                        )
                    else:
                        verdicts.append("unknown")
                except Exception:
                    logger.debug("低权重放失败: %s", asset.url, exc_info=True)
                    asset.low_code = None
                    verdicts.append("unknown")

            # 资产级综合判定：任一维度 CONFIRMED → confirmed；全部 SAFE → safe；否则 unknown
            if "confirmed" in verdicts:
                asset.verdict = "confirmed"
            elif verdicts and all(v == "safe" for v in verdicts):
                asset.verdict = "safe"
            else:
                asset.verdict = "unknown"

        return assets, vulns

    # ── 一键运行 ──

    def run(self, variant: str = "") -> Tuple[List[SurfaceAsset], List[LogicVuln]]:
        """完整流程：发现 → 盘点 → 越权矩阵

        Returns:
            (资产清单, 漏洞列表)
        """
        candidates = self.discover(variant=variant)
        assets = self.inventory(candidates)
        return self.authz_matrix(assets)


# ============================================================
# 模式入口（CLI 接线）
# ============================================================


def _login(target: str, session, username: str, password: str) -> Tuple[bool, str]:
    """登录尝试（双路）：token 型端点优先，回退标准登录链

    1. POST /prod-api/auth/login（JSON）→ 取 token 设 Authorization（RuoYi-Plus/Cloud
       风格统一认证入口，签名靶场同款）
    2. 回退 RuoYiAuthChain（/login：v4 Session / v5 JWT 双链路）

    Returns:
        (是否成功, 登录方式/失败原因)
    """
    # 1. token 型统一认证端点
    try:
        resp = session.post(
            join_url(target, "/prod-api/auth/login"),
            json={"username": username, "password": password},
        )
        body = {}
        try:
            body = resp.json()
        except (ValueError, TypeError):
            body = {}
        token = body.get("token") or ""
        if getattr(resp, "status_code", 0) == 200 and body.get("code") in (0, 200) and token:
            session.session.headers["Authorization"] = f"Bearer {token}"
            return True, "token(/prod-api/auth/login)"
    except Exception:
        logger.debug("token 型登录端点不可达，回退标准链路", exc_info=True)

    # 2. 标准登录链（/login）
    from core.auth_chain import RuoYiAuthChain

    return RuoYiAuthChain(target, session, username=username, password=password).login()


def run_auth_surface_mode(args, target: str, variant: str = "") -> Tuple[List[SurfaceAsset], List[LogicVuln]]:
    """认证后深度扫描模式入口（--auth-surface）

    登录编排：高权凭证取 --auth-login（user:pass，双路自动登录）；
    低权账号取 --surface-account（可多次，同链路登录，取第一个成功者）。

    Args:
        args: CLI 参数（需 auth_login / surface_account / proxy / debug / timeout）
        target: 目标 URL
        variant: 若依变体标识（可选）

    Returns:
        (资产清单, 漏洞列表)；高权登录失败返回 ([], [])
    """
    from core.session import SessionManager

    proxy = getattr(args, "proxy", None)
    debug = getattr(args, "debug", False)
    timeout = getattr(args, "timeout", None)

    # 1. 高权会话登录
    admin_session = SessionManager(proxy=proxy, debug=debug, timeout=timeout)
    user_pass = getattr(args, "auth_login", None)
    if not user_pass:
        logger.warning("--auth-surface 需要 --auth-login user:pass 提供高权凭证")
        return [], []
    username, _, password = user_pass.partition(":")
    ok, reason = _login(target, admin_session, username, password)
    if not ok:
        logger.warning("高权登录失败（%s），认证后深度扫描终止", reason)
        return [], []

    # 2. 低权会话登录（可选，多个取第一个成功的）
    low_session = None
    for account in getattr(args, "surface_account", None) or []:
        low_user, _, low_pass = account.partition(":")
        s = SessionManager(proxy=proxy, debug=debug, timeout=timeout)
        ok_low, _ = _login(target, s, low_user, low_pass)
        if ok_low:
            low_session = s
            break

    # 3. 扫描
    scanner = AuthSurfaceScanner(
        target,
        admin_session,
        low_session=low_session,
        use_crawler=bool(getattr(args, "crawl", False)),
    )
    assets, vulns = scanner.run(variant=variant)

    # 4. 资产清单落盘（可选）
    output_path = getattr(args, "surface_output", None)
    if output_path:
        import json
        import os

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                {"target": target, "variant": variant, "assets": [a.to_dict() for a in assets]},
                f,
                ensure_ascii=False,
                indent=2,
            )

    admin_session.close()
    if low_session is not None:
        low_session.close()
    return assets, vulns
