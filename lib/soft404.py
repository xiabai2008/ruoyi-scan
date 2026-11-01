# lib/soft404.py — 软 404（catch-all 路由）基线探测
"""软 404 基线探测：判断「HTTP 200」能否作为「文件/路径存在」的证据。

为什么需要它
============
很多站点对**任意**路径都返回 HTTP 200 加一段固定内容：

  - SPA 前端（Vue/React）配 `try_files $uri /index.html` 的 nginx 兜底
  - 自定义错误页把 404 渲染成 200
  - CDN / 网关把上游错误统一改写为 200

在这类站点上，仅凭状态码判定存在性的插件会一次性误报几十个「泄露文件」。
实测（2026-09-16）：`backup_scan` 在一个完全正常的页面上报告了 65 个可访问备份文件。

正确做法是先探测一个**必然不存在**的随机路径，把它作为基线：

  - 基线也是 2xx + 有内容  → 站点存在兜底路由，状态码不可信，必须比对响应内容
  - 基线是 404/403 等      → 状态码可信，按原有逻辑判定即可

用法
====
    from lib.soft404 import Soft404Baseline

    baseline = Soft404Baseline.probe(target, session)
    ...
    if baseline.looks_like_real_file(resp):
        found.append(path)

注意：`looks_like_real_file()` 只回答「这个响应是否指向一个独立文件」，
不判断该文件是否敏感。敏感性与危害判断仍由插件负责。
"""

import hashlib
import json
import re
import uuid
from typing import Any, Iterable, Optional, Tuple
from urllib.parse import urlparse

from common.logger import get_logger
from core.http import join_url

logger = get_logger(__name__)

# 单次基线探测的随机路径前缀，避免与真实目录命名冲突
_PROBE_PREFIX = "__ruoyi_scan_soft404_probe__"

# 计算内容摘要时只取前 N 字节：兜底页通常整页一致，取前缀足以判别，
# 同时避免大文件（如备份包）全量哈希带来的开销
_DIGEST_BYTES = 4096


def _digest(body: bytes) -> str:
    """计算响应体前 N 字节的 sha256 摘要"""
    return hashlib.sha256(body[:_DIGEST_BYTES]).hexdigest()


# 响应体里的路径 token：至少两段、以字母数字开头（可带前导斜杠）。
# 前导斜杠必须可选——若依回显的资源名是 "druid/index.html"（无前导斜杠），
# 只匹配 "/xxx" 会漏掉它，归一化后同一类错误页仍然对不上。
_PATH_TOKEN_RE = re.compile(rb"[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+")


def _is_config_server_wildcard(body: bytes) -> bool:
    """识别 Spring Cloud Config Server 的通配 JSON 响应。

    两种形态都会出现：
      - `/{name}/{profile}`：{"name":...,"profiles":[...],"propertySources":[...]}
      - `/{name}-{profile}.json`：直接返回合并后的配置源，含 spring/server 等键
    这类响应由任意路径触发，不能作为「文件存在」的证据。
    """
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except (TypeError, ValueError):
        return False
    if not isinstance(payload, dict):
        return False
    if {"name", "profiles", "propertySources"} <= set(payload):
        return True
    spring = payload.get("spring")
    return isinstance(spring, dict) and any(key in spring for key in ("datasource", "application", "redis"))


def _html_echoes_path(body: bytes, path: str) -> bool:
    """判断响应是否是「短 HTML 页面回显请求路径」的 catch-all。

    这类兜底的麻烦之处：**每个路径的响应长度都不同**（路径越长相，长度越长），
    所以长度比对、逐字节摘要、归一化摘要全部失效。只能靠「页面里出现了路径」识别。

    实测（2026-11-01 盲测 v2 C4-6）：
        GET /index.bak → <html><body><h2>页面: index.bak</h2></body></html>
        → backup_scan 把 60 个候选路径全当成「真实备份文件」

    Args:
        body: 响应体字节
        path: 请求路径（可含查询串）

    Returns:
        True 表示这是路径回显页，不能当作「文件存在」的证据。
    """
    if not body or not path:
        return False
    # 只处理短页面：真实文件（Swagger UI / Druid / 备份 SQL）不会短到这个程度
    if len(body) > 600:
        return False
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return False
    low = text.lower()
    if "<html" not in low and "<body" not in low and "<h2" not in low:
        return False
    cleaned = (urlparse(path).path or path).strip("/")
    if not cleaned:
        return False

    # 与 lib.matcher.is_path_echo_page 同一判据：剥掉路径后看剩余内容。
    # 不能用裸子串匹配 —— 真实控制台的品牌词（如 `<title>RocketMQ Dashboard</title>`）
    # 会让路径名以合法词边界出现，裸匹配会误杀真实页面。
    seg = cleaned.rsplit("/", 1)[-1].lower()
    # 同 lib.matcher：正文里没出现请求路径就谈不上回显，避免误杀短的真实页面。
    cleaned_l = cleaned.lower()
    if cleaned_l not in low and seg not in low:
        return False
    stripped = low.replace(cleaned_l, "").replace(seg, "")
    residual = re.sub(r"<[^>]*>", "", stripped)
    residual = re.sub(r"[\s:：\-—()（）\[\]{}'\"+/.,;]", "", residual)
    if len(residual) <= 20:
        return True
    # 与 lib/matcher 同款修正：按「残留 / 正文有效内容」的比例判断，而不是按整页长度。
    # 真实短页面（如 88 字节的 Druid 监控页）剥掉路径名后文案仍在，不该判成回显。
    content = re.sub(r"<[^>]*>", "", low)
    content = re.sub(r"[\s:：\-—()（）\[\]{}'\"+/.,;]", "", content)
    return len(text) <= 150 and bool(content) and len(residual) * 2 <= len(content)


def _derive_echo_tokens(path: str) -> Tuple[str, ...]:
    """从请求路径派生可能在响应正文里回显的 token。

    除了完整路径，还包含去前导斜杠、basename 和每个长度 >=3 的路径段。
    Config Server 会把 `/swagger-ui/index.html` 拆成
    `"name":"swagger-ui"` + `"profiles":["index.html"]`，只归一化连续路径
    片段匹配不上，需要按 token 单独替换。
    """
    if not path:
        return ()
    parsed_path = urlparse(path).path or path
    tokens = {parsed_path, parsed_path.lstrip("/")}
    segments = [segment for segment in parsed_path.split("/") if segment]
    if segments:
        tokens.add(segments[-1])
    tokens.update(segment for segment in segments if len(segment) >= 3)
    return tuple(sorted(token for token in tokens if token))


def _digest_canonical(body: bytes, tokens: Iterable[str] = ()) -> str:
    """把响应体里的路径片段和回显 token 归一化后再算摘要

    为什么需要：兜底错误页常把请求路径回显在正文里。Spring Boot 4（若依 v4.8.3
    使用）对不存在的资源返回 **HTTP 200** + JSON：
        {"msg":"No static resource druid/index.html for request '/druid/index.html'","code":500}
    正文随请求路径变化，逐字节摘要必然不同 → 软 404 保护失效 → 目录扫描把
    几百条「资源不存在」全判成命中（实测 v4.8.3 靶场 696 条里报出 672 条命中）。

    Config Server 还会把路径拆成 `"name":"swagger-ui"` + `"profiles":["index.html"]`，
    因此再按调用方给的 token 做一次替换。归一化后同一类错误页的摘要一致。
    """
    canon = _PATH_TOKEN_RE.sub(b"*", body[:_DIGEST_BYTES])
    for token in tokens:
        if token:
            canon = canon.replace(token.encode("utf-8"), b"*")
    return hashlib.sha256(canon).hexdigest()


# 框架自带的「资源不存在」错误页标记。这类页面在 Spring Boot 4（若依 v4.8.3）
# 下返回 HTTP 200 + JSON，正文里回显请求路径 → 逐字节与归一化比对都可能失效
# （单段路径名不含斜杠时归一化也匹配不上）。命中标记即判为「不是独立资源」。
_MISSING_RESOURCE_RE = re.compile(
    rb"no static resource|no handler found|resource not found",
    re.IGNORECASE,
)

# 登录墙的「认证失败」JSON 也不能当作「文件存在」的证据。
# 若依前后端分离版未认证访问任意受保护路径返回 HTTP 200 +
#   {"msg":"请求访问：/index.bak，认证失败，无法访问系统资源","code":401}
# 正文回显请求路径 → 逐字节摘要和归一化摘要都对不上基线，会被判成「独立文件」。
# 实测 2026-10-29 R7（RuoYi-Vue 3.8.9，nginx 只反代 /prod-api/）：
#   backup_scan 报出 60 个「备份文件」（全是 401 回显）、目录扫描 696 条报 240 条命中。
# 注意：bytes 正则不能直接写中文（SyntaxError），只匹配 ASCII 的 code 字段。
_AUTH_FAILURE_RE = re.compile(rb'"(?:code|status)"\s*:\s*(?:401|403)\b')


class Soft404Baseline:
    """软 404 基线：记录随机不存在路径的响应特征，用于判别兜底路由"""

    __slots__ = (
        "reachable",
        "status_code",
        "length",
        "digest",
        "probe_path",
        "canonical_digest",
        "echo_tokens",
        "config_server_wildcard",
    )

    def __init__(
        self,
        reachable: bool = False,
        status_code: int = 0,
        length: int = 0,
        digest: str = "",
        probe_path: str = "",
        canonical_digest: str = "",
        echo_tokens: Iterable[str] = (),
        config_server_wildcard: bool = False,
    ) -> None:
        self.reachable = reachable  # 基线请求是否成功拿到响应
        self.status_code = status_code
        self.length = length
        self.digest = digest
        self.probe_path = probe_path
        # 路径归一化后的摘要：用于识别「正文随请求路径变化」的兜底错误页
        self.canonical_digest = canonical_digest
        # 基线探测路径派生出的回显 token（完整路径/去斜杠/basename/路径段）
        self.echo_tokens = tuple(echo_tokens)
        # 基线响应是否来自 Config Server 通配路由（两种响应形态都算）
        self.config_server_wildcard = config_server_wildcard

    @property
    def is_catch_all(self) -> bool:
        """站点是否存在兜底路由（随机不存在路径也返回 2xx 且有内容）"""
        return self.reachable and 200 <= self.status_code < 300 and self.length > 0

    def looks_like_real_file(self, resp: Optional[Any], path: str = "") -> bool:
        """判断响应是否指向一个独立文件（而非兜底页）

        Args:
            resp: 待判定的响应对象（requests.Response 兼容，需有 status_code/content，
                  真实响应还应带 url 供派生回显 token）
            path: 可选请求路径；缺省时从 resp.url 派生

        Returns:
            True 表示可判定为独立文件；False 表示不存在或与兜底页无法区分
        """
        if resp is None:
            return False
        code = getattr(resp, "status_code", 0)
        # 仅 2xx 视为「有响应体返回」：3xx（重定向到登录/错误页）不构成文件存在的证据
        if not (200 <= code < 300):
            return False
        body = getattr(resp, "content", None) or b""
        if not body:
            # 部分框架对未知路径统一返回空 200，无内容不足以证明文件存在
            return False
        # 登录墙产物：先于一切「内容有差异」判断排除——它对任何路径都返回同一类
        # 「认证失败」JSON，与「文件存在」无关（见 _AUTH_FAILURE_RE 注释）
        if _AUTH_FAILURE_RE.search(body):
            return False
        if not self.is_catch_all:
            # 站点无兜底路由：状态码 2xx + 非空即视为真实文件
            return True
        # 站点有兜底路由：与基线页完全一致 → 判定为同一个兜底页，不是独立文件
        if len(body) == self.length and _digest(body) == self.digest:
            return False
        # Config Server 对 /{name}/{profile} 与 /{name}-{profile}.json 返回两种不同形态；
        # 两者都是通配响应，不能靠逐字节摘要区分。
        if self.config_server_wildcard and _is_config_server_wildcard(body):
            return False
        # 正文随请求路径变化的兜底错误页：归一化后摘要一致 → 仍是同一个兜底页。
        # 真实响应带 url 时用候选路径的 token；测试替身没有 url 时退化为旧行为。
        candidate_path = path
        if not candidate_path:
            candidate_path = urlparse(getattr(resp, "url", "") or "").path
        candidate_tokens = _derive_echo_tokens(candidate_path)
        if self.canonical_digest and _digest_canonical(body, candidate_tokens) == self.canonical_digest:
            return False
        # 框架自带的「资源不存在」错误页：正文随请求路径变化时两种比对都可能失效，
        # 靠标记判定更稳（Spring Boot 4 / 若依 v4.8.3 实测）
        if _MISSING_RESOURCE_RE.search(body):
            return False
        # HTML catch-all 把**请求路径**回显进页面：每个路径的响应长度都不同
        # （路径越长相，长度越长），所以长度/摘要/归一化比对全部失效。
        # 实测 2026-11-01 盲测 v2 C4-6：
        #   GET /index.bak → <html><body><h2>页面: index.bak</h2></body></html>
        #   → 60 个「备份文件」全是同一个 catch-all 页，被判成真文件。
        # 判据：短 HTML 页面里出现了候选路径本身。
        if _html_echoes_path(body, candidate_path):
            return False
        # 内容与兜底页不同 → 确有差异，保守放行（由插件继续做关键字校验）
        return True

    def describe(self) -> str:
        """人类可读的基线描述，供 evidence 说明使用"""
        if not self.reachable:
            return "基线探测未取得响应"
        if self.is_catch_all:
            return f"站点存在兜底路由（基线 {self.probe_path} 返回 {self.status_code} / {self.length} 字节），已启用内容比对"
        return f"基线 {self.probe_path} 返回 {self.status_code}，状态码可信"

    @classmethod
    def probe(cls, target: str, session: Any) -> "Soft404Baseline":
        """探测软 404 基线

        Args:
            target: 目标站点根 URL
            session: 已配置的 HTTP 会话（需提供 get(url)）

        Returns:
            Soft404Baseline 实例。请求异常时 reachable=False，
            此时 looks_like_real_file() 退化为纯状态码判定（与加固前行为一致），
            不会因基线探测失败而漏报。
        """
        token = uuid.uuid4().hex
        probe_path = f"/{_PROBE_PREFIX}_{token}/does-not-exist-{token}.txt"
        try:
            resp = session.get(join_url(target, probe_path))
        except Exception as e:
            # 记录失败原因：degraded 后 looks_like_real_file() 会退化为纯状态码判定，
            # 必须让操作者能区分「站点无兜底路由」与「基线探测本身失败」。
            # 不打 traceback：重定向环 / 超时等都是**预期内的目标异常**，整栈回溯会
            # 让使用者以为工具崩了（审计实测：一个 302 循环刷出两屏 Traceback）。
            logger.warning("软 404 基线探测失败（%s）：%s: %s", probe_path, type(e).__name__, e)
            logger.debug("软 404 基线探测异常详情", exc_info=True)
            return cls(reachable=False, probe_path=probe_path)
        body = getattr(resp, "content", None) or b""
        echo_tokens = _derive_echo_tokens(probe_path)
        return cls(
            reachable=True,
            status_code=getattr(resp, "status_code", 0),
            length=len(body),
            digest=_digest(body) if body else "",
            canonical_digest=_digest_canonical(body, echo_tokens) if body else "",
            probe_path=probe_path,
            echo_tokens=echo_tokens,
            config_server_wildcard=_is_config_server_wildcard(body) if body else False,
        )
