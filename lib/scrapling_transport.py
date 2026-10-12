# Scrapling 对抗型传输层（方案 A：按需接入）
#
# 定位：把 Scrapling 的「TLS/JA3 指纹伪装」与「隐身浏览器 JS 挑战绕过」能力，
#       作为 BypassSession 的一个**可选传输后端（transport engine）**接入。
#
# 为什么需要它（ruoyi-scan 的既有缺口）：
#   SessionManager 基于 requests，TLS 指纹固定、且不执行 JS。面对 Cloudflare
#   Turnstile / Interstitial 这类 JS 挑战，请求会被直接 403 拦截——既有的
#   tamper.py / waf_bypass.py 只在 payload 层变形，对传输层指纹无能为力。
#
# 设计纪律（对齐三态判定，绝不判 SAFE）：
#   1. 缺依赖 / 抓取失败 / 超时 → **抛异常**，由 WafBypassCoordinator 兜底为
#      「原状态 + UNKNOWN」，绝不因本层异常而降级为 SAFE。
#   2. 按需启用：默认引擎仍为 requests（BypassSession 的默认值），只有
#      transport_config['engine'] == 'scrapling' 时才走本层，零行为变化。
#   3. 重资源：浏览器抓取为秒级（实测 CF 挑战 3~80s），**禁止进入热扫描路径**，
#      仅在被 WAF 拦截后由绕过编排器按需调用。
from __future__ import annotations

import json as _json
import re
import time
from datetime import timedelta
from typing import Any, Dict, Optional

from lib.waf_bypass import BypassContext, WafBypassStrategy


class ResponseAdapter:
    """把 Scrapling 的 Response 适配成 ruoyi-scan 插件契约

    插件侧消费的字段（实测统计）：.text(67) / .status_code(56) / .headers(25) / .url(7)。
    其中与 Scrapling 的真实差异只有一处：Scrapling 用 .status，插件要 .status_code；
    其余（.headers/.url/.reason）同名直通，.text 由原始 body 解码得到。

    注意：Scrapling 的 Response 继承自 Selector，其 .text 是「当前节点文本」而非
    整个响应体；取响应体必须用 .body（bytes）。
    """

    def __init__(self, sf_resp: Any, elapsed_seconds: float) -> None:
        self._sf = sf_resp
        self.status_code: int = int(getattr(sf_resp, "status", 0) or 0)
        self.reason: str = getattr(sf_resp, "reason", "") or ""
        # 插件契约要求 headers 大小写不敏感（与 requests 一致），否则
        # resp.headers['Content-Type'] 这类访问会因 Scrapling 返回小写键而 KeyError
        raw_headers = getattr(sf_resp, "headers", {}) or {}
        try:
            from requests.structures import CaseInsensitiveDict

            self.headers: Any = CaseInsensitiveDict(raw_headers)
        except ImportError:  # pragma: no cover - requests 缺失时退化为普通 dict
            self.headers = dict(raw_headers)
        self.url: str = getattr(sf_resp, "url", "") or ""
        self.cookies: Any = getattr(sf_resp, "cookies", {})
        self.history: list = list(getattr(sf_resp, "history", []) or [])
        self.elapsed: timedelta = timedelta(seconds=elapsed_seconds)
        # 编码取自响应 Content-Type 声明（缺省 utf-8），避免 GBK/Big5 页面被当 utf-8 解码
        self.encoding: str = self._detect_encoding()
        body = getattr(sf_resp, "body", b"") or b""
        self.content: bytes = body.encode("utf-8", "ignore") if isinstance(body, str) else bytes(body)
        self._text: Optional[str] = None

    def _detect_encoding(self) -> str:
        """按响应 Content-Type 的 charset 推导编码，缺省 utf-8"""
        ctype = ""
        for k, v in (getattr(self._sf, "headers", None) or {}).items():
            if str(k).lower() == "content-type":
                ctype = str(v)
                break
        m = re.search(r"charset=([\w\-]+)", ctype, re.IGNORECASE)
        return m.group(1) if m else "utf-8"

    @property
    def text(self) -> str:
        if self._text is None:
            # errors="replace"：编码判断错误时以 U+FFFD 显式呈现，而非静默丢弃字节
            self._text = self.content.decode(self.encoding, "replace")
        return self._text

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def json(self) -> Any:
        return _json.loads(self.text)

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<ResponseAdapter [{self.status_code}] {len(self.content)}b {self.url}>"


class ScraplingTransport:
    """Scrapling 传输引擎（懒加载，缺依赖即安全失败）

    两种模式：
        - stealth:     StealthyFetcher（patchright 隐身浏览器），绕过 CF Turnstile/Interstitial。
                       **仅支持 GET**（挑战场景的核心是先把页面拿到手、拿到 cf_clearance）。
        - impersonate: Fetcher（curl_cffi），伪造 Chrome TLS/JA3 指纹的纯 HTTP 请求，快、支持 POST。

    Usage:
        t = ScraplingTransport(mode="stealth").get("https://protected.example/")
        print(t.status_code, len(t.text))
    """

    def __init__(
        self,
        mode: str = "stealth",
        timeout: float = 120.0,
        headless: bool = True,
        network_idle: bool = True,
        solve_cloudflare: bool = True,
    ) -> None:
        self.mode = mode
        self.timeout = timeout
        self.headless = headless
        self.network_idle = network_idle
        # 必须显式开启：否则 StealthyFetcher 仅加载挑战页就返回（403），不会调用
        # Cloudflare 求解器。实测不开启时 scrapingcourse 返回 403/7s，开启后 200。
        self.solve_cloudflare = solve_cloudflare
        self._count = 0
        self._fetchers: Optional[tuple] = None
        # cf_clearance 收割结果（prime 后填充，供 apply_clearance 注入基础会话）
        self._clearance_cookies: Dict[str, str] = {}
        self._clearance_ua: str = ""

    # -- 懒加载：未安装 scrapling 时给出可操作报错，由上游兜底为 UNKNOWN --
    def _load(self):
        if self._fetchers is None:
            try:
                from scrapling.fetchers import Fetcher, StealthyFetcher
            except ImportError as exc:  # pragma: no cover - 环境相关
                raise RuntimeError(
                    "Scrapling 未安装，对抗传输层不可用（安装：pip install 'ruoyi-scan[adversarial]'）"
                ) from exc
            self._fetchers = (Fetcher, StealthyFetcher)
        return self._fetchers

    # -- cf_clearance 收割与注入（Cookie 复用，覆盖 POST）--
    @staticmethod
    def _cookie_dict(raw: Any) -> Dict[str, str]:
        """归一化 Scrapling 的 cookies 为 {name: value}

        Scrapling 浏览器引擎返回的是 Playwright cookie 对象元组
        （含 name/value/domain/expires(float)/httpOnly...，见 engines/toolbelt/convertor.py），
        直接透传给 requests 会因 expires 是 float 而报 AttributeError，必须只取 name/value。
        """
        out: Dict[str, str] = {}
        items = raw if isinstance(raw, (list, tuple)) else [raw]
        for c in items:
            if isinstance(c, dict) and c.get("name"):
                out[str(c["name"])] = str(c.get("value", ""))
        return out

    @staticmethod
    def _header(headers: Any, name: str) -> str:
        """大小写不敏感地取请求头（浏览器 UA 头键为小写 'user-agent'）"""
        for k, v in (headers or {}).items():
            if str(k).lower() == name.lower():
                return str(v)
        return ""

    def prime(self, url: str) -> "ResponseAdapter":
        """用隐身浏览器解一次 JS 挑战并**收割 cf_clearance + UA**

        拿到后即可注入基础 SessionManager，让后续所有请求（含 POST）走快速的
        requests 路径，无需每次都起浏览器。cf_clearance 按域生效，同域后续路径通用。

        实测（scrapingcourse.com）：收割后 requests + cookie 复用可稳定 200；
        而 curl_cffi 指纹反而更易被拒——故复用目标选 requests 会话。
        """
        _Fetcher, StealthyFetcher = self._load()
        t0 = time.monotonic()
        resp = StealthyFetcher.fetch(
            url,
            headless=self.headless,
            network_idle=self.network_idle,
            timeout=int(self.timeout * 1000),
            solve_cloudflare=self.solve_cloudflare,
        )
        self._count += 1
        self._clearance_cookies = self._cookie_dict(getattr(resp, "cookies", None))
        self._clearance_ua = self._header(getattr(resp, "request_headers", None), "user-agent")
        if not self._clearance_cookies:
            raise RuntimeError("对抗传输层：隐身抓取未收割到任何 Cookie（挑战可能未解开）")
        return ResponseAdapter(resp, time.monotonic() - t0)

    @property
    def clearance_ready(self) -> bool:
        return bool(self._clearance_cookies)

    def apply_clearance(self, session: Any) -> None:
        """把收割到的 cf_clearance + UA 注入基础会话（requests 系）

        接受 SessionManager（有 .session 属性）或裸 requests.Session。
        UA 必须与解挑战时的浏览器一致——cf_clearance 绑定 UA，UA 不匹配会被 CF 判无效。
        """
        if not self._clearance_cookies:
            return
        raw = getattr(session, "session", session)
        try:
            raw.cookies.update(self._clearance_cookies)
        except AttributeError as exc:  # pragma: no cover - 契约保护
            raise RuntimeError("apply_clearance 需要 requests.Session（或其封装）") from exc
        if self._clearance_ua:
            try:
                raw.headers.update({"User-Agent": self._clearance_ua})
            except (AttributeError, TypeError) as exc:  # pragma: no cover - 契约保护
                raise RuntimeError("apply_clearance 需要可写的 requests.Session.headers") from exc

    def request(self, method: str, url: str, **kwargs: Any) -> ResponseAdapter:
        """统一出口：按 mode 选择 fetcher。任何失败均向上抛异常（不吞、不降级）。"""
        Fetcher, StealthyFetcher = self._load()
        method = method.upper()
        t0 = time.monotonic()
        if self.mode == "stealth":
            if method != "GET":
                raise RuntimeError(
                    "stealth 非复用模式仅支持 GET；POST 请启用复用模式"
                    "（transport_config['scrapling_reuse']=True）或改用 impersonate 模式"
                )
            resp = StealthyFetcher.fetch(
                url,
                headless=self.headless,
                network_idle=self.network_idle,
                timeout=int(self.timeout * 1000),
                solve_cloudflare=self.solve_cloudflare,
                **kwargs,
            )
        else:
            # impersonate：curl_cffi 指纹伪装的纯 HTTP 请求，按 method 分发
            # （此前硬编码 Fetcher.get 会把 POST 静默发成 GET，导致绕过结果失真）
            method_name = method.lower()
            if method_name not in ("get", "post", "put", "delete"):
                raise RuntimeError(f"impersonate 模式不支持 {method} 方法（仅支持 GET/POST/PUT/DELETE）")
            resp = getattr(Fetcher, method_name)(url, impersonate="chrome", timeout=self.timeout, **kwargs)
        self._count += 1
        return ResponseAdapter(resp, time.monotonic() - t0)

    def get(self, url: str, **kwargs: Any) -> ResponseAdapter:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> ResponseAdapter:
        return self.request("POST", url, **kwargs)

    @property
    def request_count(self) -> int:
        return self._count

    def close(self) -> None:
        # Scrapling 的 one-shot fetch 自行回收浏览器，无需显式关闭；
        # 会话型（StealthySession）留待二期 Cookie 复用改造时实现。
        pass


class ScraplingStealthStrategy(WafBypassStrategy):
    """对抗传输策略：把请求路由到 Scrapling 引擎

    layer 记为 L5（引擎级），与 payload 变形策略（L1/L2/L3）和源站直连（L4）区分。
    传输配置返回 {'engine': 'scrapling', 'scrapling_reuse': True}：
    由 BypassSession 先用隐身浏览器解一次挑战、收割 cf_clearance，注入基础
    SessionManager，之后所有请求（含 POST）走快速 requests 路径。
    """

    name = "对抗传输（Scrapling 指纹/隐身浏览器）"
    strategy_id = "BP-ENG-1"
    layer = "L5"
    waf_types = ["cloudflare", "js_challenge", "akamai", "imperva", "f5"]
    vuln_types = ["*"]
    priority = 45  # 在 payload 变形之后、源站直连(L4=60) 之前尝试

    def apply_transport(self, ctx: BypassContext) -> dict:
        # scrapling_reuse=True：收割 cf_clearance 后复用，支持 POST 且快（推荐）
        return {
            "engine": "scrapling",
            "scrapling_mode": "stealth",
            "scrapling_reuse": True,
            "headers": {},
        }

    def tamper_payload(self, payload: str, ctx: BypassContext) -> str:
        return payload


def register_scrapling_strategy(registry: Any) -> None:
    """把对抗传输策略注册进 StrategyRegistry（显式 opt-in，避免默认改变行为）"""
    registry.register(ScraplingStealthStrategy())
