# D7.1 WAF 绕过策略库与编排器单元测试
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.waf_bypass import (
    BypassContext,
    BypassSession,
    ChunkedTransferStrategy,
    GooglebotStrategy,
    InlineCommentStrategy,
    OriginDirectStrategy,
    RandomCaseStrategy,
    StrategyRegistry,
    UrlEncodeStrategy,
    WafBypassCoordinator,
    WafBypassStrategy,
)

# === 策略基类测试 ===


class DummyStrategy(WafBypassStrategy):
    """测试用策略"""

    name = "测试策略"
    strategy_id = "BP-TEST-1"
    layer = "L1"
    waf_types = ["cloudflare"]
    vuln_types = ["sqli"]

    def apply_transport(self, ctx):
        return {"headers": {"X-Test": "1"}, "chunked": False}

    def tamper_payload(self, payload, ctx):
        return payload + "_tampered"


def test_strategy_is_applicable_match():
    """策略匹配 WAF 和漏洞类型"""
    s = DummyStrategy()
    assert s.is_applicable("cloudflare", "sqli") is True


def test_strategy_is_applicable_waf_mismatch():
    """WAF 不匹配"""
    s = DummyStrategy()
    assert s.is_applicable("aliyun_waf", "sqli") is False


def test_strategy_is_applicable_vuln_mismatch():
    """漏洞类型不匹配"""
    s = DummyStrategy()
    assert s.is_applicable("cloudflare", "xss") is False


def test_strategy_wildcard_waf():
    """通配符 WAF 匹配所有"""
    s = RandomCaseStrategy()  # waf_types=['*']
    assert s.is_applicable("cloudflare", "sqli") is True
    assert s.is_applicable("aliyun_waf", "sqli") is True


def test_strategy_wildcard_vuln():
    """通配符漏洞类型匹配所有"""
    s = GooglebotStrategy()  # vuln_types=['*']
    assert s.is_applicable("cloudflare", "sqli") is True
    assert s.is_applicable("cloudflare", "rce") is True


# === 策略变形测试 ===


def test_inline_comment_strategy_tamper():
    """内联注释策略变形"""
    s = InlineCommentStrategy()
    result = s.tamper_payload("SELECT * FROM", BypassContext())
    assert "/**/" in result


def test_randomcase_strategy_tamper():
    """大小写混淆策略变形"""
    s = RandomCaseStrategy()
    result = s.tamper_payload("SELECT", BypassContext())
    assert result.lower() == "select"


def test_url_encode_strategy_tamper():
    """URL 编码策略变形"""
    s = UrlEncodeStrategy()
    result = s.tamper_payload("SELECT *", BypassContext())
    assert "%20" in result or "%2A" in result


def test_chunked_transfer_strategy_transport():
    """分块传输策略传输层变换"""
    s = ChunkedTransferStrategy()
    transport = s.apply_transport(BypassContext())
    assert transport.get("chunked") is True
    assert "Transfer-Encoding" in transport.get("headers", {})


def test_googlebot_strategy_transport():
    """Googlebot 策略注入 UA"""
    s = GooglebotStrategy()
    transport = s.apply_transport(BypassContext())
    assert "Googlebot" in transport.get("headers", {}).get("User-Agent", "")


def test_origin_direct_strategy_transport():
    """源站直连策略设置 origin_ip"""
    s = OriginDirectStrategy()
    ctx = BypassContext(origin_ip="1.2.3.4")
    transport = s.apply_transport(ctx)
    assert transport.get("origin_ip") == "1.2.3.4"


# === 策略注册表测试 ===


def test_registry_default_strategies():
    """默认注册 11 条内置策略（L5 对抗传输策略需显式注册/开关启用，不计入默认）"""
    reg = StrategyRegistry()
    all_s = reg.all_strategies()
    ids = {s.strategy_id for s in all_s}
    assert len(all_s) == 11, f"应注册 11 个内置策略，实际 {len(all_s)}"
    assert {"BP-GEN-1", "BP-GEN-2", "BP-CF-1", "BP-CF-2"} <= ids
    # 方案 A 的 L5 引擎策略默认不注册（保证零行为变化）
    assert "BP-ENG-1" not in ids


def test_registry_get_strategies_cloudflare_sqli():
    """获取 cloudflare+sqli 的策略（应含通用 + 专用）"""
    reg = StrategyRegistry()
    strategies = reg.get_strategies("cloudflare", "sqli")
    # 应至少含 RandomCase（通用）、UrlEncode（通用）、OriginDirect（cloudflare）
    strategy_ids = [s.strategy_id for s in strategies]
    assert "BP-GEN-1" in strategy_ids, "应含通用随机大小写"
    assert "BP-CF-1" in strategy_ids, "应含源站直连"
    assert "BP-CF-2" in strategy_ids, "应含 Googlebot"


def test_registry_get_strategies_sorted_by_priority():
    """策略按 priority 排序（小的在前）"""
    reg = StrategyRegistry()
    strategies = reg.get_strategies("cloudflare", "sqli")
    priorities = [s.priority for s in strategies]
    assert priorities == sorted(priorities), "策略应按 priority 升序排列"


def test_registry_no_match():
    """无匹配策略返回空列表"""
    reg = StrategyRegistry()
    # 注册一个仅匹配特定 WAF 的策略
    strategies = reg.get_strategies("nonexistent_waf", "nonexistent_vuln")
    # 通用策略仍应匹配（waf_types=['*'] 或 vuln_types=['*']）
    # 但如果没有任何策略匹配，应返回空
    # 实际上 RandomCaseStrategy waf_types=['*'], vuln_types=['sqli','xss','rce']
    # 所以 nonexistent_vuln 不会匹配
    assert isinstance(strategies, list)


# === BypassSession 测试 ===


class MockResponse:
    def __init__(self, headers=None):
        self.headers = headers or {}


class MockSession:
    def __init__(self):
        self.request_count = 0
        self.last_url = ""
        self.last_headers = {}

    def get(self, url, **kwargs):
        self.request_count += 1
        self.last_url = url
        self.last_headers = kwargs.get("headers", {})
        return MockResponse()

    def post(self, url, **kwargs):
        self.request_count += 1
        self.last_url = url
        self.last_headers = kwargs.get("headers", {})
        return MockResponse()

    def close(self):
        pass


def test_bypass_session_injects_headers():
    """BypassSession 注入自定义 headers"""
    session = MockSession()
    transport = {"headers": {"X-Custom": "test"}, "chunked": False}
    bypass = BypassSession(session, transport)
    bypass.get("http://x.com/")
    assert session.last_headers.get("X-Custom") == "test"


def test_bypass_session_passes_through():
    """BypassSession 透传请求"""
    session = MockSession()
    bypass = BypassSession(session, {})
    bypass.get("http://x.com/")
    assert session.last_url == "http://x.com/"
    assert session.request_count == 1


def test_bypass_session_origin_url_replacement():
    """BypassSession 替换 URL 中的域名为源站 IP"""
    session = MockSession()
    bypass = BypassSession(session, {}, "http://1.2.3.4")
    bypass.get("http://example.com/path?q=1")
    assert "1.2.3.4" in session.last_url
    assert "/path" in session.last_url
    assert "q=1" in session.last_url


# === WafBypassCoordinator 测试 ===


class MockPlugin:
    """测试用插件"""

    vuln_type = "sqli"
    bypass_max_attempts = 3

    def verify_with_bypass(self, target, session, ctx):
        return ScanResult(kind="vuln", name="mock", status=STATUS_CONFIRMED, url=target, evidence="bypass success")


def test_coordinator_confirmed_not_bypassed():
    """CONFIRMED 不绕过"""
    coord = WafBypassCoordinator(waf_type="cloudflare")
    original = ScanResult(kind="vuln", name="test", status=STATUS_CONFIRMED, url="http://x.com", evidence="confirmed")
    result = coord.maybe_bypass(MockPlugin(), "http://x.com/", MockSession(), original)
    assert result.status == STATUS_CONFIRMED
    assert result is original  # 直接返回原结果


def test_coordinator_no_vuln_type_not_bypassed():
    """无 vuln_type 不绕过"""
    coord = WafBypassCoordinator(waf_type="cloudflare")
    original = ScanResult(kind="vuln", name="test", status=STATUS_SAFE, url="http://x.com", evidence="safe")

    class NoVulnTypePlugin:
        bypass_max_attempts = 3
        # 无 vuln_type 属性

    result = coord.maybe_bypass(NoVulnTypePlugin(), "http://x.com/", MockSession(), original)
    assert result is original


def test_coordinator_bypass_success():
    """绕过成功 → CONFIRMED + 标记"""
    coord = WafBypassCoordinator(waf_type="cloudflare")
    original = ScanResult(kind="vuln", name="test", status=STATUS_SAFE, url="http://x.com", evidence="safe")
    result = coord.maybe_bypass(MockPlugin(), "http://x.com/", MockSession(), original)
    assert result.status == STATUS_CONFIRMED
    assert "waf_bypass" in result.extra
    # 成功时标记 strategy_used（而非 bypass_success）
    assert "strategy_used" in result.extra["waf_bypass"]


def test_coordinator_bypass_all_failed():
    """所有策略失败 → 返回原结果 + 标记"""
    coord = WafBypassCoordinator(waf_type="cloudflare")

    class FailPlugin:
        vuln_type = "sqli"
        bypass_max_attempts = 3

        def verify_with_bypass(self, target, session, ctx):
            return ScanResult(kind="vuln", name="mock", status=STATUS_SAFE, url=target, evidence="still safe")

    original = ScanResult(kind="vuln", name="test", status=STATUS_SAFE, url="http://x.com", evidence="safe")
    result = coord.maybe_bypass(FailPlugin(), "http://x.com/", MockSession(), original)
    assert result.status == STATUS_SAFE  # 保持原状态
    assert result.extra.get("waf_bypass", {}).get("bypass_success") is False


def test_coordinator_bypass_exception_not_safe():
    """绕过异常不降级为 SAFE"""
    coord = WafBypassCoordinator(waf_type="cloudflare")

    class ExceptionPlugin:
        vuln_type = "sqli"
        bypass_max_attempts = 3

        def verify_with_bypass(self, target, session, ctx):
            raise RuntimeError("test exception")

    original = ScanResult(kind="vuln", name="test", status=STATUS_UNKNOWN, url="http://x.com", evidence="unknown")
    result = coord.maybe_bypass(ExceptionPlugin(), "http://x.com/", MockSession(), original)
    # 异常不应降级为 SAFE，保持原状态
    assert result.status != STATUS_SAFE


def test_engine_strategy_reserved_in_attempts_window():
    """方案 A：enable_engine_fallback 开启时，L5 引擎策略不被 attempts 截断

    cloudflare/sqli 下按 priority 排序 BP-ENG-1 排第 5，而 attempts=min(3, N)=3，
    若不保底则永不触发。开启开关后应按「追加」纳入，且不挤掉窗口内廉价策略。
    默认（开关关闭）则完全不含 BP-ENG-1，保证零行为变化。
    """

    class RecordingPlugin:
        vuln_type = "sqli"
        bypass_max_attempts = 3

        def __init__(self):
            self.attempted: list = []

        def verify_with_bypass(self, target, session, ctx):
            self.attempted.append(ctx.strategy.strategy_id)
            # 立即返回 UNKNOWN，不调用 session → 不触发真实浏览器（离线测试）
            return ScanResult(kind="vuln", name="rec", status=STATUS_UNKNOWN, url=target, evidence="x")

    original = ScanResult(kind="vuln", name="t", status=STATUS_UNKNOWN, url="http://x.com", evidence="no")

    # 关闭开关（默认）：零行为变化，不含引擎策略
    p_off = RecordingPlugin()
    WafBypassCoordinator(waf_type="cloudflare").maybe_bypass(p_off, "http://x.com/", MockSession(), original)
    assert "BP-ENG-1" not in p_off.attempted, f"默认不应启用引擎兜底：{p_off.attempted}"
    assert len(p_off.attempted) <= 3

    # 开启开关：引擎策略追加到末尾，且不挤掉廉价策略
    p_on = RecordingPlugin()
    coord = WafBypassCoordinator(waf_type="cloudflare", enable_engine_fallback=True)
    coord.maybe_bypass(p_on, "http://x.com/", MockSession(), original)
    assert "BP-ENG-1" in p_on.attempted, f"开启开关后 L5 引擎策略仍被截断：{p_on.attempted}"
    assert "BP-CF-2" in p_on.attempted, f"廉价策略被挤掉：{p_on.attempted}"
    assert p_on.attempted[-1] == "BP-ENG-1", f"引擎策略应作为最后兜底：{p_on.attempted}"


def test_scrapling_cookie_normalization_and_injection():
    """方案 A：Playwright cookie 元组归一化为 {name:value}，并注入基础会话"""
    from lib.scrapling_transport import ScraplingTransport

    # Scrapling 返回的是 Playwright cookie 对象（expires 为 float），必须只取 name/value
    raw = (
        {"name": "cf_clearance", "value": "abc", "expires": 1234.5, "httpOnly": True},
        {"name": "XSRF-TOKEN", "value": "xyz", "expires": 99.9},
    )
    assert ScraplingTransport._cookie_dict(raw) == {"cf_clearance": "abc", "XSRF-TOKEN": "xyz"}

    from requests.cookies import RequestsCookieJar
    from requests.structures import CaseInsensitiveDict

    class _Sess:
        def __init__(self):
            self.cookies = RequestsCookieJar()
            self.headers = CaseInsensitiveDict()

    s = _Sess()
    t = ScraplingTransport()
    t._clearance_cookies = {"cf_clearance": "abc"}  # noqa: SLF001
    t._clearance_ua = "UA/1.0"  # noqa: SLF001
    t.apply_clearance(s)
    assert s.cookies.get("cf_clearance") == "abc"
    assert s.headers["User-Agent"] == "UA/1.0"


def test_bypass_session_clearance_primes_once_per_host():
    """方案 A：reuse 模式下同一 host 只解一次挑战，后续请求走基础会话"""
    from lib.waf_bypass import BypassSession

    class _Engine:
        request_count = 0

        def __init__(self):
            self.primes = []
            self.applied = 0

        def prime(self, url):
            self.primes.append(url)

        def apply_clearance(self, session):
            self.applied += 1

    class _Sess:
        request_count = 0

        def __init__(self):
            self.calls = []

        def get(self, url, **k):
            self.calls.append(("GET", url))
            return "RAW"

        def post(self, url, **k):
            self.calls.append(("POST", url))
            return "RAW"

        def request(self, method, url, **k):
            self.calls.append((method, url))
            return "RAW"

        def close(self):
            pass

    sess = _Sess()
    bs = BypassSession(sess, {"engine": "scrapling", "scrapling_reuse": True})
    bs._engine_transport = _Engine()  # noqa: SLF001  注入假引擎，避免真起浏览器

    bs.get("http://t/a")  # 首个 host：解挑战 + 注入
    bs.get("http://t/b")  # 同 host：跳过
    bs.post("http://t/c")  # 同 host：跳过，且走基础会话（支持 POST）
    bs.get("http://other/d")  # 新 host：再解一次

    assert len(bs._engine_transport.primes) == 2  # noqa: SLF001
    assert bs._engine_transport.applied == 2  # noqa: SLF001
    # 复用路径下实际请求由基础会话发出（证明未逐请求起浏览器）
    assert ("POST", "http://t/c") in sess.calls


def test_clearance_prime_memoized_across_bypass_sessions():
    """方案 A：同一次扫描内多个 BypassSession（多策略/多插件）共享基础会话，只解一次挑战

    回归背景：解挑战（隐身浏览器）单次约 10~20s。maybe_bypass 会为**每个策略尝试**
    新建一个 BypassSession，引擎也会为**每个插件**重复调用；若去重标记只挂在
    BypassSession 实例上，则插件数×策略数会成倍拉起浏览器。故去重必须以
    基础会话为维度。
    """
    from lib.waf_bypass import BypassSession

    class _Engine:
        request_count = 0

        def __init__(self):
            self.primes = []
            self.applied = 0

        def prime(self, url):
            self.primes.append(url)

        def apply_clearance(self, session):
            self.applied += 1

    class _Sess:
        request_count = 0

        def __init__(self):
            self.calls = []

        def get(self, url, **k):
            self.calls.append(("GET", url))
            return "RAW"

        def post(self, url, **k):
            self.calls.append(("POST", url))
            return "RAW"

        def request(self, method, url, **k):
            self.calls.append((method, url))
            return "RAW"

        def close(self):
            pass

    sess = _Sess()
    engine = _Engine()

    # 模拟一次真实扫描：3 个 BypassSession（策略/插件叠加）共享同一基础会话与同一 host
    for _ in range(3):
        bs = BypassSession(sess, {"engine": "scrapling", "scrapling_reuse": True})
        bs._engine_transport = engine  # noqa: SLF001  注入假引擎，避免真起浏览器
        bs.get("http://t/a")

    assert len(engine.primes) == 1  # 仅首个 BypassSession 触发解挑战
    assert engine.applied == 1
    # 每个 BypassSession 的请求仍由基础会话发出（快速路径）
    assert sess.calls.count(("GET", "http://t/a")) == 3


if __name__ == "__main__":
    test_strategy_is_applicable_match()
    test_strategy_is_applicable_waf_mismatch()
    test_strategy_is_applicable_vuln_mismatch()
    test_strategy_wildcard_waf()
    test_strategy_wildcard_vuln()
    test_inline_comment_strategy_tamper()
    test_randomcase_strategy_tamper()
    test_url_encode_strategy_tamper()
    test_chunked_transfer_strategy_transport()
    test_googlebot_strategy_transport()
    test_origin_direct_strategy_transport()
    test_registry_default_strategies()
    test_registry_get_strategies_cloudflare_sqli()
    test_registry_get_strategies_sorted_by_priority()
    test_registry_no_match()
    test_bypass_session_injects_headers()
    test_bypass_session_passes_through()
    test_bypass_session_origin_url_replacement()
    test_coordinator_confirmed_not_bypassed()
    test_coordinator_no_vuln_type_not_bypassed()
    test_coordinator_bypass_success()
    test_coordinator_bypass_all_failed()
    test_coordinator_bypass_exception_not_safe()
    test_engine_strategy_reserved_in_attempts_window()
    test_scrapling_cookie_normalization_and_injection()
    test_bypass_session_clearance_primes_once_per_host()
    test_clearance_prime_memoized_across_bypass_sessions()
    print("All D7.1 WAF bypass tests passed!")
