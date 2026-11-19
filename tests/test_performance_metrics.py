"""性能优化：共享请求计数、插件级埋点、无登录页跳过 brute。"""

import requests_mock

from common.models import STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.engine import ScanEngine
from core.session import RequestCounter, SessionManager
from lib.reachability import detect_login_page


class _Resp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _LoginSession:
    def __init__(self, response=None, error=False):
        self.response = response
        self.error = error
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        if self.error:
            raise ConnectionError("probe down")
        return self.response or _Resp(status_code=404, text="{}", headers={"Content-Type": "application/json"})


def test_detect_login_page_true_on_html_login():
    session = _LoginSession(_Resp(200, '<form><input name="password"></form>', {"Content-Type": "text/html"}))
    info = detect_login_page(session, "http://target/")
    assert info["available"] is True
    assert "password" in info["reason"] or "登录" in info["reason"]


def test_detect_login_page_false_on_json_404():
    session = _LoginSession()
    info = detect_login_page(session, "http://target/")
    assert info["available"] is False
    assert len(session.urls) >= 2


def test_detect_login_page_none_on_network_error():
    info = detect_login_page(_LoginSession(error=True), "http://target/")
    assert info["available"] is None


def test_anonymous_session_shares_request_counter():
    session = SessionManager()
    clone = session.anonymous()
    try:
        assert clone._request_counter is session._request_counter
        with requests_mock.Mocker() as mocker:
            mocker.get("http://target/", text="ok")
            session.get("http://target/")
            clone.get("http://target/")
        assert session.request_count == 2
        assert clone.request_count == 2
    finally:
        clone.close()
        session.close()


class _CountingPlugin:
    name = "计数插件"
    category = "vuln"
    severity = "low"
    requires_login_page = False

    called = 0

    def verify(self, target, session):
        type(self).called += 1
        session.get("http://target/api")
        session.get("http://target/api")
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE)


class _LoginPagePlugin:
    name = "爆破插件"
    category = "brute"
    severity = "high"
    requires_login_page = True

    called = 0

    def verify(self, target, session):
        type(self).called += 1
        return ScanResult(kind="brute", name=self.name, status=STATUS_SAFE)

    @classmethod
    def no_login_page_result(cls):
        return ScanResult(
            kind="brute",
            name=cls.name,
            status=STATUS_UNKNOWN,
            unknown_reason="no_login_page",
            evidence="skip",
        )


def _engine_session(login_page_available=None):
    session = SessionManager()
    session.login_page_available = login_page_available
    return session


def test_engine_records_plugin_metrics():
    session = _engine_session()
    plugin = _CountingPlugin
    try:
        with requests_mock.Mocker() as mocker:
            mocker.get("http://target/api", text="ok")
            engine = ScanEngine(threads=1)
            results = engine.run([plugin], "http://target/", session)
        assert results and results[0].status == STATUS_SAFE
        metric = engine.plugin_metrics[0]
        assert metric["plugin"] == plugin.name
        assert metric["requests"] == 2
        assert metric["duration_ms"] >= 0
    finally:
        session.close()


def test_engine_skips_brute_without_login_page():
    session = _engine_session(login_page_available=False)
    plugin = _LoginPagePlugin
    plugin.called = 0
    called_before = plugin.called
    try:
        engine = ScanEngine(threads=1)
        results = engine.run([plugin], "http://target/", session)
        assert results[0].status == STATUS_UNKNOWN
        assert results[0].unknown_reason == "no_login_page"
        assert plugin.called == called_before, "无登录页时不应执行爆破插件 verify"
        assert engine.plugin_metrics[0]["requests"] == 0
    finally:
        session.close()


def test_brute_skip_shapes_preserve_statuses():
    from plugins.common.blind_ssrf import BlindSsrfPlugin  # noqa: F401
    from plugins.jeecgboot.default_password import JeecgDefaultPasswordPlugin
    from plugins.ruoyi.default_password import DefaultPasswordPlugin
    from plugins.ruoyi.druid_brute import DruidBrutePlugin

    assert DruidBrutePlugin.no_login_page_result().status == STATUS_SAFE
    assert DefaultPasswordPlugin.no_login_page_result().status == STATUS_UNKNOWN
    assert DefaultPasswordPlugin.no_login_page_result().unknown_reason == "no_login_page"
    assert JeecgDefaultPasswordPlugin.no_login_page_result().status == STATUS_UNKNOWN


def test_request_counter_scoped_counts():
    counter = RequestCounter()
    counter.begin()
    counter.increment()
    counter.increment()
    assert counter.end() == 2
    assert counter.value() == 2
