# F6 认证链 P0 回归：/login 404 不等于「无鉴权」，默认口令必须证明登录后有数据
#
# 覆盖：
#   1. /login 404 + 受保护接口 404 → AUTH_UNKNOWN，login() 返回 False
#   2. /login 404 + 受保护接口 302 到登录页 → 发现 login_url，登录 POST 发往该地址
#      /login 302 → 直接用 Location 作为 login_url（定制登录入口）
#      部署在子路径（/ -> /portal/）→ 从受保护接口发现登录页
#   3. /login 404 + 受保护接口 200 {"rows": [...]} → AUTH_NONE
#   4. 登录 ok 但受保护接口 404 → 默认口令不 CONFIRMED（UNKNOWN）
#   5. 登录 ok 且受保护接口 total=26 → CONFIRMED
#   6. 显式 --auth-login 失败 → 退出码 4；不带认证参数 → 退出码 0
#   7. 登录响应含「动态口令」→ meta.auth_status.admin == "mfa_required"
import contextlib
import json
import os
import sys
from argparse import Namespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.auth_chain import (  # noqa: E402
    AUTH_NONE,
    AUTH_UNKNOWN,
    AUTH_V4_SESSION,
    RuoYiAuthChain,
)
from core.session import SessionManager  # noqa: E402

TARGET = "http://ruoyi-f6.test"
PROTECTED = ("/system/user/list", "/monitor/job/list", "/system/dept/list")


def _mock_all_protected_404(m):
    for path in PROTECTED:
        m.get(TARGET + path, status_code=404)
        m.post(TARGET + path, status_code=404)


# ── 1. /login 404 + 受保护接口 404 → AUTH_UNKNOWN ────────────────────────────


def test_login_404_and_protected_404_is_unknown(requests_mock):
    m = requests_mock
    m.get(TARGET + "/login", status_code=404)
    _mock_all_protected_404(m)

    chain = RuoYiAuthChain(TARGET, SessionManager())
    assert chain.detect_auth_mode() == AUTH_UNKNOWN

    ok, reason = chain.login()
    assert ok is False
    assert reason == "login_endpoint_not_found"


# ── 2. 受保护接口 302 → 发现登录页并改用该地址 POST ─────────────────────────


def test_protected_redirect_discovers_login_endpoint(requests_mock):
    m = requests_mock
    m.get(TARGET + "/login", status_code=404)
    m.get(
        TARGET + "/system/user/list",
        status_code=302,
        headers={"Location": TARGET + "/portal/auth/signin"},
    )
    m.get(
        TARGET + "/portal/auth/signin",
        text="<html><body><form>登录</form></body></html>",
        headers={"Content-Type": "text/html"},
    )
    m.post(
        TARGET + "/portal/auth/signin",
        text='{"code":0,"msg":"操作成功"}',
        headers={"Content-Type": "application/json"},
    )

    chain = RuoYiAuthChain(TARGET, SessionManager())
    assert chain.detect_auth_mode() == AUTH_V4_SESSION
    assert chain.login_url == TARGET + "/portal/auth/signin"

    ok, _reason = chain.login(captcha_code="")
    assert ok is True

    posted = [r for r in m.request_history if r.method == "POST"]
    assert [r.url for r in posted] == [TARGET + "/portal/auth/signin"]


def test_login_redirect_uses_location_as_login_url(requests_mock):
    """/login 本身 302 到登录页：必须用 Location 作为 login_url，不能继续 POST /login"""
    m = requests_mock
    m.get(TARGET + "/login", status_code=302, headers={"Location": "/portal/auth/signin"})
    m.get(
        TARGET + "/portal/auth/signin",
        text="<html><body><form>登录</form></body></html>",
        headers={"Content-Type": "text/html"},
    )
    m.post(
        TARGET + "/portal/auth/signin",
        json={"success": True, "message": "登录成功"},
        headers={"Content-Type": "application/json"},
    )

    chain = RuoYiAuthChain(TARGET, SessionManager())
    assert chain.detect_auth_mode() == AUTH_V4_SESSION
    assert chain.login_url == TARGET + "/portal/auth/signin"

    ok, _reason = chain.login(captcha_code="")
    assert ok is True
    posted = [r for r in m.request_history if r.method == "POST"]
    assert [r.url for r in posted] == [TARGET + "/portal/auth/signin"]


def test_context_path_discovered_from_root_redirect(requests_mock):
    """应用部署在 /portal：根路径受保护接口 404 时，从站点根 302 推导前缀再发现登录页"""
    m = requests_mock
    m.get(TARGET + "/login", status_code=404)
    _mock_all_protected_404(m)
    m.get(TARGET + "/", status_code=302, headers={"Location": TARGET + "/portal/"})
    m.get(
        TARGET + "/portal/system/user/list",
        status_code=302,
        headers={"Location": TARGET + "/portal/auth/signin"},
    )
    m.get(
        TARGET + "/portal/auth/signin",
        text="<html><body><form>登录</form></body></html>",
        headers={"Content-Type": "text/html"},
    )
    m.post(
        TARGET + "/portal/auth/signin",
        json={"success": True, "message": "登录成功"},
        headers={"Content-Type": "application/json"},
    )

    chain = RuoYiAuthChain(TARGET, SessionManager())
    assert chain.detect_auth_mode() == AUTH_V4_SESSION
    assert chain.base_path == "/portal"
    assert chain.login_url == TARGET + "/portal/auth/signin"

    ok, _reason = chain.login(captcha_code="")
    assert ok is True
    posted = [r.url for r in m.request_history if r.method == "POST"]
    assert TARGET + "/portal/auth/signin" in posted
    assert TARGET + "/login" not in posted


# ── 3. 受保护接口返回业务数据 → AUTH_NONE ────────────────────────────────────


def test_protected_rows_means_no_auth(requests_mock):
    m = requests_mock
    m.get(TARGET + "/login", status_code=404)
    m.get(TARGET + "/system/user/list", json={"rows": [{"userId": 1}], "total": 1})

    chain = RuoYiAuthChain(TARGET, SessionManager())
    assert chain.detect_auth_mode() == AUTH_NONE
    ok, _reason = chain.login()
    assert ok is True


# ── 4/5. 默认口令必须证明「登录后有数据」 ────────────────────────────────────


class _FakeResp:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else (json.dumps(payload) if payload is not None else "")
        self.headers = {"Content-Type": "application/json"}

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _FakeIso:
    """登录后的独立会话：受保护接口按配置返回固定响应。"""

    def __init__(self, protected_resp):
        self._protected_resp = protected_resp

    def get(self, url, **kwargs):
        return self._protected_resp

    def post(self, url, **kwargs):
        return self._protected_resp


@contextlib.contextmanager
def _fake_isolation(iso, ok=True, reason="ok"):
    yield iso, ok, reason


def _patch_default_password(monkeypatch, iso):
    import plugins.ruoyi.default_password as dp_mod

    monkeypatch.setattr(dp_mod, "isolated_auth_session", lambda *a, **k: _fake_isolation(iso))
    return dp_mod


def test_default_password_requires_protected_data(monkeypatch):
    """登录链 ok 但受保护接口 404 → 不得 CONFIRMED"""
    from common.models import STATUS_UNKNOWN

    iso = _FakeIso(_FakeResp(status_code=404, payload=None, text="not found"))
    dp_mod = _patch_default_password(monkeypatch, iso)

    result = dp_mod.DefaultPasswordPlugin().verify(TARGET + "/", SessionManager())

    assert result.status == STATUS_UNKNOWN, result.status
    assert "受保护接口未取到数据" in result.evidence


def test_default_password_confirmed_with_protected_total(monkeypatch):
    """登录链 ok 且受保护接口 total=26 → CONFIRMED，证据含计数"""
    from common.models import STATUS_CONFIRMED

    iso = _FakeIso(_FakeResp(status_code=200, payload={"total": 26, "rows": [{"userId": 1}]}))
    dp_mod = _patch_default_password(monkeypatch, iso)

    result = dp_mod.DefaultPasswordPlugin().verify(TARGET + "/", SessionManager())

    assert result.status == STATUS_CONFIRMED, result.status
    assert "total=26" in result.evidence


class _BaseAwareIso:
    """模拟登录链发现的应用前缀：只有 /portal 下的受保护接口有数据。"""

    auth_base = "/portal"

    def _resp(self, url):
        if url.startswith(TARGET + "/portal/system/user/list"):
            return _FakeResp(status_code=200, payload={"total": 26, "rows": [{"userId": 1}]})
        return _FakeResp(status_code=404, payload=None, text="not found")

    def get(self, url, **kwargs):
        return self._resp(url)

    def post(self, url, **kwargs):
        return self._resp(url)


def test_default_password_proof_uses_discovered_base(monkeypatch):
    """受保护接口在应用前缀下时，取证仍须成功（D1 /portal 场景）"""
    from common.models import STATUS_CONFIRMED

    dp_mod = _patch_default_password(monkeypatch, _BaseAwareIso())

    result = dp_mod.DefaultPasswordPlugin().verify(TARGET + "/", SessionManager())

    assert result.status == STATUS_CONFIRMED, result.status
    assert "/portal/system/user/list" in result.evidence
    assert "total=26" in result.evidence


# ── 6/7. CLI 退出码与 MFA 状态 ───────────────────────────────────────────────


def test_v4_login_response_with_otp_is_mfa(requests_mock):
    """登录响应正文含「动态口令」→ 必须识别为 mfa_required，而不是普通失败/成功"""
    from core.auth_chain import AUTH_V4_SESSION, LOGIN_MFA

    requests_mock.post(
        TARGET + "/login",
        json={"code": 500, "msg": "动态口令不能为空"},
        headers={"Content-Type": "application/json"},
    )
    chain = RuoYiAuthChain(TARGET, SessionManager())
    chain.auth_mode = AUTH_V4_SESSION

    ok, reason = chain._login_once(captcha_code="")

    assert ok is False
    assert reason == LOGIN_MFA


def _cli_args(**overrides):
    base = dict(
        auth=None,
        auth_file=None,
        auth_login=None,
        threads=1,
        rate=0,
        proxy="",
        timeout=5,
        time_budget=0.0,
        debug=False,
        report=None,
        report_format="json",
        no_dedup=False,
        no_cta=True,
        pass_level="quick",
        portscan=False,
        ports="",
        bypass_waf="auto",
        adversarial_transport=False,
        surface_account=None,
        template="",
        crawl=False,
        crawl_depth=1,
        crawl_max_pages=1,
        subdomain=False,
        js_extract=False,
        plugin_path=None,
        components=False,
        nuclei=None,
        nuclei_tags="",
        nuclei_severity="",
        nuclei_exclude_tags="",
        ci=False,
        logic_scan=False,
        auth_surface=False,
    )
    base.update(overrides)
    return Namespace(**base)


def _patch_orchestrator(monkeypatch):
    import core.orchestrator as orch_mod

    class _FakeOrch:
        last_request_count = 0
        last_block_info = {}

        def run_sync(self, req, on_event=None):
            return []

    monkeypatch.setattr(orch_mod, "ScanOrchestrator", _FakeOrch)


def test_auth_login_failure_exits_partial(monkeypatch):
    import lib.auth_scan as auth_scan

    monkeypatch.setattr(auth_scan, "auto_login", lambda *a, **k: {"cookies": {}, "headers": {}, "type": None})
    _patch_orchestrator(monkeypatch)
    from cli import runner
    from cli.preflight import EXIT_PARTIAL

    with pytest.raises(SystemExit) as exc:
        runner.run_mode("u", TARGET + "/", _cli_args(auth_login="admin:wrong-pass"), show_cta=False)
    assert exc.value.code == EXIT_PARTIAL


def test_no_auth_args_exits_zero(monkeypatch):
    _patch_orchestrator(monkeypatch)
    from cli import runner

    result = runner.run_mode("u", TARGET + "/", _cli_args(), show_cta=False)
    assert result == []


def test_mfa_login_sets_meta_auth_status(monkeypatch, tmp_path):
    import lib.auth_scan as auth_scan

    monkeypatch.setattr(
        auth_scan,
        "auto_login",
        lambda *a, **k: {"cookies": {}, "headers": {}, "type": None, "auth_status": "mfa_required"},
    )
    _patch_orchestrator(monkeypatch)
    from cli import runner
    from cli.preflight import EXIT_PARTIAL

    report_dir = str(tmp_path)
    with pytest.raises(SystemExit) as exc:
        runner.run_mode(
            "u",
            TARGET + "/",
            _cli_args(auth_login="admin:admin123", report=report_dir),
            show_cta=False,
        )
    assert exc.value.code == EXIT_PARTIAL

    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["meta"]["auth_status"]["admin"] == "mfa_required"
