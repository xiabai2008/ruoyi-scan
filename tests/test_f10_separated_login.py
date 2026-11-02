"""F10：前后端分离版登录入口识别（base path -> /prod-api/login | /auth/login | /sys/login）。

背景（2026-11-02 实测 R6/R7）：
    nginx 只反代 /prod-api/ 时，GET /login 是 SPA index.html（200 HTML），
    旧登录链据此判 v4 并 POST /login -> 405，分离版站点全部登录失败。
"""

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import basepath as basepath_mod  # noqa: E402
from core.auth_chain import AUTH_V5_JWT, RuoYiAuthChain  # noqa: E402


class FakeResp:
    def __init__(self, body, status=200, headers=None):
        self._body = body
        self.status_code = status
        self.headers = headers or {"Content-Type": "application/json"}
        self.text = body if isinstance(body, str) else str(body)
        self.url = ""

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


class FakeSession:
    """记录请求并按 URL 返回预设响应；模拟 SessionManager 的 .session.headers。"""

    def __init__(self, routes):
        self.routes = routes  # dict: (method, path) -> FakeResp
        self.session = SimpleNamespace(headers={})
        self.calls = []

    def _do(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        from urllib.parse import urlparse

        path = urlparse(url).path
        for (m, p), resp in self.routes.items():
            if m == method and path == p:
                return resp
        return FakeResp({"code": 404, "msg": "not found"}, status=404)

    def get(self, url, **kwargs):
        return self._do("get", url, **kwargs)

    def post(self, url, **kwargs):
        return self._do("post", url, **kwargs)


def _chain_with_base(monkeypatch, api_base):
    monkeypatch.setattr(basepath_mod, "detect_api_base", lambda target, session: api_base)


def test_ruoyi_vue_login_uses_prod_api_prefix(monkeypatch):
    _chain_with_base(monkeypatch, "/prod-api")
    sess = FakeSession(
        {
            ("get", "/prod-api/captchaImage"): FakeResp({"code": 200, "captchaEnabled": False}),
            ("post", "/prod-api/login"): FakeResp({"code": 200, "token": "tok-vue"}),
        }
    )
    chain = RuoYiAuthChain("http://target/", sess)
    assert chain.detect_auth_mode() == AUTH_V5_JWT
    assert chain.login_url == "http://target/prod-api/login"
    assert chain.login_style == "ruoyi-vue"
    ok, reason = chain.login(captcha_code="")
    assert ok, reason
    assert sess.session.headers["Authorization"] == "Bearer tok-vue"


def test_plus_unknown_route_json_does_not_misclassify(monkeypatch):
    """RuoYi 全局异常处理器对未知路由返回 200 + code=404 JSON，不能据此判 Plus。"""
    _chain_with_base(monkeypatch, "/prod-api")
    sess = FakeSession(
        {
            ("get", "/prod-api/auth/code"): FakeResp({"code": 404, "msg": "not found"}),
            ("get", "/prod-api/captchaImage"): FakeResp({"code": 200, "captchaEnabled": False}),
            ("post", "/prod-api/login"): FakeResp({"code": 200, "token": "tok-vue"}),
        }
    )
    chain = RuoYiAuthChain("http://target/", sess)
    chain.detect_auth_mode()
    assert chain.login_style == "ruoyi-vue"


def test_plus_login_posts_client_id_and_reads_access_token(monkeypatch):
    _chain_with_base(monkeypatch, "/prod-api")
    sess = FakeSession(
        {
            ("get", "/prod-api/auth/code"): FakeResp(
                {"code": 200, "msg": "操作成功", "data": {"captchaEnabled": False, "uuid": None, "img": None}}
            ),
            ("post", "/prod-api/auth/login"): FakeResp(
                {"code": 200, "msg": "操作成功", "data": {"access_token": "tok-plus", "expire_in": 7200}}
            ),
        }
    )
    chain = RuoYiAuthChain("http://target/", sess)
    assert chain.detect_auth_mode() == AUTH_V5_JWT
    assert chain.login_url == "http://target/prod-api/auth/login"
    assert chain.login_style == "plus"
    ok, reason = chain.login(captcha_code="")
    assert ok, reason
    assert sess.session.headers["Authorization"] == "Bearer tok-plus"
    post_call = [c for c in sess.calls if c[0] == "post"][-1]
    payload = post_call[2]["json"]
    assert payload["clientId"] == "e5cd7e4891bf95d1d19206ce24a7b32e"
    assert payload["grantType"] == "password"
    assert payload["tenantId"] == "000000"


def test_jeecg_login_uses_sys_login_and_x_access_token(monkeypatch):
    _chain_with_base(monkeypatch, "/jeecg-boot")
    sess = FakeSession(
        {
            ("post", "/jeecg-boot/sys/login"): FakeResp({"success": True, "result": {"token": "tok-jeecg"}}),
        }
    )
    chain = RuoYiAuthChain("http://target/", sess)
    assert chain.detect_auth_mode() == AUTH_V5_JWT
    assert chain.login_url == "http://target/jeecg-boot/sys/login"
    assert chain.login_style == "jeecg"
    ok, reason = chain.login()
    assert ok, reason
    assert sess.session.headers["X-Access-Token"] == "tok-jeecg"
    assert sess.session.headers["Authorization"] == "Bearer tok-jeecg"


# ── v1.5.6 WP1 配套：context-path 下的自定义登录入口 ─────────────────────
# 背景（2026-11-02 D1 实测）：应用部署在 /portal，登录入口是二开改名的
# /portal/auth/signin（不是 /portal/login）。旧逻辑在验证码形态不识别时
# **无条件假设**登录入口是 {base}/login，POST 打到 404 → --auth-login 恒 exit 4，
# 依赖会话的插件（如代码生成 SSTI）全部拿不到 CONFIRMED。

LOGIN_PAGE_HTML = """<html><body>
<form id="signupForm" action="/portal/auth/signin" method="post" autocomplete="off">
  <input name="username"><input type="password" name="password">
</form></body></html>"""


def test_custom_login_entry_read_from_form_action(monkeypatch):
    """登录入口改名时，从登录页 form action 读真实地址，而不是假设 {base}/login"""
    _chain_with_base(monkeypatch, "/portal")
    sess = FakeSession(
        {
            ("get", "/portal/"): FakeResp(LOGIN_PAGE_HTML, status=200, headers={"Content-Type": "text/html"}),
            ("get", "/portal/auth/signin"): FakeResp(
                LOGIN_PAGE_HTML, status=200, headers={"Content-Type": "text/html"}
            ),
        }
    )
    chain = RuoYiAuthChain("http://target/", sess)
    chain.detect_auth_mode()
    assert chain.login_url == "http://target/portal/auth/signin", chain.login_url


def test_default_login_entry_kept_when_no_form(monkeypatch):
    """登录页没有可识别表单时，保持 {base}/login 约定（不因读不到就乱改）"""
    _chain_with_base(monkeypatch, "/prod-api")
    sess = FakeSession({("get", "/prod-api/"): FakeResp("<html>no form</html>", status=200)})
    chain = RuoYiAuthChain("http://target/", sess)
    chain.detect_auth_mode()
    assert chain.login_url == "http://target/prod-api/login", chain.login_url


def test_form_action_requires_password_field():
    """只认含 password 输入框的 POST 表单——搜索框/筛选器不是登录入口"""
    chain = RuoYiAuthChain("http://target/", FakeSession({}))
    sess = FakeSession(
        {
            ("get", "/portal/"): FakeResp(
                '<form action="/portal/search" method="post"><input name="q"></form>', status=200
            ),
        }
    )
    chain.session = sess
    assert chain._login_form_action("http://target/portal/") == ""


def test_form_action_requires_post_method():
    """GET 表单不是登录入口（登录必须 POST）"""
    chain = RuoYiAuthChain("http://target/", FakeSession({}))
    sess = FakeSession(
        {
            ("get", "/portal/"): FakeResp(
                '<form action="/portal/auth/signin" method="get"><input type="password" name="p"></form>',
                status=200,
            ),
        }
    )
    chain.session = sess
    assert chain._login_form_action("http://target/portal/") == ""


def test_relative_form_action_is_absolutized():
    """action 是相对路径时也要能拼成绝对地址"""
    chain = RuoYiAuthChain("http://target/", FakeSession({}))
    sess = FakeSession(
        {
            ("get", "/portal/"): FakeResp(
                '<form action="auth/signin" method="post"><input type="password" name="p"></form>', status=200
            ),
        }
    )
    chain.session = sess
    assert chain._login_form_action("http://target/portal/") == "http://target/portal/auth/signin"
