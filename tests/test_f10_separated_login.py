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
