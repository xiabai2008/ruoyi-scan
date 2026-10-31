# F3-3 行为级门禁：默认口令插件的回退分支不得污染共享会话。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.auth_chain as auth_chain  # noqa: E402
import core.session as core_session  # noqa: E402
from common.models import STATUS_CONFIRMED  # noqa: E402
from plugins.ruoyi.default_password import DefaultPasswordPlugin  # noqa: E402


class FakeResp:
    status_code = 200
    text = '{"code":200,"msg":"操作成功"}'
    headers = {"Content-Type": "application/json", "Set-Cookie": "Admin-Token=leaked; Path=/"}

    def json(self):
        return {"code": 200, "msg": "操作成功"}


class FakeSession:
    """模拟 requests.Session：收到 Set-Cookie 时会写入自己的 cookie 罐。"""

    def __init__(self):
        self.cookies = {}
        self.headers = {}

    def post(self, url, **kwargs):
        self.cookies["Admin-Token"] = "leaked"
        return FakeResp()

    def get(self, url, **kwargs):
        return FakeResp()

    def close(self):
        return None


def test_default_password_does_not_authenticate_shared_session(monkeypatch):
    # 强制 isolated_auth_session 内部登录失败，走插件自己的回退分支
    monkeypatch.setattr(
        auth_chain.RuoYiAuthChain,
        "login",
        lambda self, *args, **kwargs: (False, "captcha_error"),
    )
    # 隔离会话和旧公共登录器都拿到独立的 FakeSession，不碰传入的 shared
    monkeypatch.setattr(core_session, "SessionManager", lambda *args, **kwargs: FakeSession())

    shared = FakeSession()
    result = DefaultPasswordPlugin().verify("http://target/", shared)

    assert result.status == STATUS_CONFIRMED, result
    assert shared.cookies == {}, f"共享会话被写入 cookie: {shared.cookies}"
    assert "Authorization" not in shared.headers, f"共享会话被写入 header: {shared.headers}"
