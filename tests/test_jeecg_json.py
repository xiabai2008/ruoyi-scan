# F1-3：JeecgBoot 的 /sys/login 必须校验 success 键，不能只看 200 + JSON。
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fingerprint import detect_cms


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.content = text.encode("utf-8")


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))


def _config_login_body():
    return json.dumps(
        {
            "name": "sys",
            "profiles": ["login"],
            "label": None,
            "version": None,
            "state": None,
            "propertySources": [{"name": "file:config/application.yml", "source": {"server.port": 8088}}],
        }
    )


def test_config_server_sys_login_not_jeecgboot():
    body = _config_login_body()
    session = FakeSession(
        {
            "http://target/": FakeResp(body, 200, {"Content-Type": "application/json"}),
            "http://target/sys/login": FakeResp(body, 200, {"Content-Type": "application/json"}),
        }
    )
    result = detect_cms("http://target/", session)
    assert result.cms != "jeecgboot", result


def test_real_jeecg_failure_response_is_jeecgboot():
    body = '{"success":false,"message":"验证码无效","code":500}'
    session = FakeSession(
        {
            "http://target/sys/login": FakeResp(body, 200, {"Content-Type": "application/json"}),
        }
    )
    result = detect_cms("http://target/", session)
    assert result.cms == "jeecgboot", result


def test_real_jeecg_success_response_is_jeecgboot():
    body = '{"success":true,"result":{"token":"demo-token"}}'
    session = FakeSession(
        {
            "http://target/sys/login": FakeResp(body, 200, {"Content-Type": "application/json"}),
        }
    )
    result = detect_cms("http://target/", session)
    assert result.cms == "jeecgboot", result
