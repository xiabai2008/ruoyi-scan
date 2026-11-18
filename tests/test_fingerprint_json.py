# F1-1：Spring Boot 根路径错误 JSON 也能作为强指纹，且不得误伤若依/Jeecg。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fingerprint import detect_cms


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None, content=b""):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.content = content


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))


def _json_resp(path, status=404):
    body = (
        '{"timestamp":"2026-10-31T10:42:18.832+08:00","status":%d,'
        '"error":"Not Found","message":"No message available","path":"%s"}'
    ) % (status, path)
    return FakeResp(body, status, {"Content-Type": "application/json"})


def _detect_root(resp):
    return detect_cms("http://target/", FakeSession({"http://target/": resp}))


def test_h2_root_404_json_is_spring():
    res = _detect_root(_json_resp("/h2-console"))
    assert res.cms == "spring", res
    assert any(item.startswith("root_json:") for item in res.matched), res.matched


def test_data_rest_root_404_json_is_spring():
    res = _detect_root(_json_resp("/api"))
    assert res.cms == "spring", res
    assert any(item.startswith("root_json:") for item in res.matched), res.matched


def test_config_root_404_json_is_spring():
    res = _detect_root(_json_resp("/application/default"))
    assert res.cms == "spring", res
    assert any(item.startswith("root_json:") for item in res.matched), res.matched


def test_ruoyi_login_html_still_ruoyi():
    html = "<html><head><title>若依管理系统</title></head><body>RuoYi</body></html>"
    res = _detect_root(FakeResp(html, 200, {"Content-Type": "text/html"}))
    assert res.cms == "ruoyi", res


def test_jeecg_login_html_still_jeecgboot():
    html = "<html><head><title>JeecgBoot 企业级低代码平台</title></head><body>JeecgBoot</body></html>"
    res = _detect_root(FakeResp(html, 200, {"Content-Type": "text/html"}))
    assert res.cms == "jeecgboot", res


def test_nginx_404_html_not_spring():
    html = "<html><head><title>404 Not Found</title></head><body><h1>404</h1><hr>nginx</body></html>"
    res = _detect_root(FakeResp(html, 404, {"Content-Type": "text/html"}))
    assert res.cms == "", res


def test_truncated_json_does_not_raise():
    res = _detect_root(FakeResp("{timestamp:", 404, {"Content-Type": "application/json"}))
    assert res.cms == "", res
