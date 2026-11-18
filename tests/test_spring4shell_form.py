# F7-5：Spring4Shell 不能只探根路径，也不能把「200 无错误」直接判 CONFIRMED。
#
# 背景：C2-2 POST / 返回 405，真实表单接口 /device/add 返回 200；
# 插件固定 join_url(target, "/")，把「根路径方法不允许」误写成 SAFE。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN  # noqa: E402
from plugins.spring.spring4shell import S4S_MARKER, Spring4shellPlugin  # noqa: E402

FORM_PAGE = (
    "<html><body><h1>园区设备登记</h1>"
    '<form action="/device/add" method="post">'
    '<input name="deviceName"><button type="submit">提交</button></form></body></html>'
)


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self.handler("GET", url, kw)

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self.handler("POST", url, kw)


def test_root_405_form_action_200_unknown():
    """根 POST 405 + 同源表单 action 200 → UNKNOWN（可达但未验证代码执行）。"""

    def handler(method, url, kwargs):
        if method == "GET" and url == "http://target/":
            return FakeResp(FORM_PAGE, 200)
        if method == "POST" and url == "http://target/":
            return FakeResp("<html><body>405 Method Not Allowed</body></html>", 405)
        if method == "POST" and url == "http://target/device/add":
            return FakeResp('{"code":200,"message":"设备登记成功"}', 200, {"Content-Type": "application/json"})
        return FakeResp("", 404)

    session = FakeSession(handler)
    result = Spring4shellPlugin().verify("http://target/", session)

    assert result.status == STATUS_UNKNOWN, result
    assert "表单端点可达" in result.evidence
    assert "未验证代码执行" in result.evidence
    assert any(method == "POST" and url.endswith("/device/add") for method, url, _ in session.calls)
    benign = next(kw for method, url, kw in session.calls if method == "POST" and url.endswith("/device/add"))
    assert benign.get("data") == {"name": "probe", "value": "probe"}


def test_root_marker_confirmed():
    """内置签名靶场：根路径 POST 返回 S4S_MARKER → CONFIRMED。"""

    def handler(method, url, kwargs):
        if method == "GET":
            return FakeResp("<html><body>root</body></html>", 200)
        if method == "POST" and url == "http://target/":
            return FakeResp('{"status":200,"_marker":"' + S4S_MARKER + '"}', 200)
        return FakeResp("", 404)

    result = Spring4shellPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_CONFIRMED, result
    assert S4S_MARKER in result.evidence


def test_root_404_no_form_unknown():
    """根路径 404 且无表单 → UNKNOWN，不许判 SAFE。"""

    def handler(method, url, kwargs):
        return FakeResp("", 404)

    result = Spring4shellPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_UNKNOWN, result
    assert "测不到" in result.evidence


def test_benign_200_without_form_safe():
    """根路径 200、无表单、无 marker → SAFE（不能仅凭 200 判 CONFIRMED）。"""

    def handler(method, url, kwargs):
        if method == "GET":
            return FakeResp("<html><body>plain page</body></html>", 200)
        if method == "POST" and url == "http://target/":
            return FakeResp('{"timestamp":"2026-11-01","status":400,"error":"Bad Request"}', 400)
        return FakeResp("", 404)

    result = Spring4shellPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_SAFE, result


def test_external_form_action_not_submitted():
    """跨站 action 不发送探针（只收同源表单）。"""

    page = '<html><form action="http://evil.example/collect" method="post"></form></html>'

    def handler(method, url, kwargs):
        if method == "GET":
            return FakeResp(page, 200)
        if method == "POST" and url == "http://target/":
            return FakeResp('{"status":400,"error":"Bad Request"}', 400)
        if url.startswith("http://evil.example/"):
            raise AssertionError("不应向第三方站点发送表单探针")
        return FakeResp("", 404)

    result = Spring4shellPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_SAFE, result
