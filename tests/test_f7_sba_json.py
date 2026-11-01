# F7-2：Spring Boot Admin 必须请求 JSON API，而不是只看 SPA 壳页。
#
# 背景：C2-1a 的 /applications 默认返回 1279 字节 SPA 壳（判 SAFE）；
# 带 Accept: application/json 返回 1876 字节、1 个实例列表。
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE  # noqa: E402
from plugins.spring.spring_boot_admin import SpringBootAdminPlugin  # noqa: E402


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.handler(url, kwargs)


def test_json_instance_list_confirmed():
    """Accept: application/json 返回非空实例列表 → CONFIRMED。"""
    instances = [{"name": "ruoyi-admin", "status": "UP", "version": "1.0.0"}]

    def handler(url, kwargs):
        if url.endswith("/applications"):
            return FakeResp(json.dumps(instances), 200, {"Content-Type": "application/json"})
        return FakeResp("<html><body>spa shell</body></html>", 200)

    session = FakeSession(handler)
    result = SpringBootAdminPlugin().verify("http://target/", session)

    assert result.status == STATUS_CONFIRMED, result
    assert "JSON" in result.evidence
    assert session.calls[0][1].get("headers") == {"Accept": "application/json"}


def test_spa_shell_safe():
    """只有 SPA 壳页（无 JSON 列表、无 SBA 标识）→ SAFE。"""
    shell = (
        "<!DOCTYPE html><html><head><title>Admin</title></head>"
        "<body><div id='app'></div><script src='/assets/index.js'></script></body></html>"
    )

    def handler(url, kwargs):
        return FakeResp(shell, 200, {"Content-Type": "text/html"})

    result = SpringBootAdminPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_SAFE, result


def test_empty_200_safe():
    """三个路径都 200 + 空 body：解析失败，不算命中。"""
    result = SpringBootAdminPlugin().verify(
        "http://target/",
        FakeSession(lambda url, kwargs: FakeResp("", 200)),
    )

    assert result.status == STATUS_SAFE, result


def test_json_error_object_not_confirmed():
    """JSON 错误对象（无 instances/applications）不算命中。"""
    error = {"timestamp": "2026-11-01T00:00:00", "status": 404, "error": "Not Found", "path": "/applications"}

    def handler(url, kwargs):
        return FakeResp(json.dumps(error), 200, {"Content-Type": "application/json"})

    result = SpringBootAdminPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_SAFE, result


def test_dict_instances_confirmed():
    """部分 SBA 版本包一层 {"instances": [...]} → CONFIRMED。"""
    body = json.dumps({"instances": [{"name": "app-a"}, {"name": "app-b"}]})

    def handler(url, kwargs):
        if url.endswith("/instances"):
            return FakeResp(body, 200, {"Content-Type": "application/json"})
        return FakeResp("", 200)

    result = SpringBootAdminPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_CONFIRMED, result
    assert "2 个实例/应用" in result.evidence
