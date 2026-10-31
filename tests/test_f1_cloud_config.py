# F1-4：Spring Cloud Config 未授权配置读取的真检测与三态契约。
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from plugins.spring.spring_cloud_config import SpringCloudConfigPlugin


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "application/json"}
        self.content = text.encode("utf-8")


class FakeSession:
    def __init__(self, handler):
        self.handler = handler

    def get(self, url, **kw):
        return self.handler(url)


def test_config_server_confirmed_with_key_names_only():
    body = json.dumps(
        {
            "name": "application",
            "profiles": ["default"],
            "propertySources": [
                {
                    "name": "file:config/application.yml",
                    "source": {
                        "spring.datasource.password": "demo_only_change_me",
                        "spring.redis.password": "demo_only_change_me",
                        "server.port": 8088,
                    },
                }
            ],
        }
    )

    def handler(url):
        if url.endswith("/application/default"):
            return FakeResp(body)
        if "..%252F" in url:
            return FakeResp("root:x:0:0:root:/root:/bin/bash")
        return FakeResp("", 404)

    result = SpringCloudConfigPlugin().verify("http://target/", FakeSession(handler))
    assert result.status == STATUS_CONFIRMED, result
    assert "propertySources" in result.evidence
    assert "spring.datasource.password" in result.evidence
    assert "spring.redis.password" in result.evidence
    assert "demo_only_change_me" not in result.evidence
    assert "CVE-2020-5410" in result.evidence


def test_normal_spring_404_json_is_safe():
    body = '{"timestamp":"2026-10-31T10:00:00+08:00","status":404,"error":"Not Found","path":"/application/default"}'

    def handler(url):
        return FakeResp(body, 404)

    result = SpringCloudConfigPlugin().verify("http://target/", FakeSession(handler))
    assert result.status == STATUS_SAFE, result


def test_all_timeout_is_unknown():
    def handler(url):
        raise TimeoutError("timed out")

    result = SpringCloudConfigPlugin().verify("http://target/", FakeSession(handler))
    assert result.status == STATUS_UNKNOWN, result


def test_parse_failure_is_unknown():
    def handler(url):
        return FakeResp("{propertySources:", 200)

    result = SpringCloudConfigPlugin().verify("http://target/", FakeSession(handler))
    assert result.status == STATUS_UNKNOWN, result
