# F1-2：Config Server 通配 JSON 不得被 Swagger / IDE 残留插件当成真实文件；
# 真 Swagger 与 SPA 图标样本的行为保持不变。
import json
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE
from plugins.common.source_leak import SourceLeakPlugin
from plugins.common.swagger_leak import SwaggerLeakPlugin


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None, url=""):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.content = text.encode("utf-8")
        self.url = url


class FakeSession:
    def __init__(self, handler):
        self.handler = handler

    def get(self, url, **kw):
        return self.handler(url)


def _config_wrapper(url):
    path = urlparse(url).path.strip("/")
    parts = [part for part in path.split("/") if part]
    name = parts[0] if parts else "application"
    profiles = [parts[1]] if len(parts) > 1 else ["default"]
    body = {
        "name": name,
        "profiles": profiles,
        "label": None,
        "version": None,
        "state": None,
        "propertySources": [
            {
                "name": "file:config/application.yml",
                "source": {
                    "server.port": 8088,
                    "spring.datasource.url": "jdbc:mysql://10.20.30.21/customer_center",
                    "feature.order-audit": False,
                },
            }
        ],
    }
    return FakeResp(json.dumps(body), 200, {"Content-Type": "application/json"}, url=url)


def _config_source(url):
    body = {
        "server": {"port": 8088},
        "spring": {
            "application": {"name": "customer-service"},
            "datasource": {"url": "jdbc:mysql://10.20.30.21/customer_center"},
            "redis": {"host": "10.20.30.31", "port": 6379},
        },
        "feature": {"order-audit": False},
    }
    return FakeResp(json.dumps(body), 200, {"Content-Type": "application/json"}, url=url)


def _not_found(url):
    return FakeResp("", 404, {"Content-Type": "text/html"}, url=url)


def test_config_wildcard_not_swagger_and_not_ide_residue():
    def handler(url):
        if url.endswith("/package-lock.json"):
            return _config_source(url)
        return _config_wrapper(url)

    session = FakeSession(handler)
    swagger = SwaggerLeakPlugin().verify("http://target/", session)
    ide = SourceLeakPlugin().verify("http://target/", session)
    assert swagger.status == STATUS_SAFE, swagger
    assert ide.status == STATUS_SAFE, ide


def test_true_swagger_json_still_confirmed():
    def handler(url):
        if url.endswith("/v2/api-docs"):
            body = json.dumps({"swagger": "2.0", "paths": {"/user": {"get": {}}}})
            return FakeResp(body, 200, {"Content-Type": "application/json"}, url=url)
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))
    assert result.status == STATUS_CONFIRMED, result
    assert "/v2/api-docs" in result.evidence


def test_spa_swagger_icon_not_confirmed():
    def handler(url):
        if url.endswith("/swagger-ui/index.html"):
            html = '<html><body><svg><symbol id="icon-swagger"></symbol></svg></body></html>'
            return FakeResp(html, 200, {"Content-Type": "text/html"}, url=url)
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))
    assert result.status == STATUS_SAFE, result


def test_swagger_resources_array_confirmed():
    def handler(url):
        if url.endswith("/swagger-resources"):
            body = json.dumps([{"name": "default", "url": "/v2/api-docs", "swaggerVersion": "2.0"}])
            return FakeResp(body, 200, {"Content-Type": "application/json"}, url=url)
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))
    assert result.status == STATUS_CONFIRMED, result
    assert "/swagger-resources" in result.evidence


def test_swagger_config_object_confirmed():
    def handler(url):
        if url.endswith("/v3/api-docs/swagger-config"):
            body = json.dumps(
                {
                    "configUrl": "/v3/api-docs/swagger-config",
                    "url": "/v3/api-docs",
                    "urls": [{"name": "default", "url": "/v3/api-docs"}],
                }
            )
            return FakeResp(body, 200, {"Content-Type": "application/json"}, url=url)
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))
    assert result.status == STATUS_CONFIRMED, result
    assert "/v3/api-docs/swagger-config" in result.evidence


def test_config_echo_v3_api_docs_not_confirmed():
    def handler(url):
        body = json.dumps({"name": "v3", "profiles": ["api-docs"]})
        return FakeResp(body, 200, {"Content-Type": "application/json"}, url=url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))
    assert result.status == STATUS_SAFE, result
