# F7-4：Swagger 文档泄露只认「有实际接口」的文档，不认空 paths / 空 urls / 纯 UI。
#
# 背景：C3 蜜罐 /v2/api-docs 返回 {"swagger":"2.0","paths":{}}，
# 旧实现仍判 CONFIRMED（B 类硬误报）。纯 UI 页面交给 ruoyi_swagger_unauth。
import json
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE  # noqa: E402
from plugins.common.swagger_leak import SwaggerLeakPlugin  # noqa: E402

UI_PAGE = (
    "<!DOCTYPE html><html><head><title>Swagger UI</title>"
    '<link rel="stylesheet" href="/webjars/swagger-ui/swagger-ui.css" /></head>'
    '<body><div id="swagger-ui"></div>'
    '<script>window.ui = SwaggerUIBundle({url: "/v2/api-docs"});</script></body></html>'
)


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}


class FakeSession:
    def __init__(self, handler):
        self.handler = handler

    def get(self, url, **kw):
        return self.handler(url)


def _not_found(url):
    return FakeResp("", 404)


def test_empty_paths_safe():
    """{"swagger":"2.0","paths":{}} → SAFE。"""
    body = json.dumps({"swagger": "2.0", "info": {"title": "doc"}, "paths": {}})

    def handler(url):
        if url.endswith("/v2/api-docs"):
            return FakeResp(body, 200, {"Content-Type": "application/json"})
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_SAFE, result


def test_one_path_confirmed():
    """paths 至少有一条 → CONFIRMED，evidence 带端点。"""
    body = json.dumps({"swagger": "2.0", "paths": {"/user/list": {"get": {}}}})

    def handler(url):
        if url.endswith("/v2/api-docs"):
            return FakeResp(body, 200, {"Content-Type": "application/json"})
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_CONFIRMED, result
    assert "/v2/api-docs" in result.evidence


def test_empty_urls_config_safe():
    """swagger-config 的 urls 为空 → SAFE（configUrl 本身不是文档）。"""
    body = json.dumps({"configUrl": "/v3/api-docs/swagger-config", "urls": []})

    def handler(url):
        if url.endswith("/v3/api-docs/swagger-config"):
            return FakeResp(body, 200, {"Content-Type": "application/json"})
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_SAFE, result


def test_ui_only_with_empty_doc_safe():
    """C3 复扫形态：UI 页面 200 + /v2/api-docs paths={} → 本插件不再报文档泄露。"""
    docs = json.dumps({"swagger": "2.0", "info": {"title": "C3 API"}, "paths": {}})

    def handler(url):
        path = urlparse(url).path
        if path == "/swagger-ui.html":
            return FakeResp(UI_PAGE, 200, {"Content-Type": "text/html"})
        if path == "/v2/api-docs":
            return FakeResp(docs, 200, {"Content-Type": "application/json"})
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_SAFE, result
    assert "Swagger API" not in result.evidence or "未发现" in result.evidence


def test_empty_swagger_resources_array_safe():
    """swagger-resources 返回空数组 → SAFE。"""

    def handler(url):
        if url.endswith("/swagger-resources"):
            return FakeResp("[]", 200, {"Content-Type": "application/json"})
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_SAFE, result


def test_swagger_resources_with_version_confirmed():
    """swagger-resources 非空且元素含 swaggerVersion → CONFIRMED。"""
    body = json.dumps([{"name": "default", "url": "/v2/api-docs", "swaggerVersion": "2.0"}])

    def handler(url):
        if url.endswith("/swagger-resources"):
            return FakeResp(body, 200, {"Content-Type": "application/json"})
        return _not_found(url)

    result = SwaggerLeakPlugin().verify("http://target/", FakeSession(handler))

    assert result.status == STATUS_CONFIRMED, result
    assert "/swagger-resources" in result.evidence
