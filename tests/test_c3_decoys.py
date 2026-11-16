# C3 蜜罐两类 B 类误报的回归（2026-11-16 真实靶场实测）
#
# C3 期望只报 `.git` / `.env` 两条 A 类诱饵。旧实现额外报：
#   1. RuoYi Swagger 未授权访问 —— 假 `/swagger-ui.html` + `/v2/api-docs` paths={}
#   2. 未授权访问（批量） —— 假 Actuator env / Druid 登录页 / 假 Swagger UI
#
# 判定原则：关键字只能证明「页面长得像」，必须再有真实结构才算未授权暴露。
import json
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE  # noqa: E402
from plugins.ruoyi.ruoyi_swagger_unauth import RuoyiSwaggerUnauthPlugin  # noqa: E402
from plugins.ruoyi.unauth_batch import UnauthBatchPlugin  # noqa: E402

# ── C3 蜜罐响应（取自 2026-11-16 实测） ─────────────────────────────────────
C3_SWAGGER_UI = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Swagger UI</title>
<link rel="stylesheet" href="/webjars/swagger-ui/swagger-ui.css" /></head>
<body><div id="swagger-ui"></div>
<script src="/webjars/swagger-ui/swagger-ui-bundle.js"></script>
<script>window.ui = SwaggerUIBundle({url: "/v2/api-docs", dom_id: "#swagger-ui"});</script>
</body></html>"""

C3_EMPTY_DOCS = json.dumps(
    {
        "basePath": "/",
        "host": "127.0.0.1:19331",
        "info": {"title": "邕江云服务门户 API", "version": "1.0"},
        "paths": {},
        "schemes": ["http"],
        "swagger": "2.0",
    }
)

C3_DRUID_LOGIN = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Druid Stat Index</title></head>
<body>
<h2>Druid Stat Index</h2>
<form action="/druid/submitLogin" method="post">
  <p><input type="text" name="loginUsername" placeholder="用户名" /></p>
  <p><input type="password" name="loginPassword" placeholder="密码" /></p>
  <p><button type="submit">登录</button></p>
</form>
</body>
</html>"""

# C3 的假 env：有 propertySources + systemEnvironment，但没有 systemProperties，
# 应用配置项也没有 origin —— 真实 Actuator 不会这样。
C3_FAKE_ENV = json.dumps(
    {
        "activeProfiles": ["prod"],
        "propertySources": [
            {
                "name": "systemEnvironment",
                "properties": {
                    "DB_HOST": {"value": "10.20.30.21"},
                    "DB_PASSWORD": {"value": "ChangeMe_2024"},
                    "DB_USER": {"value": "erp_app"},
                },
            },
            {
                "name": "applicationConfig: [classpath:/application-prod.yml]",
                "properties": {
                    "logging.level.root": {"value": "INFO"},
                    "spring.datasource.url": {"value": "jdbc:mysql://10.20.30.21:3306/erp_portal"},
                },
            },
        ],
    }
)

# 未知路径的统一 catch-all：普通门户页，不含任何漏洞关键字
CATCH_ALL = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>邕江云服务门户</title></head>
<body><h1>邕江云服务门户</h1><p>请从统一入口访问业务系统。</p></body></html>"""


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html; charset=utf-8"}
        self.content = text.encode("utf-8")


class FakeSession:
    def __init__(self, handler):
        self.handler = handler

    def get(self, url, **kwargs):
        return self.handler(url)


def _json(text):
    return FakeResp(text, 200, {"Content-Type": "application/json"})


def _html(text):
    return FakeResp(text, 200, {"Content-Type": "text/html; charset=utf-8"})


def _c3_handler(url):
    path = urlparse(url).path
    if path == "/swagger-ui.html":
        return _html(C3_SWAGGER_UI)
    if path == "/v2/api-docs":
        return _json(C3_EMPTY_DOCS)
    if path == "/druid/index.html":
        return _html(C3_DRUID_LOGIN)
    if path == "/actuator/env":
        return _json(C3_FAKE_ENV)
    return _html(CATCH_ALL)


# ── RuoYi Swagger：假 UI 页不能单独成立 ────────────────────────────────────


def test_c3_fake_swagger_ui_is_not_confirmed():
    result = RuoyiSwaggerUnauthPlugin().verify("http://c3/", FakeSession(_c3_handler))
    assert result.status == STATUS_SAFE, result
    assert "文档" in result.evidence, result.evidence


def test_real_swagger_docs_still_confirmed():
    docs = json.dumps({"swagger": "2.0", "paths": {"/system/user/list": {"post": {}}}})

    def handler(url):
        if urlparse(url).path == "/v2/api-docs":
            return _json(docs)
        return _html(CATCH_ALL)

    result = RuoyiSwaggerUnauthPlugin().verify("http://real/", FakeSession(handler))
    assert result.status == STATUS_CONFIRMED, result
    assert "/v2/api-docs" in result.evidence


def test_swagger_ui_without_any_docs_endpoint_is_not_confirmed():
    """只有 UI 页、文档端点 404：没有接口定义可泄露，不能判 CONFIRMED。"""

    def handler(url):
        path = urlparse(url).path
        if path == "/swagger-ui.html":
            return _html(C3_SWAGGER_UI)
        return FakeResp("Not Found", 404, {"Content-Type": "text/html"})

    result = RuoyiSwaggerUnauthPlugin().verify("http://ui-only/", FakeSession(handler))
    assert result.status == STATUS_SAFE, result


# ── 未授权访问（批量）：三个假端点都不能成立 ───────────────────────────────


def test_c3_unauth_batch_decoys_are_all_safe():
    result = UnauthBatchPlugin().verify("http://c3/", FakeSession(_c3_handler))
    assert result.status == STATUS_SAFE, result
    assert "hit_endpoints" not in result.extra or not result.extra["hit_endpoints"], result.extra

    assert "Druid 监控:SAFE(Druid 登录页" in result.evidence, result.evidence
    assert "Spring Actuator env:SAFE(JSON 结构不是真实 Actuator env" in result.evidence, result.evidence
    assert "Swagger UI:SAFE(Swagger UI 页面可达但文档 JSON 为空" in result.evidence, result.evidence


def test_unauth_batch_real_actuator_env_confirmed():
    real_env = json.dumps(
        {
            "activeProfiles": ["prod"],
            "propertySources": [
                {
                    "name": "systemProperties",
                    "properties": {"java.runtime.name": {"value": "Java(TM) SE Runtime Environment"}},
                },
                {
                    "name": "applicationConfig: [classpath:/application.yml]",
                    "properties": {
                        "server.port": {"value": 8080, "origin": "class path resource [application.yml]:1:5"}
                    },
                },
            ],
        }
    )

    def handler(url):
        if urlparse(url).path == "/actuator/env":
            return _json(real_env)
        return FakeResp("Not Found", 404, {"Content-Type": "text/html"})

    result = UnauthBatchPlugin().verify("http://real/", FakeSession(handler))
    assert result.status == STATUS_CONFIRMED, result
    assert [h["name"] for h in result.extra["hit_endpoints"]] == ["Spring Actuator env"]


def test_unauth_batch_real_druid_index_confirmed():
    druid_index = (
        "<html><head><title>Druid Stat Index</title></head>"
        "<body><a href='/druid/sql.html'>SQL Monitor</a> Druid Monitor</body></html>"
    )

    def handler(url):
        if urlparse(url).path == "/druid/index.html":
            return _html(druid_index)
        return FakeResp("Not Found", 404, {"Content-Type": "text/html"})

    result = UnauthBatchPlugin().verify("http://real/", FakeSession(handler))
    assert result.status == STATUS_CONFIRMED, result
    assert [h["name"] for h in result.extra["hit_endpoints"]] == ["Druid 监控"]


def test_unauth_batch_swagger_confirmed_only_with_real_docs():
    docs = json.dumps({"openapi": "3.1.0", "paths": {"/system/user/list": {"get": {}}}})

    def handler(url):
        path = urlparse(url).path
        if path == "/swagger-ui.html":
            return _html(C3_SWAGGER_UI)
        if path == "/v3/api-docs":
            return _json(docs)
        return FakeResp("Not Found", 404, {"Content-Type": "text/html"})

    result = UnauthBatchPlugin().verify("http://real/", FakeSession(handler))
    assert result.status == STATUS_CONFIRMED, result
    assert "Swagger UI" in [h["name"] for h in result.extra["hit_endpoints"]]
