# 网络异常 → UNKNOWN（三态铁律）契约测试：批量覆盖插件的异常分支
# 背景：覆盖率棘轮发现大量 except→UNKNOWN 分支无常驻用例；本文件以最小替身统一守护该契约。
import importlib
from unittest.mock import patch

import pytest
import requests

from common.models import STATUS_SAFE, STATUS_UNKNOWN

# 契约要求：网络不可达（请求抛异常）→ 必须返回 UNKNOWN，绝不冒充 SAFE/CONFIRMED
CANDIDATES = [
    ("plugins.spring.cloud_function_rce", "SpringCloudFunctionRcePlugin"),
    ("plugins.spring.mappings_leak", "SpringMappingsLeakPlugin"),
    ("plugins.spring.spring_data_rest", "SpringDataRestPlugin"),
    ("plugins.spring.spring_cloud_config", "SpringCloudConfigPlugin"),
    ("plugins.spring.trace_leak", "SpringTraceLeakPlugin"),
    ("plugins.spring.heapdump_leak", "SpringHeapdumpLeakPlugin"),
    ("plugins.spring.jolokia_rce", "SpringJolokiaRcePlugin"),
    ("plugins.spring.jolokia_mlet_rce", "SpringJolokiaMletRcePlugin"),
    ("plugins.spring.h2_console_rce", "SpringH2ConsoleRcePlugin"),
    ("plugins.spring.gateway_rce", "SpringGatewayRcePlugin"),
    ("plugins.spring.spring4shell", "Spring4shellPlugin"),
    ("plugins.spring.actuator_env_rce", "SpringActuatorEnvRcePlugin"),
    ("plugins.spring.actuator_unauth", "SpringActuatorUnauthPlugin"),
    ("plugins.common.swagger_leak", "SwaggerLeakPlugin"),
    ("plugins.common.trace_method", "TraceMethodPlugin"),
    ("plugins.common.dir_listing", "DirListingPlugin"),
    ("plugins.common.source_leak", "SourceLeakPlugin"),
    ("plugins.common.env_leak", "EnvLeakPlugin"),
    ("plugins.common.git_leak", "GitLeakPlugin"),
    ("plugins.common.minio_unauth", "MinioUnauthPlugin"),
    ("plugins.common.rocketmq_unauth", "RocketmqUnauthPlugin"),
    ("plugins.common.redis_unauth", "RedisUnauthPlugin"),
    ("plugins.common.cors_misconfig", "CorsMisconfigPlugin"),
]


class _RaisingSession:
    """所有请求均抛连接异常（模拟目标不可达/断网）

    使用 requests.exceptions.ConnectionError：与真实会话一致；
    部分插件按最佳实践收窄为 `except requests.exceptions.RequestException`，
    只有该层级的异常才会被正确地映射为 UNKNOWN。
    """

    def get(self, *args, **kwargs):
        raise requests.exceptions.ConnectionError("target unreachable")

    def post(self, *args, **kwargs):
        raise requests.exceptions.ConnectionError("target unreachable")

    def request(self, *args, **kwargs):
        raise requests.exceptions.ConnectionError("target unreachable")

    def close(self):
        pass


class _StaticResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class _StaticSession:
    def __init__(self, resp):
        self._resp = resp

    def get(self, *args, **kwargs):
        return self._resp


@pytest.mark.parametrize("module,klass", CANDIDATES)
def test_network_error_returns_unknown(module, klass):
    cls = getattr(importlib.import_module(module), klass)
    # 部分中间件插件（Redis/RocketMQ 等）绕过 HTTP 会话直连 socket；
    # 本机恰好在跑这些服务时会把“网络异常”用例变成真实探测，结果依赖环境。
    # 统一把 socket 连接也置为失败，保证该契约在任何机器上都可重复。
    with patch("socket.create_connection", side_effect=OSError("target unreachable")):
        result = cls().verify("http://127.0.0.1:1/", _RaisingSession())
    assert result.status == STATUS_UNKNOWN, f"{klass} 网络异常应判 UNKNOWN，实际 {result.status}"


def test_shiro_rememberme_feature_returns_unknown():
    from plugins.common.shiro_rememberme import ShiroRemembermePlugin

    resp = _StaticResp(200, "", {"Set-Cookie": "rememberMe=deleteMe; Path=/"})
    result = ShiroRemembermePlugin().verify("http://x/", _StaticSession(resp))
    assert result.status == STATUS_UNKNOWN


def test_shiro_all_failed_returns_unknown():
    from plugins.common.shiro_rememberme import ShiroRemembermePlugin

    result = ShiroRemembermePlugin().verify("http://x/", _RaisingSession())
    assert result.status == STATUS_UNKNOWN


def test_shiro_no_feature_returns_safe():
    from plugins.common.shiro_rememberme import ShiroRemembermePlugin

    result = ShiroRemembermePlugin().verify("http://x/", _StaticSession(_StaticResp()))
    assert result.status == STATUS_SAFE


def test_shiro_plugin_does_not_claim_rce_capability():
    """能力边界护栏：Shiro 插件只做指纹，不得挂 CVE / high / vuln 类别

    历史问题（2026-11-02 方案 A 收口）：插件曾挂 CVE-2016-4437 + severity=high +
    name 带「反序列化」，但判定只到 UNKNOWN，永远 CONFIRMED 不了——报告里出现一条
    「high 级 Shiro 反序列化 RCE」会让读者以为扫描器确认了可利用性。

    这条断言的作用是**挡住回退**：以后谁想再挂回 CVE 或提回 high，必须先让插件
    真的能验证密钥（v1.6 计划中的回显验证），而不是改个字段把报告做好看。
    """
    from common.models import SEVERITY_LOW
    from plugins.common.shiro_rememberme import ShiroRemembermePlugin

    assert ShiroRemembermePlugin.cve == "N/A", "指纹类插件不得挂 CVE 编号（会造成 CVE 统计虚报）"
    assert ShiroRemembermePlugin.severity == SEVERITY_LOW, "指纹本身不是 high 风险，风险取决于密钥是否可利用"
    assert ShiroRemembermePlugin.category == "recon", "属侦察信息，不是漏洞判定"
    assert "反序列化" not in ShiroRemembermePlugin.name, "名称不得暗示已完成反序列化验证"
    # vuln_type 置空：否则 dedup 会把指纹结果和真正的 rce 结果聚合到一起
    assert ShiroRemembermePlugin.vuln_type == ""


def test_swagger_non_200_is_skipped_then_safe():
    from plugins.common.swagger_leak import SwaggerLeakPlugin

    result = SwaggerLeakPlugin().verify("http://x/", _StaticSession(_StaticResp(404)))
    assert result.status == STATUS_SAFE


def test_swagger_ui_only_is_not_document_leak():
    """F7-4：纯 UI 页面不算文档泄露；由 ruoyi_swagger_unauth 单独报「UI 可访问」。"""
    from plugins.common.swagger_leak import SwaggerLeakPlugin

    resp = _StaticResp(200, "<html><head><title>swagger-ui</title></head></html>", {"Content-Type": "text/html"})
    result = SwaggerLeakPlugin().verify("http://x/", _StaticSession(resp))
    assert result.status == STATUS_SAFE


def test_backup_scan_survives_request_errors():
    """备份扫描在请求全部异常时不得崩溃：允许 SAFE/UNKNOWN（软 404 基线自行处理异常）"""
    from plugins.common.backup_scan import BackupScanPlugin

    result = BackupScanPlugin().verify("http://x/", _RaisingSession())
    assert result.status in (STATUS_SAFE, STATUS_UNKNOWN)
