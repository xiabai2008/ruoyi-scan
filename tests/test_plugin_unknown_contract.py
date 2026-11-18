# 网络异常 → UNKNOWN（三态铁律）契约测试：批量覆盖插件的异常分支
# 背景：覆盖率棘轮发现大量 except→UNKNOWN 分支无常驻用例；本文件以最小替身统一守护该契约。
import importlib
from unittest.mock import patch

import pytest
import requests

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.engine import ScanEngine

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
    """F7-4/v1.7.1：纯 UI 页面不算文档泄露，也不能单独证明接口泄露（C3 假 UI 页）。"""
    from plugins.common.swagger_leak import SwaggerLeakPlugin

    resp = _StaticResp(200, "<html><head><title>swagger-ui</title></head></html>", {"Content-Type": "text/html"})
    result = SwaggerLeakPlugin().verify("http://x/", _StaticSession(resp))
    assert result.status == STATUS_SAFE


def test_backup_scan_survives_request_errors():
    """备份扫描在请求全部异常时不得崩溃：允许 SAFE/UNKNOWN（软 404 基线自行处理异常）"""
    from plugins.common.backup_scan import BackupScanPlugin

    result = BackupScanPlugin().verify("http://x/", _RaisingSession())
    assert result.status in (STATUS_SAFE, STATUS_UNKNOWN)


# === D14 攻击面回流：consumes_surface 契约 ===


class _RecordingSurfaceSession:
    """记录 get / anonymous 调用次数：用于断言「无清单时零请求」"""

    def __init__(self, surface=None):
        self.surface = surface
        self.get_calls = 0
        self.anonymous_calls = 0

    def get(self, *args, **kwargs):
        self.get_calls += 1
        raise AssertionError("无攻击面清单时不应发出任何请求")

    def anonymous(self):
        self.anonymous_calls += 1
        return self


def test_surface_sweep_empty_inventory_unknown():
    from lib.surface_inventory import SurfaceInventory
    from plugins.common.surface_sweep import SurfaceSweepPlugin

    # (a) surface 为 None：未启用 --crawl/--js-extract
    none_session = _RecordingSurfaceSession(surface=None)
    result = SurfaceSweepPlugin().verify("http://target/", none_session)
    assert result.status == STATUS_UNKNOWN
    assert result.unknown_reason == "insufficient_evidence"
    assert none_session.get_calls == 0
    assert none_session.anonymous_calls == 0

    # (b) 空清单：启用了 crawl 但什么也没发现，同样不得探测
    empty_session = _RecordingSurfaceSession(surface=SurfaceInventory())
    result = SurfaceSweepPlugin().verify("http://target/", empty_session)
    assert result.status == STATUS_UNKNOWN
    assert result.unknown_reason == "insufficient_evidence"
    assert empty_session.get_calls == 0


def _confirm_plugin(consumes_surface):
    """构造一个恒返回 CONFIRMED 的最小插件（非 PluginBase，模拟引擎契约）"""

    class _ConfirmPlugin:
        name = "消费攻击面"
        consumes_surface = False

        def verify(self, target, session):
            return ScanResult(kind="info", name=self.name, status=STATUS_CONFIRMED, evidence="ok")

    _ConfirmPlugin.consumes_surface = consumes_surface
    return _ConfirmPlugin


def test_engine_forces_unknown_for_consumer():
    # session 传哑对象：引擎必须用 getattr 读取 surface，不能直接属性访问
    results = ScanEngine(threads=1).run([_confirm_plugin(True)], "http://target/", object())
    assert results[0].status == STATUS_UNKNOWN
    assert results[0].unknown_reason == "insufficient_evidence"


def test_engine_leaves_non_consumer_alone():
    results = ScanEngine(threads=1).run([_confirm_plugin(False)], "http://target/", object())
    assert results[0].status == STATUS_CONFIRMED
    assert results[0].unknown_reason == ""


class _SurfaceResp:
    def __init__(self, text, status=200):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {"Content-Type": "application/json"}
        self.url = "http://target/"


class _SurfaceSession:
    """probe 走兜底页，入口返回业务 JSON（长度/摘要与基线不同）"""

    def __init__(self, surface):
        self.surface = surface
        self.calls = []

    def get(self, url, *args, **kwargs):
        self.calls.append(url)
        if "soft404_probe" in url:
            return _SurfaceResp("not found")
        return _SurfaceResp('{"code":200,"rows":[{"id":1,"name":"admin"}]}')


def test_surface_sweep_no_confirm():
    """清单非空且全部命中：只做资产盘点，结果必须是 recon/UNKNOWN，不得出现 CONFIRMED"""
    from lib.surface_inventory import SurfaceInventory
    from plugins.common.surface_sweep import SurfaceSweepPlugin

    inv = SurfaceInventory()
    assert inv.add("http://target/system/user/list", "crawl") is True
    session = _SurfaceSession(inv)

    result = SurfaceSweepPlugin().verify("http://target/", session)
    assert result.kind == "recon"
    assert result.status == STATUS_UNKNOWN
    assert result.status != STATUS_CONFIRMED
    hits = result.extra["hits"]
    assert len(hits) == 1
    assert hits[0]["auth"] == "anon_ok"
    assert hits[0]["json_rows"] == 1
    assert all(h.get("status") != STATUS_CONFIRMED for h in hits)


class _RecordingProbeSession:
    """记录收到的请求与关闭动作（模拟 anonymous() 返回的会话）"""

    def __init__(self):
        self.get_calls = []
        self.closed = False

    def get(self, url, *args, **kwargs):
        self.get_calls.append(url)
        if "soft404_probe" in url:
            return _SurfaceResp("not found")
        return _SurfaceResp('{"code":200,"rows":[{"id":1}]}')

    def close(self):
        self.closed = True


class _AnonymousDispatchSession:
    """共享会话：自身不应收到请求，基线/探测都必须经 anonymous() 下发的会话"""

    def __init__(self, surface):
        self.surface = surface
        self.shared_get_calls = []
        self.anonymous_calls = 0
        self.anon = _RecordingProbeSession()

    def get(self, url, *args, **kwargs):
        self.shared_get_calls.append(url)
        raise AssertionError("基线探测与端点探测都必须走匿名会话")

    def anonymous(self):
        self.anonymous_calls += 1
        return self.anon


def test_surface_sweep_baseline_uses_anonymous_session():
    """软 404 基线必须与端点探测同用匿名会话（共享会话可能已登录、形态不一致）"""
    from lib.surface_inventory import SurfaceInventory
    from plugins.common.surface_sweep import SurfaceSweepPlugin

    inv = SurfaceInventory()
    assert inv.add("http://target/system/user/list", "crawl") is True
    shared = _AnonymousDispatchSession(inv)

    result = SurfaceSweepPlugin().verify("http://target/", shared)

    assert shared.anonymous_calls == 1
    assert shared.shared_get_calls == [], "共享会话不应收到任何请求"
    probe_urls = [u for u in shared.anon.get_calls if "soft404_probe" in u]
    assert len(probe_urls) == 1, "基线探测必须发生在匿名会话上"
    assert len(result.extra["hits"]) == 1
    assert shared.anon.closed is True, "自建的匿名会话必须被关闭"

