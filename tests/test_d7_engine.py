# D7.2 引擎接入与插件改造集成测试
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import ScanEngine
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from plugins.base import PluginBase
from plugins.ruoyi.sql_inject_role import SqlInjectRolePlugin
from plugins.ruoyi.file_read import FileReadPlugin
from plugins.ruoyi.job_rce import JobRcePlugin
from plugins.ruoyi.file_upload import FileUploadPlugin


# === 插件 WAF 绕过属性测试 ===

def test_sql_inject_role_has_bypass_attrs():
    """SQL 注入插件含 WAF 绕过属性"""
    assert SqlInjectRolePlugin.vuln_type == 'sqli'
    assert SqlInjectRolePlugin.supports_waf_bypass is True

def test_file_read_has_bypass_attrs():
    """文件读取插件含 WAF 绕过属性"""
    assert FileReadPlugin.vuln_type == 'file_read'
    assert FileReadPlugin.supports_waf_bypass is True

def test_job_rce_has_bypass_attrs():
    """定时任务 RCE 插件含 WAF 绕过属性"""
    assert JobRcePlugin.vuln_type == 'rce'
    assert JobRcePlugin.supports_waf_bypass is True

def test_file_upload_has_bypass_attrs():
    """文件上传插件含 WAF 绕过属性"""
    assert FileUploadPlugin.vuln_type == 'rce'
    assert FileUploadPlugin.supports_waf_bypass is True


# === PluginBase 默认属性测试 ===

def test_plugin_base_default_no_bypass():
    """PluginBase 默认不支持 WAF 绕过"""
    assert PluginBase.vuln_type == ''
    assert PluginBase.supports_waf_bypass is False

def test_plugin_base_has_verify_with_bypass():
    """PluginBase 含 verify_with_bypass 方法"""
    assert hasattr(PluginBase, 'verify_with_bypass')
    assert callable(PluginBase.verify_with_bypass)


# === ScanEngine 集成测试 ===

class MockBypassCoordinator:
    """Mock 绕过协调器"""
    def __init__(self, should_succeed=False):
        self.should_succeed = should_succeed
        self.called = False

    def maybe_bypass(self, plugin, target, session, original_result):
        self.called = True
        if self.should_succeed:
            return ScanResult(kind='vuln', name='bypassed',
                              status=STATUS_CONFIRMED, url=target,
                              evidence='bypass success',
                              extra={'waf_bypass': {'strategy_used': 'BP-TEST'}})
        return original_result


class MockSession:
    def __init__(self):
        self.request_count = 0
    def get(self, url, **kwargs):
        self.request_count += 1
        return MagicMock(text='', status_code=200, headers={})
    def post(self, url, **kwargs):
        self.request_count += 1
        return MagicMock(text='', status_code=200, headers={})
    def close(self):
        pass


# 测试用插件：支持绕过
class BypassSupportedPlugin(PluginBase):
    name = '测试插件'
    severity = 'high'
    vuln_type = 'sqli'
    supports_waf_bypass = True

    def verify(self, target, session):
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                          url=target, evidence='safe (maybe blocked)')


# 测试用插件：不支持绕过
class BypassUnsupportedPlugin(PluginBase):
    name = '不支持绕过插件'
    severity = 'medium'

    def verify(self, target, session):
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                          url=target, evidence='safe')


def test_engine_no_coordinator():
    """无协调器时不触发绕过"""
    engine = ScanEngine(threads=1)
    session = MockSession()
    results = engine.run([BypassSupportedPlugin], 'http://x.com/', session)
    assert len(results) == 1
    assert results[0].status == STATUS_SAFE

def test_engine_bypass_triggered_for_supported_plugin():
    """支持绕过的插件触发绕过"""
    engine = ScanEngine(threads=1)
    coord = MockBypassCoordinator(should_succeed=True)
    session = MockSession()
    results = engine.run([BypassSupportedPlugin], 'http://x.com/', session,
                          waf_bypass_coordinator=coord)
    assert coord.called is True, '绕过协调器应被调用'
    assert results[0].status == STATUS_CONFIRMED, '绕过成功应为 CONFIRMED'

def test_engine_bypass_not_triggered_for_unsupported_plugin():
    """不支持绕过的插件不触发绕过"""
    engine = ScanEngine(threads=1)
    coord = MockBypassCoordinator(should_succeed=True)
    session = MockSession()
    results = engine.run([BypassUnsupportedPlugin], 'http://x.com/', session,
                          waf_bypass_coordinator=coord)
    assert coord.called is False, '不支持绕过的插件不应触发协调器'
    assert results[0].status == STATUS_SAFE

def test_engine_bypass_not_triggered_for_confirmed():
    """CONFIRMED 结果不触发绕过"""
    class ConfirmedPlugin(PluginBase):
        name = '已确认插件'
        severity = 'high'
        vuln_type = 'sqli'
        supports_waf_bypass = True

        def verify(self, target, session):
            return ScanResult(kind='vuln', name=self.name, status=STATUS_CONFIRMED,
                              url=target, evidence='confirmed')

    engine = ScanEngine(threads=1)
    coord = MockBypassCoordinator(should_succeed=True)
    session = MockSession()
    results = engine.run([ConfirmedPlugin], 'http://x.com/', session,
                          waf_bypass_coordinator=coord)
    assert coord.called is False, 'CONFIRMED 不应触发绕过'
    assert results[0].status == STATUS_CONFIRMED

def test_engine_bypass_failure_preserves_status():
    """绕过失败保持原状态"""
    engine = ScanEngine(threads=1)
    coord = MockBypassCoordinator(should_succeed=False)
    session = MockSession()
    results = engine.run([BypassSupportedPlugin], 'http://x.com/', session,
                          waf_bypass_coordinator=coord)
    assert results[0].status == STATUS_SAFE, '绕过失败应保持原 SAFE 状态'


# === CLI 参数测试 ===

def test_parser_accepts_bypass_waf():
    """解析器接受 --bypass-waf 参数"""
    from main import build_parser
    parser = build_parser()
    args = parser.parse_args(['-u', 'http://x.com', '--bypass-waf', 'on'])
    assert args.bypass_waf == 'on'

def test_parser_bypass_waf_default_auto():
    """--bypass-waf 默认 auto"""
    from main import build_parser
    parser = build_parser()
    args = parser.parse_args(['-u', 'http://x.com'])
    assert args.bypass_waf == 'auto'

def test_parser_bypass_waf_choices():
    """--bypass-waf 仅接受 auto/on/off"""
    from main import build_parser
    parser = build_parser()
    # 有效值
    for val in ['auto', 'on', 'off']:
        args = parser.parse_args(['-u', 'http://x.com', '--bypass-waf', val])
        assert args.bypass_waf == val


if __name__ == '__main__':
    test_sql_inject_role_has_bypass_attrs()
    test_file_read_has_bypass_attrs()
    test_job_rce_has_bypass_attrs()
    test_file_upload_has_bypass_attrs()
    test_plugin_base_default_no_bypass()
    test_plugin_base_has_verify_with_bypass()
    test_engine_no_coordinator()
    test_engine_bypass_triggered_for_supported_plugin()
    test_engine_bypass_not_triggered_for_unsupported_plugin()
    test_engine_bypass_not_triggered_for_confirmed()
    test_engine_bypass_failure_preserves_status()
    test_parser_accepts_bypass_waf()
    test_parser_bypass_waf_default_auto()
    test_parser_bypass_waf_choices()
    print('All D7.2 engine integration tests passed!')
