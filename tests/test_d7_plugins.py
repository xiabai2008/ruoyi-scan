# D7.3 全量插件 WAF 绕过适配验证测试
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 导入所有 ruoyi 插件
from plugins.ruoyi.sql_inject_role import SqlInjectRolePlugin
from plugins.ruoyi.sql_inject_dept import SqlInjectDeptPlugin
from plugins.ruoyi.file_read import FileReadPlugin
from plugins.ruoyi.file_read_path import RuoyiFileReadPathPlugin
from plugins.ruoyi.file_read_time import FileReadTimePlugin
from plugins.ruoyi.file_upload import FileUploadPlugin
from plugins.ruoyi.job_rce import JobRcePlugin
from plugins.ruoyi.thymeleaf_ssti import ThymeleafSstiPlugin
from plugins.ruoyi.default_password import DefaultPasswordPlugin
from plugins.ruoyi.druid_brute import DruidBrutePlugin
from plugins.ruoyi.nacos_unauth import RuoyiNacosUnauthPlugin
from plugins.ruoyi.ruoyi_cloud_nacos import RuoyiCloudNacosPlugin
from plugins.ruoyi.ruoyi_swagger_unauth import RuoyiSwaggerUnauthPlugin
from plugins.ruoyi.ruoyi_gen_rce import RuoyiGenRcePlugin
from plugins.ruoyi.unauth_batch import UnauthBatchPlugin
from plugins.ruoyi.directory_scan import DirectoryScanPlugin


# 全量插件列表（除 directory_scan 外都应支持绕过）
_BYPASS_PLUGINS = [
    (SqlInjectRolePlugin, 'sqli'),
    (SqlInjectDeptPlugin, 'sqli'),
    (FileReadPlugin, 'file_read'),
    (RuoyiFileReadPathPlugin, 'file_read'),
    (FileReadTimePlugin, 'file_read'),
    (FileUploadPlugin, 'rce'),
    (JobRcePlugin, 'rce'),
    (ThymeleafSstiPlugin, 'rce'),
    (DefaultPasswordPlugin, 'auth'),
    (DruidBrutePlugin, 'auth'),
    (RuoyiNacosUnauthPlugin, 'info_leak'),
    (RuoyiCloudNacosPlugin, 'info_leak'),
    (RuoyiSwaggerUnauthPlugin, 'info_leak'),
    (RuoyiGenRcePlugin, 'rce'),
    (UnauthBatchPlugin, 'info_leak'),
]

# 不支持绕过的插件
_NO_BYPASS_PLUGINS = [
    DirectoryScanPlugin,
]


def test_all_bypass_plugins_have_vuln_type():
    """所有支持绕过的插件含 vuln_type 属性"""
    for plugin_cls, expected_type in _BYPASS_PLUGINS:
        assert hasattr(plugin_cls, 'vuln_type'), f'{plugin_cls.__name__} 缺 vuln_type'
        assert plugin_cls.vuln_type == expected_type, \
            f'{plugin_cls.__name__}.vuln_type 应为 {expected_type}，实际 {plugin_cls.vuln_type}'


def test_all_bypass_plugins_support_waf_bypass():
    """所有支持绕过的插件 supports_waf_bypass=True"""
    for plugin_cls, _ in _BYPASS_PLUGINS:
        assert plugin_cls.supports_waf_bypass is True, \
            f'{plugin_cls.__name__}.supports_waf_bypass 应为 True'


def test_no_bypass_plugins_not_supported():
    """不支持绕过的插件 supports_waf_bypass=False"""
    for plugin_cls in _NO_BYPASS_PLUGINS:
        assert plugin_cls.supports_waf_bypass is False, \
            f'{plugin_cls.__name__}.supports_waf_bypass 应为 False'


def test_all_plugins_have_bypass_max_attempts():
    """所有插件含 bypass_max_attempts 属性（默认 3）"""
    all_plugins = _BYPASS_PLUGINS + [(cls, '') for cls in _NO_BYPASS_PLUGINS]
    for plugin_cls, _ in all_plugins:
        assert hasattr(plugin_cls, 'bypass_max_attempts'), \
            f'{plugin_cls.__name__} 缺 bypass_max_attempts'
        assert plugin_cls.bypass_max_attempts == 3


def test_all_plugins_have_verify_with_bypass():
    """所有插件继承 verify_with_bypass 方法"""
    all_plugins = _BYPASS_PLUGINS + [(cls, '') for cls in _NO_BYPASS_PLUGINS]
    for plugin_cls, _ in all_plugins:
        assert hasattr(plugin_cls, 'verify_with_bypass'), \
            f'{plugin_cls.__name__} 应继承 verify_with_bypass'


def test_vuln_type_coverage():
    """漏洞类型覆盖完整（sqli/file_read/rce/auth/info_leak）"""
    vuln_types = {cls.vuln_type for cls, _ in _BYPASS_PLUGINS}
    expected_types = {'sqli', 'file_read', 'rce', 'auth', 'info_leak'}
    assert vuln_types == expected_types, \
        f'漏洞类型不完整: {vuln_types} vs {expected_types}'


# === WAF 特征库测试 ===

def test_waf_features_have_block_signatures():
    """所有 WAF 特征含 block_signatures 字段"""
    from lib.waf_features import WAF_FEATURES
    for waf_name, waf_data in WAF_FEATURES.items():
        assert 'block_signatures' in waf_data, \
            f'{waf_name} 缺 block_signatures'
        assert isinstance(waf_data['block_signatures'], list)
        assert len(waf_data['block_signatures']) > 0, \
            f'{waf_name} 的 block_signatures 不应为空'


def test_waf_features_have_recommended_strategies():
    """所有 WAF 特征含 recommended_strategies 字段"""
    from lib.waf_features import WAF_FEATURES
    for waf_name, waf_data in WAF_FEATURES.items():
        assert 'recommended_strategies' in waf_data, \
            f'{waf_name} 缺 recommended_strategies'
        assert isinstance(waf_data['recommended_strategies'], list)


def test_is_waf_blocked_status_code():
    """is_waf_blocked 按状态码判定"""
    from lib.waf_features import is_waf_blocked
    # Cloudflare 拦截码 403/503
    assert is_waf_blocked('cloudflare', status_code=403) is True
    assert is_waf_blocked('cloudflare', status_code=503) is True
    assert is_waf_blocked('cloudflare', status_code=200) is False


def test_is_waf_blocked_body_signature():
    """is_waf_blocked 按响应体特征判定"""
    from lib.waf_features import is_waf_blocked
    # Cloudflare 拦截页特征
    assert is_waf_blocked('cloudflare', response_text='Attention Required! cloudflare') is True
    assert is_waf_blocked('cloudflare', response_text='normal page') is False


def test_is_waf_blocked_unknown_waf():
    """未知 WAF 返回 False（不拦截）"""
    from lib.waf_features import is_waf_blocked
    assert is_waf_blocked('nonexistent', status_code=403) is False


# === 策略匹配矩阵测试 ===

def test_strategy_matrix_cloudflare():
    """Cloudflare 策略矩阵：含 Googlebot + 源站直连 + 通用"""
    from lib.waf_bypass import StrategyRegistry
    reg = StrategyRegistry()
    strategies = reg.get_strategies('cloudflare', 'sqli')
    ids = [s.strategy_id for s in strategies]
    # 应含 cloudflare 专用策略
    assert 'BP-CF-1' in ids, '应含源站直连策略'
    assert 'BP-CF-2' in ids, '应含 Googlebot 策略'
    # 应含通用策略
    assert 'BP-GEN-1' in ids, '应含通用大小写混淆'


def test_strategy_matrix_safedog():
    """安全狗策略矩阵：含内联注释 + BETWEEN 替换"""
    from lib.waf_bypass import StrategyRegistry
    reg = StrategyRegistry()
    strategies = reg.get_strategies('safedog', 'sqli')
    ids = [s.strategy_id for s in strategies]
    assert 'BP-SD-1' in ids, '应含内联注释策略'
    assert 'BP-SD-3' in ids, '应含 BETWEEN 替换策略'


def test_strategy_matrix_modsecurity():
    """ModSecurity 策略矩阵：含内联注释"""
    from lib.waf_bypass import StrategyRegistry
    reg = StrategyRegistry()
    strategies = reg.get_strategies('modsecurity', 'sqli')
    ids = [s.strategy_id for s in strategies]
    assert 'BP-SD-1' in ids, '应含内联注释策略'


def test_strategy_matrix_file_read():
    """file_read 漏洞类型的策略矩阵"""
    from lib.waf_bypass import StrategyRegistry
    reg = StrategyRegistry()
    strategies = reg.get_strategies('cloudflare', 'file_read')
    # file_read 应有通用策略（URL 编码、分块传输）
    ids = [s.strategy_id for s in strategies]
    assert 'BP-GEN-2' in ids, '应含 URL 编码策略'
    assert 'BP-GEN-3' in ids, '应含分块传输策略'


if __name__ == '__main__':
    test_all_bypass_plugins_have_vuln_type()
    test_all_bypass_plugins_support_waf_bypass()
    test_no_bypass_plugins_not_supported()
    test_all_plugins_have_bypass_max_attempts()
    test_all_plugins_have_verify_with_bypass()
    test_vuln_type_coverage()
    test_waf_features_have_block_signatures()
    test_waf_features_have_recommended_strategies()
    test_is_waf_blocked_status_code()
    test_is_waf_blocked_body_signature()
    test_is_waf_blocked_unknown_waf()
    test_strategy_matrix_cloudflare()
    test_strategy_matrix_safedog()
    test_strategy_matrix_modsecurity()
    test_strategy_matrix_file_read()
    print('All D7.3 full plugin adaptation tests passed!')
