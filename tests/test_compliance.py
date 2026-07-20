# D12 测试：CVE / CVSS / 合规映射
#
# 覆盖：
#   1. CVSS v3.1 Base Score 计算（cvss_score 函数）
#   2. 合规标签解析（parse_compliance 函数）
#   3. PluginBase.meta() 返回新字段
#   4. ScanResult 新字段（cve/cvss_score/cvss_vector/compliance）
#   5. _build_result 自动填充
#   6. CSV/JSON 报告包含新列
#   7. 插件实例字段完整性（抽样校验）
import io
import json
import os
import sys
import tempfile
import pytest

# 路径修正
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from plugins.base import PluginBase, cvss_score, parse_compliance
from common.models import ScanResult, STATUS_CONFIRMED, SEVERITY_HIGH
from core.report import ReportBuilder


# === 1. CVSS v3.1 计算 ===

class TestCvssScore:
    """CVSS v3.1 Base Score 计算测试"""

    def test_empty_vector_returns_zero(self):
        """空向量返回 0.0"""
        assert cvss_score('') == 0.0
        assert cvss_score(None) == 0.0

    def test_full_high_severity(self):
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8"""
        score = cvss_score('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
        assert score == 9.8

    def test_sql_injection_vector(self):
        """SQL 注入典型向量 AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5"""
        score = cvss_score('AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N')
        assert score == 6.5

    def test_info_leak_vector(self):
        """信息泄露 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3"""
        score = cvss_score('AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N')
        assert score == 5.3

    def test_scope_changed(self):
        """Scope Changed 向量 AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0"""
        score = cvss_score('AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
        assert score == 10.0

    def test_with_cvss_prefix(self):
        """带 CVSS:3.1/ 前缀"""
        score = cvss_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
        assert score == 9.8

    def test_missing_metric_returns_zero(self):
        """缺少必要指标返回 0.0"""
        score = cvss_score('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')
        assert score == 0.0

    def test_score_range(self):
        """所有评分在 0.0~10.0 之间"""
        vectors = [
            'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',
            'AV:L/AC:H/PR:H/UI:P/S:U/C:N/I:N/A:L',
        ]
        for v in vectors:
            s = cvss_score(v)
            assert 0.0 <= s <= 10.0


# === 2. 合规标签解析 ===

class TestParseCompliance:
    """合规映射标签解析测试"""

    def test_empty_returns_empty_dict(self):
        assert parse_compliance('') == {}
        assert parse_compliance(None) == {}

    def test_single_tag(self):
        result = parse_compliance('等保2.0:8.1.3')
        assert result == {'等保2.0': '8.1.3'}

    def test_multiple_tags(self):
        result = parse_compliance('等保2.0:8.1.3;OWASP:A03:2021')
        assert result == {'等保2.0': '8.1.3', 'OWASP': 'A03:2021'}

    def test_with_spaces(self):
        result = parse_compliance(' 等保2.0 : 8.1.3 ; OWASP : A01:2021 ')
        assert result == {'等保2.0': '8.1.3', 'OWASP': 'A01:2021'}

    def test_invalid_parts_skipped(self):
        result = parse_compliance('等保2.0:8.1.3;invalid;')
        assert result == {'等保2.0': '8.1.3'}


# === 3. PluginBase.meta() ===

class TestPluginMeta:
    """插件元信息包含 D12 字段"""

    def test_meta_includes_cvss_and_compliance(self):
        """meta() 返回 cvss_vector/cvss_score/compliance"""
        class TestPlugin(PluginBase):
            name = '测试漏洞'
            cve = 'CVE-2024-0001'
            cvss_vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            compliance = '等保2.0:8.1.3;OWASP:A03:2021'

            def verify(self, target, session):
                pass

        plugin = TestPlugin()
        meta = plugin.meta()
        assert meta['cve'] == 'CVE-2024-0001'
        assert meta['cvss_vector'] == 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        assert meta['cvss_score'] == 9.8
        assert meta['compliance'] == {'等保2.0': '8.1.3', 'OWASP': 'A03:2021'}

    def test_meta_empty_cvss(self):
        """未设置 cvss_vector 时 score=0.0"""
        class TestPlugin(PluginBase):
            name = '测试'
            def verify(self, target, session):
                pass

        meta = TestPlugin().meta()
        assert meta['cvss_vector'] == ''
        assert meta['cvss_score'] == 0.0
        assert meta['compliance'] == {}


# === 4. ScanResult 新字段 ===

class TestScanResultFields:
    """ScanResult 数据模型新字段"""

    def test_default_values(self):
        """新字段默认值（向后兼容）"""
        r = ScanResult(kind='vuln', name='测试')
        assert r.cve == ''
        assert r.cvss_score == 0.0
        assert r.cvss_vector == ''
        assert r.compliance == {}

    def test_to_dict_includes_new_fields(self):
        """to_dict() 包含新字段"""
        r = ScanResult(
            kind='vuln', name='SQL注入', severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED, cve='CVE-2024-0001',
            cvss_score=9.8, cvss_vector='AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            compliance={'等保2.0': '8.1.3'},
        )
        d = r.to_dict()
        assert d['cve'] == 'CVE-2024-0001'
        assert d['cvss_score'] == 9.8
        assert d['cvss_vector'] == 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        assert d['compliance'] == {'等保2.0': '8.1.3'}


# === 5. _build_result 自动填充 ===

class TestBuildResultAutoFill:
    """_build_result 自动填充 D12 字段"""

    def test_build_result_inherits_plugin_fields(self):
        class TestPlugin(PluginBase):
            name = 'RCE漏洞'
            cve = 'CVE-2024-1234'
            severity = 'high'
            cvss_vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            compliance = '等保2.0:8.1.3;OWASP:A03:2021'
            fix = '升级到最新版本'
            def verify(self, target, session):
                pass

        plugin = TestPlugin()
        result = plugin._build_result(STATUS_CONFIRMED, url='http://x.com', evidence='proof')
        assert result.cve == 'CVE-2024-1234'
        assert result.cvss_score == 9.8
        assert result.cvss_vector == 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        assert result.compliance == {'等保2.0': '8.1.3', 'OWASP': 'A03:2021'}
        assert result.fix == '升级到最新版本'


# === 6. 报告渲染包含新字段 ===

class TestReportRendering:
    """CSV/JSON/HTML 报告包含 D12 字段"""

    @pytest.fixture
    def sample_results(self):
        return [
            ScanResult(
                kind='vuln', name='SQL注入', severity=SEVERITY_HIGH,
                status=STATUS_CONFIRMED, url='http://x.com/test',
                evidence='proof', fix='patch it',
                cve='CVE-2024-0001', cvss_score=9.8,
                cvss_vector='AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                compliance={'等保2.0': '8.1.3', 'OWASP': 'A03:2021'},
            ),
            ScanResult(
                kind='vuln', name='信息泄露', severity='medium',
                status=STATUS_CONFIRMED, url='http://x.com/leak',
                evidence='leaked', fix='close it',
                cve='N/A', cvss_score=5.3,
                cvss_vector='AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                compliance={'等保2.0': '8.1.4'},
            ),
        ]

    def test_csv_includes_cve_cvss_compliance(self, sample_results):
        """CSV 报告包含 CVE/CVSS/合规列"""
        builder = ReportBuilder(results=sample_results, target='http://x.com')
        csv_text = builder.to_csv()
        assert 'CVE' in csv_text
        assert 'CVSS' in csv_text
        assert '合规映射' in csv_text
        assert 'CVE-2024-0001' in csv_text
        assert '9.8' in csv_text
        assert '等保2.0:8.1.3' in csv_text

    def test_json_includes_new_fields(self, sample_results):
        """JSON 报告包含新字段"""
        builder = ReportBuilder(results=sample_results, target='http://x.com')
        json_text = builder.to_json()
        data = json.loads(json_text)
        assert 'results' in data
        first = data['results'][0]
        assert first['cve'] == 'CVE-2024-0001'
        assert first['cvss_score'] == 9.8
        assert first['cvss_vector'] == 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        assert first['compliance'] == {'等保2.0': '8.1.3', 'OWASP': 'A03:2021'}

    def test_html_includes_cve_column(self, sample_results):
        """HTML 报告包含 CVE 列"""
        builder = ReportBuilder(results=sample_results, target='http://x.com')
        html_text = builder.to_html()
        assert '<th>CVE</th>' in html_text
        assert '<th>CVSS</th>' in html_text
        assert '<th>合规映射</th>' in html_text
        assert 'CVE-2024-0001' in html_text


# === 7. 插件实例字段完整性（抽样校验）===

class TestPluginFieldsIntegrity:
    """校验实际 POC 文件的 D12 字段完整性"""

    def test_ruoyi_sql_inject_dept_has_cvss(self):
        from plugins.ruoyi.sql_inject_dept import SqlInjectDeptPlugin
        plugin = SqlInjectDeptPlugin()
        assert plugin.cve == 'CNVD-2021-01931'
        assert plugin.cvss_vector != ''
        assert plugin.compliance != ''
        meta = plugin.meta()
        assert meta['cvss_score'] > 0
        assert '等保2.0' in meta['compliance']

    def test_ruoyi_thymeleaf_ssti_has_cve(self):
        from plugins.ruoyi.thymeleaf_ssti import ThymeleafSstiPlugin
        plugin = ThymeleafSstiPlugin()
        assert plugin.cve == 'CVE-2023-38286'
        assert plugin.cvss_vector != ''
        assert 'OWASP' in plugin.compliance

    def test_spring_spring4shell_has_cve(self):
        from plugins.spring.spring4shell import Spring4shellPlugin
        plugin = Spring4shellPlugin()
        assert plugin.cve == 'CVE-2022-22965'
        assert plugin.cvss_vector != ''
        meta = plugin.meta()
        assert meta['cvss_score'] == 9.8

    def test_common_git_leak_has_cvss(self):
        from plugins.common.git_leak import GitLeakPlugin
        plugin = GitLeakPlugin()
        assert plugin.cve == 'N/A'
        assert plugin.cvss_vector != ''
        assert '等保2.0' in plugin.compliance

    def test_all_ruoyi_pocs_have_cvss_vector(self):
        """所有若依 POC 都有 cvss_vector"""
        from core.loader import load_plugins
        plugins = load_plugins('plugins.ruoyi')
        for cls in plugins:
            assert cls.cvss_vector != '', f'{cls.__name__} 缺少 cvss_vector'
            assert cls.compliance != '', f'{cls.__name__} 缺少 compliance'
            assert cls.cve != '', f'{cls.__name__} 缺少 cve'

    def test_all_spring_pocs_have_cvss_vector(self):
        """所有 Spring POC 都有 cvss_vector"""
        from core.loader import load_plugins
        plugins = load_plugins('plugins.spring')
        for cls in plugins:
            assert cls.cvss_vector != '', f'{cls.__name__} 缺少 cvss_vector'
            assert cls.compliance != '', f'{cls.__name__} 缺少 compliance'

    def test_all_common_pocs_have_cvss_vector(self):
        """所有通用 POC 都有 cvss_vector"""
        from core.loader import load_plugins
        plugins = load_plugins('plugins.common')
        for cls in plugins:
            assert cls.cvss_vector != '', f'{cls.__name__} 缺少 cvss_vector'
            assert cls.compliance != '', f'{cls.__name__} 缺少 compliance'
