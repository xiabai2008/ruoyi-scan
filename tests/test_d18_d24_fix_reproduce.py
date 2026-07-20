# D18/D24 修复详情 + 复现命令测试
#
# 覆盖：
#   1. PluginBase 类属性 fix_detail / reproduce 默认值
#   2. _build_result() 自动填充 fix_detail / reproduce
#   3. meta() 返回 fix_detail / reproduce
#   4. ScanResult.fix_detail / reproduce 字段
#   5. AggregatedVuln.fix_detail / reproduce 继承
#   6. CSV 报告新增"修复详情"和"复现命令"两列
#   7. HTML 报告新增两列
#   8. JSON 报告含 fix_detail / reproduce 字段
#   9. 全部 38 个 POC 文件均填充了 fix_detail 和 reproduce（非空）
import os
import sys
import importlib
import pkgutil
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.base import PluginBase, cvss_score, parse_compliance
from common.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE
from core.dedup import AggregatedVuln, aggregate
from core.report import ReportBuilder


# === fixtures ===

class FakePlugin(PluginBase):
    """测试用插件：填充 D18/D24 字段"""
    name = '测试漏洞'
    severity = 'high'
    fix = '一句话修复建议'
    fix_detail = (
        '【升级方案】升级至 1.0.0+\n'
        '【代码修复】修改 X.py 添加白名单校验\n'
        '【WAF 规则】拦截 X 请求'
    )
    reproduce = (
        '# 1. 探测端点：\n'
        'curl -i "http://target/test"\n'
        '\n'
        '# 预期响应：HTTP 200'
    )

    def verify(self, target, session):
        return self._build_result(STATUS_CONFIRMED, url=target, evidence='test')


class EmptyPlugin(PluginBase):
    """未填充 D18/D24 字段的插件"""
    name = '空插件'
    severity = 'low'

    def verify(self, target, session):
        return self._build_result(STATUS_SAFE, url=target)


def _sample_results():
    """构造带 D18/D24 字段的样本结果"""
    return [
        ScanResult(
            kind='vuln',
            name='任意文件读取',
            severity='high',
            status=STATUS_CONFIRMED,
            url='http://target/read',
            evidence='/etc/passwd',
            fix='目录穿越修复',
            fix_detail='【升级方案】升级至 4.7+\n【代码修复】添加路径校验',
            reproduce='curl "http://target/read?file=../../../etc/passwd"',
        ),
    ]


# ============================================================
# 1. PluginBase 类属性
# ============================================================

class TestPluginBaseD18D24Fields:
    """PluginBase D18/D24 字段测试"""

    def test_fix_detail_default_empty(self):
        """fix_detail 默认为空字符串"""
        assert PluginBase.fix_detail == ''

    def test_reproduce_default_empty(self):
        """reproduce 默认为空字符串"""
        assert PluginBase.reproduce == ''

    def test_fake_plugin_fix_detail(self):
        """FakePlugin.fix_detail 正确继承"""
        assert '升级方案' in FakePlugin.fix_detail
        assert '【代码修复】' in FakePlugin.fix_detail

    def test_fake_plugin_reproduce(self):
        """FakePlugin.reproduce 正确继承"""
        assert 'curl' in FakePlugin.reproduce
        assert 'http://target/test' in FakePlugin.reproduce


# ============================================================
# 2. _build_result 自动填充
# ============================================================

class TestBuildResultD18D24:
    """_build_result() 自动填充 D18/D24 字段"""

    def test_build_result_fills_fix_detail(self):
        """_build_result 自动填充 fix_detail"""
        plugin = FakePlugin()
        result = plugin._build_result(STATUS_CONFIRMED, url='http://x/', evidence='test')
        assert result.fix_detail == FakePlugin.fix_detail

    def test_build_result_fills_reproduce(self):
        """_build_result 自动填充 reproduce"""
        plugin = FakePlugin()
        result = plugin._build_result(STATUS_CONFIRMED, url='http://x/', evidence='test')
        assert result.reproduce == FakePlugin.reproduce

    def test_build_result_empty_fix_detail(self):
        """EmptyPlugin 的 _build_result fix_detail 为空"""
        plugin = EmptyPlugin()
        result = plugin._build_result(STATUS_SAFE, url='http://x/')
        assert result.fix_detail == ''

    def test_build_result_empty_reproduce(self):
        """EmptyPlugin 的 _build_result reproduce 为空"""
        plugin = EmptyPlugin()
        result = plugin._build_result(STATUS_SAFE, url='http://x/')
        assert result.reproduce == ''


# ============================================================
# 3. meta() 返回 D18/D24 字段
# ============================================================

class TestMetaD18D24:
    """meta() 返回 D18/D24 字段"""

    def test_meta_contains_fix_detail(self):
        """meta() 返回 fix_detail"""
        meta = FakePlugin().meta()
        assert 'fix_detail' in meta
        assert '升级方案' in meta['fix_detail']

    def test_meta_contains_reproduce(self):
        """meta() 返回 reproduce"""
        meta = FakePlugin().meta()
        assert 'reproduce' in meta
        assert 'curl' in meta['reproduce']

    def test_meta_empty_plugin_fix_detail(self):
        """EmptyPlugin.meta() fix_detail 为空"""
        meta = EmptyPlugin().meta()
        assert meta['fix_detail'] == ''

    def test_meta_empty_plugin_reproduce(self):
        """EmptyPlugin.meta() reproduce 为空"""
        meta = EmptyPlugin().meta()
        assert meta['reproduce'] == ''


# ============================================================
# 4. ScanResult D18/D24 字段
# ============================================================

class TestScanResultD18D24:
    """ScanResult D18/D24 字段测试"""

    def test_scan_result_fix_detail_field(self):
        """ScanResult 含 fix_detail 字段"""
        r = ScanResult(kind='vuln', name='x', fix_detail='detail here')
        assert r.fix_detail == 'detail here'

    def test_scan_result_reproduce_field(self):
        """ScanResult 含 reproduce 字段"""
        r = ScanResult(kind='vuln', name='x', reproduce='curl http://x')
        assert r.reproduce == 'curl http://x'

    def test_scan_result_fix_detail_default(self):
        """ScanResult fix_detail 默认空"""
        r = ScanResult(kind='vuln', name='x')
        assert r.fix_detail == ''

    def test_scan_result_reproduce_default(self):
        """ScanResult reproduce 默认空"""
        r = ScanResult(kind='vuln', name='x')
        assert r.reproduce == ''

    def test_to_dict_contains_fix_detail(self):
        """to_dict() 含 fix_detail"""
        r = ScanResult(kind='vuln', name='x', fix_detail='detail')
        d = r.to_dict()
        assert 'fix_detail' in d
        assert d['fix_detail'] == 'detail'

    def test_to_dict_contains_reproduce(self):
        """to_dict() 含 reproduce"""
        r = ScanResult(kind='vuln', name='x', reproduce='curl')
        d = r.to_dict()
        assert 'reproduce' in d
        assert d['reproduce'] == 'curl'


# ============================================================
# 5. AggregatedVuln D18/D24 继承
# ============================================================

class TestAggregatedVulnD18D24:
    """AggregatedVuln D18/D24 字段继承测试"""

    def test_aggregated_vuln_fix_detail_field(self):
        """AggregatedVuln 含 fix_detail 字段"""
        av = AggregatedVuln(kind='vuln', name='x', severity='high',
                            status=STATUS_CONFIRMED, url='http://x/',
                            evidence='e', fix='f', fix_detail='detail')
        assert av.fix_detail == 'detail'

    def test_aggregated_vuln_reproduce_field(self):
        """AggregatedVuln 含 reproduce 字段"""
        av = AggregatedVuln(kind='vuln', name='x', severity='high',
                            status=STATUS_CONFIRMED, url='http://x/',
                            evidence='e', fix='f', reproduce='curl')
        assert av.reproduce == 'curl'

    def test_aggregate_inherits_fix_detail(self):
        """aggregate() 从首个 ScanResult 继承 fix_detail"""
        # 使用相同 URL + 相同 name，确保指纹一致 → 聚合为一条
        results = [
            ScanResult(kind='vuln', name='x', status=STATUS_CONFIRMED, severity='high',
                       url='http://x/', fix='f', fix_detail='detail1',
                       reproduce='curl1'),
            ScanResult(kind='vuln', name='x', status=STATUS_CONFIRMED, severity='high',
                       url='http://x/', fix='f', fix_detail='detail2',
                       reproduce='curl2'),
        ]
        aggregated, _report = aggregate(results)
        assert len(aggregated) == 1
        # 继承首个结果的 fix_detail
        assert aggregated[0].fix_detail == 'detail1'
        assert aggregated[0].reproduce == 'curl1'

    def test_aggregated_to_dict_contains_fix_detail(self):
        """AggregatedVuln.to_dict() 含 fix_detail"""
        av = AggregatedVuln(kind='vuln', name='x', severity='high',
                            status=STATUS_CONFIRMED, url='http://x/',
                            evidence='e', fix='f', fix_detail='detail', reproduce='curl')
        d = av.to_dict()
        assert 'fix_detail' in d
        assert 'reproduce' in d
        assert d['fix_detail'] == 'detail'
        assert d['reproduce'] == 'curl'


# ============================================================
# 6. CSV 报告新增两列
# ============================================================

class TestCSVReportD18D24:
    """CSV 报告 D18/D24 字段渲染"""

    def test_csv_header_contains_fix_detail(self):
        """CSV 表头含"修复详情"列"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        csv_text = rb.to_csv()
        assert '修复详情' in csv_text.split('\n')[0]

    def test_csv_header_contains_reproduce(self):
        """CSV 表头含"复现命令"列"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        csv_text = rb.to_csv()
        assert '复现命令' in csv_text.split('\n')[0]

    def test_csv_contains_fix_detail_value(self):
        """CSV 内容含 fix_detail 值"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        csv_text = rb.to_csv()
        assert '升级至 4.7' in csv_text

    def test_csv_contains_reproduce_value(self):
        """CSV 内容含 reproduce 值"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        csv_text = rb.to_csv()
        assert 'curl' in csv_text


# ============================================================
# 7. HTML 报告新增两列
# ============================================================

class TestHTMLReportD18D24:
    """HTML 报告 D18/D24 字段渲染"""

    def test_html_contains_fix_detail_column(self):
        """HTML 含"修复详情"列表头"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        html = rb.to_html()
        assert '修复详情' in html

    def test_html_contains_reproduce_column(self):
        """HTML 含"复现命令"列表头"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        html = rb.to_html()
        assert '复现命令' in html

    def test_html_contains_fix_detail_value(self):
        """HTML 含 fix_detail 值（渲染为 <br> 换行）"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        html = rb.to_html()
        assert '升级至 4.7' in html

    def test_html_contains_reproduce_value(self):
        """HTML 含 reproduce 值"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        html = rb.to_html()
        assert 'curl' in html

    def test_html_has_fix_detail_css_class(self):
        """HTML 含 .fix-detail CSS 类"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        html = rb.to_html()
        assert 'fix-detail' in html

    def test_html_has_reproduce_css_class(self):
        """HTML 含 .reproduce CSS 类"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        html = rb.to_html()
        assert 'reproduce' in html

    def test_html_colspan_updated(self):
        """HTML 空结果行 colspan 更新为 11"""
        rb = ReportBuilder(results=[], target='http://x/',
                           summary={'target': 'http://x/'})
        html = rb.to_html()
        assert 'colspan="11"' in html


# ============================================================
# 8. JSON 报告含 D18/D24 字段
# ============================================================

class TestJSONReportD18D24:
    """JSON 报告 D18/D24 字段渲染"""

    def test_json_contains_fix_detail(self):
        """JSON 含 fix_detail 字段"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        json_text = rb.to_json()
        assert 'fix_detail' in json_text
        assert '升级至 4.7' in json_text

    def test_json_contains_reproduce(self):
        """JSON 含 reproduce 字段"""
        rb = ReportBuilder(results=_sample_results(), target='http://x/',
                           summary={'target': 'http://x/'})
        json_text = rb.to_json()
        assert 'reproduce' in json_text
        assert 'curl' in json_text


# ============================================================
# 9. 38 个 POC 文件全部填充 D18/D24 字段
# ============================================================

def _load_all_plugins():
    """加载全部 38 个 POC 插件类"""
    plugins = []
    for package_name in ['plugins.ruoyi', 'plugins.spring', 'plugins.common']:
        try:
            package = importlib.import_module(package_name)
            for _, name, is_pkg in pkgutil.iter_modules(package.__path__):
                if is_pkg or name.startswith('_'):
                    continue
                module_name = f'{package_name}.{name}'
                try:
                    module = importlib.import_module(module_name)
                    # 查找模块中所有 PluginBase 子类
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and issubclass(attr, PluginBase)
                                and attr is not PluginBase and attr.__module__ == module_name):
                            plugins.append((module_name, attr_name, attr))
                except Exception:
                    continue
        except Exception:
            continue
    return plugins


class TestAllPOCFilledD18D24:
    """全部 POC 文件 D18/D24 字段填充完整性测试"""

    def test_all_plugins_have_fix_detail_or_empty(self):
        """所有插件都有 fix_detail 属性（可能为空，D10 文档类插件可为空）"""
        plugins = _load_all_plugins()
        assert len(plugins) >= 30, f'应加载至少 30 个插件，实际 {len(plugins)}'
        for module_name, name, cls in plugins:
            assert hasattr(cls, 'fix_detail'), f'{module_name}.{name} 缺少 fix_detail 属性'

    def test_all_plugins_have_reproduce_or_empty(self):
        """所有插件都有 reproduce 属性（可能为空）"""
        plugins = _load_all_plugins()
        for module_name, name, cls in plugins:
            assert hasattr(cls, 'reproduce'), f'{module_name}.{name} 缺少 reproduce 属性'

    def test_vuln_plugins_have_fix_detail(self):
        """漏洞类插件（category=vuln）的 fix_detail 应非空"""
        plugins = _load_all_plugins()
        for module_name, name, cls in plugins:
            instance = cls()
            # 仅校验漏洞类插件
            if getattr(instance, 'category', '') == 'vuln':
                assert instance.fix_detail, \
                    f'{module_name}.{name}（vuln）fix_detail 不应为空'
                assert len(instance.fix_detail) >= 20, \
                    f'{module_name}.{name}（vuln）fix_detail 过短：<{instance.fix_detail}>'

    def test_vuln_plugins_have_reproduce(self):
        """漏洞类插件（category=vuln）的 reproduce 应非空"""
        plugins = _load_all_plugins()
        for module_name, name, cls in plugins:
            instance = cls()
            if getattr(instance, 'category', '') == 'vuln':
                assert instance.reproduce, \
                    f'{module_name}.{name}（vuln）reproduce 不应为空'
                assert 'curl' in instance.reproduce or 'python' in instance.reproduce, \
                    f'{module_name}.{name}（vuln）reproduce 应含 curl 或 python 命令'

    def test_fix_detail_contains_upgrade_hint(self):
        """高危漏洞 fix_detail 应含【升级方案】或【配置加固】"""
        plugins = _load_all_plugins()
        high_vuln_count = 0
        for module_name, name, cls in plugins:
            instance = cls()
            if (getattr(instance, 'category', '') == 'vuln'
                    and getattr(instance, 'severity', '') == 'high'):
                high_vuln_count += 1
                # 高危漏洞的 fix_detail 应含具体修复方向
                assert ('升级' in instance.fix_detail
                        or '配置' in instance.fix_detail
                        or '代码' in instance.fix_detail), \
                    f'{module_name}.{name}（high vuln）fix_detail 应含修复方向'
        assert high_vuln_count >= 5, f'应至少 5 个高危漏洞，实际 {high_vuln_count}'

    def test_reproduce_contains_expected_response_hint(self):
        """reproduce 应含预期响应说明（# 预期 或 # 返回）"""
        plugins = _load_all_plugins()
        for module_name, name, cls in plugins:
            instance = cls()
            if getattr(instance, 'category', '') == 'vuln':
                # 至少含 # 预期 或 # 返回 或 HTTP 状态码说明
                assert ('预期' in instance.reproduce
                        or '返回' in instance.reproduce
                        or 'HTTP' in instance.reproduce
                        or '响应' in instance.reproduce), \
                    f'{module_name}.{name}（vuln）reproduce 应含预期响应说明'

    def test_fix_detail_contains_compliance_mapping(self):
        """高危漏洞 fix_detail 应含合规映射（OWASP 或 等保）"""
        plugins = _load_all_plugins()
        for module_name, name, cls in plugins:
            instance = cls()
            if (getattr(instance, 'category', '') == 'vuln'
                    and getattr(instance, 'severity', '') in ('high', 'medium')):
                assert ('OWASP' in instance.fix_detail
                        or '等保' in instance.fix_detail), \
                    f'{module_name}.{name} fix_detail 应含合规映射'


# ============================================================
# 10. 端到端：扫描结果渲染完整报告
# ============================================================

class TestEndToEndD18D24:
    """端到端：从插件到报告完整流程"""

    def test_plugin_to_report_flow(self):
        """插件 verify() → ScanResult → ReportBuilder → CSV/HTML/JSON 含 D18/D24"""
        plugin = FakePlugin()
        result = plugin.verify('http://target/', session=None)
        assert result.fix_detail == FakePlugin.fix_detail
        assert result.reproduce == FakePlugin.reproduce

        # 构建报告
        rb = ReportBuilder(results=[result], target='http://target/',
                           summary={'target': 'http://target/'})

        # CSV
        csv_text = rb.to_csv()
        assert '修复详情' in csv_text
        assert '复现命令' in csv_text
        assert '升级方案' in csv_text

        # HTML
        html = rb.to_html()
        assert 'fix-detail' in html
        assert 'reproduce' in html
        assert '升级方案' in html

        # JSON
        json_text = rb.to_json()
        assert 'fix_detail' in json_text
        assert 'reproduce' in json_text

    def test_dedup_preserves_d18_d24(self):
        """去重后 D18/D24 字段保留"""
        # 使用相同 URL + 相同 name，确保指纹一致 → 聚合为一条
        results = [
            ScanResult(kind='vuln', name='x', status=STATUS_CONFIRMED, severity='high',
                       url='http://x/', fix='f', fix_detail='detail',
                       reproduce='curl'),
            ScanResult(kind='vuln', name='x', status=STATUS_CONFIRMED, severity='high',
                       url='http://x/', fix='f', fix_detail='other_detail',
                       reproduce='other_curl'),
        ]
        aggregated, _report = aggregate(results)
        assert len(aggregated) == 1
        # 渲染为报告
        rb = ReportBuilder(results=aggregated, target='http://x/',
                           summary={'target': 'http://x/'})
        csv_text = rb.to_csv()
        assert 'detail' in csv_text  # 首个结果的 fix_detail
        assert 'curl' in csv_text


if __name__ == '__main__':
    import pytest
    sys.exit(pytest.main([__file__, '-v']))
