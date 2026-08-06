# D23/D25/D28/D29 测试：国际化 + 插件 SDK + CI/CD + 漏洞知识库
import json
import os
import sys
import tempfile
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, ScanResult

# ============================================================
# D23：国际化
# ============================================================

class TestI18n:
    """国际化模块测试"""

    def test_get_text_zh(self):
        from lib.i18n import get_text
        assert get_text('report_title', 'zh') == '扫描报告'
        assert get_text('target', 'zh') == '目标'

    def test_get_text_en(self):
        from lib.i18n import get_text
        assert get_text('report_title', 'en') == 'Scan Report'
        assert get_text('target', 'en') == 'Target'

    def test_get_text_default_lang(self):
        """默认语言为中文"""
        from lib.i18n import DEFAULT_LANG, get_text
        assert DEFAULT_LANG == 'zh'
        assert get_text('target') == '目标'

    def test_get_text_unknown_key(self):
        """未知 key 返回 key 本身"""
        from lib.i18n import get_text
        assert get_text('nonexistent_key', 'zh') == 'nonexistent_key'

    def test_get_text_unsupported_lang(self):
        """不支持的语言回退到中文"""
        from lib.i18n import get_text
        assert get_text('target', 'fr') == '目标'  # 回退到中文

    def test_get_status_cn(self):
        from lib.i18n import get_status_cn
        assert get_status_cn('CONFIRMED', 'zh') == '确认存在'
        assert get_status_cn('CONFIRMED', 'en') == 'Confirmed'
        assert get_status_cn('SAFE', 'en') == 'Safe'
        assert get_status_cn('UNKNOWN', 'en') == 'Unknown'

    def test_get_severity_cn(self):
        from lib.i18n import get_severity_cn
        assert get_severity_cn('high', 'zh') == '高'
        assert get_severity_cn('high', 'en') == 'High'
        assert get_severity_cn('medium', 'en') == 'Medium'

    def test_get_csv_header_zh(self):
        from lib.i18n import get_csv_header
        header = get_csv_header('zh')
        assert '漏洞名称' in header
        assert '修复详情' in header

    def test_get_csv_header_en(self):
        from lib.i18n import get_csv_header
        header = get_csv_header('en')
        assert 'Vulnerability' in header
        assert 'Fix Details' in header

    def test_get_html_title_zh(self):
        from lib.i18n import get_html_title
        assert '扫描报告' in get_html_title('', 'zh')

    def test_get_html_title_en(self):
        from lib.i18n import get_html_title
        assert 'Scan Report' in get_html_title('', 'en')

    def test_get_html_title_with_cms(self):
        from lib.i18n import get_html_title
        title = get_html_title('ruoyi', 'en')
        assert 'Ruoyi' in title
        assert 'Scan Report' in title

    def test_localize_report_dict_zh(self):
        """中文报告不转换"""
        from lib.i18n import localize_report_dict
        report = {'target': 'http://x/', 'risk_distribution': {'high': 1, 'medium': 0, 'low': 0, 'total': 1}}
        result = localize_report_dict(report, 'zh')
        assert result == report  # 中文不转换

    def test_localize_report_dict_en(self):
        """英文报告翻译风险分布 key"""
        from lib.i18n import localize_report_dict
        report = {
            'target': 'http://x/',
            'risk_distribution': {'high': 1, 'medium': 0, 'low': 0, 'total': 1},
            'results': [{'name': 'SQL', 'status': 'CONFIRMED', 'severity': 'high'}],
        }
        result = localize_report_dict(report, 'en')
        assert 'High' in result['risk_distribution']
        assert result['risk_distribution']['High'] == 1
        assert result['results'][0]['status_cn'] == 'Confirmed'

    def test_is_supported(self):
        from lib.i18n import is_supported
        assert is_supported('zh') is True
        assert is_supported('en') is True
        assert is_supported('fr') is False


# ============================================================
# D25：插件 SDK
# ============================================================

class TestPluginSDK:
    """插件 SDK 测试"""

    def test_to_pascal_case(self):
        from lib.plugin_sdk import _to_pascal_case
        assert _to_pascal_case('file_read') == 'FileReadPlugin'
        assert _to_pascal_case('SQL注入') == 'SQL注入Plugin'
        assert _to_pascal_case('my-plugin') == 'MyPluginPlugin'

    def test_to_filename(self):
        from lib.plugin_sdk import _to_filename
        assert _to_filename('FileRead') == 'file_read'
        assert _to_filename('SQL注入') == 's_q_l注入'

    def test_generate_plugin(self):
        """生成插件源代码"""
        from lib.plugin_sdk import generate_plugin
        source = generate_plugin('测试漏洞', category='common', severity='high')
        assert 'class 测试漏洞Plugin' in source
        assert "name = '测试漏洞'" in source
        assert "severity = 'high'" in source
        assert 'def verify(self, target, session):' in source

    def test_generate_plugin_with_params(self):
        """带参数生成插件"""
        from lib.plugin_sdk import generate_plugin
        source = generate_plugin(
            'XSS漏洞', category='ruoyi', severity='medium',
            cve='CVE-2024-1234', description='XSS 漏洞检测',
            fix='输入过滤', probe_path='/search',
        )
        assert 'CVE-2024-1234' in source
        assert 'XSS 漏洞检测' in source
        assert '/search' in source

    def test_init_plugin_file(self):
        """生成插件文件到磁盘"""
        from lib.plugin_sdk import init_plugin_file
        with tempfile.TemporaryDirectory() as d:
            filepath = init_plugin_file('测试漏洞', category='common', output_dir=d)
            assert os.path.exists(filepath)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            assert 'class 测试漏洞Plugin' in content

    def test_init_plugin_file_exists(self):
        """文件已存在时抛错"""
        from lib.plugin_sdk import init_plugin_file
        with tempfile.TemporaryDirectory() as d:
            # 第一次生成
            filepath = init_plugin_file('测试', category='common', output_dir=d)
            # 第二次应抛错
            with pytest.raises(FileExistsError):
                init_plugin_file('测试', category='common', output_dir=d)

    def test_check_plugin_valid(self):
        """验证合法插件"""
        from lib.plugin_sdk import check_plugin
        with tempfile.TemporaryDirectory() as d:
            from lib.plugin_sdk import init_plugin_file
            filepath = init_plugin_file('测试漏洞', category='common', output_dir=d)
            ok, errors, warnings = check_plugin(filepath)
            assert ok is True
            assert len(errors) == 0

    def test_check_plugin_missing_file(self):
        """文件不存在"""
        from lib.plugin_sdk import check_plugin
        ok, errors, warnings = check_plugin('/nonexistent/plugin.py')
        assert ok is False
        assert '文件不存在' in errors[0]

    def test_check_plugin_missing_name(self):
        """缺少 name 属性"""
        from lib.plugin_sdk import check_plugin
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write('# no name here\nclass X:\n    pass\n')
            filepath = f.name
        try:
            ok, errors, warnings = check_plugin(filepath)
            assert ok is False
            assert any('name' in e for e in errors)
        finally:
            os.unlink(filepath)

    def test_check_plugin_by_import_valid(self):
        """导入验证合法插件"""
        from lib.plugin_sdk import check_plugin_by_import, init_plugin_file
        with tempfile.TemporaryDirectory() as d:
            filepath = init_plugin_file('导入测试', category='common', output_dir=d)
            ok, errors, warnings = check_plugin_by_import(filepath)
            assert ok is True

    def test_list_all_plugins(self):
        """列出所有插件"""
        from lib.plugin_sdk import list_all_plugins
        plugins = list_all_plugins()
        assert len(plugins) > 0
        # 检查字段完整性
        for p in plugins:
            assert 'name' in p
            assert 'category' in p
            assert 'severity' in p

    def test_generate_plugin_docs(self):
        """生成插件文档"""
        from lib.plugin_sdk import generate_plugin_docs
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'plugins.md')
            result = generate_plugin_docs(path)
            assert os.path.exists(path)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            assert '插件列表' in content
            assert '统计' in content


# ============================================================
# D28：CI/CD 集成
# ============================================================

class TestCIRunner:
    """CI/CD 集成测试"""

    def _make_results(self, confirmed_count=2, severity='high'):
        """构造扫描结果"""
        results = []
        for i in range(confirmed_count):
            results.append(ScanResult(
                kind='vuln', name=f'漏洞{i}', severity=severity,
                status=STATUS_CONFIRMED, url=f'http://x/{i}',
            ))
        return results

    def test_should_fail_ci_high(self):
        """高危漏洞应让 CI 失败"""
        from lib.ci_runner import should_fail_ci
        results = self._make_results(1, 'high')
        assert should_fail_ci(results, 'high') is True

    def test_should_fail_ci_below_threshold(self):
        """低危漏洞不触发 high 阈值"""
        from lib.ci_runner import should_fail_ci
        results = self._make_results(1, 'low')
        assert should_fail_ci(results, 'high') is False

    def test_should_fail_ci_medium_threshold(self):
        """中危漏洞触发 medium 阈值"""
        from lib.ci_runner import should_fail_ci
        results = self._make_results(1, 'medium')
        assert should_fail_ci(results, 'medium') is True

    def test_should_fail_ci_no_confirmed(self):
        """无确认漏洞不失败"""
        from lib.ci_runner import should_fail_ci
        results = [ScanResult(kind='vuln', name='安全', status=STATUS_SAFE, url='http://x/')]
        assert should_fail_ci(results, 'high') is False

    def test_get_ci_exit_code_success(self):
        """成功退出码 0"""
        from lib.ci_runner import get_ci_exit_code
        results = []
        assert get_ci_exit_code(results, 'high') == 0

    def test_get_ci_exit_code_vuln_found(self):
        """发现漏洞退出码 1"""
        from lib.ci_runner import get_ci_exit_code
        results = self._make_results(1, 'high')
        assert get_ci_exit_code(results, 'high') == 1

    def test_get_ci_exit_code_error(self):
        """异常退出码 2"""
        from lib.ci_runner import get_ci_exit_code
        assert get_ci_exit_code([], 'high', has_error=True) == 2

    def test_format_ci_summary(self):
        """CI 摘要格式化"""
        from lib.ci_runner import format_ci_summary
        results = self._make_results(2, 'high')
        summary = format_ci_summary(results, 'http://x/', 5.0)
        assert 'Ruoyi-Scan CI Summary' in summary
        assert 'http://x/' in summary
        assert 'High:   2' in summary

    def test_format_ci_vulns(self):
        """漏洞列表格式化"""
        from lib.ci_runner import format_ci_vulns
        results = self._make_results(3, 'high')
        text = format_ci_vulns(results)
        assert 'Confirmed vulnerabilities (3)' in text
        assert '漏洞0' in text

    def test_format_ci_vulns_empty(self):
        """空漏洞列表"""
        from lib.ci_runner import format_ci_vulns
        text = format_ci_vulns([])
        assert 'No confirmed' in text

    def test_format_ci_vulns_truncation(self):
        """漏洞列表截断"""
        from lib.ci_runner import format_ci_vulns
        results = self._make_results(60, 'high')
        text = format_ci_vulns(results, max_display=10)
        assert 'and 50 more' in text

    def test_generate_ci_config_github(self):
        """生成 GitHub Actions 配置"""
        from lib.ci_runner import generate_ci_config
        content = generate_ci_config('github')
        assert 'name: Security Scan' in content
        assert 'runs-on: ubuntu-latest' in content
        assert 'upload-sarif' in content

    def test_generate_ci_config_gitlab(self):
        """生成 GitLab CI 配置"""
        from lib.ci_runner import generate_ci_config
        content = generate_ci_config('gitlab')
        assert 'security-scan:' in content
        assert 'stage: test' in content

    def test_generate_ci_config_jenkins(self):
        """生成 Jenkins 配置"""
        from lib.ci_runner import generate_ci_config
        content = generate_ci_config('jenkins')
        assert 'pipeline' in content
        assert 'Jenkinsfile' not in content  # 内容不含文件名

    def test_generate_ci_config_unsupported(self):
        """不支持的平台报错"""
        from lib.ci_runner import generate_ci_config
        with pytest.raises(ValueError):
            generate_ci_config('travis')

    def test_generate_ci_config_to_file(self):
        """生成配置文件到磁盘"""
        from lib.ci_runner import generate_ci_config
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'security-scan.yml')
            generate_ci_config('github', path)
            assert os.path.exists(path)
            with open(path, 'r', encoding='utf-8') as f:
                assert 'Security Scan' in f.read()

    def test_run_ci_mode_success(self, capsys):
        """CI 模式成功"""
        from lib.ci_runner import run_ci_mode
        args = types.SimpleNamespace(severity_threshold='high')
        results = []
        exit_code = run_ci_mode(args, results, 'http://x/', 5.0)
        assert exit_code == 0

    def test_run_ci_mode_failed(self, capsys):
        """CI 模式失败"""
        from lib.ci_runner import run_ci_mode
        args = types.SimpleNamespace(severity_threshold='high')
        results = self._make_results(1, 'high')
        exit_code = run_ci_mode(args, results, 'http://x/', 5.0)
        assert exit_code == 1


# ============================================================
# D29：漏洞知识库
# ============================================================

class TestVulnWiki:
    """漏洞知识库测试"""

    def _make_plugins(self, count=3):
        """构造插件元数据列表"""
        plugins = []
        for i in range(count):
            plugins.append({
                'module': f'plugins.common.vuln{i}',
                'class': f'Vuln{i}Plugin',
                'name': f'漏洞{i}',
                'category': 'common',
                'severity': 'high' if i % 2 == 0 else 'medium',
                'cve': f'CVE-2024-{1000+i}',
                'cvss_vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'compliance': 'OWASP:A03:2021;等保2.0:8.1.3',
                'has_fix_detail': True,
                'has_reproduce': True,
            })
        return plugins

    def test_build_wiki_data(self):
        """构建知识库数据"""
        from lib.vuln_wiki import build_wiki_data
        plugins = self._make_plugins(3)
        data = build_wiki_data(plugins)
        assert data['stats']['total'] == 3
        assert data['stats']['by_severity']['high'] == 2  # i=0,2
        assert data['stats']['by_severity']['medium'] == 1  # i=1
        assert data['stats']['with_cve'] == 3
        assert data['stats']['with_fix_detail'] == 3
        assert data['stats']['with_reproduce'] == 3
        assert data['stats']['by_compliance']['OWASP'] == 3
        assert data['stats']['by_compliance']['等保'] == 3

    def test_render_wiki_html(self):
        """渲染 HTML 知识库"""
        from lib.vuln_wiki import render_wiki_html
        plugins = self._make_plugins(3)
        html = render_wiki_html(plugins)
        assert '<html' in html
        assert '漏洞知识库' in html
        assert '漏洞0' in html
        assert '漏洞1' in html
        assert 'CVE-2024-1000' in html
        # 含统计卡片
        assert 'stat-card' in html
        # 含搜索框
        assert 'searchBox' in html
        # 含筛选按钮
        assert 'filter-btn' in html

    def test_render_wiki_html_empty(self):
        """空插件列表"""
        from lib.vuln_wiki import render_wiki_html
        html = render_wiki_html([])
        assert '<html' in html
        assert '暂无漏洞数据' in html

    def test_render_wiki_json(self):
        """渲染 JSON 知识库"""
        from lib.vuln_wiki import render_wiki_json
        plugins = self._make_plugins(2)
        json_str = render_wiki_json(plugins)
        data = json.loads(json_str)
        assert 'plugins' in data
        assert 'stats' in data
        assert data['stats']['total'] == 2

    def test_generate_wiki_html(self):
        """生成 HTML 知识库文件"""
        from lib.vuln_wiki import generate_wiki
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'wiki.html')
            paths = generate_wiki(path, formats=['html'])
            assert len(paths) == 1
            assert os.path.exists(paths[0])
            with open(paths[0], 'r', encoding='utf-8') as f:
                content = f.read()
            assert '<html' in content

    def test_generate_wiki_both_formats(self):
        """生成 HTML + JSON 知识库"""
        from lib.vuln_wiki import generate_wiki
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'wiki.html')
            paths = generate_wiki(path, formats=['html', 'json'])
            assert len(paths) == 2
            for p in paths:
                assert os.path.exists(p)

    def test_generate_wiki_with_real_plugins(self):
        """使用真实插件生成知识库"""
        from lib.plugin_sdk import list_all_plugins
        from lib.vuln_wiki import generate_wiki
        plugins = list_all_plugins()
        assert len(plugins) > 0
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'wiki.html')
            paths = generate_wiki(path, formats=['html'])
            assert len(paths) == 1
            with open(paths[0], 'r', encoding='utf-8') as f:
                content = f.read()
            # 应含真实漏洞名称
            assert '漏洞知识库' in content


# ============================================================
# 集成测试
# ============================================================

class TestD23D25D28D29Integration:
    """集成测试"""

    def test_plugin_init_then_check(self):
        """生成插件后验证"""
        from lib.plugin_sdk import check_plugin, check_plugin_by_import, init_plugin_file
        with tempfile.TemporaryDirectory() as d:
            filepath = init_plugin_file('集成测试漏洞', category='common', output_dir=d)
            # 静态检查
            ok1, errors1, warnings1 = check_plugin(filepath)
            assert ok1 is True
            # 导入检查
            ok2, errors2, warnings2 = check_plugin_by_import(filepath)
            assert ok2 is True

    def test_ci_with_i18n(self):
        """CI 模式 + 国际化"""
        from lib.ci_runner import format_ci_summary
        # CI 摘要始终用英文（适合国际日志）
        results = [ScanResult(kind='vuln', name='Test', severity=SEVERITY_HIGH,
                              status=STATUS_CONFIRMED, url='http://x/')]
        summary = format_ci_summary(results, 'http://x/', 1.0)
        assert 'Ruoyi-Scan CI Summary' in summary  # 英文

    def test_wiki_with_ci_exit_code(self):
        """知识库生成不影响 CI 退出码"""
        from lib.ci_runner import get_ci_exit_code
        from lib.vuln_wiki import generate_wiki
        # 生成知识库
        with tempfile.TemporaryDirectory() as d:
            paths = generate_wiki(os.path.join(d, 'wiki.html'), formats=['html'])
            assert len(paths) == 1
        # CI 退出码独立计算
        results = [ScanResult(kind='vuln', name='High', severity=SEVERITY_HIGH,
                              status=STATUS_CONFIRMED, url='http://x/')]
        assert get_ci_exit_code(results, 'high') == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
