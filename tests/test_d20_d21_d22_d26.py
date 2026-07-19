# D20/D21/D22/D26 测试：增量扫描 + 告警通知 + SARIF + 认证扫描
import json
import os
import sys
import tempfile
import types
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import (ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN,
                          SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW)
from core.report import ReportBuilder


# ============================================================
# D20：增量扫描与差异对比
# ============================================================

class TestVulnFingerprint:
    """漏洞指纹测试"""

    def test_fingerprint_key(self):
        from lib.diff_scan import VulnFingerprint
        fp = VulnFingerprint(name='SQL注入', url='http://x/system/role/list')
        assert fp.key() == 'SQL注入|http://x/system/role/list'

    def test_fingerprint_strips_query(self):
        from lib.diff_scan import VulnFingerprint
        fp = VulnFingerprint(name='X', url='http://x/path?token=abc')
        assert '?token=abc' not in fp.key()
        assert 'http://x/path' in fp.key()


class TestDiffReport:
    """差异报告测试"""

    def _make_report(self, target='http://x/', vulns=None, scan_time='2026-01-01'):
        """构造报告字典"""
        results = []
        for v in (vulns or []):
            results.append({
                'name': v['name'],
                'url': v.get('url', 'http://x/'),
                'status': v.get('status', STATUS_CONFIRMED),
                'severity': v.get('severity', 'high'),
                'cve': v.get('cve', ''),
            })
        return {
            'target': target,
            'scan_time': scan_time,
            'results': results,
        }

    def test_diff_new_vuln(self):
        """新增漏洞检测"""
        from lib.diff_scan import diff_reports
        old = self._make_report(vulns=[
            {'name': 'A', 'url': 'http://x/a'},
        ])
        new = self._make_report(vulns=[
            {'name': 'A', 'url': 'http://x/a'},
            {'name': 'B', 'url': 'http://x/b'},  # 新增
        ])
        diff = diff_reports(old, new)
        assert diff.total_new == 1
        assert diff.new_vulns[0].name == 'B'
        assert diff.total_fixed == 0
        assert diff.total_persisted == 1

    def test_diff_fixed_vuln(self):
        """已修复漏洞检测"""
        from lib.diff_scan import diff_reports
        old = self._make_report(vulns=[
            {'name': 'A', 'url': 'http://x/a'},
            {'name': 'B', 'url': 'http://x/b'},
        ])
        new = self._make_report(vulns=[
            {'name': 'A', 'url': 'http://x/a'},  # B 已修复
        ])
        diff = diff_reports(old, new)
        assert diff.total_fixed == 1
        assert diff.fixed_vulns[0].name == 'B'
        assert diff.total_new == 0

    def test_diff_persisted_vuln(self):
        """未变漏洞检测"""
        from lib.diff_scan import diff_reports
        old = self._make_report(vulns=[{'name': 'A', 'url': 'http://x/a'}])
        new = self._make_report(vulns=[{'name': 'A', 'url': 'http://x/a'}])
        diff = diff_reports(old, new)
        assert diff.total_persisted == 1
        assert diff.total_new == 0
        assert diff.total_fixed == 0

    def test_diff_changed_severity(self):
        """严重度变化检测"""
        from lib.diff_scan import diff_reports
        old = self._make_report(vulns=[{'name': 'A', 'url': 'http://x/a', 'severity': 'medium'}])
        new = self._make_report(vulns=[{'name': 'A', 'url': 'http://x/a', 'severity': 'high'}])
        diff = diff_reports(old, new)
        assert diff.total_changed == 1
        assert diff.changed_vulns[0].old_severity == 'medium'
        assert diff.changed_vulns[0].new_severity == 'high'

    def test_diff_ignores_safe(self):
        """SAFE 状态不计入差异对比"""
        from lib.diff_scan import diff_reports
        old = self._make_report(vulns=[
            {'name': 'A', 'url': 'http://x/a', 'status': STATUS_CONFIRMED},
            {'name': 'B', 'url': 'http://x/b', 'status': STATUS_SAFE},
        ])
        new = self._make_report(vulns=[
            {'name': 'A', 'url': 'http://x/a', 'status': STATUS_CONFIRMED},
        ])
        diff = diff_reports(old, new)
        # B 是 SAFE，不计入对比
        assert diff.total_fixed == 0
        assert diff.total_persisted == 1

    def test_diff_to_json(self):
        """差异报告转 JSON"""
        from lib.diff_scan import diff_reports
        old = self._make_report(vulns=[{'name': 'A', 'url': 'http://x/a'}])
        new = self._make_report(vulns=[{'name': 'B', 'url': 'http://x/b'}])
        diff = diff_reports(old, new)
        j = diff.to_json()
        data = json.loads(j)
        assert 'summary' in data
        assert data['summary']['new'] == 1
        assert data['summary']['fixed'] == 1

    def test_diff_to_html(self):
        """差异报告转 HTML"""
        from lib.diff_scan import diff_reports
        old = self._make_report(vulns=[{'name': 'A', 'url': 'http://x/a'}])
        new = self._make_report(vulns=[{'name': 'B', 'url': 'http://x/b'}])
        diff = diff_reports(old, new)
        html = diff.to_html()
        assert '<html' in html
        assert '新增' in html
        assert '已修复' in html

    def test_save_and_load_baseline(self):
        """保存和加载基线"""
        from lib.diff_scan import save_baseline, load_report
        report_data = self._make_report(vulns=[{'name': 'A', 'url': 'http://x/a'}])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'baseline.json')
            save_baseline(report_data, path)
            assert os.path.exists(path)
            loaded = load_report(path)
            assert loaded['target'] == 'http://x/'

    def test_render_diff_report(self):
        """渲染差异报告到文件"""
        from lib.diff_scan import diff_reports, render_diff_report
        old = self._make_report(vulns=[{'name': 'A', 'url': 'http://x/a'}])
        new = self._make_report(vulns=[{'name': 'B', 'url': 'http://x/b'}])
        diff = diff_reports(old, new)
        with tempfile.TemporaryDirectory() as d:
            paths = render_diff_report(diff, os.path.join(d, 'diff'))
            assert len(paths) == 2  # JSON + HTML
            for p in paths:
                assert os.path.exists(p)
                assert os.path.getsize(p) > 0


# ============================================================
# D22：SARIF 报告格式
# ============================================================

class TestSarifReport:
    """SARIF 报告测试"""

    def _make_builder(self):
        """构造含漏洞的 ReportBuilder"""
        results = [
            ScanResult(kind='vuln', name='SQL注入', severity=SEVERITY_HIGH,
                       status=STATUS_CONFIRMED, url='http://x/system/role',
                       evidence='database() 报错', fix='参数化查询',
                       cve='CVE-2023-1234', cvss_score=9.8,
                       compliance={'OWASP': 'A03:2021'}),
            ScanResult(kind='vuln', name='文件读取', severity=SEVERITY_MEDIUM,
                       status=STATUS_CONFIRMED, url='http://x/common/download',
                       evidence='/etc/passwd', fix='限制路径'),
            ScanResult(kind='vuln', name='安全项', severity=SEVERITY_LOW,
                       status=STATUS_SAFE, url='http://x/safe'),
        ]
        return ReportBuilder(results=results, target='http://x/',
                             summary={'started_at': '2026-01-01', 'duration': 1.0})

    def test_sarif_version(self):
        """SARIF 版本为 2.1.0"""
        from core.report_sarif import to_sarif
        builder = self._make_builder()
        sarif = json.loads(to_sarif(builder))
        assert sarif['version'] == '2.1.0'

    def test_sarif_schema(self):
        """SARIF 含 $schema"""
        from core.report_sarif import to_sarif
        builder = self._make_builder()
        sarif = json.loads(to_sarif(builder))
        assert '$schema' in sarif

    def test_sarif_runs(self):
        """SARIF 含 runs 数组"""
        from core.report_sarif import to_sarif
        builder = self._make_builder()
        sarif = json.loads(to_sarif(builder))
        assert len(sarif['runs']) == 1
        run = sarif['runs'][0]
        assert 'tool' in run
        assert 'results' in run

    def test_sarif_tool_name(self):
        """SARIF 工具名为 Ruoyi-Scan"""
        from core.report_sarif import to_sarif
        builder = self._make_builder()
        sarif = json.loads(to_sarif(builder))
        assert sarif['runs'][0]['tool']['driver']['name'] == 'Ruoyi-Scan'

    def test_sarif_results_confirmed_only(self):
        """SARIF 仅含 CONFIRMED 结果"""
        from core.report_sarif import to_sarif
        builder = self._make_builder()
        sarif = json.loads(to_sarif(builder))
        results = sarif['runs'][0]['results']
        assert len(results) == 2  # 2 个 CONFIRMED（SQL注入 + 文件读取）

    def test_sarif_result_level(self):
        """SARIF 结果 level 映射正确"""
        from core.report_sarif import to_sarif
        builder = self._make_builder()
        sarif = json.loads(to_sarif(builder))
        results = sarif['runs'][0]['results']
        # CVSS 9.8 → error
        levels = [r['level'] for r in results]
        assert 'error' in levels

    def test_sarif_rules(self):
        """SARIF 含 rules 定义"""
        from core.report_sarif import to_sarif
        builder = self._make_builder()
        sarif = json.loads(to_sarif(builder))
        rules = sarif['runs'][0]['tool']['driver']['rules']
        assert len(rules) >= 2
        rule_ids = [r['id'] for r in rules]
        assert 'SQL注入' in rule_ids

    def test_sarif_rule_cve(self):
        """SARIF rule 含 CVE 属性"""
        from core.report_sarif import to_sarif
        builder = self._make_builder()
        sarif = json.loads(to_sarif(builder))
        rules = sarif['runs'][0]['tool']['driver']['rules']
        sql_rule = [r for r in rules if r['id'] == 'SQL注入'][0]
        assert sql_rule['properties']['cve'] == 'CVE-2023-1234'

    def test_sarif_location(self):
        """SARIF 结果含 location"""
        from core.report_sarif import to_sarif
        builder = self._make_builder()
        sarif = json.loads(to_sarif(builder))
        results = sarif['runs'][0]['results']
        assert results[0]['locations'][0]['physicalLocation']['artifactLocation']['uri']

    def test_sarif_render_to_file(self):
        """SARIF 渲染到文件"""
        from core.report_sarif import render_sarif
        builder = self._make_builder()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'report.sarif')
            render_sarif(builder, path)
            assert os.path.exists(path)
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            assert data['version'] == '2.1.0'

    def test_sarif_via_render_all(self):
        """通过 render_all 生成 sarif 格式"""
        builder = self._make_builder()
        with tempfile.TemporaryDirectory() as d:
            paths = builder.render_all(d, formats=['sarif'])
            assert len(paths) == 1
            assert paths[0].endswith('.sarif')
            assert os.path.exists(paths[0])

    def test_cvss_to_level(self):
        """CVSS → level 映射"""
        from core.report_sarif import _cvss_to_level
        assert _cvss_to_level(9.5) == 'error'
        assert _cvss_to_level(7.0) == 'error'
        assert _cvss_to_level(5.0) == 'warning'
        assert _cvss_to_level(2.0) == 'note'
        assert _cvss_to_level(0.0) == 'none'


# ============================================================
# D21：告警通知
# ============================================================

class TestParseNotifyArg:
    """--notify 参数解析测试"""

    def test_parse_webhook(self):
        from lib.notifier import parse_notify_arg
        result = parse_notify_arg(['webhook=https://hooks.example.com/x'])
        assert len(result) == 1
        assert result[0]['type'] == 'webhook'
        assert result[0]['target'] == 'https://hooks.example.com/x'

    def test_parse_dingtalk(self):
        from lib.notifier import parse_notify_arg
        result = parse_notify_arg(['dingtalk=https://oapi.dingtalk.com/x'])
        assert result[0]['type'] == 'dingtalk'

    def test_parse_email(self):
        from lib.notifier import parse_notify_arg
        result = parse_notify_arg(['email=security@example.com'])
        assert result[0]['type'] == 'email'
        assert result[0]['target'] == 'security@example.com'

    def test_parse_multiple(self):
        from lib.notifier import parse_notify_arg
        result = parse_notify_arg([
            'webhook=https://x',
            'email=y@z.com',
        ])
        assert len(result) == 2

    def test_parse_auto_detect_url(self):
        """URL 自动识别为 webhook"""
        from lib.notifier import parse_notify_arg
        result = parse_notify_arg(['https://hooks.example.com/x'])
        assert result[0]['type'] == 'webhook'

    def test_parse_auto_detect_email(self):
        """含 @ 自动识别为 email"""
        from lib.notifier import parse_notify_arg
        result = parse_notify_arg(['user@example.com'])
        assert result[0]['type'] == 'email'

    def test_parse_invalid(self):
        """无效格式跳过"""
        from lib.notifier import parse_notify_arg
        result = parse_notify_arg(['invalid_no_equals'])
        assert len(result) == 0


class TestBuildNotificationMessage:
    """通知消息构建测试"""

    def _make_builder(self):
        results = [
            ScanResult(kind='vuln', name='SQL注入', severity=SEVERITY_HIGH,
                       status=STATUS_CONFIRMED, url='http://x/a',
                       evidence='err', cve='CVE-2023-1'),
            ScanResult(kind='vuln', name='文件读取', severity=SEVERITY_MEDIUM,
                       status=STATUS_CONFIRMED, url='http://x/b'),
        ]
        return ReportBuilder(results=results, target='http://x/',
                             summary={'started_at': '2026-01-01', 'duration': 5.0,
                                      'request_count': 10, 'mode': '综合'})

    def test_build_message_target(self):
        from lib.notifier import build_notification_message
        msg = build_notification_message(self._make_builder())
        assert msg['target'] == 'http://x/'
        assert msg['vuln_count'] == 2
        assert msg['high_count'] == 1
        assert msg['medium_count'] == 1

    def test_build_message_vulns(self):
        from lib.notifier import build_notification_message
        msg = build_notification_message(self._make_builder())
        assert len(msg['vulns']) == 2
        assert msg['vulns'][0]['name'] == 'SQL注入'

    def test_build_text_message(self):
        from lib.notifier import build_notification_message, _build_text_message
        msg = build_notification_message(self._make_builder())
        text = _build_text_message(msg)
        assert 'Ruoyi-Scan' in text
        assert 'http://x/' in text
        assert 'SQL注入' in text

    def test_build_markdown_message(self):
        from lib.notifier import build_notification_message, _build_markdown_message
        msg = build_notification_message(self._make_builder())
        md = _build_markdown_message(msg)
        assert '##' in md  # Markdown 标题
        assert 'SQL注入' in md

    def test_build_message_truncation(self):
        """超过 20 条漏洞截断"""
        from lib.notifier import build_notification_message
        results = [
            ScanResult(kind='vuln', name=f'vuln-{i}', severity=SEVERITY_HIGH,
                       status=STATUS_CONFIRMED, url=f'http://x/{i}')
            for i in range(25)
        ]
        builder = ReportBuilder(results=results, target='http://x/', summary={})
        msg = build_notification_message(builder)
        assert len(msg['vulns']) == 20  # 截断为 20
        assert msg['truncated'] is True
        assert msg['total_vulns'] == 25


class TestSendNotifications:
    """通知发送测试（mock，不实际发送）"""

    def test_send_webhook_mock(self, monkeypatch):
        """Webhook 发送 mock 测试"""
        from lib.notifier import send_webhook
        # mock requests.post
        import requests
        class MockResp:
            status_code = 200
        monkeypatch.setattr(requests, 'post', lambda *a, **kw: MockResp())
        msg = {'target': 'http://x/', 'vuln_count': 1, 'high_count': 1,
               'medium_count': 0, 'low_count': 0, 'vulns': [],
               'scan_time': '', 'duration': 0, 'request_count': 0, 'mode': '',
               'truncated': False, 'total_vulns': 0}
        result = send_webhook('https://hooks.x/test', msg, verbose=False)
        assert result is True

    def test_send_webhook_failure(self, monkeypatch):
        """Webhook 发送失败"""
        from lib.notifier import send_webhook
        import requests
        class MockResp:
            status_code = 500
        monkeypatch.setattr(requests, 'post', lambda *a, **kw: MockResp())
        msg = {'target': '', 'vuln_count': 0, 'high_count': 0, 'medium_count': 0,
               'low_count': 0, 'vulns': [], 'scan_time': '', 'duration': 0,
               'request_count': 0, 'mode': '', 'truncated': False, 'total_vulns': 0}
        result = send_webhook('https://x', msg, verbose=False)
        assert result is False

    def test_send_email_no_smtp_config(self):
        """邮件无 SMTP 配置跳过"""
        from lib.notifier import send_email
        # 确保无 SMTP 环境变量
        for key in ['SMTP_HOST', 'SMTP_USER']:
            if key in os.environ:
                del os.environ[key]
        msg = {'target': '', 'vuln_count': 0, 'high_count': 0, 'medium_count': 0,
               'low_count': 0, 'vulns': [], 'scan_time': '', 'duration': 0,
               'request_count': 0, 'mode': '', 'truncated': False, 'total_vulns': 0}
        result = send_email('test@example.com', msg, verbose=False)
        assert result is False


# ============================================================
# D26：认证扫描增强
# ============================================================

class TestParseAuthArg:
    """--auth 参数解析测试"""

    def test_parse_cookie(self):
        from lib.auth_scan import parse_auth_arg
        config = parse_auth_arg(['cookie=JSESSIONID=abc123; token=xyz'])
        assert config['type'] == 'cookie'
        assert config['cookies']['JSESSIONID'] == 'abc123'
        assert config['cookies']['token'] == 'xyz'

    def test_parse_bearer(self):
        from lib.auth_scan import parse_auth_arg
        config = parse_auth_arg(['bearer=eyJhbGciOiJIUzI1NiJ9'])
        assert config['type'] == 'bearer'
        assert config['headers']['Authorization'] == 'Bearer eyJhbGciOiJIUzI1NiJ9'

    def test_parse_header(self):
        from lib.auth_scan import parse_auth_arg
        config = parse_auth_arg(['header=X-API-Key: mykey123'])
        assert config['type'] == 'header'
        assert config['headers']['X-API-Key'] == 'mykey123'

    def test_parse_basic(self):
        from lib.auth_scan import parse_auth_arg
        config = parse_auth_arg(['basic=admin:password'])
        assert config['type'] == 'basic'
        assert config['headers']['Authorization'].startswith('Basic ')

    def test_parse_multiple(self):
        from lib.auth_scan import parse_auth_arg
        config = parse_auth_arg([
            'cookie=JSESSIONID=abc',
            'header=X-API-Key: xyz',
        ])
        assert config['cookies']['JSESSIONID'] == 'abc'
        assert config['headers']['X-API-Key'] == 'xyz'

    def test_parse_invalid(self):
        from lib.auth_scan import parse_auth_arg
        config = parse_auth_arg(['invalid_no_equals'])
        assert config['type'] is None
        assert config['cookies'] == {}


class TestLoadAuthFile:
    """认证文件加载测试"""

    def test_load_structured_file(self):
        from lib.auth_scan import load_auth_file
        content = 'type: cookie\nJSESSIONID: abc123\ntoken: xyz\n'
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(content)
            path = f.name
        try:
            config = load_auth_file(path)
            assert config['type'] == 'cookie'
            assert config['cookies']['JSESSIONID'] == 'abc123'
            assert config['cookies']['token'] == 'xyz'
        finally:
            os.unlink(path)

    def test_load_plain_cookie_string(self):
        from lib.auth_scan import load_auth_file
        content = 'JSESSIONID=abc123; token=xyz'
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(content)
            path = f.name
        try:
            config = load_auth_file(path)
            assert config['type'] == 'cookie'
            assert config['cookies']['JSESSIONID'] == 'abc123'
        finally:
            os.unlink(path)

    def test_load_file_not_found(self):
        from lib.auth_scan import load_auth_file
        with pytest.raises(FileNotFoundError):
            load_auth_file('/nonexistent/auth.txt')

    def test_load_bearer_file(self):
        from lib.auth_scan import load_auth_file
        content = 'type: bearer\ntoken: eyJabc123\n'
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(content)
            path = f.name
        try:
            config = load_auth_file(path)
            assert config['type'] == 'bearer'
            assert config['headers']['Authorization'] == 'Bearer eyJabc123'
        finally:
            os.unlink(path)


class TestParseLoginArg:
    """--auth-login 参数解析测试"""

    def test_parse_login(self):
        from lib.auth_scan import parse_login_arg
        username, password = parse_login_arg('admin:password123')
        assert username == 'admin'
        assert password == 'password123'

    def test_parse_login_invalid(self):
        from lib.auth_scan import parse_login_arg
        with pytest.raises(ValueError):
            parse_login_arg('invalid_no_colon')


class TestApplyAuthToSession:
    """认证信息应用到 SessionManager 测试"""

    def test_apply_cookies(self):
        from lib.auth_scan import apply_auth_to_session
        from core.session import SessionManager
        session = SessionManager()
        auth_config = {
            'cookies': {'JSESSIONID': 'abc123'},
            'headers': {},
            'type': 'cookie',
        }
        apply_auth_to_session(session, auth_config)
        assert session.session.cookies.get('JSESSIONID') == 'abc123'

    def test_apply_headers(self):
        from lib.auth_scan import apply_auth_to_session
        from core.session import SessionManager
        session = SessionManager()
        auth_config = {
            'cookies': {},
            'headers': {'Authorization': 'Bearer xyz'},
            'type': 'bearer',
        }
        apply_auth_to_session(session, auth_config)
        assert session.session.headers['Authorization'] == 'Bearer xyz'

    def test_apply_empty_config(self):
        from lib.auth_scan import apply_auth_to_session
        from core.session import SessionManager
        session = SessionManager()
        original_cookie = session.session.cookies.get('test', None)
        apply_auth_to_session(session, {'cookies': {}, 'headers': {}, 'type': None})
        # 不应抛异常
        assert session.session is not None


# ============================================================
# 集成测试
# ============================================================

class TestD20D22Integration:
    """D20 + D22 集成测试"""

    def test_diff_with_real_report(self):
        """使用真实 ReportBuilder 生成的报告做差异对比"""
        from lib.diff_scan import diff_reports
        # 旧报告：1 个漏洞
        old_builder = ReportBuilder(
            results=[ScanResult(kind='vuln', name='A', severity=SEVERITY_HIGH,
                                status=STATUS_CONFIRMED, url='http://x/a')],
            target='http://x/', summary={'started_at': '2026-01-01'})
        # 新报告：A 已修复，新增 B
        new_builder = ReportBuilder(
            results=[ScanResult(kind='vuln', name='B', severity=SEVERITY_HIGH,
                                status=STATUS_CONFIRMED, url='http://x/b')],
            target='http://x/', summary={'started_at': '2026-01-02'})
        diff = diff_reports(old_builder.to_dict(), new_builder.to_dict())
        assert diff.total_new == 1  # B 新增
        assert diff.total_fixed == 1  # A 已修复

    def test_sarif_with_diff_scenario(self):
        """SARIF 报告 + 差异场景"""
        from core.report_sarif import to_sarif
        builder = ReportBuilder(
            results=[ScanResult(kind='vuln', name='新漏洞', severity=SEVERITY_HIGH,
                                status=STATUS_CONFIRMED, url='http://x/new',
                                cve='CVE-2024-9999', cvss_score=9.0)],
            target='http://x/', summary={'started_at': '2026-01-01'})
        sarif = json.loads(to_sarif(builder))
        assert len(sarif['runs'][0]['results']) == 1
        assert sarif['runs'][0]['results'][0]['level'] == 'error'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
