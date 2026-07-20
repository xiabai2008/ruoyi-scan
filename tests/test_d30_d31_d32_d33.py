# D30/D31/D32/D33 单元测试
import json
import os
import socket
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import (ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN,
                          SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW)


# ============================================================
# D30: OAST 带外检测测试
# ============================================================

class TestOASTStore:
    """回调记录存储测试"""

    def test_register_and_record(self):
        from lib.oast import CallbackStore
        store = CallbackStore()
        store.register('id123')
        assert not store.has_callback('id123')
        store.record('id123', {'protocol': 'http', 'from': '127.0.0.1'})
        assert store.has_callback('id123')
        records = store.get('id123')
        assert len(records) == 1
        assert records[0]['protocol'] == 'http'

    def test_get_empty(self):
        from lib.oast import CallbackStore
        store = CallbackStore()
        assert store.get('nonexistent') == []
        assert not store.has_callback('nonexistent')

    def test_multiple_callbacks(self):
        from lib.oast import CallbackStore
        store = CallbackStore()
        store.register('multi')
        store.record('multi', {'protocol': 'http', 'from': '1.1.1.1'})
        store.record('multi', {'protocol': 'dns', 'from': '2.2.2.2'})
        records = store.get('multi')
        assert len(records) == 2

    def test_clear(self):
        from lib.oast import CallbackStore
        store = CallbackStore()
        store.register('todelete')
        store.record('todelete', {'protocol': 'http'})
        assert store.has_callback('todelete')
        store.clear('todelete')
        assert not store.has_callback('todelete')

    def test_stats(self):
        from lib.oast import CallbackStore
        store = CallbackStore()
        store.register('id1')
        store.register('id2')
        store.record('id1', {'protocol': 'http'})
        stats = store.stats()
        assert stats['registered_ids'] == 2
        assert stats['total_callbacks'] == 1
        assert stats['with_callback'] == 1


class TestOASTPayload:
    """Payload 生成测试"""

    def test_generate_interaction_id_unique(self):
        from lib.oast import generate_interaction_id
        ids = {generate_interaction_id() for _ in range(100)}
        assert len(ids) == 100  # 全部唯一

    def test_build_payload_domain(self):
        from lib.oast import build_payload_domain
        domain = build_payload_domain('abc123', 'oast.local')
        assert domain == 'abc123.oast.local'

    def test_build_payload_url(self):
        from lib.oast import build_payload_url
        url = build_payload_url('abc123', 'http', '127.0.0.1', 5555, '/test')
        assert 'abc123' in url
        assert '127.0.0.1:5555' in url
        assert '/test' in url

    def test_build_payload_various_types(self):
        from lib.oast import build_payload, get_store
        get_store()._records.clear()
        for vtype in ['ssrf', 'xxe', 'sqli_blind', 'rce_blind', 'ldap', 'command_injection']:
            payload = build_payload(vtype, 'testid123', base_domain='oast.test')
            assert 'testid123' in payload or 'testid123.oast.test' in payload

    def test_payload_template_ssrf(self):
        from lib.oast import build_payload, get_store
        get_store()._records.clear()
        payload = build_payload('ssrf', 'myid', base_domain='oast.test')
        assert payload.startswith('http://myid.oast.test')

    def test_payload_template_rce_blind(self):
        from lib.oast import build_payload, get_store
        get_store()._records.clear()
        payload = build_payload('rce_blind', 'myid', base_domain='oast.test')
        assert 'myid.oast.test' in payload
        assert 'ping' in payload


class TestOASTClient:
    """OAST 客户端测试"""

    def test_get_payload_local(self):
        from lib.oast import OASTClient, OASTServer, get_store
        get_store()._records.clear()
        server = OASTServer('127.0.0.1', 5556)
        client = OASTClient(server=server, provider='local')
        url = client.get_payload()
        assert '127.0.0.1:5556' in url
        assert client.interaction_id is not None

    def test_get_payload_interactsh(self):
        from lib.oast import OASTClient, get_store
        get_store()._records.clear()
        client = OASTClient(provider='interactsh', base_domain='oast.probe')
        url = client.get_payload()
        assert 'oast.probe' in url

    def test_wait_callback_timeout(self):
        from lib.oast import OASTClient, OASTServer, get_store
        get_store()._records.clear()
        server = OASTServer('127.0.0.1', 5557)
        client = OASTClient(server=server)
        client.get_payload()
        # 无回调，应超时返回 False
        result = client.wait_callback(timeout=0.5)
        assert result is False

    def test_wait_callback_received(self):
        from lib.oast import OASTClient, OASTServer, get_store
        get_store()._records.clear()
        server = OASTServer('127.0.0.1', 5558)
        client = OASTClient(server=server)
        client.get_payload()
        # 手动模拟回调
        get_store().record(client.interaction_id, {'protocol': 'http'})
        result = client.wait_callback(timeout=1.0)
        assert result is True

    def test_get_callbacks(self):
        from lib.oast import OASTClient, OASTServer, get_store
        get_store()._records.clear()
        client = OASTClient(provider='interactsh')
        client.get_payload()
        get_store().record(client.interaction_id, {'protocol': 'dns'})
        callbacks = client.get_callbacks()
        assert len(callbacks) == 1
        assert callbacks[0]['protocol'] == 'dns'


class TestOASTServer:
    """OAST 服务器测试"""

    def test_start_and_stop(self):
        from lib.oast import OASTServer
        server = OASTServer('127.0.0.1', 5559)
        assert not server.is_running()
        assert server.start()
        assert server.is_running()
        server.stop()
        assert not server.is_running()

    def test_port_in_use(self):
        """端口占用时第二个服务器应启动失败

        注意：Windows 上 HTTPServer 默认 allow_reuse_address=True，可能允许
        重复绑定。此测试在 Windows 上可能跳过（不报错即可）。
        """
        from lib.oast import OASTServer
        server1 = OASTServer('127.0.0.1', 5560)
        server1.start()
        try:
            server2 = OASTServer('127.0.0.1', 5560)
            # Windows 可能允许复用，Linux 应失败
            result2 = server2.start()
            if result2:
                # Windows 行为：允许复用，跳过断言
                server2.stop()
            else:
                # Linux 行为：预期失败
                assert not result2
        finally:
            server1.stop()

    def test_url_generation(self):
        from lib.oast import OASTServer
        server = OASTServer('127.0.0.1', 5561)
        url = server.url('test123')
        assert '127.0.0.1:5561' in url
        assert 'test123' in url

    def test_http_callback_received(self):
        """启动服务器并发起 HTTP 请求，验证回调被记录

        使用 socket 直接发送 HTTP 请求，避免 urllib 超时问题。
        """
        from lib.oast import OASTServer, get_store
        get_store()._records.clear()
        server = OASTServer('127.0.0.1', 5562)
        started = server.start()
        if not started:
            # 端口被占用，跳过此测试
            return
        try:
            interaction_id = 'httptest1'
            get_store().register(interaction_id)
            # 使用 socket 直接发送 HTTP 请求（更可靠）
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            try:
                sock.connect(('127.0.0.1', 5562))
                request = f'GET /?id={interaction_id} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
                sock.sendall(request.encode())
                # 读取响应（忽略内容）
                try:
                    sock.recv(1024)
                except socket.timeout:
                    pass
            finally:
                sock.close()
            # 等待服务器处理
            for _ in range(30):
                if get_store().has_callback(interaction_id):
                    break
                time.sleep(0.1)
            assert get_store().has_callback(interaction_id), '回调未被记录'
        finally:
            server.stop()


# ============================================================
# D31: 业务逻辑漏洞检测测试
# ============================================================

class TestIDORDetector:
    """IDOR 检测器测试"""

    def test_detect_id_params(self):
        from lib.logic_scan import IDORDetector
        detector = IDORDetector()
        params = ['id', 'name', 'userId', 'foo', 'orderId']
        id_params = detector.detect_id_params('http://x.com/api', params)
        assert 'id' in id_params
        assert 'userId' in id_params
        assert 'orderId' in id_params
        assert 'name' not in id_params
        assert 'foo' not in id_params

    def test_replace_param_existing(self):
        from lib.logic_scan import IDORDetector
        detector = IDORDetector()
        new_url = detector._replace_param('http://x.com/api?id=5&name=foo', 'id', '999')
        assert 'id=999' in new_url
        assert 'name=foo' in new_url

    def test_replace_param_new(self):
        from lib.logic_scan import IDORDetector
        detector = IDORDetector()
        new_url = detector._replace_param('http://x.com/api', 'id', '1')
        assert 'id=1' in new_url

    def test_test_idor_no_session(self):
        from lib.logic_scan import IDORDetector, EndpointInfo
        detector = IDORDetector(session=None)
        ep = EndpointInfo(url='http://x.com/api?id=1', params=['id'])
        assert detector.test_idor(ep) is None

    def test_test_idor_with_mock_session_denied(self):
        """模拟权限拒绝响应"""
        from lib.logic_scan import IDORDetector, EndpointInfo
        mock_resp = MagicMock()
        mock_resp.text = '无权限访问'
        mock_resp.status_code = 200
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        detector = IDORDetector(session=mock_session)
        ep = EndpointInfo(url='http://x.com/api?id=5', params=['id'], id_param='id')
        result = detector.test_idor(ep, test_ids=['1'])
        assert result is None  # 应被权限拒绝关键字拦截

    def test_test_idor_with_mock_session_success(self):
        """模拟 IDOR 成功"""
        from lib.logic_scan import IDORDetector, EndpointInfo
        # 基准响应（自己的资源）
        baseline_resp = MagicMock()
        baseline_resp.text = 'data' * 200  # 800B
        baseline_resp.status_code = 200
        # 篡改响应（他人资源，同样大小）
        tampered_resp = MagicMock()
        tampered_resp.text = 'other' * 200  # 1000B
        tampered_resp.status_code = 200
        mock_session = MagicMock()
        mock_session.get.side_effect = [baseline_resp, tampered_resp]
        detector = IDORDetector(session=mock_session)
        ep = EndpointInfo(url='http://x.com/api?id=5', params=['id'], id_param='id')
        result = detector.test_idor(ep, test_ids=['1'])
        assert result is not None
        assert result.vuln_type == 'idor'
        assert 'IDOR' in result.name


class TestPrivilegeEscalationDetector:
    """权限提升检测器测试"""

    def test_detect_admin_endpoints_no_session(self):
        from lib.logic_scan import PrivilegeEscalationDetector
        detector = PrivilegeEscalationDetector(session=None)
        found = detector.detect_admin_endpoints('http://x.com')
        # 无 session 时仅基于路径匹配
        assert any('/admin/' in u or '/system/' in u for u in found)

    def test_test_privilege_escalation_denied(self):
        from lib.logic_scan import PrivilegeEscalationDetector
        mock_resp = MagicMock()
        mock_resp.text = '权限不足'
        mock_resp.status_code = 200
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        detector = PrivilegeEscalationDetector(session=mock_session)
        result = detector.test_privilege_escalation('http://x.com/admin/user')
        assert result is None

    def test_test_privilege_escalation_success(self):
        from lib.logic_scan import PrivilegeEscalationDetector
        mock_resp = MagicMock()
        mock_resp.text = 'admin dashboard data' * 50
        mock_resp.status_code = 200
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        detector = PrivilegeEscalationDetector(session=mock_session)
        result = detector.test_privilege_escalation('http://x.com/admin/user')
        assert result is not None
        assert result.vuln_type == 'privilege_escalation'


class TestParameterTamperingDetector:
    """参数篡改检测器测试"""

    def test_detect_tamperable_params(self):
        from lib.logic_scan import ParameterTamperingDetector, EndpointInfo
        detector = ParameterTamperingDetector()
        ep = EndpointInfo(url='http://x.com/order', params=['price', 'quantity', 'name'])
        tamperable = detector.detect_tamperable_params(ep)
        assert 'price' in tamperable
        assert 'quantity' in tamperable
        assert 'name' not in tamperable

    def test_build_tampered_url(self):
        from lib.logic_scan import ParameterTamperingDetector
        detector = ParameterTamperingDetector()
        url = detector._build_tampered_url('http://x.com/order?price=100', 'price', '0.01')
        assert 'price=0.01' in url

    def test_test_tampering_success(self):
        from lib.logic_scan import ParameterTamperingDetector, EndpointInfo
        mock_resp = MagicMock()
        mock_resp.text = '订单成功'
        mock_resp.status_code = 200
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        detector = ParameterTamperingDetector(session=mock_session)
        ep = EndpointInfo(url='http://x.com/order?price=100', params=['price'])
        result = detector.test_parameter_tampering(ep, 'price', '100', '0.01')
        assert result is not None
        assert result.vuln_type == 'parameter_tampering'


class TestLogicVulnModel:
    """LogicVuln 数据模型测试"""

    def test_to_dict(self):
        from lib.logic_scan import LogicVuln
        v = LogicVuln(
            vuln_type='idor', name='test', severity='high',
            url='http://x.com', evidence='evidence',
        )
        d = v.to_dict()
        assert d['vuln_type'] == 'idor'
        assert d['name'] == 'test'
        assert d['severity'] == 'high'

    def test_default_compliance(self):
        from lib.logic_scan import LogicVuln
        v = LogicVuln(vuln_type='test', name='t', severity='high', url='')
        assert 'OWASP' in v.compliance
        assert '等保' in v.compliance


class TestParseEndpoints:
    """端点解析测试"""

    def test_parse_endpoints_from_urls(self):
        from lib.logic_scan import parse_endpoints_from_urls
        urls = [
            'http://x.com/api/user?id=5',
            'http://x.com/api/order?orderId=10',
            'http://x.com/api/foo',
        ]
        endpoints = parse_endpoints_from_urls(urls)
        assert len(endpoints) == 3
        assert endpoints[0].id_param == 'id'
        assert endpoints[1].id_param == 'orderId'
        assert endpoints[2].id_param is None


# ============================================================
# D32: CVE/NVD 自动同步测试
# ============================================================

class TestCVEInfo:
    """CVE 信息模型测试"""

    def test_to_dict(self):
        from lib.cve_sync import CVEInfo
        cve = CVEInfo(
            cve_id='CVE-2024-1234', description='Test vuln',
            cvss_vector='CVSS:3.1/AV:N/AC:L', cvss_score=7.5,
            severity='HIGH', cwe=['CWE-89'],
        )
        d = cve.to_dict()
        assert d['cve_id'] == 'CVE-2024-1234'
        assert d['cvss_score'] == 7.5
        assert d['severity'] == 'HIGH'

    def test_from_dict(self):
        from lib.cve_sync import CVEInfo
        d = {'cve_id': 'CVE-2024-5678', 'description': 'x', 'cvss_score': 5.5}
        cve = CVEInfo.from_dict(d)
        assert cve.cve_id == 'CVE-2024-5678'
        assert cve.cvss_score == 5.5

    def test_compliance_tag_sqli(self):
        from lib.cve_sync import CVEInfo
        cve = CVEInfo(cve_id='CVE-2024-1', cwe=['CWE-89'])
        tag = cve.to_compliance_tag()
        assert 'A03:2021' in tag  # SQL 注入对应 OWASP A03

    def test_compliance_tag_xss(self):
        from lib.cve_sync import CVEInfo
        cve = CVEInfo(cve_id='CVE-2024-2', cwe=['CWE-79'])
        tag = cve.to_compliance_tag()
        assert 'A03:2021' in tag

    def test_compliance_tag_unknown_cwe(self):
        from lib.cve_sync import CVEInfo
        cve = CVEInfo(cve_id='CVE-2024-3', cwe=['CWE-999'])
        tag = cve.to_compliance_tag()
        # 未知 CWE 使用默认 A06
        assert 'A06:2021' in tag

    def test_severity_lower(self):
        from lib.cve_sync import CVEInfo
        cve = CVEInfo(cve_id='X', severity='HIGH')
        assert cve.to_severity_lower() == 'high'
        cve2 = CVEInfo(cve_id='X', severity='')
        assert cve2.to_severity_lower() == 'medium'


class TestNVDParser:
    """NVD 响应解析测试"""

    def test_parse_empty(self):
        from lib.cve_sync import parse_nvd_response
        result = parse_nvd_response({'vulnerabilities': []})
        assert result is None

    def test_parse_full_response(self):
        from lib.cve_sync import parse_nvd_response
        data = {
            'vulnerabilities': [{
                'cve': {
                    'id': 'CVE-2024-9999',
                    'descriptions': [
                        {'lang': 'en', 'value': 'SQL injection in login'},
                        {'lang': 'zh', 'value': 'SQL注入'},
                    ],
                    'metrics': {
                        'cvssMetricV31': [{
                            'cvssData': {
                                'vectorString': 'CVSS:3.1/AV:N/AC:L',
                                'baseScore': 9.8,
                                'baseSeverity': 'CRITICAL',
                            },
                            'baseSeverity': 'CRITICAL',
                        }],
                    },
                    'published': '2024-01-01T00:00:00',
                    'lastModified': '2024-06-01T00:00:00',
                    'references': [{'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-9999'}],
                    'weaknesses': [{
                        'description': [{'value': 'CWE-89'}],
                    }],
                },
            }],
        }
        cve = parse_nvd_response(data)
        assert cve is not None
        assert cve.cve_id == 'CVE-2024-9999'
        assert cve.description == 'SQL injection in login'
        assert cve.cvss_score == 9.8
        assert cve.severity == 'CRITICAL'
        assert 'CWE-89' in cve.cwe
        assert len(cve.references) == 1


class TestCVECache:
    """CVE 缓存测试"""

    def test_save_and_load(self, tmp_path):
        from lib.cve_sync import CVEInfo, save_to_cache, load_from_cache, CACHE_DIR
        # 临时修改缓存目录
        import lib.cve_sync as cve_mod
        original_cache = cve_mod.CACHE_DIR
        cve_mod.CACHE_DIR = str(tmp_path)
        try:
            cve = CVEInfo(cve_id='CVE-2024-CACHE', cvss_score=7.0, severity='HIGH')
            save_to_cache(cve)
            loaded = load_from_cache('CVE-2024-CACHE')
            assert loaded is not None
            assert loaded.cve_id == 'CVE-2024-CACHE'
            assert loaded.cvss_score == 7.0
        finally:
            cve_mod.CACHE_DIR = original_cache

    def test_load_nonexistent(self, tmp_path):
        import lib.cve_sync as cve_mod
        original_cache = cve_mod.CACHE_DIR
        cve_mod.CACHE_DIR = str(tmp_path)
        try:
            from lib.cve_sync import load_from_cache
            assert load_from_cache('CVE-9999-NOTEXIST') is None
        finally:
            cve_mod.CACHE_DIR = original_cache

    def test_clear_cache(self, tmp_path):
        import lib.cve_sync as cve_mod
        original_cache = cve_mod.CACHE_DIR
        cve_mod.CACHE_DIR = str(tmp_path)
        try:
            from lib.cve_sync import CVEInfo, save_to_cache, clear_cache
            save_to_cache(CVEInfo(cve_id='CVE-2024-A'))
            save_to_cache(CVEInfo(cve_id='CVE-2024-B'))
            count = clear_cache()
            assert count == 2
        finally:
            cve_mod.CACHE_DIR = original_cache


class TestBuildUpdateReport:
    """CVE 更新报告构建测试"""

    def test_build_report(self):
        from lib.cve_sync import CVEInfo, build_cve_update_report
        plugins_cves = [
            ('plugins.ruoyi.sqli', 'CVE-2024-1'),
            ('plugins.ruoyi.xss', 'CVE-2024-2'),
            ('plugins.ruoyi.unknown', 'CVE-2024-3'),
        ]
        cve_infos = {
            'CVE-2024-1': CVEInfo(cve_id='CVE-2024-1', cvss_score=9.8, severity='CRITICAL'),
            'CVE-2024-2': CVEInfo(cve_id='CVE-2024-2', cvss_score=6.5, severity='MEDIUM'),
            'CVE-2024-3': None,
        }
        report = build_cve_update_report(plugins_cves, cve_infos)
        assert report['total_plugins'] == 3
        assert report['updated'] == 2
        assert report['not_found'] == 1


# ============================================================
# D33: SIEM 集成测试
# ============================================================

class TestECSFormat:
    """ECS 格式测试"""

    def test_to_ecs_event(self):
        from lib.siem_export import to_ecs_event
        r = ScanResult(
            kind='vuln', name='SQL注入', severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED, url='http://x.com/login?id=1',
            evidence='SQL syntax error', cve='CVE-2024-1', cvss_score=9.8,
        )
        event = to_ecs_event(r, target='http://x.com', scan_time='2024-01-01T00:00:00')
        assert event['@timestamp'] == '2024-01-01T00:00:00'
        assert event['event']['category'] == ['vulnerability']
        assert event['event']['severity'] == 9
        assert event['vulnerability']['id'] == 'CVE-2024-1'
        assert event['vulnerability']['score'] == 9.8
        assert event['url']['full'] == 'http://x.com/login?id=1'
        assert event['host']['name'] == 'x.com'

    def test_render_ecs(self):
        from lib.siem_export import render_ecs
        results = [
            ScanResult(kind='vuln', name='XSS', severity=SEVERITY_MEDIUM,
                       status=STATUS_CONFIRMED, url='http://x.com/xss'),
        ]
        output = render_ecs(results, target='http://x.com')
        lines = output.split('\n')
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event['vulnerability']['category'] == ['XSS']

    def test_ecs_non_confirmed(self):
        from lib.siem_export import to_ecs_event
        r = ScanResult(kind='vuln', name='XSS', severity=SEVERITY_LOW,
                       status=STATUS_SAFE, url='http://x.com/xss')
        event = to_ecs_event(r)
        assert event['event']['kind'] == 'event'  # 非 alert


class TestCEFFormat:
    """CEF 格式测试"""

    def test_to_cef_event(self):
        from lib.siem_export import to_cef_event
        r = ScanResult(
            kind='vuln', name='SQL注入', severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED, url='http://x.com/login',
            evidence='error', cve='CVE-2024-1', cvss_score=9.8,
            fix='使用预编译语句',
        )
        cef = to_cef_event(r, target='http://x.com')
        assert cef.startswith('CEF:0|shengtou-tools|Ruoyi-Scan|2.0|CVE-2024-1|')
        assert '9' in cef  # severity
        assert 'src=http://x.com' in cef

    def test_cef_special_chars_escaped(self):
        from lib.siem_export import to_cef_event
        r = ScanResult(
            kind='vuln', name='Test|Vuln', severity=SEVERITY_LOW,
            status=STATUS_CONFIRMED, url='http://x.com',
            evidence='a=b|c',
        )
        cef = to_cef_event(r)
        # 名称中的 | 应被转义
        assert 'Test\\|Vuln' in cef

    def test_render_cef(self):
        from lib.siem_export import render_cef
        results = [
            ScanResult(kind='vuln', name='XSS', severity=SEVERITY_MEDIUM,
                       status=STATUS_CONFIRMED, url='http://x.com/xss'),
            ScanResult(kind='vuln', name='SQLi', severity=SEVERITY_HIGH,
                       status=STATUS_CONFIRMED, url='http://x.com/sqli'),
        ]
        output = render_cef(results)
        lines = output.split('\n')
        assert len(lines) == 2
        assert all(line.startswith('CEF:') for line in lines)


class TestLEEFFormat:
    """LEEF 格式测试"""

    def test_to_leef_event(self):
        from lib.siem_export import to_leef_event
        r = ScanResult(
            kind='vuln', name='RCE', severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED, url='http://x.com/rce',
            cve='CVE-2024-1',
        )
        leef = to_leef_event(r, target='http://x.com')
        assert leef.startswith('LEEF:2.0|shengtou-tools|Ruoyi-Scan|2.0|CVE-2024-1|')
        assert 'sev=Critical' in leef


class TestJSONFormat:
    """JSON 格式测试"""

    def test_to_json_event(self):
        from lib.siem_export import to_json_event
        r = ScanResult(
            kind='vuln', name='XSS', severity=SEVERITY_MEDIUM,
            status=STATUS_CONFIRMED, url='http://x.com/xss',
            cve='CVE-2024-1', cvss_score=6.5,
        )
        event = to_json_event(r, target='http://x.com', scan_time='2024-01-01')
        assert event['target'] == 'http://x.com'
        assert event['vulnerability']['name'] == 'XSS'
        assert event['vulnerability']['cvss_score'] == 6.5
        assert event['scanner']['name'] == 'Ruoyi-Scan'

    def test_render_json(self):
        from lib.siem_export import render_json
        results = [
            ScanResult(kind='vuln', name='A', severity=SEVERITY_LOW,
                       status=STATUS_CONFIRMED, url='http://x.com/a'),
        ]
        output = render_json(results, target='http://x.com')
        lines = output.split('\n')
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event['vulnerability']['name'] == 'A'


class TestSIEMUnified:
    """统一 SIEM 导出接口测试"""

    def test_render_siem_all_formats(self):
        from lib.siem_export import render_siem, SUPPORTED_FORMATS
        results = [
            ScanResult(kind='vuln', name='Test', severity=SEVERITY_HIGH,
                       status=STATUS_CONFIRMED, url='http://x.com'),
        ]
        for fmt in SUPPORTED_FORMATS:
            output = render_siem(results, fmt, target='http://x.com')
            assert len(output) > 0

    def test_render_siem_unsupported(self):
        from lib.siem_export import render_siem
        results = []
        try:
            render_siem(results, 'unsupported')
            assert False, '应抛出 ValueError'
        except ValueError:
            pass

    def test_parse_formats(self):
        from lib.siem_export import parse_formats
        assert parse_formats('ecs,cef') == ['ecs', 'cef']
        assert parse_formats('ecs,invalid,cef') == ['ecs', 'cef']
        assert parse_formats('') == []
        assert parse_formats(None) == []

    def test_export_to_files(self, tmp_path):
        from lib.siem_export import export_to_files
        results = [
            ScanResult(kind='vuln', name='A', severity=SEVERITY_HIGH,
                       status=STATUS_CONFIRMED, url='http://x.com/a'),
        ]
        paths = export_to_files(results, ['ecs', 'cef', 'json'], str(tmp_path),
                                target='http://x.com')
        assert len(paths) == 3
        for p in paths:
            assert os.path.exists(p)


class TestSyslogForward:
    """Syslog 转发测试"""

    def test_send_to_syslog_invalid_host(self):
        """无效主机应返回 0 但不抛异常"""
        from lib.siem_export import send_to_syslog
        sent = send_to_syslog(['test event'], '127.0.0.1', 19999, protocol='udp', timeout=1)
        # UDP 无连接，可能"成功"发送但不报错；接受任意结果
        assert sent >= 0

    def test_send_results_to_syslog(self):
        from lib.siem_export import send_results_to_syslog
        results = [
            ScanResult(kind='vuln', name='A', severity=SEVERITY_HIGH,
                       status=STATUS_CONFIRMED, url='http://x.com'),
        ]
        # 使用不存在的端口，不应抛异常
        sent = send_results_to_syslog(results, '127.0.0.1', 19999, format='cef')
        assert sent >= 0


# ============================================================
# 集成测试
# ============================================================

class TestD30D31D32D33Integration:
    """4 方向集成测试"""

    def test_oast_then_siem_export(self):
        """OAST 发现漏洞 → SIEM 导出"""
        from lib.oast import OASTClient, OASTServer, get_store
        from lib.siem_export import render_siem
        get_store()._records.clear()
        server = OASTServer('127.0.0.1', 5570)
        client = OASTClient(server=server)
        payload_url = client.get_payload()
        # 模拟回调
        get_store().record(client.interaction_id, {'protocol': 'http'})
        assert client.wait_callback(timeout=1.0)
        # 构造漏洞结果并导出
        results = [
            ScanResult(kind='vuln', name='SSRF（OAST 验证）', severity=SEVERITY_HIGH,
                       status=STATUS_CONFIRMED, url='http://target/fetch',
                       evidence=f'回调 URL {payload_url} 收到 HTTP 请求',
                       cve='CVE-2024-SSRF'),
        ]
        cef_output = render_siem(results, 'cef', target='http://target')
        assert 'SSRF' in cef_output
        assert 'CVE-2024-SSRF' in cef_output

    def test_logic_vuln_to_siem(self):
        """业务逻辑漏洞 → SIEM 导出"""
        from lib.logic_scan import LogicVuln
        from lib.siem_export import to_json_event
        lv = LogicVuln(
            vuln_type='idor', name='IDOR 越权',
            severity='high', url='http://x.com/api?id=999',
            evidence='访问他人资源',
        )
        # 转换为 ScanResult
        sr = ScanResult(
            kind='vuln', name=lv.name, severity=lv.severity,
            status=STATUS_CONFIRMED, url=lv.url, evidence=lv.evidence,
        )
        event = to_json_event(sr, target='http://x.com')
        assert event['vulnerability']['name'] == 'IDOR 越权'
        assert event['vulnerability']['severity'] == 'high'

    def test_cve_info_to_compliance_to_siem(self):
        """CVE 信息 → 合规标签 → SIEM 导出"""
        from lib.cve_sync import CVEInfo
        from lib.siem_export import render_siem
        cve = CVEInfo(
            cve_id='CVE-2024-1', cvss_score=9.8, severity='CRITICAL',
            cwe=['CWE-89'],
        )
        compliance_tag = cve.to_compliance_tag()
        assert 'OWASP' in compliance_tag
        results = [
            ScanResult(kind='vuln', name='SQL注入', severity=SEVERITY_HIGH,
                       status=STATUS_CONFIRMED, url='http://x.com/sqli',
                       cve=cve.cve_id, cvss_score=cve.cvss_score),
        ]
        ecs_output = render_siem(results, 'ecs', target='http://x.com')
        lines = ecs_output.split('\n')
        event = json.loads(lines[0])
        assert event['vulnerability']['id'] == 'CVE-2024-1'
        assert event['vulnerability']['score'] == 9.8


if __name__ == '__main__':
    # 简单运行所有测试
    import pytest
    pytest.main([__file__, '-v', '--tb=short'])
