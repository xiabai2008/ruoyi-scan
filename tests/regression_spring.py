# -*- coding: utf-8 -*-
# Spring Boot 插件回归验收（requests_mock 模拟响应）
#
# 验收范围：plugins/spring 五个 POC 插件的 vuln→CONFIRMED / safe→SAFE 判定正确性。
# 运行：python tests/regression_spring.py
# 退出码：0 全部通过，非 0 表示有失败用例
import os
import sys
import unittest

# 将项目根目录加入 sys.path，便于直接运行
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import requests_mock
except ImportError:
    print('缺少依赖 requests_mock，请先执行：pip install requests_mock')
    sys.exit(1)

from core.session import SessionManager
from core.models import STATUS_CONFIRMED, STATUS_SAFE

from plugins.spring.spring4shell import (
    Spring4shellPlugin, S4S_MARKER as MARKER_S4S)
from plugins.spring.gateway_rce import (
    SpringGatewayRcePlugin, GW_MARKER as MARKER_GW)
from plugins.spring.actuator_env_rce import (
    SpringActuatorEnvRcePlugin, ENV_MARKER as MARKER_ENV)
from plugins.spring.actuator_unauth import SpringActuatorUnauthPlugin
from plugins.spring.heapdump_leak import (
    SpringHeapdumpLeakPlugin, HEAP_MARKER as MARKER_HEAP)
from plugins.spring.jolokia_rce import (
    SpringJolokiaRcePlugin, JOLOKIA_MARKER as MARKER_JOLOKIA)
from plugins.spring.jolokia_mlet_rce import (
    SpringJolokiaMletRcePlugin, JOLOKIA_MLET_MARKER as MARKER_JOLOKIA_MLET)
from plugins.spring.cloud_function_rce import (
    SpringCloudFunctionRcePlugin, SCF_MARKER as MARKER_SCF)
from plugins.spring.h2_console_rce import (
    SpringH2ConsoleRcePlugin, H2_MARKER as MARKER_H2)
from plugins.spring.mappings_leak import SpringMappingsLeakPlugin
from plugins.spring.trace_leak import (
    SpringTraceLeakPlugin, TRACE_LEAK_MARKER as MARKER_TRACE)

# 统一 mock 目标
MOCK_TARGET = 'http://spring-mock.test'


def json_ok(body=''):
    """返回 application/json 的 mock 响应头"""
    return {'Content-Type': 'application/json;charset=UTF-8'}


def json_body(d, indent=None):
    import json as _json
    return _json.dumps(d)


class TestSpring4shell(unittest.TestCase):
    """Spring4Shell：响应含 MARKER_S4S → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/', text='{"status":200,"_marker":"' + MARKER_S4S + '"}')
        r = Spring4shellPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 Spring4Shell 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_S4S, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/', text='{"status":400,"error":"Bad Request"}')
        r = Spring4shellPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'响应不含签名应判 SAFE，实际 {r.status}')


class TestGatewayRce(unittest.TestCase):
    """Gateway RCE：响应含 MARKER_GW → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/actuator/gateway/routes/test',
               text='{"status":201,"_marker":"' + MARKER_GW + '"}')
        r = SpringGatewayRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 Gateway 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_GW, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/actuator/gateway/routes/test',
               text='{"status":404,"error":"Not Found"}', status_code=404)
        r = SpringGatewayRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestActuatorEnvRce(unittest.TestCase):
    """Actuator env 配置覆盖 RCE：响应含 MARKER_ENV → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/actuator/env',
               text='{"status":200,"_marker":"' + MARKER_ENV + '"}')
        r = SpringActuatorEnvRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 env 配置签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_ENV, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/actuator/env',
               text='{"status":404,"error":"Not Found"}', status_code=404)
        r = SpringActuatorEnvRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestJolokiaRce(unittest.TestCase):
    """Jolokia RCE：响应含 MARKER_JOLOKIA → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/actuator/jolokia',
               text='{"status":200,"value":"' + MARKER_JOLOKIA + '"}')
        r = SpringJolokiaRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 Jolokia 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_JOLOKIA, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/actuator/jolokia',
               text='{"status":404,"error":"Not Found"}', status_code=404)
        r = SpringJolokiaRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestJolokiaMletRce(unittest.TestCase):
    """Jolokia MLet 链 RCE：响应含 MARKER_JOLOKIA_MLET → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/actuator/jolokia/list',
              text='{"status":200,"value":"' + MARKER_JOLOKIA_MLET + '"}')
        r = SpringJolokiaMletRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 Jolokia MLet 链签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_JOLOKIA_MLET, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/actuator/jolokia/list',
              text='{"status":404,"error":"Not Found"}', status_code=404)
        r = SpringJolokiaMletRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestCloudFunctionRce(unittest.TestCase):
    """CVE-2022-22963 Cloud Function RCE：响应含 MARKER_SCF → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/functionRouter',
               text='{"status":200,"_marker":"' + MARKER_SCF + '"}')
        r = SpringCloudFunctionRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 Cloud Function 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_SCF, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/functionRouter',
               text='{"status":404}', status_code=404)
        r = SpringCloudFunctionRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestH2ConsoleRce(unittest.TestCase):
    """H2 Console RCE：响应含 MARKER_H2 → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/h2-console',
               text='<html>H2 Console<!--' + MARKER_H2 + '--></html>')
        r = SpringH2ConsoleRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 H2 Console 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_H2, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/h2-console',
               text='{"status":404}', status_code=404)
        r = SpringH2ConsoleRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestMappingsLeak(unittest.TestCase):
    """/actuator/mappings 泄露：200+JSON+含 dispatcherServlets → CONFIRMED；否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/actuator/mappings',
              text='{"contexts":{"application":{"mappings":{"dispatcherServlets":{}}}}}',
              headers={'Content-Type': 'application/vnd.spring-boot.actuator.v3+json'})
        r = SpringMappingsLeakPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 dispatcherServlets 应判 CONFIRMED，实际 {r.status}')
        self.assertIn('dispatcherServlets', r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/actuator/mappings',
              text='{"status":404}', status_code=404,
              headers={'Content-Type': 'application/json'})
        r = SpringMappingsLeakPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestActuatorUnauth(unittest.TestCase):
    """Actuator 未授权：/actuator 200+JSON 且 /actuator/env 200+JSON → CONFIRMED；否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        # 两个端点均可匿名访问
        m.get(MOCK_TARGET + '/actuator',
              text='{"_links":{}}', headers=json_ok())
        m.get(MOCK_TARGET + '/actuator/env',
              text='{"activeProfiles":[],"_marker":"actuator-env-accessible"}',
              headers=json_ok())
        r = SpringActuatorUnauthPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'两个端点均可匿名访问应判 CONFIRMED，实际 {r.status}')

    @requests_mock.Mocker()
    def test_safe(self, m):
        # /actuator 可达但 /actuator/env 需认证（404）
        m.get(MOCK_TARGET + '/actuator',
              text='{"_links":{}}', headers=json_ok())
        m.get(MOCK_TARGET + '/actuator/env',
              text='{"status":404,"error":"Not Found"}',
              headers=json_ok(), status_code=404)
        r = SpringActuatorUnauthPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'/actuator/env 需认证应判 SAFE，实际 {r.status}')


class TestHeapdumpLeak(unittest.TestCase):
    """heapdump 泄露：200+octet-stream+含 MARKER_HEAP → CONFIRMED；否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        body = b'\x01\x0bJAVA PROFILE 1.0.2\n' + MARKER_HEAP.encode() + b'\nHEAPDUMP_END'
        m.get(MOCK_TARGET + '/actuator/heapdump',
              content=body, headers={'Content-Type': 'application/octet-stream'})
        r = SpringHeapdumpLeakPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 heapdump 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_HEAP, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/actuator/heapdump',
              text='{"status":404,"error":"Not Found"}', status_code=404,
              headers=json_ok())
        r = SpringHeapdumpLeakPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestTraceLeak(unittest.TestCase):
    """/actuator/trace 泄露：响应含 MARKER_TRACE → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/actuator/trace',
              text='{"traces":[{"request":{"headers":{"Cookie":["SESSION='
              + MARKER_TRACE + '"]}}}]}',
              headers=json_ok())
        r = SpringTraceLeakPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 /trace 泄露签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_TRACE, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/actuator/trace',
              text='{"status":404,"error":"Not Found"}', status_code=404,
              headers=json_ok())
        r = SpringTraceLeakPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
