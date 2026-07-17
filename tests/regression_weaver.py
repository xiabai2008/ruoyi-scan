# -*- coding: utf-8 -*-
# 泛微 e-cology 插件回归验收（requests_mock 模拟响应）
#
# 验收范围：plugins/weaver 八个 POC 插件的 vuln→CONFIRMED / safe→SAFE 判定正确性。
# 运行：python tests/regression_weaver.py
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

from plugins.weaver.file_upload import (
    WeaverFileUploadPlugin, UPLOAD_MARKER as MARKER_UPLOAD)
from plugins.weaver.file_download import (
    WeaverFileDownloadPlugin, FILE_DOWNLOAD_MARKER as MARKER_FILE_DOWNLOAD)
from plugins.weaver.xml_rce import (
    WeaverXmlRcePlugin, XML_MARKER as MARKER_XML)
from plugins.weaver.bsh_rce import (
    WeaverBshRcePlugin, BSH_MARKER as MARKER_BSH)
from plugins.weaver.sqli import (
    WeaverSqliPlugin, SQLI_MARKER as MARKER_SQLI)
from plugins.weaver.unauth import WeaverUnauthPlugin
from plugins.weaver.info_leak import (
    WeaverInfoLeakPlugin, LEAK_MARKER as MARKER_LEAK)
from plugins.weaver.xss import (
    WeaverXssPlugin, XSS_MARKER as MARKER_XSS)

# 统一 mock 目标
MOCK_TARGET = 'http://weaver-mock.test'


class TestFileUpload(unittest.TestCase):
    """任意文件上传：响应含 MARKER_UPLOAD → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/weaver/weaver.file.FileDownloadForOutDoc',
               text='{"status":200,"_marker":"' + MARKER_UPLOAD + '"}')
        r = WeaverFileUploadPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含文件上传签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_UPLOAD, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/weaver/weaver.file.FileDownloadForOutDoc',
               text='{"status":404,"error":"Not Found"}', status_code=404)
        r = WeaverFileUploadPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestXmlRce(unittest.TestCase):
    """XMLDecoder RCE：响应含 MARKER_XML → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/weaver/xml_endpoint', text=MARKER_XML)
        r = WeaverXmlRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 XML RCE 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_XML, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/weaver/xml_endpoint',
               text='{"status":404,"error":"Not Found"}', status_code=404)
        r = WeaverXmlRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestBshRce(unittest.TestCase):
    """Beanshell RCE：响应含 MARKER_BSH → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/weaver/bsh.servlet.BshServlet',
               text=MARKER_BSH + ' <!-- bsh executed -->')
        r = WeaverBshRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 Beanshell 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_BSH, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/weaver/bsh.servlet.BshServlet',
               text='{"status":404,"error":"Not Found"}', status_code=404)
        r = WeaverBshRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestSqli(unittest.TestCase):
    """SQL 注入：响应含 MARKER_SQLI → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/weaver/sqlinject',
              text='{"code":500,"msg":"' + MARKER_SQLI + '","error":"XPATH syntax error"}')
        r = WeaverSqliPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 SQL 注入签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_SQLI, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/weaver/sqlinject',
              text='{"status":404,"error":"Not Found"}', status_code=404)
        r = WeaverSqliPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestUnauth(unittest.TestCase):
    """未授权访问：GET /weaver/ 200+weaver 关键字+无重定向 → CONFIRMED；401 → SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        # 200 + 含 weaver 关键字，且无重定向（requests_mock 默认 history 为空）
        m.get(MOCK_TARGET + '/weaver/',
              text='<html><body>泛微 e-cology 内部控制台 weaver admin</body></html>')
        r = WeaverUnauthPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'/weaver/ 可匿名访问含关键字应判 CONFIRMED，实际 {r.status}')

    @requests_mock.Mocker()
    def test_safe(self, m):
        # 401 鉴权拦截 → SAFE
        m.get(MOCK_TARGET + '/weaver/',
              text='Unauthorized', status_code=401)
        r = WeaverUnauthPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'/weaver/ 已鉴权应判 SAFE，实际 {r.status}')


class TestInfoLeak(unittest.TestCase):
    """配置文件泄露：响应含 MARKER_LEAK → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/weaver/ecology.properties',
              text='# ecology config\n' + MARKER_LEAK + '\ndb.url=jdbc:mysql://...')
        r = WeaverInfoLeakPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含配置泄露签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_LEAK, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/weaver/ecology.properties',
              text='Not Found', status_code=404)
        r = WeaverInfoLeakPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestFileDownload(unittest.TestCase):
    """任意文件下载路径穿越：GET + file 参数，响应含 FILE_DOWNLOAD_MARKER → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        # 仅注册精确 GET 匹配器；query 参数由插件自动附加，requests_mock 默认忽略 query 比对
        m.get(MOCK_TARGET + '/weaver/weaver.file.FileDownloadForOutDoc',
              text='{"status":200,"_marker":"' + MARKER_FILE_DOWNLOAD + '"}')
        r = WeaverFileDownloadPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含文件下载签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_FILE_DOWNLOAD, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/weaver/weaver.file.FileDownloadForOutDoc',
              text='{"status":404,"error":"Not Found"}', status_code=404)
        r = WeaverFileDownloadPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


class TestXss(unittest.TestCase):
    """反射型 XSS：GET + keyword 参数，响应含 XSS_MARKER → CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/weaver/search.jsp',
              text='<html><body>搜索结果:' + MARKER_XSS + '</body></html>')
        r = WeaverXssPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 XSS 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_XSS, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/weaver/search.jsp',
              text='{"status":404,"error":"Not Found"}', status_code=404)
        r = WeaverXssPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'端点不可达应判 SAFE，实际 {r.status}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
