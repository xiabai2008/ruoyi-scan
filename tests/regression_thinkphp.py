# -*- coding: utf-8 -*-
# ThinkPHP 插件回归验收（requests_mock 模拟响应）
#
# 验收范围：plugins/thinkphp 十个 POC 插件的 vuln→CONFIRMED / safe→SAFE 判定正确性。
# 运行：python tests/regression_thinkphp.py
# 退出码：0 全部通过，非 0 表示有失败用例
import os
import sys
import datetime
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

from plugins.thinkphp.invoke_rce import (
    ThinkphpInvokeRcePlugin, RCE_MARKER as MARKER_INVOKE)
from plugins.thinkphp.method_construct_rce import (
    ThinkphpMethodConstructRcePlugin, RCE_MARKER as MARKER_CONSTRUCT)
from plugins.thinkphp.lang_rce import (
    ThinkphpLangRcePlugin, LANG_RCE_MARKER as MARKER_LANG)
from plugins.thinkphp.rce_51 import (
    Thinkphp51RcePlugin, RCE_51_MARKER as MARKER_51)
from plugins.thinkphp.cache_write import (
    ThinkphpCacheWritePlugin, CACHE_MARKER as MARKER_CACHE)
from plugins.thinkphp.deserialize import (
    ThinkphpDeserializePlugin, DESER_MARKER as MARKER_DESER)
from plugins.thinkphp.debug_info import (
    ThinkphpDebugInfoPlugin, DEBUG_MARKER)
from plugins.thinkphp.log_disclosure import (
    ThinkphpLogDisclosurePlugin, LOG_MARKER)
from plugins.thinkphp.file_read import (
    ThinkphpFileReadPlugin, FILE_MARKER as MARKER_FILE)
from plugins.thinkphp.where_inject import (
    ThinkphpWhereInjectPlugin, SQLI_MARKER as MARKER_SQLI)

# 统一 mock 目标（不使用真实域名，避免误发请求；无尾部斜杠，配合 join_url 归一化）
MOCK_TARGET = 'http://thinkphp-mock.test'
# 日志暴露插件按当天日期探测
TODAY = datetime.datetime.now().strftime('%Y%m%d')
LOG_URL = MOCK_TARGET + '/runtime/log/' + TODAY + '.log'
CACHE_URL = MOCK_TARGET + '/runtime/cache/9d31792b4ec3cfa3b3a4b9b9b3e2c7d1.php'


class TestInvokeRce(unittest.TestCase):
    """invokefunction RCE：命中 MARKER_INVOKE，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/index.php', text='PHP Version 7.3.2\n' + MARKER_INVOKE)
        r = ThinkphpInvokeRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 invokefunction 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_INVOKE, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/index.php', text='<html><body>ThinkPHP</body></html>')
        r = ThinkphpInvokeRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'响应不含签名应判 SAFE，实际 {r.status}')


class TestMethodConstructRce(unittest.TestCase):
    """5.0.23 method 覆盖 RCE：命中 MARKER_CONSTRUCT，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/index.php?s=captcha',
               text='PHP Version 7.3.2\n' + MARKER_CONSTRUCT)
        r = ThinkphpMethodConstructRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 construct 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_CONSTRUCT, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/index.php?s=captcha',
               text='<html><body>ThinkPHP</body></html>')
        r = ThinkphpMethodConstructRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'响应不含签名应判 SAFE，实际 {r.status}')


class TestLangRce(unittest.TestCase):
    """5.0.x 多语言 RCE(CVE-2022-25481)：命中 MARKER_LANG，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/index.php', text='PHP Version 7.3.2\n' + MARKER_LANG)
        r = ThinkphpLangRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含多语言 RCE 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_LANG, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/index.php', text='<html><body>ThinkPHP</body></html>')
        r = ThinkphpLangRcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'响应不含签名应判 SAFE，实际 {r.status}')


class Test51Rce(unittest.TestCase):
    """5.1.x 路由 RCE：命中 MARKER_51，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/index.php', text='PHP Version 7.3.2\n' + MARKER_51)
        r = Thinkphp51RcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 5.1 路由 RCE 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_51, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/index.php', text='<html><body>ThinkPHP</body></html>')
        r = Thinkphp51RcePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'响应不含签名应判 SAFE，实际 {r.status}')


class TestCacheWrite(unittest.TestCase):
    """缓存文件包含 getshell：命中 MARKER_CACHE 且 200，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(CACHE_URL, text='<?php /* cache */ ' + MARKER_CACHE + ' ?>', status_code=200)
        r = ThinkphpCacheWritePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含缓存 shell 签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_CACHE, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(CACHE_URL, status_code=404, text='404 Not Found')
        r = ThinkphpCacheWritePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'缓存文件不可访问应判 SAFE，实际 {r.status}')


class TestDeserialize(unittest.TestCase):
    """反序列化 POP 链 RCE：命中 MARKER_DESER，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.post(MOCK_TARGET + '/index.php', text='PHP Version 7.3.2\n' + MARKER_DESER)
        r = ThinkphpDeserializePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含反序列化签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_DESER, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.post(MOCK_TARGET + '/index.php', text='<html><body>ThinkPHP</body></html>')
        r = ThinkphpDeserializePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'响应不含签名应判 SAFE，实际 {r.status}')


class TestDebugInfo(unittest.TestCase):
    """APP_DEBUG 信息泄露：响应含 think\\exception 判 CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/index.php?debug_probe=1',
              text='<pre>think\\exception\\ErrorException: Undefined variable</pre>')
        r = ThinkphpDebugInfoPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含调试异常特征应判 CONFIRMED，实际 {r.status}')
        self.assertIn(DEBUG_MARKER, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/index.php?debug_probe=1',
              text='<html><body>ThinkPHP Framework</body></html>')
        r = ThinkphpDebugInfoPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'响应不含调试特征应判 SAFE，实际 {r.status}')


class TestLogDisclosure(unittest.TestCase):
    """runtime 日志暴露：200 且含 LOG_MARKER 判 CONFIRMED，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(LOG_URL, text='[ INFO ] ' + LOG_MARKER + ' SQL: SELECT * FROM user',
              status_code=200)
        r = ThinkphpLogDisclosurePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'日志暴露应判 CONFIRMED，实际 {r.status}')
        self.assertIn(LOG_MARKER, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(LOG_URL, status_code=404, text='404 Not Found')
        r = ThinkphpLogDisclosurePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'日志路径不可访问应判 SAFE，实际 {r.status}')


class TestFileRead(unittest.TestCase):
    """模板驱动文件读取：命中 MARKER_FILE，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/index.php', text='PHP Version 7.3.2\n' + MARKER_FILE)
        r = ThinkphpFileReadPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含文件读取签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_FILE, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/index.php', text='<html><body>ThinkPHP</body></html>')
        r = ThinkphpFileReadPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'响应不含签名应判 SAFE，实际 {r.status}')


class TestWhereInject(unittest.TestCase):
    """where 子句注入：命中 MARKER_SQLI，否则 SAFE"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        m.get(MOCK_TARGET + '/index.php', text='SQL error\n' + MARKER_SQLI)
        r = ThinkphpWhereInjectPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_CONFIRMED,
                         f'响应含 where 注入签名应判 CONFIRMED，实际 {r.status}')
        self.assertIn(MARKER_SQLI, r.evidence)

    @requests_mock.Mocker()
    def test_safe(self, m):
        m.get(MOCK_TARGET + '/index.php', text='<html><body>ThinkPHP</body></html>')
        r = ThinkphpWhereInjectPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(r.status, STATUS_SAFE,
                         f'响应不含签名应判 SAFE，实际 {r.status}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
