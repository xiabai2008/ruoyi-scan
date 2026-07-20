# D2 多版本 POC 适配单元测试
# 运行：python tests/test_ruoyi_versions.py 或 python -m pytest tests/test_ruoyi_versions.py -q
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import requests_mock
except ImportError:
    print('缺少依赖 requests_mock，请先执行：pip install requests_mock')
    sys.exit(1)

from core.ruoyi_versions import (
    extract_version, detect_version, parse_version, version_in_range,
)
from core.session import SessionManager
from core.router import Router
from core.models import FingerprintResult

MOCK_TARGET = 'http://ruoyi-version.test'


class TestExtractVersion(unittest.TestCase):
    """版本号提取"""

    def test_extract_from_login_page(self):
        """从 /login 页面 HTML 提取版本号"""
        html = '<html><head><title>登录若依系统</title></head><body><footer>RuoYi 4.7.8</footer></body></html>'
        self.assertEqual(extract_version(html), '4.7.8')

    def test_extract_multiple_matches(self):
        """多个版本号取第一个"""
        html = 'version 4.2.0 and 4.7.8'
        self.assertEqual(extract_version(html), '4.2.0')

    def test_extract_v5(self):
        """v5 版本号"""
        html = 'RuoYi-Vue 5.1.0'
        self.assertEqual(extract_version(html), '5.1.0')

    def test_extract_no_version(self):
        """无版本号返回空串"""
        self.assertEqual(extract_version('<html>无版本</html>'), '')
        self.assertEqual(extract_version(''), '')


class TestParseVersion(unittest.TestCase):
    """版本号解析"""

    def test_parse_4_7_8(self):
        self.assertEqual(parse_version('4.7.8'), (4, 7, 8))

    def test_parse_4_7(self):
        self.assertEqual(parse_version('4.7'), (4, 7, 0))

    def test_parse_empty(self):
        self.assertEqual(parse_version(''), (0, 0, 0))

    def test_parse_invalid(self):
        self.assertEqual(parse_version('abc'), (0, 0, 0))


class TestVersionInRange(unittest.TestCase):
    """版本范围判定"""

    def test_empty_range_all_versions(self):
        """空范围 → 全版本适用"""
        self.assertTrue(version_in_range('4.7.8', ''))
        self.assertTrue(version_in_range('4.2.0', ''))
        self.assertTrue(version_in_range('5.0.0', ''))

    def test_empty_version_all_ranges(self):
        """版本未识别 → 不过滤（保守策略：跑 POC）"""
        self.assertTrue(version_in_range('', '>=4.2,<4.6'))
        self.assertTrue(version_in_range('', '>=4.7'))

    def test_range_ge_lt(self):
        """>=4.0,<4.6"""
        spec = '>=4.0,<4.6'
        self.assertTrue(version_in_range('4.2.0', spec))
        self.assertTrue(version_in_range('4.5.9', spec))
        self.assertFalse(version_in_range('4.6.0', spec))
        self.assertFalse(version_in_range('4.7.8', spec))

    def test_range_ge_only(self):
        """>=4.7"""
        spec = '>=4.7'
        self.assertTrue(version_in_range('4.7.0', spec))
        self.assertTrue(version_in_range('4.7.8', spec))
        self.assertTrue(version_in_range('5.0.0', spec))
        self.assertFalse(version_in_range('4.6.9', spec))

    def test_range_le_only(self):
        """<=4.5"""
        spec = '<=4.5'
        self.assertTrue(version_in_range('4.2.0', spec))
        self.assertTrue(version_in_range('4.5.0', spec))
        self.assertFalse(version_in_range('4.6.0', spec))


class TestDetectVersion(unittest.TestCase):
    """版本探测（mock HTTP）"""

    @requests_mock.Mocker()
    def test_detect_from_login_page(self, m):
        """从 /login 页面探测版本号"""
        m.get(MOCK_TARGET + '/login',
              text='<html><footer>RuoYi 4.7.8</footer></html>',
              headers={'Content-Type': 'text/html'})
        version = detect_version(MOCK_TARGET, SessionManager())
        self.assertEqual(version, '4.7.8')

    @requests_mock.Mocker()
    def test_detect_from_root(self, m):
        """/login 无版本号，根路径 HTML 含 ?v=4.7"""
        m.get(MOCK_TARGET + '/login', text='<html>登录</html>',
              headers={'Content-Type': 'text/html'})
        m.get(MOCK_TARGET, text='<html><script src="/static/js/main.js?v=4.7"></script></html>',
              headers={'Content-Type': 'text/html'})
        version = detect_version(MOCK_TARGET, SessionManager())
        self.assertEqual(version, '4.7.0')

    @requests_mock.Mocker()
    def test_detect_not_found(self, m):
        """所有探测点都无版本号 → 返回空串"""
        m.get(MOCK_TARGET + '/login', text='<html>登录</html>',
              headers={'Content-Type': 'text/html'})
        m.get(MOCK_TARGET, text='<html>首页</html>',
              headers={'Content-Type': 'text/html'})
        m.get(MOCK_TARGET + '/actuator/info', status_code=404)
        version = detect_version(MOCK_TARGET, SessionManager())
        self.assertEqual(version, '')


class TestRouterVersionFilter(unittest.TestCase):
    """Router 按版本过滤 POC"""

    def test_filter_by_version_4_2(self):
        """4.2.0 版本：应包含 <4.6 和 <4.7 的 POC，不包含 >=4.7 的"""
        fp = FingerprintResult(cms='ruoyi', version='4.2.0', confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        # 4.2.0 应跑全部 16 个 POC（所有 <4.6 和 <4.7 都满足，全版本的也满足）
        self.assertEqual(len(plugins), 16,
                         f'4.2.0 应跑全部 16 个 POC，实际 {len(plugins)}')

    def test_filter_by_version_4_7_8(self):
        """4.7.8 版本：应过滤掉 <4.6 和 <4.7 的 POC（6 个），只跑全版本的（10 个）"""
        fp = FingerprintResult(cms='ruoyi', version='4.7.8', confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        # 4.7.8 应过滤掉 sql_inject_role/dept(2) + file_read/file_read_path(2) +
        # file_upload + job_rce + file_read_time(3) = 7 个，剩 9 个全版本
        # 实际：affected_versions=<4.7 的有 sql_inject_role/dept/file_read/file_read_path/file_upload/job_rce/file_read_time = 7 个
        self.assertEqual(len(plugins), 9,
                         f'4.7.8 应过滤掉 7 个 <4.7 的 POC，剩 9 个，实际 {len(plugins)}')

    def test_filter_by_version_4_6_0(self):
        """4.6.0 版本：<4.6 的 POC 被过滤（sql_inject_role/dept），<4.7 的保留"""
        fp = FingerprintResult(cms='ruoyi', version='4.6.0', confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        # 4.6.0 应过滤掉 sql_inject_role/dept(2)，剩 14 个
        self.assertEqual(len(plugins), 14,
                         f'4.6.0 应过滤掉 2 个 <4.6 的 POC，剩 14 个，实际 {len(plugins)}')

    def test_no_version_runs_all(self):
        """版本未识别 → 跑全部 POC（保守策略）"""
        fp = FingerprintResult(cms='ruoyi', version='', confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        self.assertEqual(len(plugins), 16,
                         f'版本未识别应跑全部 16 个 POC，实际 {len(plugins)}')

    def test_filterd_out_plugins(self):
        """4.7.8 过滤掉的 POC 类名正确（sql_inject_role/dept 等）"""
        fp = FingerprintResult(cms='ruoyi', version='4.7.8', confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        plugin_names = [cls.name for cls in plugins]
        # 4.7.8 不应跑的 POC
        self.assertNotIn('POST型报错注入（role）', plugin_names)
        self.assertNotIn('第二种POST型报错注入（dept）', plugin_names)
        self.assertNotIn('任意文件上传漏洞', plugin_names)
        # 4.7.8 应跑的 POC
        self.assertIn('Thymeleaf/SpEL 模板注入', plugin_names)


if __name__ == '__main__':
    unittest.main(verbosity=2)
