# 阶段五：FingerprintCache 单元测试 + detect_cms 去重验证
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import requests_mock

from core.cache import FingerprintCache
from core.session import SessionManager
from lib.fingerprint_features import list_cms


class TestFingerprintCache(unittest.TestCase):
    """FingerprintCache 行为验证（阶段五步骤3）"""

    def test_cache_hit(self):
        """同一 URL 第二次 get 不发起新请求（request_count 不增加）"""
        sess = SessionManager()
        cache = FingerprintCache(sess)
        url = 'http://cache-test.invalid/'
        with requests_mock.Mocker() as m:
            m.get(url, text='hello', status_code=200)
            r1 = cache.get(url)
            count_after_first = sess.request_count
            r2 = cache.get(url)
            count_after_second = sess.request_count
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)
        self.assertIs(r1, r2, '第二次 get 应返回缓存对象（同一实例）')
        self.assertEqual(count_after_second, count_after_first,
                         '第二次 get 不应增加请求计数（缓存命中）')

    def test_cache_key_url(self):
        """不同 URL 缓存隔离，各自独立请求"""
        sess = SessionManager()
        cache = FingerprintCache(sess)
        u1 = 'http://cache-test.invalid/a'
        u2 = 'http://cache-test.invalid/b'
        with requests_mock.Mocker() as m:
            m.get(u1, text='A', status_code=200)
            m.get(u2, text='B', status_code=200)
            r1 = cache.get(u1)
            r2 = cache.get(u2)
            r1b = cache.get(u1)  # 第二次取 u1，应命中缓存
        self.assertEqual(r1.text, 'A')
        self.assertEqual(r2.text, 'B')
        self.assertIs(r1, r1b, 'u1 第二次应命中缓存')
        self.assertEqual(sess.request_count, 2, '两个不同 URL 各请求一次')

    def test_cache_exception_returns_none(self):
        """请求异常时缓存 None，不抛出，再次 get 也不重新请求"""
        sess = SessionManager()
        cache = FingerprintCache(sess)
        url = 'http://cache-test.invalid/'
        with requests_mock.Mocker() as m:
            m.register_uri('GET', url, exc=requests.exceptions.ConnectionError)
            r1 = cache.get(url)
        self.assertIsNone(r1, '异常应缓存 None')
        # 第二次 get 同一 URL：应返回缓存的 None，不重新发请求
        # （此时已离开 requests_mock 上下文，若发请求会真正连接并报错）
        r2 = cache.get(url)
        self.assertIsNone(r2, '缓存的 None 应直接返回')


class TestDetectCmsCaching(unittest.TestCase):
    """detect_cms 多 CMS 遍历时缓存共享验证（阶段五步骤4）"""

    def test_detect_cms_caches_root_request(self):
        """detect_cms 遍历多 CMS 时根路径只请求一次（缓存生效）"""
        from core.fingerprint import detect_cms
        sess = SessionManager()
        target = 'http://detect-cache.invalid/'
        with requests_mock.Mocker() as m:
            # 注意 requests_mock 采用 LIFO 匹配顺序（后注册优先），
            # 因此 catch-all (ANY) 必须先注册，再注册精确 URL，否则 ANY 抢先匹配所有请求
            m.get(requests_mock.ANY, status_code=404)
            # 根返回含若依关键字（让 ruoyi 命中，但不影响缓存验证）
            m.get(target, text='<html><title>若依管理系统</title>RuoYi</html>', status_code=200)
            detect_cms(target, sess)
            root_hits = [r for r in m.request_history if r.url == target]
            favicon_hits = [r for r in m.request_history
                            if r.url == target + 'favicon.ico']
        # 注册 CMS 数（用于校验去重效果）
        n_cms = len(list_cms())
        self.assertGreaterEqual(n_cms, 2, '至少应有 2 个注册 CMS（ruoyi/spring）')
        # 不带缓存：每个 CMS 都 GET 根 + favicon → n_cms 次
        # 带缓存：根 1 次 + favicon 1 次（共享）
        self.assertEqual(len(root_hits), 1,
                         '根路径应只请求 1 次（缓存去重），实际 %d 次（%d CMS）'
                         % (len(root_hits), n_cms))
        self.assertEqual(len(favicon_hits), 1,
                         'favicon 应只请求 1 次（缓存去重），实际 %d 次（%d CMS）'
                         % (len(favicon_hits), n_cms))

    def test_detect_cms_result_unchanged(self):
        """缓存引入后 detect_cms 识别结果不变（ruoyi 命中）"""
        from core.fingerprint import detect_cms
        sess = SessionManager()
        target = 'http://detect-cache.invalid/'
        html = '<html><head><title>若依管理系统</title></head><body>RuoYi</body></html>'
        with requests_mock.Mocker() as m:
            # 注意 requests_mock 采用 LIFO 匹配顺序（后注册优先），
            # 因此 catch-all (ANY) 必须先注册，再注册精确 URL，否则 ANY 抢先匹配所有请求
            m.get(requests_mock.ANY, status_code=404)
            m.get(target, text=html, status_code=200)
            res = detect_cms(target, sess)
        self.assertEqual(res.cms, 'ruoyi', '缓存不应影响识别结果')
        self.assertGreater(res.confidence, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
