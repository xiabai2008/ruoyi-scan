# D13 测试：代理池 + 请求轮换
import os
import sys
import tempfile
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.proxy_pool import ProxyPool, ProxyStats


class TestProxyPool:
    """代理池基础功能"""

    def test_empty_pool_returns_none(self):
        """空池返回 None"""
        pool = ProxyPool()
        assert pool.get() is None

    def test_single_proxy(self):
        """单代理"""
        pool = ProxyPool(['http://1.1.1.1:8080'])
        assert pool.get() == 'http://1.1.1.1:8080'

    def test_round_robin_rotation(self):
        """round-robin 轮换"""
        pool = ProxyPool(['http://1.1.1.1:8080', 'http://2.2.2.2:8080', 'http://3.3.3.3:8080'],
                         strategy='round-robin')
        results = [pool.get() for _ in range(6)]
        # round-robin 应该循环
        assert results[0] != results[1] or results[1] != results[2]
        # 第 4 次应该回到第 1 个
        assert results[3] == results[0]

    def test_random_strategy(self):
        """random 策略返回池中代理"""
        pool = ProxyPool(['http://1.1.1.1:8080', 'http://2.2.2.2:8080'], strategy='random')
        for _ in range(10):
            proxy = pool.get()
            assert proxy in ('http://1.1.1.1:8080', 'http://2.2.2.2:8080')

    def test_least_fail_strategy(self):
        """least-fail 策略优先用失败率低的"""
        pool = ProxyPool(['http://1.1.1.1:8080', 'http://2.2.2.2:8080'], strategy='least-fail')
        # 让 1.1.1.1 失败一次
        pool.record_result('http://1.1.1.1:8080', success=False)
        # 让 2.2.2.2 成功一次
        pool.record_result('http://2.2.2.2:8080', success=True)
        # least-fail 应该优先用 2.2.2.2（失败率 0%）
        proxy = pool.get()
        assert proxy == 'http://2.2.2.2:8080'

    def test_record_success(self):
        """记录成功"""
        pool = ProxyPool(['http://1.1.1.1:8080'])
        pool.record_result('http://1.1.1.1:8080', success=True)
        stats = pool.get_stats()
        assert stats[0]['success'] == 1
        assert stats[0]['fail'] == 0

    def test_record_failure(self):
        """记录失败"""
        pool = ProxyPool(['http://1.1.1.1:8080'])
        pool.record_result('http://1.1.1.1:8080', success=False)
        stats = pool.get_stats()
        assert stats[0]['fail'] == 1
        assert stats[0]['consecutive_fails'] == 1

    def test_auto_disable_after_threshold(self):
        """连续失败 3 次自动剔除"""
        pool = ProxyPool(['http://1.1.1.1:8080'])
        for _ in range(3):
            pool.record_result('http://1.1.1.1:8080', success=False)
        # 被剔除后 get() 返回 None
        assert pool.get() is None
        assert pool.healthy_count() == 0

    def test_success_resets_consecutive_fails(self):
        """成功重置连续失败计数"""
        pool = ProxyPool(['http://1.1.1.1:8080'])
        pool.record_result('http://1.1.1.1:8080', success=False)
        pool.record_result('http://1.1.1.1:8080', success=False)
        pool.record_result('http://1.1.1.1:8080', success=True)  # 重置
        assert pool.get() is not None  # 仍可用

    def test_from_file(self, tmp_path):
        """从文件加载"""
        proxy_file = tmp_path / 'proxies.txt'
        proxy_file.write_text(
            '# 代理列表\n'
            'http://1.1.1.1:8080\n'
            '\n'
            'http://2.2.2.2:8080\n'
            '# 注释行\n'
            'http://user:pass@3.3.3.3:8080\n',
            encoding='utf-8'
        )
        pool = ProxyPool.from_file(str(proxy_file))
        assert pool.total_count() == 3
        proxies = set()
        for _ in range(10):
            proxies.add(pool.get())
        assert 'http://1.1.1.1:8080' in proxies
        assert 'http://2.2.2.2:8080' in proxies
        assert 'http://user:pass@3.3.3.3:8080' in proxies

    def test_from_nonexistent_file(self):
        """文件不存在返回空池"""
        pool = ProxyPool.from_file('nonexistent.txt')
        assert pool.total_count() == 0
        assert pool.get() is None

    def test_add_proxy(self):
        """动态添加代理"""
        pool = ProxyPool()
        pool.add('http://1.1.1.1:8080')
        assert pool.total_count() == 1
        assert pool.get() == 'http://1.1.1.1:8080'

    def test_get_stats(self):
        """获取统计"""
        pool = ProxyPool(['http://1.1.1.1:8080', 'http://2.2.2.2:8080'])
        pool.record_result('http://1.1.1.1:8080', success=True)
        pool.record_result('http://2.2.2.2:8080', success=False)
        stats = pool.get_stats()
        assert len(stats) == 2

    def test_remove_disabled(self):
        """清除被剔除的代理"""
        pool = ProxyPool(['http://1.1.1.1:8080', 'http://2.2.2.2:8080'])
        for _ in range(3):
            pool.record_result('http://1.1.1.1:8080', success=False)
        assert pool.healthy_count() == 1
        pool.remove_disabled()
        assert pool.total_count() == 1


class TestSessionManagerIntegration:
    """SessionManager 与代理池集成"""

    def test_session_with_proxy_pool(self):
        """SessionManager 接受 proxy_pool 参数"""
        from core.session import SessionManager
        pool = ProxyPool(['http://1.1.1.1:8080'])
        session = SessionManager(proxy_pool=pool, timeout=5)
        assert session.proxy_pool is pool
        assert session._get_proxy_for_request() == 'http://1.1.1.1:8080'

    def test_session_without_pool_uses_fixed_proxy(self):
        """无代理池时用固定代理"""
        from core.session import SessionManager
        session = SessionManager(proxy='http://fixed:8080', timeout=5)
        assert session._get_proxy_for_request() == 'http://fixed:8080'

    def test_session_pool_overrides_fixed(self):
        """代理池优先于固定代理"""
        from core.session import SessionManager
        pool = ProxyPool(['http://pool:8080'])
        session = SessionManager(proxy='http://fixed:8080', proxy_pool=pool, timeout=5)
        assert session._get_proxy_for_request() == 'http://pool:8080'
