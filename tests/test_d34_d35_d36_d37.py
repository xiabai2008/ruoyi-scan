# D34/D35/D36/D37 单元测试
import asyncio
import json
import os
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# D34: 异步扫描引擎测试
# ============================================================

class TestAsyncScanEngine:
    """异步扫描引擎测试"""

    def test_submit_and_result(self):
        from lib.async_engine import AsyncScanEngine
        with AsyncScanEngine(max_workers=4) as engine:
            future = engine.submit(lambda x: x * 2, 5)
            assert future.result(timeout=5) == 10

    def test_stats_tracked(self):
        from lib.async_engine import AsyncScanEngine
        with AsyncScanEngine(max_workers=2) as engine:
            engine.submit(lambda: 42).result(timeout=5)
            stats = engine.stats
            assert stats['submitted'] == 1
            assert stats['completed'] == 1

    def test_map_basic(self):
        from lib.async_engine import AsyncScanEngine
        with AsyncScanEngine(max_workers=4) as engine:
            results = engine.map(lambda x: x + 1, [1, 2, 3])
            assert sorted(results) == [2, 3, 4]

    def test_exception_handling(self):
        from lib.async_engine import AsyncScanEngine
        def fail(x):
            raise ValueError('test error')
        with AsyncScanEngine(max_workers=2) as engine:
            future = engine.submit(fail, 1)
            with pytest.raises(ValueError):
                future.result(timeout=5)
            assert engine.stats['failed'] == 1

    def test_context_manager(self):
        from lib.async_engine import AsyncScanEngine
        engine = AsyncScanEngine(max_workers=2)
        assert engine._executor is None
        with engine:
            assert engine._executor is not None
        assert engine._executor is None

    def test_reset_stats(self):
        from lib.async_engine import AsyncScanEngine
        with AsyncScanEngine(max_workers=2) as engine:
            engine.submit(lambda: 1).result(timeout=5)
            assert engine.stats['submitted'] == 1
            engine.reset_stats()
            assert engine.stats['submitted'] == 0

    def test_map_async(self):
        """异步 map 测试"""
        from lib.async_engine import AsyncScanEngine

        async def run():
            engine = AsyncScanEngine(max_workers=4)
            results = await engine.map_async(lambda x: x * 2, [1, 2, 3])
            engine.stop()
            return results

        results = asyncio.run(run())
        # 结果顺序可能不一致（并发），用集合比较
        assert set(results) == {2, 4, 6}

    def test_submit_async(self):
        from lib.async_engine import AsyncScanEngine

        async def run():
            engine = AsyncScanEngine(max_workers=2)
            result = await engine.submit_async(lambda x: x + 10, 5)
            engine.stop()
            return result

        assert asyncio.run(run()) == 15


class TestBatchScan:
    """批量扫描测试"""

    def test_scan_batch_targets(self):
        from lib.async_engine import scan_batch_targets
        # 模拟扫描函数
        def mock_scan(target):
            return [{'target': target, 'vuln': 'test'}]
        targets = ['http://a.com', 'http://b.com', 'http://c.com']
        results = scan_batch_targets(mock_scan, targets, max_workers=3)
        assert len(results) == 3

    def test_scan_batch_with_progress(self):
        from lib.async_engine import scan_batch_targets
        progress = []
        def mock_scan(t):
            return [t]
        def progress_cb(completed, total, target):
            progress.append((completed, total))
        results = scan_batch_targets(mock_scan, ['a', 'b'], max_workers=2,
                                      progress_callback=progress_cb)
        assert len(results) == 2
        assert len(progress) == 2

    def test_scan_batch_empty(self):
        from lib.async_engine import scan_batch_targets
        results = scan_batch_targets(lambda t: [], [], max_workers=2)
        assert results == []

    def test_scan_batch_exception(self):
        """单个目标失败不影响其他"""
        from lib.async_engine import scan_batch_targets
        def mock_scan(t):
            if t == 'fail':
                raise Exception('scan error')
            return [{'target': t}]
        results = scan_batch_targets(mock_scan, ['ok1', 'fail', 'ok2'], max_workers=3)
        # 失败的目标返回空，成功的正常
        assert len(results) == 2  # ok1 + ok2


class TestPluginsConcurrent:
    """插件并发扫描测试"""

    def test_scan_plugins_concurrent(self):
        from lib.async_engine import scan_plugins_concurrent
        plugins = ['plugin1', 'plugin2', 'plugin3']
        def verify_fn(plugin, target, session):
            return {'plugin': plugin, 'target': target}
        results = scan_plugins_concurrent(verify_fn, plugins, 'http://x.com', None)
        assert len(results) == 3


class TestBenchmark:
    """性能基准测试"""

    def test_benchmark_sync_vs_async(self):
        from lib.async_engine import benchmark_sync_vs_async
        def slow_scan(t):
            time.sleep(0.1)
            return [{'target': t}]
        result = benchmark_sync_vs_async(slow_scan, ['a', 'b', 'c', 'd'], max_workers=4)
        assert 'sync_duration' in result
        assert 'async_duration' in result
        assert 'speedup' in result
        # 异步应比同步快
        assert result['async_duration'] < result['sync_duration']


# ============================================================
# D35: Web UI 控制台测试
# ============================================================

class TestWebUIGeneration:
    """Web UI 生成测试"""

    def test_generate_web_ui_default(self, tmp_path):
        from lib.web_ui import generate_web_ui
        output = str(tmp_path / 'index.html')
        path = generate_web_ui(output_path=output)
        assert os.path.exists(path)
        assert os.path.getsize(path) > 1000  # 应有实质内容

    def test_generate_web_ui_creates_dir(self, tmp_path):
        from lib.web_ui import generate_web_ui
        output = str(tmp_path / 'subdir' / 'deep' / 'index.html')
        path = generate_web_ui(output_path=output)
        assert os.path.exists(path)

    def test_web_ui_contains_key_elements(self, tmp_path):
        from lib.web_ui import generate_web_ui
        output = str(tmp_path / 'index.html')
        generate_web_ui(output_path=output)
        with open(output, 'r', encoding='utf-8') as f:
            content = f.read()
        # 检查关键 HTML 元素
        assert 'Ruoyi-Scan' in content or '控制台' in content
        assert 'WebSocket' in content
        assert 'startScan' in content
        assert 'scanMode' in content
        assert 'progressFill' in content
        assert 'vulnTableBody' in content

    def test_web_ui_with_custom_title(self, tmp_path):
        from lib.web_ui import generate_web_ui
        output = str(tmp_path / 'index.html')
        generate_web_ui(output_path=output, title='自定义标题')
        with open(output, 'r', encoding='utf-8') as f:
            content = f.read()
        assert '自定义标题' in content

    def test_web_ui_responsive_design(self, tmp_path):
        from lib.web_ui import generate_web_ui
        output = str(tmp_path / 'index.html')
        generate_web_ui(output_path=output)
        with open(output, 'r', encoding='utf-8') as f:
            content = f.read()
        # 响应式 viewport
        assert 'viewport' in content
        assert 'max-width: 768px' in content or '768px' in content

    def test_web_ui_has_css_styles(self, tmp_path):
        from lib.web_ui import generate_web_ui
        output = str(tmp_path / 'index.html')
        generate_web_ui(output_path=output)
        with open(output, 'r', encoding='utf-8') as f:
            content = f.read()
        assert '<style>' in content
        assert '.header' in content
        assert '.card' in content
        assert '.btn' in content

    def test_web_ui_has_javascript(self, tmp_path):
        from lib.web_ui import generate_web_ui
        output = str(tmp_path / 'index.html')
        generate_web_ui(output_path=output)
        with open(output, 'r', encoding='utf-8') as f:
            content = f.read()
        assert '<script>' in content
        assert 'connectWebSocket' in content
        assert 'function startScan' in content

    def test_get_web_ui_info(self):
        from lib.web_ui import get_web_ui_info
        info = get_web_ui_info('test.html')
        assert 'path' in info
        assert 'features' in info
        assert 'dependencies' in info
        assert len(info['features']) > 0


# ============================================================
# D36: 分布式任务队列测试
# ============================================================

class TestScanTask:
    """扫描任务模型测试"""

    def test_to_dict(self):
        from lib.distributed import ScanTask
        task = ScanTask(task_id='t1', target='http://x.com', mode='full')
        d = task.to_dict()
        assert d['task_id'] == 't1'
        assert d['target'] == 'http://x.com'
        assert d['mode'] == 'full'

    def test_from_dict(self):
        from lib.distributed import ScanTask
        d = {'task_id': 't2', 'target': 'http://y.com', 'mode': 'vuln'}
        task = ScanTask.from_dict(d)
        assert task.task_id == 't2'
        assert task.target == 'http://y.com'

    def test_json_roundtrip(self):
        from lib.distributed import ScanTask
        task = ScanTask(target='http://z.com', mode='dir', config={'key': 'value'})
        json_str = task.to_json()
        restored = ScanTask.from_json(json_str)
        assert restored.target == 'http://z.com'
        assert restored.config == {'key': 'value'}

    def test_auto_generate_id(self):
        from lib.distributed import ScanTask
        task1 = ScanTask(target='a')
        task2 = ScanTask(target='b')
        assert task1.task_id != task2.task_id


class TestTaskResult:
    """任务结果模型测试"""

    def test_to_dict(self):
        from lib.distributed import TaskResult
        r = TaskResult(task_id='t1', worker_id='w1', results=[{'vuln': 'x'}])
        d = r.to_dict()
        assert d['task_id'] == 't1'
        assert d['worker_id'] == 'w1'
        assert len(d['results']) == 1

    def test_from_dict(self):
        from lib.distributed import TaskResult
        d = {'task_id': 't2', 'worker_id': 'w2', 'results': [], 'error': 'fail'}
        r = TaskResult.from_dict(d)
        assert r.error == 'fail'


class TestStandaloneDistributor:
    """独立模式分发器测试（无需 Redis）"""

    def test_distribute_and_collect(self):
        from lib.distributed import StandaloneDistributor
        def mock_scan(target):
            return [{'target': target, 'vuln': 'test'}]
        dist = StandaloneDistributor(max_workers=4)
        results = dist.distribute_and_collect(['a', 'b', 'c'], mock_scan)
        assert len(results) == 3

    def test_distribute_with_progress(self):
        from lib.distributed import StandaloneDistributor
        progress = []
        def mock_scan(t):
            return [t]
        def progress_cb(completed, total, target):
            progress.append(completed)
        dist = StandaloneDistributor(max_workers=2)
        results = dist.distribute_and_collect(['a', 'b'], mock_scan, progress_cb)
        assert len(results) == 2
        assert sorted(progress) == [1, 2]

    def test_distribute_exception_handling(self):
        from lib.distributed import StandaloneDistributor
        def mock_scan(t):
            if t == 'fail':
                raise Exception('error')
            return [{'t': t}]
        dist = StandaloneDistributor(max_workers=3)
        results = dist.distribute_and_collect(['ok1', 'fail', 'ok2'], mock_scan)
        # 失败的被跳过
        assert len(results) == 2

    def test_distribute_empty(self):
        from lib.distributed import StandaloneDistributor
        dist = StandaloneDistributor(max_workers=2)
        results = dist.distribute_and_collect([], lambda t: [t])
        assert results == []


class TestDistributedRedisMock:
    """分布式队列测试（mock Redis）"""

    def test_queue_push_pop_mock(self):
        """使用 mock 测试队列逻辑（不依赖真实 Redis）"""
        from lib.distributed import ScanTask
        # 不实际连接 Redis，只测试任务模型
        task = ScanTask(target='http://test.com', mode='full')
        assert task.status == 'pending'
        task.status = 'completed'
        assert task.status == 'completed'

    def test_master_aggregate_results(self):
        """测试 Master 结果聚合"""
        from lib.distributed import MasterNode, TaskResult
        # 直接测试聚合逻辑（不连接 Redis）
        master = MasterNode.__new__(MasterNode)  # 跳过 __init__
        results = [
            TaskResult(task_id='t1', worker_id='w1', results=[{'severity': 'high'}]),
            TaskResult(task_id='t2', worker_id='w1', results=[{'severity': 'low'}]),
            TaskResult(task_id='t3', worker_id='w2', error='failed'),
        ]
        report = master.aggregate_results(results)
        assert report['total_tasks'] == 3
        assert report['successful'] == 2
        assert report['failed'] == 1
        assert report['total_vulns'] == 2
        assert report['severity_distribution']['high'] == 1
        assert report['severity_distribution']['low'] == 1


# ============================================================
# D37: 结果缓存测试
# ============================================================

class TestCacheKey:
    """缓存键生成测试"""

    def test_generate_cache_key_consistent(self):
        from lib.cache import generate_cache_key
        key1 = generate_cache_key('http://x.com', {'a': 1}, 'full')
        key2 = generate_cache_key('http://x.com', {'a': 1}, 'full')
        assert key1 == key2

    def test_generate_cache_key_different_target(self):
        from lib.cache import generate_cache_key
        key1 = generate_cache_key('http://x.com')
        key2 = generate_cache_key('http://y.com')
        assert key1 != key2

    def test_generate_cache_key_different_config(self):
        from lib.cache import generate_cache_key
        key1 = generate_cache_key('http://x.com', {'a': 1})
        key2 = generate_cache_key('http://x.com', {'a': 2})
        assert key1 != key2

    def test_generate_cache_key_normalizes_trailing_slash(self):
        from lib.cache import generate_cache_key
        key1 = generate_cache_key('http://x.com/')
        key2 = generate_cache_key('http://x.com')
        assert key1 == key2  # 尾部斜杠应被归一化

    def test_generate_cache_key_normalizes_case(self):
        from lib.cache import generate_cache_key
        key1 = generate_cache_key('http://X.COM')
        key2 = generate_cache_key('http://x.com')
        assert key1 == key2

    def test_generate_plugin_cache_key(self):
        from lib.cache import generate_plugin_cache_key
        key1 = generate_plugin_cache_key('http://x.com', 'sqli')
        key2 = generate_plugin_cache_key('http://x.com', 'xss')
        assert key1 != key2


class TestCacheStorage:
    """缓存存储测试"""

    def test_set_and_get(self, tmp_path):
        from lib.cache import CacheStorage
        storage = CacheStorage(str(tmp_path / 'cache.db'))
        storage.set('key1', 'http://x.com', {'vuln': 'sqli'}, ttl=3600)
        result = storage.get('key1')
        assert result is not None
        assert result['vuln'] == 'sqli'

    def test_get_nonexistent(self, tmp_path):
        from lib.cache import CacheStorage
        storage = CacheStorage(str(tmp_path / 'cache.db'))
        assert storage.get('nonexistent') is None

    def test_delete(self, tmp_path):
        from lib.cache import CacheStorage
        storage = CacheStorage(str(tmp_path / 'cache.db'))
        storage.set('key1', 'http://x.com', {'data': 1})
        assert storage.delete('key1') is True
        assert storage.get('key1') is None
        assert storage.delete('key1') is False  # 已删除

    def test_clear_all(self, tmp_path):
        from lib.cache import CacheStorage
        storage = CacheStorage(str(tmp_path / 'cache.db'))
        storage.set('k1', 'http://a.com', {'1': 1})
        storage.set('k2', 'http://b.com', {'2': 2})
        count = storage.clear_all()
        assert count == 2
        assert storage.get('k1') is None

    def test_expired_auto_cleanup(self, tmp_path):
        """过期缓存自动清除"""
        from lib.cache import CacheStorage
        storage = CacheStorage(str(tmp_path / 'cache.db'))
        # TTL=0 立即过期
        storage.set('key1', 'http://x.com', {'data': 1}, ttl=0)
        time.sleep(0.1)  # 等待过期
        result = storage.get('key1')
        assert result is None  # 已过期

    def test_hit_count_increment(self, tmp_path):
        from lib.cache import CacheStorage
        storage = CacheStorage(str(tmp_path / 'cache.db'))
        storage.set('key1', 'http://x.com', {'data': 1})
        storage.get('key1')
        storage.get('key1')
        stats = storage.get_stats()
        assert stats['total_hits'] == 2

    def test_get_stats(self, tmp_path):
        from lib.cache import CacheStorage
        storage = CacheStorage(str(tmp_path / 'cache.db'))
        storage.set('k1', 'http://a.com', {'1': 1})
        storage.set('k2', 'http://b.com', {'2': 2})
        stats = storage.get_stats()
        assert stats['total_entries'] == 2
        assert stats['active_entries'] == 2

    def test_get_by_target(self, tmp_path):
        from lib.cache import CacheStorage
        storage = CacheStorage(str(tmp_path / 'cache.db'))
        storage.set('k1', 'http://x.com', {'1': 1}, plugin_name='sqli')
        storage.set('k2', 'http://x.com', {'2': 2}, plugin_name='xss')
        storage.set('k3', 'http://y.com', {'3': 3}, plugin_name='sqli')
        entries = storage.get_by_target('http://x.com')
        assert len(entries) == 2

    def test_clear_expired(self, tmp_path):
        from lib.cache import CacheStorage
        storage = CacheStorage(str(tmp_path / 'cache.db'))
        storage.set('k1', 'http://a.com', {'1': 1}, ttl=0)  # 立即过期
        storage.set('k2', 'http://b.com', {'2': 2}, ttl=3600)
        time.sleep(0.1)
        count = storage.clear_expired()
        assert count == 1


class TestScanCache:
    """扫描缓存管理器测试"""

    def test_get_scan_result_miss(self, tmp_path):
        from lib.cache import ScanCache
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))
        result = cache.get_scan_result('http://x.com')
        assert result is None
        assert cache.miss_count == 1

    def test_set_and_get_scan_result(self, tmp_path):
        from lib.cache import ScanCache
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))
        results = [{'vuln': 'sqli', 'severity': 'high'}]
        cache.set_scan_result('http://x.com', results, scan_mode='full')
        cached = cache.get_scan_result('http://x.com', scan_mode='full')
        assert cached is not None
        assert cached['results'] == results
        assert cache.hit_count == 1

    def test_plugin_result_cache(self, tmp_path):
        from lib.cache import ScanCache
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))
        result = {'status': 'CONFIRMED', 'evidence': 'test'}
        cache.set_plugin_result('http://x.com', 'sqli_plugin', result)
        cached = cache.get_plugin_result('http://x.com', 'sqli_plugin')
        assert cached is not None
        assert cached['result'] == result

    def test_invalidate_target(self, tmp_path):
        from lib.cache import ScanCache
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))
        cache.set_scan_result('http://x.com', [{'v': 1}])
        cache.set_plugin_result('http://x.com', 'p1', {'v': 2})
        count = cache.invalidate_target('http://x.com')
        assert count == 2
        assert cache.get_scan_result('http://x.com') is None

    def test_hit_rate(self, tmp_path):
        from lib.cache import ScanCache
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))
        cache.set_scan_result('http://x.com', [{'v': 1}])
        cache.get_scan_result('http://x.com')  # hit
        cache.get_scan_result('http://y.com')  # miss
        assert cache.hit_rate == 0.5

    def test_clear_all(self, tmp_path):
        from lib.cache import ScanCache
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))
        cache.set_scan_result('http://x.com', [{'v': 1}])
        count = cache.clear_all()
        assert count == 1
        assert cache.get_scan_result('http://x.com') is None

    def test_get_stats(self, tmp_path):
        from lib.cache import ScanCache
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))
        cache.set_scan_result('http://x.com', [{'v': 1}])
        cache.get_scan_result('http://x.com')  # hit
        stats = cache.get_stats()
        assert stats['total_entries'] == 1
        assert stats['session_hits'] == 1


class TestCachedDecorator:
    """缓存装饰器测试"""

    def test_decorator_caches_result(self, tmp_path):
        from lib.cache import ScanCache, cached_scan
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))
        call_count = [0]

        @cached_scan(cache, plugin_name='test_plugin')
        def scan(target):
            call_count[0] += 1
            return {'result': 'data'}

        # 第一次调用：未缓存
        r1 = scan(target='http://x.com')
        assert r1 == {'result': 'data'}
        assert call_count[0] == 1

        # 第二次调用：命中缓存
        r2 = scan(target='http://x.com')
        assert r2 == {'result': 'data'}
        assert call_count[0] == 1  # 未再次执行


# ============================================================
# 集成测试
# ============================================================

class TestD34D35D36D37Integration:
    """4 方向集成测试"""

    def test_async_with_cache(self, tmp_path):
        """异步扫描 + 缓存"""
        from lib.async_engine import AsyncScanEngine
        from lib.cache import ScanCache
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))

        def scan_fn(target):
            return [{'target': target, 'vuln': 'test'}]

        # 首次扫描 + 缓存
        with AsyncScanEngine(max_workers=4) as engine:
            future = engine.submit(scan_fn, 'http://x.com')
            results = future.result(timeout=5)
            cache.set_scan_result('http://x.com', results)

        # 缓存命中
        cached = cache.get_scan_result('http://x.com')
        assert cached is not None
        assert cached['results'] == results

    def test_distributed_with_cache(self, tmp_path):
        """分布式 standalone + 缓存"""
        from lib.distributed import StandaloneDistributor
        from lib.cache import ScanCache
        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))

        def scan_fn(target):
            # 先查缓存
            cached = cache.get_scan_result(target)
            if cached:
                return cached['results']
            # 执行扫描
            results = [{'target': target, 'vuln': 'test'}]
            cache.set_scan_result(target, results)
            return results

        dist = StandaloneDistributor(max_workers=4)
        results1 = dist.distribute_and_collect(['http://a.com', 'http://b.com'], scan_fn)
        assert len(results1) == 2

        # 第二次扫描应命中缓存
        results2 = dist.distribute_and_collect(['http://a.com', 'http://b.com'], scan_fn)
        assert len(results2) == 2
        assert cache.hit_count >= 2

    def test_web_ui_with_async_stats(self, tmp_path):
        """Web UI 文件生成 + 异步引擎统计"""
        from lib.web_ui import generate_web_ui
        from lib.async_engine import AsyncScanEngine

        # 生成 Web UI
        web_ui_path = generate_web_ui(output_path=str(tmp_path / 'ui' / 'index.html'))
        assert os.path.exists(web_ui_path)

        # 异步扫描统计
        with AsyncScanEngine(max_workers=2) as engine:
            engine.submit(lambda: 42).result(timeout=5)
            stats = engine.stats
            assert stats['completed'] == 1

    def test_cache_with_distributed_aggregation(self, tmp_path):
        """缓存 + 分布式结果聚合"""
        from lib.cache import ScanCache
        from lib.distributed import MasterNode, TaskResult

        cache = ScanCache(db_path=str(tmp_path / 'cache.db'))

        # 缓存扫描结果
        cache.set_scan_result('http://a.com', [{'severity': 'high'}])
        cache.set_scan_result('http://b.com', [{'severity': 'low'}])

        # 模拟分布式任务结果
        master = MasterNode.__new__(MasterNode)
        results = [
            TaskResult(task_id='t1', worker_id='w1',
                       results=cache.get_scan_result('http://a.com')['results']),
            TaskResult(task_id='t2', worker_id='w1',
                       results=cache.get_scan_result('http://b.com')['results']),
        ]
        report = master.aggregate_results(results)
        assert report['total_vulns'] == 2
        assert report['severity_distribution']['high'] == 1
        assert report['severity_distribution']['low'] == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
