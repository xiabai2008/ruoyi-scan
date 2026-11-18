# D34/D35/D36/D37 单元测试
import asyncio
import os
import sys
import time

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
            assert stats["submitted"] == 1
            assert stats["completed"] == 1

    def test_map_basic(self):
        from lib.async_engine import AsyncScanEngine

        with AsyncScanEngine(max_workers=4) as engine:
            results = engine.map(lambda x: x + 1, [1, 2, 3])
            assert sorted(results) == [2, 3, 4]

    def test_exception_handling(self):
        from lib.async_engine import AsyncScanEngine

        def fail(x):
            raise ValueError("test error")

        with AsyncScanEngine(max_workers=2) as engine:
            future = engine.submit(fail, 1)
            with pytest.raises(ValueError):
                future.result(timeout=5)
            assert engine.stats["failed"] == 1

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
            assert engine.stats["submitted"] == 1
            engine.reset_stats()
            assert engine.stats["submitted"] == 0

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
        from lib.async_engine import flatten, scan_batch_targets

        # 模拟扫描函数
        def mock_scan(target):
            return [{"target": target, "vuln": "test"}]

        targets = ["http://a.com", "http://b.com", "http://c.com"]
        results = scan_batch_targets(mock_scan, targets, max_workers=3)
        # 新契约：返回 {target: results}，结果按 target 归位（旧契约返回扁平列表，丢失归属）
        assert isinstance(results, dict)
        assert set(results.keys()) == set(targets)
        assert all(len(v) == 1 for v in results.values())
        # flatten() 提供旧扁平行为，向后兼容旧调用方
        assert len(flatten(results)) == 3

    def test_scan_batch_with_progress(self):
        from lib.async_engine import flatten, scan_batch_targets

        progress = []

        def mock_scan(t):
            return [t]

        def progress_cb(completed, total, target):
            progress.append((completed, total))

        results = scan_batch_targets(mock_scan, ["a", "b"], max_workers=2, progress_callback=progress_cb)
        assert len(flatten(results)) == 2
        assert len(progress) == 2

    def test_scan_batch_empty(self):
        from lib.async_engine import scan_batch_targets

        results = scan_batch_targets(lambda t: [], [], max_workers=2)
        assert results == {}

    def test_scan_batch_exception(self):
        """单个目标失败不影响其他；失败目标在字典中保留为空列表"""
        from lib.async_engine import flatten, scan_batch_targets

        def mock_scan(t):
            if t == "fail":
                raise Exception("scan error")
            return [{"target": t}]

        results = scan_batch_targets(mock_scan, ["ok1", "fail", "ok2"], max_workers=3)
        # 失败的目标归为空列表，成功的正常归位
        assert len(flatten(results)) == 2  # ok1 + ok2
        assert results["ok1"] == [{"target": "ok1"}]
        assert results["ok2"] == [{"target": "ok2"}]
        assert results["fail"] == []


class TestPluginsConcurrent:
    """插件并发扫描测试"""

    def test_scan_plugins_concurrent(self):
        from lib.async_engine import scan_plugins_concurrent

        plugins = ["plugin1", "plugin2", "plugin3"]

        def verify_fn(plugin, target, session):
            return {"plugin": plugin, "target": target}

        results = scan_plugins_concurrent(verify_fn, plugins, "http://x.com", None)
        assert len(results) == 3


class TestBenchmark:
    """性能基准测试"""

    def test_benchmark_sync_vs_async(self):
        from lib.async_engine import benchmark_sync_vs_async

        def slow_scan(t):
            time.sleep(0.1)
            return [{"target": t}]

        result = benchmark_sync_vs_async(slow_scan, ["a", "b", "c", "d"], max_workers=4)
        assert "sync_duration" in result
        assert "async_duration" in result
        assert "speedup" in result
        # 异步应比同步快
        assert result["async_duration"] < result["sync_duration"]


# ============================================================
# D35: Web UI 控制台测试
# ============================================================


# ============================================================
# D36: 分布式任务队列测试
# ============================================================


class TestScanTask:
    """扫描任务模型测试"""

    def test_to_dict(self):
        from lib.distributed import ScanTask

        task = ScanTask(task_id="t1", target="http://x.com", mode="full")
        d = task.to_dict()
        assert d["task_id"] == "t1"
        assert d["target"] == "http://x.com"
        assert d["mode"] == "full"

    def test_from_dict(self):
        from lib.distributed import ScanTask

        d = {"task_id": "t2", "target": "http://y.com", "mode": "vuln"}
        task = ScanTask.from_dict(d)
        assert task.task_id == "t2"
        assert task.target == "http://y.com"

    def test_json_roundtrip(self):
        from lib.distributed import ScanTask

        task = ScanTask(target="http://z.com", mode="dir", config={"key": "value"})
        json_str = task.to_json()
        restored = ScanTask.from_json(json_str)
        assert restored.target == "http://z.com"
        assert restored.config == {"key": "value"}

    def test_auto_generate_id(self):
        from lib.distributed import ScanTask

        task1 = ScanTask(target="a")
        task2 = ScanTask(target="b")
        assert task1.task_id != task2.task_id


class TestTaskResult:
    """任务结果模型测试"""

    def test_to_dict(self):
        from lib.distributed import TaskResult

        r = TaskResult(task_id="t1", worker_id="w1", results=[{"vuln": "x"}])
        d = r.to_dict()
        assert d["task_id"] == "t1"
        assert d["worker_id"] == "w1"
        assert len(d["results"]) == 1

    def test_from_dict(self):
        from lib.distributed import TaskResult

        d = {"task_id": "t2", "worker_id": "w2", "results": [], "error": "fail"}
        r = TaskResult.from_dict(d)
        assert r.error == "fail"


class TestDistributedRedisMock:
    """分布式队列测试（mock Redis）"""

    def test_queue_push_pop_mock(self):
        """使用 mock 测试队列逻辑（不依赖真实 Redis）"""
        from lib.distributed import ScanTask

        # 不实际连接 Redis，只测试任务模型
        task = ScanTask(target="http://test.com", mode="full")
        assert task.status == "pending"
        task.status = "completed"
        assert task.status == "completed"

    def test_master_aggregate_results(self):
        """测试 Master 结果聚合"""
        from lib.distributed import MasterNode, TaskResult

        # 直接测试聚合逻辑（不连接 Redis）
        master = MasterNode.__new__(MasterNode)  # 跳过 __init__
        results = [
            TaskResult(task_id="t1", worker_id="w1", results=[{"severity": "high"}]),
            TaskResult(task_id="t2", worker_id="w1", results=[{"severity": "low"}]),
            TaskResult(task_id="t3", worker_id="w2", error="failed"),
        ]
        report = master.aggregate_results(results)
        assert report["total_tasks"] == 3
        assert report["successful"] == 2
        assert report["failed"] == 1
        assert report["total_vulns"] == 2
        assert report["severity_distribution"]["high"] == 1
        assert report["severity_distribution"]["low"] == 1


# ============================================================
# D37: 结果缓存测试
# ============================================================


# ============================================================
# 集成测试
# ============================================================


class TestD34D35D36D37Integration:
    """4 方向集成测试"""


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
