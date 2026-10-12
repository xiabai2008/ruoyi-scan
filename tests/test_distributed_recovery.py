# B-2：分布式任务租约恢复（Worker 崩溃后任务不丢、调用方不干等）
# 使用最小内存 Redis 替身覆盖 DistributedTaskQueue 所需命令，不依赖真实 Redis。
import time

from lib.distributed import (
    PROCESSING_LIST_KEY,
    TASK_CLAIM_KEY,
    TASK_QUEUE_KEY,
    TASK_STATUS_KEY,
    DistributedTaskQueue,
    MasterNode,
    ScanTask,
    TaskResult,
)


class _FakeRedis:
    """最小内存 Redis：覆盖队列用到的命令"""

    def __init__(self):
        self.lists = {}
        self.hashes = {}

    # ---- list ----
    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)
        return len(self.lists[key])

    def brpoplpush(self, src, dst, timeout=0):
        lst = self.lists.get(src) or []
        if not lst:
            return None
        raw = lst.pop()
        self.lists.setdefault(dst, []).insert(0, raw)
        return raw

    def brpop(self, key, timeout=0):
        lst = self.lists.get(key) or []
        if not lst:
            return None
        return (key, lst.pop())

    def lrem(self, key, count, value):
        lst = self.lists.get(key) or []
        removed = 0
        kept = []
        for item in lst:
            if removed < count and item == value:
                removed += 1
                continue
            kept.append(item)
        self.lists[key] = kept
        return removed

    def lrange(self, key, start, end):
        lst = self.lists.get(key) or []
        return lst[start:] if end == -1 else lst[start : end + 1]

    def llen(self, key):
        return len(self.lists.get(key) or [])

    def delete(self, *keys):
        for k in keys:
            self.lists.pop(k, None)
            self.hashes.pop(k, None)

    # ---- hash ----
    def hset(self, key, field, value):
        self.hashes.setdefault(key, {})[field] = value

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def hdel(self, key, field):
        self.hashes.get(key, {}).pop(field, None)


def _queue(lease_timeout: float = 60.0) -> DistributedTaskQueue:
    """构造绕过 Redis 连接的队列实例（仅注入内存替身）"""
    q = DistributedTaskQueue.__new__(DistributedTaskQueue)
    q.redis = _FakeRedis()
    q.redis_url = "redis://fake"
    q.lease_timeout = lease_timeout
    return q


def test_pop_claim_and_ack_clears_state():
    """正常路径：出队产生租约与载荷；ack 后清除，不会被误判为崩溃"""
    q = _queue()
    task = ScanTask(target="http://a.test")
    q.push_task(task)

    popped = q.pop_task(timeout=1)
    assert popped is not None and popped.task_id == task.task_id
    assert q.redis.llen(PROCESSING_LIST_KEY) == 1
    assert q.redis.hget(TASK_CLAIM_KEY, task.task_id)
    assert q.redis.hget(TASK_STATUS_KEY, task.task_id) == "running"

    q.push_result(TaskResult(task_id=task.task_id, worker_id="w1", results=[]))
    q.ack_task(popped)

    assert q.redis.llen(PROCESSING_LIST_KEY) == 0
    assert q.redis.hget(TASK_CLAIM_KEY, task.task_id) is None
    assert q.redis.hget(TASK_STATUS_KEY, task.task_id) == "completed"
    assert q.recover_stale_tasks() == 0, "已确认任务不得被重入队"


def test_stale_claim_requeues_task():
    """崩溃路径：租约过期 → 任务携原始载荷回到队列，状态回到 pending"""
    q = _queue(lease_timeout=1.0)
    task = ScanTask(target="http://b.test")
    q.push_task(task)
    q.pop_task(timeout=1)  # 模拟 Worker 取走后崩溃：不 push_result、不 ack

    q.redis.hset(TASK_CLAIM_KEY, task.task_id, str(time.time() - 10))
    assert q.recover_stale_tasks() == 1

    assert q.redis.llen(TASK_QUEUE_KEY) == 1
    assert q.redis.hget(TASK_STATUS_KEY, task.task_id) == "pending"
    assert q.redis.hget(TASK_CLAIM_KEY, task.task_id) is None
    assert q.redis.llen(PROCESSING_LIST_KEY) == 0

    again = q.pop_task(timeout=1)
    assert again is not None and again.task_id == task.task_id, "重入队后应能再次被 Worker 取到"


def test_stale_claim_with_lost_payload_marked_failed():
    """极端窗口：租约过期但载荷已丢失 → 标记 failed，调用方不再干等到超时"""
    q = _queue(lease_timeout=1.0)
    task = ScanTask(target="http://c.test")
    q.push_task(task)
    q.pop_task(timeout=1)

    q.redis.lists[PROCESSING_LIST_KEY] = []  # 模拟载荷丢失
    q.redis.hset(TASK_CLAIM_KEY, task.task_id, str(time.time() - 10))

    assert q.recover_stale_tasks() == 0
    assert q.redis.hget(TASK_STATUS_KEY, task.task_id) == "failed"
    assert q.redis.hget(TASK_CLAIM_KEY, task.task_id) is None


def test_fresh_claim_not_requeued():
    """未过期的租约（Worker 正常处理中）不得被重入队"""
    q = _queue(lease_timeout=60.0)
    q.push_task(ScanTask(target="http://d.test"))
    q.pop_task(timeout=1)
    assert q.recover_stale_tasks() == 0
    assert q.redis.llen(TASK_QUEUE_KEY) == 0


def test_collect_results_exits_when_queue_drained():
    """空队列且无运行中任务：collect_results 立即退出，不空等满超时"""
    q = _queue()
    master = MasterNode.__new__(MasterNode)
    master.queue = q

    t0 = time.time()
    results = master.collect_results(expected_count=1, timeout=5)
    assert results == []
    assert time.time() - t0 < 2.0, "应提前退出而不是等到超时"


def test_collect_results_waits_for_requeued_then_times_out():
    """仅剩过期租约任务时：恢复逻辑先重入队（无 Worker 消费则最终按超时返回）"""
    q = _queue(lease_timeout=1.0)
    task = ScanTask(target="http://e.test")
    q.push_task(task)
    q.pop_task(timeout=1)
    q.redis.hset(TASK_CLAIM_KEY, task.task_id, str(time.time() - 10))

    master = MasterNode.__new__(MasterNode)
    master.queue = q

    t0 = time.time()
    results = master.collect_results(expected_count=1, timeout=2)
    assert results == []
    assert q.redis.hget(TASK_STATUS_KEY, task.task_id) == "pending", "过期任务应被恢复为 pending"
    assert 1.0 <= time.time() - t0 <= 4.0
