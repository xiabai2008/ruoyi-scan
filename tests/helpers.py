"""测试辅助：轮询等待替代 time.sleep，减少测试 flaky 和耗时

用法：
    from tests.helpers import wait_for, wait_for_status

    # 等待条件成立（默认 5s 超时，100ms 轮询）
    wait_for(lambda: registry.register.called, timeout=3)

    # 等待任务状态
    wait_for_status(client, task_id, "done", timeout=5)
"""

import time
from typing import Callable


def wait_for(condition: Callable[[], bool], timeout: float = 5.0, interval: float = 0.05) -> bool:
    """轮询等待条件成立

    替代 time.sleep(N) 的固定等待，条件满足立即返回，
    超时返回 False（不抛异常，由调用方决定是否断言）。

    Args:
        condition: 返回 bool 的可调用对象
        timeout: 最大等待秒数
        interval: 轮询间隔秒数

    Returns:
        True 如果条件在超时前成立，False 如果超时
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return condition()  # 最后检查一次


def wait_for_status(client, task_id: str, status: str, timeout: float = 5.0) -> bool:
    """等待 API 任务达到指定状态

    Args:
        client: FastAPI TestClient
        task_id: 任务 ID
        status: 期望状态（done/failed/running/pending）
        timeout: 最大等待秒数

    Returns:
        True 如果在超时前达到指定状态
    """
    return wait_for(
        lambda: client.get(f"/api/scan/{task_id}").json().get("status") == status,
        timeout=timeout,
    )


def wait_for_task_done(client, task_id: str, timeout: float = 5.0) -> bool:
    """等待 API 任务完成（done 或 failed）

    Args:
        client: FastAPI TestClient
        task_id: 任务 ID
        timeout: 最大等待秒数

    Returns:
        True 如果任务在超时前完成
    """
    return wait_for(
        lambda: client.get(f"/api/scan/{task_id}").json().get("status") in ("done", "failed"),
        timeout=timeout,
    )


def wait_for_events(registry, task_id: str, min_count: int = 1, timeout: float = 3.0) -> bool:
    """等待 registry 中任务事件数达到指定数量

    Args:
        registry: TaskRegistry 实例
        task_id: 任务 ID
        min_count: 最少事件数
        timeout: 最大等待秒数

    Returns:
        True 如果事件数在超时前达标
    """
    return wait_for(
        lambda: len(registry.get_history(task_id)) >= min_count,
        timeout=timeout,
    )
