"""测试辅助：轮询等待替代 time.sleep，减少测试 flaky 和耗时

用法：
    from tests.helpers import wait_for, wait_for_status

    # 等待条件成立（默认 5s 超时，50ms 轮询）
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

    interval 在内部下限钳制（≥10ms）：0 会退化为吃满 CPU 的忙轮询，
    负数会让 time.sleep 在轮询循环里抛 ValueError 而不是正常超时返回。

    Args:
        condition: 返回 bool 的可调用对象
        timeout: 最大等待秒数
        interval: 轮询间隔秒数

    Returns:
        True 如果条件在超时前成立，False 如果超时
    """
    # interval 钳制到 ≥10ms：0 → 忙轮询吃满 CPU；负数 → time.sleep 抛 ValueError
    interval = max(0.01, interval)
    # time.monotonic：墙钟（time.time）会因 NTP 校时跳变，导致提前退出或超时失真
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return condition()  # 最后检查一次


def _task_status(client, task_id: str):
    """读取任务状态；请求失败（非 2xx）/ 响应非 JSON 时返回 None 而非抛异常

    wait_for 的状态轮询只关心「是否已达目标状态」，瞬时 5xx 或 HTML 错误页
    不应让测试直接崩溃（旧实现在 .json() 处抛异常，掩盖了真正的超时结果）。
    """
    try:
        return client.get(f"/api/scan/{task_id}").json().get("status")
    except Exception:
        return None


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
        lambda: _task_status(client, task_id) == status,
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
        lambda: _task_status(client, task_id) in ("done", "failed"),
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
