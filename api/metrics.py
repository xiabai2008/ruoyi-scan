# D16 Prometheus 指标端点
#
# 暴露 /api/system/metrics 端点，返回 Prometheus 格式指标：
#   - ruoyi_scan_tasks_total：任务总数（按状态分）
#   - ruoyi_scan_tasks_active：当前活跃任务数
#   - ruoyi_scan_results_total：扫描结果总数（按状态分）
#   - ruoyi_scan_storage_tasks：持久化任务数
#   - ruoyi_scan_uptime_seconds：服务运行时间

import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from starlette.concurrency import run_in_threadpool

from api.deps import get_registry
from common.logger import get_logger
from core.task_registry import TaskRegistry

logger = get_logger(__name__)

router = APIRouter()

# 服务启动时间（monotonic：不受 NTP/系统时钟调整影响，保证 uptime 单调递增）
_START_TIME = time.monotonic()


@router.get("/system/metrics", summary="Prometheus 指标", response_class=PlainTextResponse)
async def prometheus_metrics(request: Request, registry: TaskRegistry = Depends(get_registry)):
    """返回 Prometheus 格式指标

    指标列表：
        ruoyi_scan_tasks_total{status}    任务总数（按状态分）
        ruoyi_scan_tasks_active           当前活跃任务数
        ruoyi_scan_results_total{status}  扫描结果总数
        ruoyi_scan_uptime_seconds         服务运行时间
        ruoyi_scan_storage_tasks          持久化任务数
    """
    lines = []

    # 1. 服务运行时间
    uptime = time.monotonic() - _START_TIME
    lines.append("# HELP ruoyi_scan_uptime_seconds 服务运行时间")
    lines.append("# TYPE ruoyi_scan_uptime_seconds gauge")
    lines.append(f"ruoyi_scan_uptime_seconds {uptime:.1f}")

    # 2. 任务统计（从 registry 获取）
    task_stats = _get_task_stats(registry)
    lines.append("# HELP ruoyi_scan_tasks_total 任务总数（按状态分）")
    lines.append("# TYPE ruoyi_scan_tasks_total gauge")
    for status, count in task_stats.items():
        lines.append(f'ruoyi_scan_tasks_total{{status="{status}"}} {count}')

    # 活跃任务数 = 运行中 + 排队中，其余状态均视为非活跃
    # 3. 活跃任务数
    active_count = task_stats.get("running", 0) + task_stats.get("pending", 0)
    lines.append("# HELP ruoyi_scan_tasks_active 当前活跃任务数")
    lines.append("# TYPE ruoyi_scan_tasks_active gauge")
    lines.append(f"ruoyi_scan_tasks_active {active_count}")

    # 4. 持久化任务数（如果 storage 可用）
    storage = getattr(request.app.state, "storage", None)
    if storage:
        # 同步 SQLite COUNT：放入线程池执行，避免阻塞事件循环（其余请求并发受限）
        storage_count = await run_in_threadpool(storage.count_tasks)
        lines.append("# HELP ruoyi_scan_storage_tasks 持久化任务数")
        lines.append("# TYPE ruoyi_scan_storage_tasks gauge")
        lines.append(f"ruoyi_scan_storage_tasks {storage_count}")

    # 5. 结果统计
    result_stats = _get_result_stats(registry)
    lines.append("# HELP ruoyi_scan_results_total 扫描结果总数（按状态分）")
    lines.append("# TYPE ruoyi_scan_results_total gauge")
    for status, count in result_stats.items():
        lines.append(f'ruoyi_scan_results_total{{status="{status}"}} {count}')

    return "\n".join(lines) + "\n"


def _get_task_stats(registry: TaskRegistry) -> dict:
    """从 registry 获取任务统计"""
    stats = {"pending": 0, "running": 0, "done": 0, "failed": 0}
    # 直接读 registry 内部任务表（无公开统计接口），加锁避免与写入线程竞争
    try:
        with registry._lock:
            for record in registry._tasks.values():
                status = record.status
                if status in stats:
                    stats[status] += 1
                else:
                    stats[status] = 1
    except Exception:
        # 采集失败不能静默：metrics 会退化为零值，运维需能从日志发现
        logger.warning("任务统计采集异常", exc_info=True)
    return stats


def _get_result_stats(registry: TaskRegistry) -> dict:
    """从 registry 获取结果统计"""
    stats = {"confirmed": 0, "safe": 0, "unknown": 0}
    try:
        with registry._lock:
            for record in registry._tasks.values():
                td = record.task_dict or {}
                # 防御 None/非数值：task_dict 来自反序列化/外部写入，直接参与算术会抛 TypeError
                confirmed = int(td.get("confirmed_count", 0) or 0)
                safe = int(td.get("safe_count", 0) or 0)
                total = int(td.get("result_count", 0) or 0)
                stats["confirmed"] += confirmed
                stats["safe"] += safe
                # unknown 取 total - confirmed - safe 的近似，max(0, ...) 防御数据不一致导致的负数
                stats["unknown"] += max(0, total - confirmed - safe)
    except Exception:
        # 采集失败不能静默：metrics 会退化为零值，运维需能从日志发现
        logger.warning("结果统计采集异常", exc_info=True)
    return stats
