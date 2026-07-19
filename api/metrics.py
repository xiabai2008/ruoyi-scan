# D16 Prometheus 指标端点
#
# 暴露 /api/system/metrics 端点，返回 Prometheus 格式指标：
#   - ruoyi_scan_tasks_total：任务总数（按状态分）
#   - ruoyi_scan_tasks_active：当前活跃任务数
#   - ruoyi_scan_results_total：扫描结果总数（按状态分）
#   - ruoyi_scan_duration_seconds：扫描耗时（直方图）
#   - ruoyi_scan_uptime_seconds：服务运行时间
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse

from core.task_registry import TaskRegistry
from api.deps import get_registry

router = APIRouter()

# 服务启动时间
import time
_START_TIME = time.time()


@router.get('/system/metrics', summary='Prometheus 指标',
            response_class=PlainTextResponse)
async def prometheus_metrics(request: Request,
                             registry: TaskRegistry = Depends(get_registry)):
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
    uptime = time.time() - _START_TIME
    lines.append(f'# HELP ruoyi_scan_uptime_seconds 服务运行时间')
    lines.append(f'# TYPE ruoyi_scan_uptime_seconds gauge')
    lines.append(f'ruoyi_scan_uptime_seconds {uptime:.1f}')

    # 2. 任务统计（从 registry 获取）
    task_stats = _get_task_stats(registry)
    lines.append(f'# HELP ruoyi_scan_tasks_total 任务总数（按状态分）')
    lines.append(f'# TYPE ruoyi_scan_tasks_total gauge')
    for status, count in task_stats.items():
        lines.append(f'ruoyi_scan_tasks_total{{status="{status}"}} {count}')

    # 3. 活跃任务数
    active_count = task_stats.get('running', 0) + task_stats.get('pending', 0)
    lines.append(f'# HELP ruoyi_scan_tasks_active 当前活跃任务数')
    lines.append(f'# TYPE ruoyi_scan_tasks_active gauge')
    lines.append(f'ruoyi_scan_tasks_active {active_count}')

    # 4. 持久化任务数（如果 storage 可用）
    storage = getattr(request.app.state, 'storage', None)
    if storage:
        storage_count = storage.count_tasks()
        lines.append(f'# HELP ruoyi_scan_storage_tasks 持久化任务数')
        lines.append(f'# TYPE ruoyi_scan_storage_tasks gauge')
        lines.append(f'ruoyi_scan_storage_tasks {storage_count}')

    # 5. 结果统计
    result_stats = _get_result_stats(registry)
    lines.append(f'# HELP ruoyi_scan_results_total 扫描结果总数（按状态分）')
    lines.append(f'# TYPE ruoyi_scan_results_total gauge')
    for status, count in result_stats.items():
        lines.append(f'ruoyi_scan_results_total{{status="{status}"}} {count}')

    return '\n'.join(lines) + '\n'


def _get_task_stats(registry: TaskRegistry) -> dict:
    """从 registry 获取任务统计"""
    stats = {'pending': 0, 'running': 0, 'done': 0, 'failed': 0}
    try:
        with registry._lock:
            for record in registry._tasks.values():
                status = record.status
                if status in stats:
                    stats[status] += 1
                else:
                    stats[status] = 1
    except Exception:
        pass
    return stats


def _get_result_stats(registry: TaskRegistry) -> dict:
    """从 registry 获取结果统计"""
    stats = {'confirmed': 0, 'safe': 0, 'unknown': 0}
    try:
        with registry._lock:
            for record in registry._tasks.values():
                td = record.task_dict or {}
                confirmed = td.get('confirmed_count', 0)
                total = td.get('result_count', 0)
                stats['confirmed'] += confirmed
                stats['unknown'] += max(0, total - confirmed)
    except Exception:
        pass
    return stats
