# D9 依赖注入：获取 orchestrator/registry 实例
from fastapi import HTTPException, Request

from core.orchestrator import ScanOrchestrator
from core.task_registry import TaskRegistry


def get_registry(request: Request) -> TaskRegistry:
    """获取 TaskRegistry 实例"""
    registry = getattr(request.app.state, "registry", None)
    if registry is None:
        raise HTTPException(status_code=503, detail="TaskRegistry 未初始化")
    return registry


def get_orchestrator(request: Request) -> ScanOrchestrator:
    """获取 ScanOrchestrator 实例"""
    orch = getattr(request.app.state, "orchestrator", None)
    if orch is None:
        raise HTTPException(status_code=503, detail="ScanOrchestrator 未初始化")
    return orch
