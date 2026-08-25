# D9 扫描任务路由：提交/查询/取消/结果
import os

from fastapi import APIRouter, Depends, HTTPException, Request

from api.deps import get_orchestrator, get_registry
from api.models.schemas import ScanCreateRequest, ScanCreateResponse, ScanResultDTO, ScanTaskDTO
from core.orchestrator import ScanOrchestrator, ScanRequest
from core.task_registry import TaskRegistry

router = APIRouter(tags=["扫描任务"])

# E9：定时扫描任务路由（管理端）
schedule_router = APIRouter(tags=["定时扫描"])


@schedule_router.get("/schedule", summary="列出定时扫描任务")
async def list_schedules(request: Request):
    """列出全部定时扫描任务（E9）"""
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        raise HTTPException(status_code=503, detail="调度器未初始化")
    return scheduler.list_jobs()


@schedule_router.post("/schedule", summary="创建定时扫描任务")
async def create_schedule(request: Request, body: dict):
    """创建定时扫描任务（E9）

    body: {"cron": "*/5 * * * *" 或 "every:300", "target": "http://...", "mode": "u"}
    """
    from lib.scheduler import parse_schedule_expr

    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        raise HTTPException(status_code=503, detail="调度器未初始化")
    cron = body.get("cron", "")
    target = body.get("target", "")
    mode = body.get("mode", "u")
    if not cron or not target:
        raise HTTPException(status_code=400, detail="cron 与 target 必填")
    try:
        parse_schedule_expr(cron)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    job_id = scheduler.add_job(cron, target, mode=mode, payload=body.get("payload") or {})
    return {"job_id": job_id, "cron": cron, "target": target, "status": "scheduled"}


@schedule_router.delete("/schedule/{job_id}", summary="删除定时扫描任务")
async def delete_schedule(job_id: str, request: Request):
    """删除定时扫描任务（E9）"""
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        raise HTTPException(status_code=503, detail="调度器未初始化")
    scheduler.remove_job(job_id)
    return {"job_id": job_id, "status": "removed"}


@router.post("/scan", response_model=ScanCreateResponse, summary="提交扫描任务")
async def create_scan(
    req: ScanCreateRequest,
    orch: ScanOrchestrator = Depends(get_orchestrator),
    registry: TaskRegistry = Depends(get_registry),
):
    """提交扫描任务，返回 task_id（非阻塞）"""
    scan_req = ScanRequest(
        target=req.target,
        mode=req.mode,
        cms=req.cms,
        threads=req.threads,
        rate=req.rate,
        proxy=req.proxy,
        timeout=req.timeout,
        report_dir=os.path.join("reports", "api"),  # API 模式固定输出目录
        report_format=req.report_format,
        no_dedup=req.no_dedup,
        pass_level=req.pass_level,
        portscan=req.portscan,
        ports=req.ports,
        bypass_waf=req.bypass_waf,
        plugins=req.plugins,
    )
    task_id = orch.submit(scan_req)
    return ScanCreateResponse(task_id=task_id, status="pending")


@router.get("/scan", response_model=list, summary="列出所有任务")
async def list_scans(registry: TaskRegistry = Depends(get_registry)):
    """列出所有扫描任务"""
    records = registry.list()
    return [r.task_dict for r in records if r.task_dict]


@router.get("/scan/{task_id}", response_model=ScanTaskDTO, summary="查询单个任务状态")
async def get_scan(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """查询单个扫描任务状态"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
    data = record.task_dict or {
        "task_id": task_id,
        "status": record.status,
        "target": "",
        "mode": "u",
    }
    # 只取 DTO 声明的字段再构造，防止 task_dict 中的额外键导致校验失败
    return ScanTaskDTO(**{k: v for k, v in data.items() if k in ScanTaskDTO.model_fields})


@router.delete("/scan/{task_id}", summary="取消任务")
async def cancel_scan(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """取消扫描任务（标记为 cancelled，实际执行中的任务无法立即中断）"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
    # 软取消：只置内存状态标志并广播事件，执行中的插件线程在下一轮检查状态时自行退出
    record.status = "cancelled"
    registry.notify(task_id, "status", {"status": "cancelled", "task_id": task_id})
    return {"task_id": task_id, "status": "cancelled"}


@router.get("/scan/{task_id}/results", response_model=list, summary="获取任务结果列表")
async def get_scan_results(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """获取扫描任务的结果列表"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
    # 从历史事件中提取 result 事件
    results = []
    for event in record.events:
        if event.get("type") == "result":
            data = event.get("data", {})
            results.append(
                ScanResultDTO(
                    name=data.get("name", ""),
                    status=data.get("status", ""),
                    severity=data.get("severity", "low"),
                    url=data.get("url", ""),
                    evidence=data.get("evidence", ""),
                    extra=data.get("extra", {}),
                )
            )
    return results
