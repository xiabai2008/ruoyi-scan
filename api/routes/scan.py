# D9 扫描任务路由：提交/查询/取消/结果
import os

from fastapi import APIRouter, Depends, HTTPException, Request

from api.deps import get_orchestrator, get_registry, get_storage
from api.models.schemas import ScanCreateRequest, ScanCreateResponse, ScanResultDTO, ScanTaskDTO
from core.orchestrator import ScanOrchestrator, ScanRequest
from core.storage import Storage
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
        job_id = scheduler.add_job(cron, target, mode=mode, payload=body.get("payload") or {})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    job = next((j for j in scheduler.list_jobs() if j["job_id"] == job_id), {})
    return {
        "job_id": job_id,
        "cron": cron,
        "target": target,
        "status": "scheduled",
        # 降级/警告显式回传，前端必须提示用户“cron 实际按每 5 分钟执行”
        "degraded": bool(job.get("degraded")),
        "effective_cron": job.get("effective_cron", cron),
        "warning": job.get("warning", ""),
    }


def _delete_schedule_impl(job_id: str, request: Request):
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        raise HTTPException(status_code=503, detail="调度器未初始化")
    removed = scheduler.remove_job(job_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"定时任务不存在: {job_id}")
    return {"job_id": job_id, "status": "removed"}


@schedule_router.delete("/schedule/{job_id:path}", summary="删除定时扫描任务")
async def delete_schedule(job_id: str, request: Request):
    """删除定时扫描任务（支持历史 id 中的 `/`、`*`）

    `{job_id:path}` 是为了兼容旧版本生成的 `job_*/30_...`：普通路径参数遇到
    `/` 会路由不匹配并返回 405，默认预设“每 30 分钟”的调度因此删不掉。
    """
    return _delete_schedule_impl(job_id, request)


@schedule_router.delete("/schedule", summary="删除定时扫描任务（查询参数）")
async def delete_schedule_query(job_id: str, request: Request):
    """删除定时扫描任务（前端统一走查询参数，避免 `%2F` 解码差异）"""
    return _delete_schedule_impl(job_id, request)


@schedule_router.post("/schedule/resume", summary="恢复已暂停的定时任务")
async def resume_schedule(request: Request, body: dict):
    """恢复连续失败自动暂停的任务"""
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        raise HTTPException(status_code=503, detail="调度器未初始化")
    job_id = body.get("job_id", "")
    if not job_id:
        raise HTTPException(status_code=400, detail="job_id 必填")
    if not scheduler.resume_job(job_id):
        raise HTTPException(status_code=404, detail=f"定时任务不存在: {job_id}")
    return {"job_id": job_id, "status": "resumed"}


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
        adversarial_transport=getattr(req, "adversarial_transport", False),
        plugins=req.plugins,
    )
    task_id = orch.submit(scan_req)
    return ScanCreateResponse(task_id=task_id, status="pending")


@router.get("/scan", response_model=list, summary="列出所有任务")
async def list_scans(registry: TaskRegistry = Depends(get_registry)):
    """列出所有扫描任务"""
    records = registry.list()
    # 用 is not None 而非真值判断：register 默认 task_dict={}，空快照也是有效任务。
    # status 必须以 registry 的 record.status 为准：取消路径只改 record.status，
    # 直接返回 task_dict 会让已取消任务继续显示 running（测评 P1-9）。
    out = []
    for r in records:
        if r.task_dict is None:
            continue
        data = dict(r.task_dict)
        data["status"] = r.status
        if not data.get("task_id"):
            data["task_id"] = r.task_id
        out.append(data)
    return out


@router.get("/scan/{task_id}", response_model=ScanTaskDTO, summary="查询单个任务状态")
async def get_scan(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """查询单个扫描任务状态"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
    data = dict(record.task_dict or {})
    # status 以 registry 维护的 record.status 为准：cancel_scan 只更新 record.status，
    # 不更新 task_dict，直接用 task_dict['status'] 会返回取消前的旧状态
    data["status"] = record.status
    if not data.get("task_id"):
        data["task_id"] = task_id
    if "target" not in data:
        data["target"] = ""
    if "mode" not in data:
        data["mode"] = "u"
    # 只取 DTO 声明的字段再构造，防止 task_dict 中的额外键导致校验失败
    return ScanTaskDTO(**{k: v for k, v in data.items() if k in ScanTaskDTO.model_fields})


@router.delete("/scan/{task_id}", summary="取消任务")
async def cancel_scan(
    task_id: str,
    registry: TaskRegistry = Depends(get_registry),
    orch: ScanOrchestrator = Depends(get_orchestrator),
):
    """取消扫描任务（协作式：立即置 cancelled，执行线程在插件边界退出）"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
    # 已是终态：幂等返回当前状态，避免 UI 重复点击报错
    if record.status in ("done", "failed", "cancelled", "interrupted"):
        return {"task_id": task_id, "status": record.status}
    # 真取消：置 Event + 立即更新并持久化状态。
    # 旧实现只广播 status 事件（软取消），执行线程继续跑满全部插件，
    # 多个取消任务叠加后占满线程池，新任务 0/0 卡死（测评 P1-9）。
    if not orch.cancel(task_id):
        # 执行线程可能已结束但状态尚未落定：以 registry 当前状态为准
        return {"task_id": task_id, "status": record.status}
    return {"task_id": task_id, "status": "cancelled"}


@router.get("/scan/{task_id}/results", response_model=list, summary="获取任务结果列表")
async def get_scan_results(
    task_id: str,
    registry: TaskRegistry = Depends(get_registry),
    storage: Storage = Depends(get_storage),
):
    """获取扫描任务的结果列表（实时事件优先，持久化明细兜底）"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
    # 优先从内存事件提取（实时任务/刚完成的任务，事件最完整）
    results = []
    for event in record.events:
        if event.get("type") == "result":
            data = event.get("data", {})
            if isinstance(data, dict):
                results.append(data)
    # 进程重启后事件可能被 500 条上限截断，或任务来自更早版本：读 findings 表
    if not results:
        try:
            results = storage.get_results(task_id)
        except Exception:
            results = []
    # 只取 DTO 声明的字段，兼容旧事件里缺少的新字段
    return [ScanResultDTO(**{k: v for k, v in r.items() if k in ScanResultDTO.model_fields}) for r in results]
