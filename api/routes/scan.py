# D9 扫描任务路由：提交/查询/取消/结果
import os
from fastapi import APIRouter, Depends, HTTPException, Query

from api.deps import get_orchestrator, get_registry
from api.models.schemas import (ScanCreateRequest, ScanCreateResponse,
                                 ScanTaskDTO, ScanResultDTO)
from core.orchestrator import ScanOrchestrator, ScanRequest
from core.task_registry import TaskRegistry

router = APIRouter(tags=['扫描任务'])


@router.post('/scan', response_model=ScanCreateResponse, summary='提交扫描任务')
async def create_scan(req: ScanCreateRequest,
                      orch: ScanOrchestrator = Depends(get_orchestrator),
                      registry: TaskRegistry = Depends(get_registry)):
    """提交扫描任务，返回 task_id（非阻塞）"""
    scan_req = ScanRequest(
        target=req.target,
        mode=req.mode,
        cms=req.cms,
        threads=req.threads,
        rate=req.rate,
        proxy=req.proxy,
        timeout=req.timeout,
        report_dir=os.path.join('reports', 'api'),  # API 模式固定输出目录
        report_format=req.report_format,
        no_dedup=req.no_dedup,
        pass_level=req.pass_level,
        portscan=req.portscan,
        ports=req.ports,
        bypass_waf=req.bypass_waf,
        plugins=req.plugins,
    )
    task_id = orch.submit(scan_req)
    return ScanCreateResponse(task_id=task_id, status='pending')


@router.get('/scan', response_model=list, summary='列出所有任务')
async def list_scans(registry: TaskRegistry = Depends(get_registry)):
    """列出所有扫描任务"""
    records = registry.list()
    return [r.task_dict for r in records if r.task_dict]


@router.get('/scan/{task_id}', response_model=ScanTaskDTO, summary='查询单个任务状态')
async def get_scan(task_id: str,
                   registry: TaskRegistry = Depends(get_registry)):
    """查询单个扫描任务状态"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f'任务不存在: {task_id}')
    data = record.task_dict or {
        'task_id': task_id,
        'status': record.status,
        'target': '',
        'mode': 'u',
    }
    return ScanTaskDTO(**{k: v for k, v in data.items() if k in ScanTaskDTO.model_fields})


@router.delete('/scan/{task_id}', summary='取消任务')
async def cancel_scan(task_id: str,
                      registry: TaskRegistry = Depends(get_registry)):
    """取消扫描任务（标记为 cancelled，实际执行中的任务无法立即中断）"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f'任务不存在: {task_id}')
    record.status = 'cancelled'
    registry.notify(task_id, 'status', {'status': 'cancelled', 'task_id': task_id})
    return {'task_id': task_id, 'status': 'cancelled'}


@router.get('/scan/{task_id}/results', response_model=list, summary='获取任务结果列表')
async def get_scan_results(task_id: str,
                           registry: TaskRegistry = Depends(get_registry)):
    """获取扫描任务的结果列表"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f'任务不存在: {task_id}')
    # 从历史事件中提取 result 事件
    results = []
    for event in record.events:
        if event.get('type') == 'result':
            data = event.get('data', {})
            results.append(ScanResultDTO(
                name=data.get('name', ''),
                status=data.get('status', ''),
                severity=data.get('severity', 'low'),
                url=data.get('url', ''),
                evidence=data.get('evidence', ''),
                extra=data.get('extra', {}),
            ))
    return results
