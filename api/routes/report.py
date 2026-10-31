# D9 报告路由：查询/下载报告
import os
import re
import time
from dataclasses import fields as dataclass_fields

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from api.deps import get_registry, get_storage
from api.models.schemas import ReportMetadataDTO
from common.models import ScanResult
from core.report import ReportBuilder
from core.storage import Storage
from core.task_registry import TaskRegistry

router = APIRouter(tags=["报告"])

# 报告格式 → 文件扩展名映射
_FORMAT_EXT = {
    "html": ".html",
    "json": ".json",
    "csv": ".csv",
    "pdf": ".pdf",
    "docx": ".docx",
    "xlsx": ".xlsx",
}


def _find_report_file(task_id: str, fmt: str, registry: TaskRegistry = None, dir_listing: list = None) -> str:
    """查找任务报告文件路径

    查找顺序：
        1. 从 registry 的 task_dict.report_paths 中匹配扩展名（最准确，且文件名须含 task_id）
        2. reports/api/{task_id}.{ext}（按 task_id 命名）
        3. 扫描 reports/api/ 目录下文件名含 task_id（后接 / 或边界）且扩展名匹配的文件

    不再回退到共享的 report.{ext}：该文件属于“最后一次扫描”，无法判断归属，
    回退会把最新报告当成任意历史任务的报告（测评 P0-2）。步骤 3 要求 task_id
    后紧跟路径边界，避免短 id（如 "1"）误命中其他任务的文件（如 "task10_report.html"）。

    Args:
        dir_listing: 可选的 reports/api 目录清单。多格式批量查询时由调用方
            一次列目录后复用，避免每个格式重复 listdir（O(formats × 目录项)）。
    """
    # 防路径穿越：task_id 仅允许字母/数字/下划线/连字符（系统生成规则为 uuid hex 子串），
    # 含路径分隔符或 .. 的值直接视为无报告，避免拼出 reports/api 之外的任意文件路径
    if not task_id or not re.fullmatch(r"[A-Za-z0-9_-]+", task_id):
        return ""

    # 未登记格式按 .<fmt> 兜底扩展名（未来新增格式无需改映射表）
    ext = _FORMAT_EXT.get(fmt, f".{fmt}")

    # 1. 从 task_dict.report_paths 匹配（API 模式生成的实际路径）
    if registry:
        record = registry.get(task_id)
        if record and record.task_dict:
            for path in record.task_dict.get("report_paths", []):
                # 归属校验：旧版本把共享的 reports/api/report.html 写进每个任务，
                # 只按扩展名匹配会把最新报告当成任意历史任务的报告（测评 P0-2）。
                # 任务 id 后必须是路径边界，避免 "abc" 命中 "abc123.html"。
                if not re.search(re.escape(task_id) + r"(?:$|[._-])", os.path.basename(path)):
                    continue
                if path.endswith(ext):
                    if os.path.exists(path):
                        return path
                    # 尝试相对路径（CWD 可能不同）
                    if os.path.exists(os.path.basename(path)):
                        return os.path.basename(path)

    # 2. reports/api/{task_id}.{ext}
    report_dir = os.path.join("reports", "api")
    filepath = os.path.join(report_dir, f"{task_id}{ext}")
    if os.path.exists(filepath):
        return filepath

    # 3. 扫描目录下文件名含 task_id（按路径边界匹配，防止 "1" 命中 "task10_report.html"）
    # 不再回退到共享的 report.{ext}：无法判断它属于哪个任务，宁可 404 也不串号
    if dir_listing is not None:
        listing = dir_listing
    elif os.path.isdir(report_dir):
        listing = os.listdir(report_dir)
    else:
        listing = []
    pattern = re.compile(re.escape(task_id) + r"(?:$|[._-])")
    for f in listing:
        if f.endswith(ext) and pattern.search(f):
            return os.path.join(report_dir, f)
    return ""


def _resolve_report(task_id: str, fmt: str, registry: TaskRegistry) -> str:
    """校验任务存在后定位报告文件（download 系列处理器共用）

    与 get_report_metadata 一致：任务不存在直接 404，避免对未知 task_id
    执行无谓的目录扫描，也避免泄露无关文件。
    """
    if registry.get(task_id) is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
    return _find_report_file(task_id, fmt, registry)


@router.get("/report/{task_id}", response_model=ReportMetadataDTO, summary="查询报告元数据")
def get_report_metadata(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """查询任务报告的元数据（可用格式 + 文件路径）

    同步 def：_find_report_file 为阻塞式文件系统 IO，FastAPI 会在线程池执行，
    避免阻塞事件循环（_FORMAT_EXT 六个格式逐个探测，含 listdir）。
    """
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")

    available_formats = []
    paths = []
    # 目录只列一次，六个格式复用（_find_report_file 每次调用不再重复 listdir）
    report_dir = os.path.join("reports", "api")
    dir_listing = os.listdir(report_dir) if os.path.isdir(report_dir) else None
    for fmt in _FORMAT_EXT:
        filepath = _find_report_file(task_id, fmt, registry, dir_listing=dir_listing)
        if filepath:
            available_formats.append(fmt)
            paths.append(filepath)

    return ReportMetadataDTO(
        task_id=task_id,
        formats=available_formats,
        paths=paths,
    )


@router.get("/report/{task_id}/html", summary="下载 HTML 报告")
def download_html_report(
    task_id: str,
    inline: bool = Query(False, description="true=浏览器内联预览；false=作为附件下载"),
    registry: TaskRegistry = Depends(get_registry),
):
    """下载/预览 HTML 格式报告"""
    filepath = _resolve_report(task_id, "html", registry)
    if not filepath:
        raise HTTPException(status_code=404, detail="HTML 报告未生成")
    return FileResponse(
        filepath,
        media_type="text/html",
        filename=f"{task_id}_report.html",
        content_disposition_type="inline" if inline else "attachment",
    )


@router.get("/report/{task_id}/json", summary="下载 JSON 报告")
def download_json_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 JSON 格式报告"""
    filepath = _resolve_report(task_id, "json", registry)
    if not filepath:
        raise HTTPException(status_code=404, detail="JSON 报告未生成")
    return FileResponse(filepath, media_type="application/json", filename=f"{task_id}_report.json")


@router.get("/report/{task_id}/csv", summary="下载 CSV 报告")
def download_csv_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 CSV 格式报告"""
    filepath = _resolve_report(task_id, "csv", registry)
    if not filepath:
        raise HTTPException(status_code=404, detail="CSV 报告未生成")
    return FileResponse(filepath, media_type="text/csv", filename=f"{task_id}_report.csv")


@router.get("/report/{task_id}/pdf", summary="下载 PDF 报告")
def download_pdf_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 PDF 格式报告（D8 依赖）"""
    filepath = _resolve_report(task_id, "pdf", registry)
    if not filepath:
        # 501 区别于 404：表示该格式当前不可用（依赖未安装），而非任务不存在
        raise HTTPException(status_code=501, detail="PDF 报告未生成（需安装 reportlab）")
    return FileResponse(filepath, media_type="application/pdf", filename=f"{task_id}_report.pdf")


@router.get("/report/{task_id}/docx", summary="下载 Word 报告")
def download_docx_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 Word 格式报告（D8 依赖）"""
    filepath = _resolve_report(task_id, "docx", registry)
    if not filepath:
        raise HTTPException(status_code=501, detail="Word 报告未生成（需安装 python-docx）")
    return FileResponse(
        filepath,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=f"{task_id}_report.docx",
    )


@router.get("/report/{task_id}/xlsx", summary="下载 Excel 报告")
def download_xlsx_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 Excel 格式报告（D8 依赖）"""
    filepath = _resolve_report(task_id, "xlsx", registry)
    if not filepath:
        raise HTTPException(status_code=501, detail="Excel 报告未生成（需安装 openpyxl）")
    return FileResponse(
        filepath,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=f"{task_id}_report.xlsx",
    )


def _collect_task_results(record, storage: Storage) -> list:
    """取任务结果明细：内存/恢复事件优先，findings 表兜底

    旧版本任务没有 findings 行（表是 v1.5.3 新增的），但事件表里的 result 事件
    在恢复时已归一化。只查 findings 会让“重建报告”对历史任务必然失败
    （实测 6a9fb7ee：/results 有 32 条，重建却提示没有结果）。
    """
    rows = []
    for event in record.events or []:
        if event.get("type") == "result" and isinstance(event.get("data"), dict):
            rows.append(event["data"])
    if not rows:
        try:
            rows = storage.get_results(record.task_id)
        except Exception:
            rows = []
    return rows


@router.post("/report/{task_id}/rebuild", summary="用持久化结果重建报告")
def rebuild_report(
    task_id: str,
    registry: TaskRegistry = Depends(get_registry),
    storage: Storage = Depends(get_storage),
):
    """从事件/findings 重建该任务的报告（修复历史任务报告被共享文件覆盖的问题）

    旧版本所有任务写同一个 reports/api/report.*，后续扫描会覆盖前者，历史报告
    无法追溯。结果明细已持久化，因此可以按当前任务的 target/summary 重新生成
    `{task_id}_report.{ext}`，避免继续依赖不可归属的旧文件。
    """
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
    rows = _collect_task_results(record, storage)
    if not rows:
        raise HTTPException(status_code=409, detail="该任务没有可重建的结果明细")

    # 只取 ScanResult 的 dataclass 字段：落盘快照含 severity_cn 等展示字段。
    # 旧版本事件没有 kind/name 必填字段（v1.5.3 之前 _on_result 只发 6 个字段），
    # 必须补默认值，否则 ScanResult(**payload) 直接 TypeError → 500。
    allowed = {f.name for f in dataclass_fields(ScanResult)}
    results = []
    for r in rows:
        payload = {k: v for k, v in r.items() if k in allowed}
        payload.setdefault("kind", "")
        payload.setdefault("name", "")
        results.append(ScanResult(**payload))
    td = record.task_dict or {}
    started = td.get("started_at", "")
    if isinstance(started, (int, float)) and started:
        # ReportBuilder 的 summary.started_at 是展示字符串；直接塞 Unix 时间戳
        # 会让重建报告显示 1793290940.86（实测）。
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started))
    summary = {
        "started_at": started,
        "duration": td.get("duration", 0),
        "request_count": td.get("request_count", 0),
        "mode": td.get("mode", "u"),
        "fingerprint": td.get("fingerprint") or {},
        "blocked": {"blocked": False},
        "rebuilt": True,
    }
    builder = ReportBuilder(results=results, target=td.get("target", ""), summary=summary, dedup=True)
    try:
        paths = builder.render_all(os.path.join("reports", "api"), formats=["html", "json", "csv"], stem=task_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"报告重建失败: {e}") from e
    registry.update_task_dict(task_id, {**td, "report_paths": paths})
    return {"task_id": task_id, "paths": paths}
