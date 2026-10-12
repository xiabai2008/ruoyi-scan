# D9 报告路由：查询/下载报告
import os
import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from api.deps import get_registry
from api.models.schemas import ReportMetadataDTO
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
        1. 从 registry 的 task_dict.report_paths 中匹配扩展名（最准确）
        2. reports/api/{task_id}.{ext}（按 task_id 命名）
        3. reports/api/report.{ext}（ReportBuilder 默认命名，仅当任务在 registry 中存在）
        4. 扫描 reports/api/ 目录下文件名含 task_id（后接 / 或边界）且扩展名匹配的文件

    注意：步骤 3 的 report.{ext} 回退仅在任务存在于 registry 时生效，
    避免对不存在的 task_id 误返回已有报告文件；步骤 4 要求 task_id 后
    紧跟路径边界，避免短 id（如 "1"）误命中其他任务的文件（如 "task10_report.html"）。

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

    # 检查任务是否在 registry 中存在
    task_exists = False
    if registry:
        record = registry.get(task_id)
        task_exists = record is not None
        # 1. 从 task_dict.report_paths 匹配（API 模式生成的实际路径）
        if record and record.task_dict:
            for path in record.task_dict.get("report_paths", []):
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

    # 3. reports/api/report.{ext}（ReportBuilder 默认命名，仅当任务存在）
    if task_exists:
        filepath = os.path.join(report_dir, f"report{ext}")
        if os.path.exists(filepath):
            return filepath

    # 4. 扫描目录下文件名含 task_id（按路径边界匹配，防止 "1" 命中 "task10_report.html"）
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
def download_html_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 HTML 格式报告"""
    filepath = _resolve_report(task_id, "html", registry)
    if not filepath:
        raise HTTPException(status_code=404, detail="HTML 报告未生成")
    return FileResponse(filepath, media_type="text/html", filename=f"{task_id}_report.html")


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
