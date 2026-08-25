# D9 报告路由：查询/下载报告
import os

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


def _find_report_file(task_id: str, fmt: str, registry: TaskRegistry = None) -> str:
    """查找任务报告文件路径

    查找顺序：
        1. 从 registry 的 task_dict.report_paths 中匹配扩展名（最准确）
        2. reports/api/{task_id}.{ext}（按 task_id 命名）
        3. reports/api/report.{ext}（ReportBuilder 默认命名，仅当任务在 registry 中存在）
        4. 扫描 reports/api/ 目录下任何含 task_id 且扩展名匹配的文件

    注意：步骤 3 的 report.{ext} 回退仅在任务存在于 registry 时生效，
    避免对不存在的 task_id 误返回已有报告文件。
    """
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

    # 4. 扫描目录下任何含 task_id 且扩展名匹配的文件
    if os.path.isdir(report_dir):
        for f in os.listdir(report_dir):
            if f.endswith(ext) and task_id in f:
                return os.path.join(report_dir, f)
    return ""


@router.get("/report/{task_id}", response_model=ReportMetadataDTO, summary="查询报告元数据")
async def get_report_metadata(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """查询任务报告的元数据（可用格式 + 文件路径）"""
    record = registry.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")

    available_formats = []
    paths = []
    for fmt, ext in _FORMAT_EXT.items():
        filepath = _find_report_file(task_id, fmt, registry)
        if filepath:
            available_formats.append(fmt)
            paths.append(filepath)

    return ReportMetadataDTO(
        task_id=task_id,
        formats=available_formats,
        paths=paths,
    )


@router.get("/report/{task_id}/html", summary="下载 HTML 报告")
async def download_html_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 HTML 格式报告"""
    filepath = _find_report_file(task_id, "html", registry)
    if not filepath:
        raise HTTPException(status_code=404, detail="HTML 报告未生成")
    return FileResponse(filepath, media_type="text/html", filename=f"{task_id}_report.html")


@router.get("/report/{task_id}/json", summary="下载 JSON 报告")
async def download_json_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 JSON 格式报告"""
    filepath = _find_report_file(task_id, "json", registry)
    if not filepath:
        raise HTTPException(status_code=404, detail="JSON 报告未生成")
    return FileResponse(filepath, media_type="application/json", filename=f"{task_id}_report.json")


@router.get("/report/{task_id}/csv", summary="下载 CSV 报告")
async def download_csv_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 CSV 格式报告"""
    filepath = _find_report_file(task_id, "csv", registry)
    if not filepath:
        raise HTTPException(status_code=404, detail="CSV 报告未生成")
    return FileResponse(filepath, media_type="text/csv", filename=f"{task_id}_report.csv")


@router.get("/report/{task_id}/pdf", summary="下载 PDF 报告")
async def download_pdf_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 PDF 格式报告（D8 依赖）"""
    filepath = _find_report_file(task_id, "pdf", registry)
    if not filepath:
        # 501 区别于 404：表示该格式当前不可用（依赖未安装），而非任务不存在
        raise HTTPException(status_code=501, detail="PDF 报告未生成（需安装 reportlab）")
    return FileResponse(filepath, media_type="application/pdf", filename=f"{task_id}_report.pdf")


@router.get("/report/{task_id}/docx", summary="下载 Word 报告")
async def download_docx_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 Word 格式报告（D8 依赖）"""
    filepath = _find_report_file(task_id, "docx", registry)
    if not filepath:
        raise HTTPException(status_code=501, detail="Word 报告未生成（需安装 python-docx）")
    return FileResponse(
        filepath,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=f"{task_id}_report.docx",
    )


@router.get("/report/{task_id}/xlsx", summary="下载 Excel 报告")
async def download_xlsx_report(task_id: str, registry: TaskRegistry = Depends(get_registry)):
    """下载 Excel 格式报告（D8 依赖）"""
    filepath = _find_report_file(task_id, "xlsx", registry)
    if not filepath:
        raise HTTPException(status_code=501, detail="Excel 报告未生成（需安装 openpyxl）")
    return FileResponse(
        filepath,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=f"{task_id}_report.xlsx",
    )
