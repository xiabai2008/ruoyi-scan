# G5：合规报告模板引擎（安服交付物定制）
#
# 场景：安服公司用自己的渗透测试报告 docx 模板（公司抬头/Logo/排版/整改声明），
# 扫描结束后一键把结果填进模板出交付物——国内安服最高频的交付痛点。
#
# 模板占位符（docx 中直接书写，双花括号）：
#   标量：
#     {{target}}  {{scan_date}}  {{mode}}
#     {{total}} {{confirmed}} {{unknown}} {{safe}}
#     {{high}} {{medium}} {{low}}
#     {{duration}} {{request_count}}
#   块占位符（在该段落位置插入内容，占位符段落本身被移除）：
#     {{vuln_table}}    漏洞明细表（名称/等级/URL/修复建议，CONFIRMED 结果）
#     {{vuln_details}}  逐漏洞详述（标题 + 证据 + 修复建议）
#
# 用法：
#   python main.py -u http://target/ --report ./reports --report-template ./公司模板.docx
#
# 设计原则：
#   - 占位符替换尽量保留 run 级格式；跨 run 拆断的占位符整段合并替换（占位符段落
#     通常为纯占位符，格式损失可接受）
#   - 块占位符用低层 XML 移动（addnext），不依赖文档尾部追加
#   - 模板缺占位符即不输出对应内容（零侵入，模板不合规也不报错）
import datetime
import os
import re
from typing import Any, Dict, List, Optional

from common.logger import get_logger

logger = get_logger(__name__)

# 占位符正则：{{key}}
_PLACEHOLDER = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")

# 块占位符（特殊处理，不出现在标量替换表）
_BLOCK_KEYS = {"vuln_table", "vuln_details"}


def build_scalar_values(builder: Any) -> Dict[str, str]:
    """从 ReportBuilder 提取标量占位符值（全部字符串化）"""
    dist = builder.risk_distribution()
    summary = getattr(builder, "summary", None) or {}
    results = builder._effective_results()
    status_count: Dict[str, int] = {"CONFIRMED": 0, "UNKNOWN": 0, "SAFE": 0}
    for r in results:
        status = getattr(r, "status", "")
        if status in status_count:
            status_count[status] += 1
    return {
        "target": str(getattr(builder, "target", "") or ""),
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "mode": str(summary.get("mode", "") or ""),
        "duration": "%.2f" % float(summary.get("duration", 0) or 0),
        "request_count": str(summary.get("request_count", 0) or 0),
        "total": str(dist.get("total", 0)),
        "confirmed": str(status_count["CONFIRMED"]),
        "unknown": str(status_count["UNKNOWN"]),
        "safe": str(status_count["SAFE"]),
        "high": str(dist.get("high", 0)),
        "medium": str(dist.get("medium", 0)),
        "low": str(dist.get("low", 0)),
    }


def _replace_in_paragraph(paragraph, scalars: Dict[str, str]) -> bool:
    """段落内替换标量占位符（先逐 run 保格式替换，跨 run 拆断则整段合并）

    Returns:
        True 表示段落文本仍含未替换的占位符（调用方用于块占位符判定）
    """

    def _sub(text: str) -> str:
        return _PLACEHOLDER.sub(lambda m: scalars.get(m.group(1), m.group(0)), text)

    for run in paragraph.runs:
        new_text = _sub(run.text)
        if new_text != run.text:
            run.text = new_text

    # 跨 run 拆断的占位符：合并整段文本到首 run 后统一替换（格式损失可接受）
    if _PLACEHOLDER.search(paragraph.text):
        full_text = paragraph.text
        if "{{" in full_text:
            merged = _sub(full_text)
            runs = paragraph.runs
            if runs:
                runs[0].text = merged
                for run in runs[1:]:
                    run.text = ""

    # 返回替换后段落是否仍残留未解析占位符（供 fail_on_unresolved 校验）
    return "{{" in paragraph.text


def _style_table(table, header: List[str], rows: List[List[str]]) -> None:
    """填充表格并尽量套用网格样式（模板无 Table Grid 样式时静默降级）"""
    try:
        table.style = "Table Grid"
    except Exception:
        logger.debug("模板缺少 Table Grid 样式，表格以无边框渲染", exc_info=True)
    for j, text in enumerate(header):
        cell = table.rows[0].cells[j]
        cell.text = text
    for row in rows:
        cells = table.add_row().cells
        for j, text in enumerate(row):
            cells[j].text = text


def _fill_block_vuln_table(paragraph, doc, builder: Any) -> None:
    """{{vuln_table}}：在占位符段落位置插入漏洞明细表"""
    confirmed = builder.confirmed_results()
    header = ["漏洞名称", "危害等级", "URL", "修复建议"]
    rows = [
        [
            str(r.name),
            str(r.severity),
            str(r.url or ""),
            str(r.fix or "")[:120],
        ]
        for r in confirmed
    ]
    if not rows:
        rows = [["（本次扫描未发现已确认漏洞）", "-", "-", "-"]]
    # 尾部创建表格后移动 XML 到占位符段落后（python-docx 不支持定点插入，低层 XML 完成）
    table = doc.add_table(rows=1, cols=len(header))
    _style_table(table, header, rows)
    paragraph._p.addnext(table._tbl)
    # 清空占位符文本（段落保留作为表格后间距）
    for run in paragraph.runs:
        run.text = ""


def _fill_block_vuln_details(paragraph, doc, builder: Any) -> None:
    """{{vuln_details}}：在占位符段落位置逐漏洞插入详述（标题/证据/修复）"""
    confirmed = builder.confirmed_results()
    blocks = []
    for i, r in enumerate(confirmed, start=1):
        blocks.append(f"{i}. {r.name}（{r.severity}）")
        if r.url:
            blocks.append(f"URL：{r.url}")
        if r.evidence:
            blocks.append(f"证据：{str(r.evidence)[:500]}")
        if r.fix:
            blocks.append(f"修复建议：{r.fix}")
        blocks.append("")

    if not blocks:
        blocks = ["（本次扫描未发现已确认漏洞）"]

    # 从尾部构造段落链后整体插到占位符前（保持顺序：addprevious 逆序插入）
    anchor = paragraph._p
    for text in reversed(blocks):
        new_p = anchor.makeelement("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p", {})
        anchor.addprevious(new_p)
        # 用 python-docx 的 Paragraph 包装写入文本（继承文档默认样式）
        from docx.text.paragraph import Paragraph

        Paragraph(new_p, paragraph._parent).text = text
    for run in paragraph.runs:
        run.text = ""


def render_docx_template(
    template_path: str, builder: Any, out_path: str, fail_on_unresolved: bool = False
) -> Optional[str]:
    """用 docx 模板渲染合规报告

    Args:
        template_path: 模板 docx 路径（内含 {{占位符}}）
        builder: ReportBuilder 实例（结果来源）
        out_path: 输出 docx 路径
        fail_on_unresolved: True 时存在未识别占位符则抛异常（模板校验模式）

    Returns:
        out_path；模板加载失败返回 None（调用方降级默认报告）
    """
    try:
        from docx import Document
    except ImportError:
        logger.warning("python-docx 未安装，模板报告跳过（pip install python-docx）")
        return None
    if not os.path.isfile(template_path):
        logger.warning("报告模板不存在: %s（跳过模板渲染）", template_path)
        return None

    doc = Document(template_path)
    scalars = build_scalar_values(builder)

    unresolved: List[str] = []

    def _process_paragraphs(paragraphs):
        for paragraph in paragraphs:
            text = paragraph.text
            if "{{" not in text:
                continue
            # 块占位符优先（占位符段通常为纯 {{key}}）
            m = _PLACEHOLDER.search(text)
            if m and m.group(1) in _BLOCK_KEYS:
                key = m.group(1)
                if key == "vuln_table":
                    _fill_block_vuln_table(paragraph, doc, builder)
                elif key == "vuln_details":
                    _fill_block_vuln_details(paragraph, doc, builder)
                continue
            still = _replace_in_paragraph(paragraph, scalars)
            if still and fail_on_unresolved:
                for m2 in _PLACEHOLDER.finditer(text):
                    unresolved.append(m2.group(1))

    _process_paragraphs(doc.paragraphs)
    # 表格单元格（安服模板常有占位符表格）
    for t in doc.tables:
        for row in t.rows:
            for cell in row.cells:
                _process_paragraphs(cell.paragraphs)

    if unresolved and fail_on_unresolved:
        raise ValueError("模板存在未识别占位符: %s" % ", ".join(sorted(set(unresolved))))

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    doc.save(out_path)
    logger.info("模板报告已生成: %s", out_path)
    return out_path
