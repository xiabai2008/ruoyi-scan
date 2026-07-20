# PDF 报告生成（reportlab，零系统依赖）— D8.2
#
# 使用 Platypus 布局引擎 + STSong-Light CJK 字体（reportlab 内置，无需系统字体），
# 生成 A4 纵向 PDF：封面 → 漏洞详情表 → 其他结果 → 修复建议汇总。
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.models import (
    SEVERITY_CN,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    STATUS_CONFIRMED,
    STATUS_SAFE,
    STATUS_UNKNOWN,
)

# 注册 CJK 字体（reportlab 内置 STSong-Light，零系统依赖）
_FONT_REGISTERED = False
_FONT_NAME = "STSong-Light"


def _ensure_font():
    """注册中文字体（仅首次调用时注册）"""
    global _FONT_REGISTERED
    if not _FONT_REGISTERED:
        pdfmetrics.registerFont(UnicodeCIDFont(_FONT_NAME))
        _FONT_REGISTERED = True


# 严重度颜色映射
_SEV_COLOR = {
    SEVERITY_HIGH: colors.HexColor("#cf222e"),
    SEVERITY_MEDIUM: colors.HexColor("#9a6700"),
    SEVERITY_LOW: colors.HexColor("#1a7f37"),
}

# 状态中文名
_STATUS_CN = {
    STATUS_CONFIRMED: "已确认",
    STATUS_SAFE: "安全",
    STATUS_UNKNOWN: "未知",
}


def render_pdf(builder, out_path):
    """渲染 PDF 报告到 out_path

    Args:
        builder: ReportBuilder 实例（使用 _effective_results() 获取去重后结果）
        out_path: 输出文件路径
    Returns:
        out_path
    """
    _ensure_font()
    F = _FONT_NAME

    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title="若依综合漏洞检测报告",
    )

    # === 样式定义 ===
    title_style = ParagraphStyle("ChTitle", fontName=F, fontSize=24, alignment=1, spaceAfter=10, leading=30)
    subtitle_style = ParagraphStyle(
        "ChSubtitle",
        fontName=F,
        fontSize=12,
        alignment=1,
        textColor=colors.HexColor("#656d76"),
        spaceAfter=6,
        leading=18,
    )
    h2_style = ParagraphStyle(
        "ChH2", fontName=F, fontSize=16, spaceBefore=20, spaceAfter=10, leading=22, textColor=colors.HexColor("#1f2328")
    )
    body_style = ParagraphStyle("ChBody", fontName=F, fontSize=10, leading=16, textColor=colors.HexColor("#1f2328"))
    cell_style = ParagraphStyle("ChCell", fontName=F, fontSize=8, leading=12, textColor=colors.HexColor("#1f2328"))
    cell_header = ParagraphStyle("ChCellH", fontName=F, fontSize=9, leading=13, textColor=colors.white, alignment=1)
    fix_title_style = ParagraphStyle("FixTitle", fontName=F, fontSize=11, spaceBefore=10, leading=16)

    story = []

    # === 封面 ===
    story.append(Spacer(1, 60 * mm))
    story.append(Paragraph("若依综合漏洞检测报告", title_style))
    story.append(Spacer(1, 10 * mm))

    target = builder.target or "未指定"
    scan_time = builder.summary.get("started_at", "")
    if isinstance(scan_time, (int, float)) and scan_time:
        scan_time = datetime.fromtimestamp(scan_time).strftime("%Y-%m-%d %H:%M:%S")
    if not scan_time:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story.append(Paragraph(f"扫描目标：{target}", subtitle_style))
    story.append(Paragraph(f"扫描时间：{scan_time}", subtitle_style))
    story.append(Paragraph(f"报告生成：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    story.append(Spacer(1, 15 * mm))

    # 风险分布
    dist = builder.risk_distribution()
    story.append(
        Paragraph(
            f"风险分布：高危 {dist['high']} | 中危 {dist['medium']} | 低危 {dist['low']} | 共计 {dist['total']}",
            subtitle_style,
        )
    )

    # 去重统计
    dr = builder.dedup_report()
    if dr and dr.merged_groups > 0:
        story.append(
            Paragraph(
                f"去重统计：原始 {dr.original_count} 条 → 聚合后 {dr.aggregated_count} 条（{dr.merged_groups} 组合并）",
                subtitle_style,
            )
        )

    story.append(PageBreak())

    # === 漏洞详情 ===
    story.append(Paragraph("漏洞详情", h2_style))

    confirmed = builder.confirmed_results()
    if not confirmed:
        story.append(Paragraph("未发现确认漏洞。", body_style))
    else:
        header = [
            Paragraph("漏洞名称", cell_header),
            Paragraph("严重度", cell_header),
            Paragraph("URL", cell_header),
            Paragraph("证据", cell_header),
            Paragraph("修复建议", cell_header),
        ]
        data = [header]
        for r in confirmed:
            sev_cn = SEVERITY_CN.get(r.severity, r.severity)
            hit_info = ""
            if hasattr(r, "hit_count") and r.hit_count > 1:
                hit_info = f" (x{r.hit_count})"
            data.append(
                [
                    Paragraph(r.name + hit_info, cell_style),
                    Paragraph(sev_cn, cell_style),
                    Paragraph(r.url or "", cell_style),
                    Paragraph(r.evidence or "", cell_style),
                    Paragraph(r.fix or "", cell_style),
                ]
            )

        col_widths = [35 * mm, 18 * mm, 45 * mm, 40 * mm, 32 * mm]
        table = Table(data, colWidths=col_widths, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0969da")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, -1), F),
                    ("FONTSIZE", (0, 0), (-1, 0), 9),
                    ("FONTSIZE", (0, 1), (-1, -1), 8),
                    ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(table)

    # === 其他结果（非 CONFIRMED）===
    all_results = builder._effective_results()
    others = [r for r in all_results if r.status != STATUS_CONFIRMED]
    if others:
        story.append(PageBreak())
        story.append(Paragraph("其他结果（未确认/安全）", h2_style))
        other_data = [
            [
                Paragraph("名称", cell_header),
                Paragraph("状态", cell_header),
                Paragraph("URL", cell_header),
                Paragraph("证据", cell_header),
            ]
        ]
        for r in others:
            other_data.append(
                [
                    Paragraph(r.name, cell_style),
                    Paragraph(_STATUS_CN.get(r.status, r.status), cell_style),
                    Paragraph(r.url or "", cell_style),
                    Paragraph(r.evidence or "", cell_style),
                ]
            )
        other_table = Table(other_data, colWidths=[40 * mm, 20 * mm, 60 * mm, 50 * mm], repeatRows=1)
        other_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#656d76")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, -1), F),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(other_table)

    # === 修复建议汇总 ===
    if confirmed:
        story.append(PageBreak())
        story.append(Paragraph("修复建议汇总", h2_style))
        for i, r in enumerate(confirmed, 1):
            sev_cn = SEVERITY_CN.get(r.severity, r.severity)
            title_color = _SEV_COLOR.get(r.severity, colors.black)
            story.append(
                Paragraph(
                    f"{i}. {r.name}（{sev_cn}）",
                    ParagraphStyle("FixItem", parent=fix_title_style, textColor=title_color),
                )
            )
            story.append(Paragraph(f"URL：{r.url}", body_style))
            story.append(Paragraph(f"修复：{r.fix or '暂无建议'}", body_style))

    doc.build(story)
    return out_path
