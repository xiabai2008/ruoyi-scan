# 报告渲染：HTML / JSON / CSV（标准库 json/csv/string 模板，无第三方依赖）
import csv
import datetime
import html as html_module
import io
import json
import os

from common.models import (
    SEVERITY_CN,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    STATUS_CONFIRMED,
    STATUS_SAFE,
    STATUS_UNKNOWN,
)
from config import settings


class ReportBuilder:
    """扫描报告构建器：HTML（风险着色+修复建议）/ JSON（供 CI）/ CSV

    字段：漏洞名称、URL、危害等级（高/中/低）、证据、修复建议
    摘要：目标、耗时、请求数、风险分布、扫描时间
    """

    def __init__(self, results=None, target="", summary=None, dedup=True):
        self.results = results or []
        self.target = target
        # summary: {duration, request_count, started_at, ended_at, mode, fingerprint}
        self.summary = summary or {}
        # D8: 结果去重聚合（渲染前合并同指纹漏洞，可 --no-dedup 关闭）
        self.dedup_enabled = dedup
        self._cached_effective = None  # 缓存去重后结果
        self._cached_dedup_report = None  # 缓存去重统计

    def _effective_results(self):
        """返回渲染用结果：dedup=True 时返回去重聚合后结果，否则返回原始结果

        去重层位于 ReportBuilder 渲染前（不破坏 ScanEngine 契约），
        AggregatedVuln 鸭子类型兼容 ScanResult，现有渲染方法零改动即可接受。
        """
        if not self.dedup_enabled:
            return self.results
        if self._cached_effective is None:
            from core.dedup import aggregate

            self._cached_effective, self._cached_dedup_report = aggregate(self.results)
        return self._cached_effective

    def dedup_report(self):
        """返回去重统计报告（dedup 关闭时返回 None）"""
        if not self.dedup_enabled:
            return None
        if self._cached_dedup_report is None:
            self._effective_results()  # 触发计算
        return self._cached_dedup_report

    def add(self, result):
        self.results.append(result)

    # 风险分布：仅统计 CONFIRMED 漏洞
    def risk_distribution(self):
        dist = {"high": 0, "medium": 0, "low": 0, "total": 0}
        for r in self._effective_results():
            if r.status != STATUS_CONFIRMED:
                continue
            dist["total"] += 1
            if r.severity in dist:
                dist[r.severity] += 1
        return dist

    # 仅保留确认存在的漏洞条目（UNKNOWN/SAFE 不计入漏洞数，见开发方案 §三 Step 4）
    def confirmed_results(self):
        return [r for r in self._effective_results() if r.status == STATUS_CONFIRMED]

    def sorted_results(self, confirmed_first=True):
        """排序结果：CONFIRMED 在前，同状态按危害度 high→medium→low→其他排序"""
        sev_order = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
        status_order = {STATUS_CONFIRMED: 0, STATUS_UNKNOWN: 1, STATUS_SAFE: 2}

        def key(r):
            s = status_order.get(r.status, 99)
            v = sev_order.get(r.severity, 99)
            return (s if confirmed_first else 0, v, r.name)

        return sorted(self._effective_results(), key=key)

    def to_dict(self):
        """整体报告字典（JSON 用）"""
        dist = self.risk_distribution()
        return {
            "target": self.target,
            "scan_time": self.summary.get("started_at", ""),
            "duration_sec": round(self.summary.get("duration", 0), 2),
            "request_count": self.summary.get("request_count", 0),
            "mode": self.summary.get("mode", ""),
            "fingerprint": self.summary.get("fingerprint", {}),
            "risk_distribution": dist,
            "vuln_count": dist["total"],
            "results": [r.to_dict() for r in self._effective_results()],
        }

    def to_json(self):
        """JSON 格式（供 CI 解析，UTF-8，缩进 2）"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def to_csv(self):
        """CSV 格式（漏洞名称/URL/危害等级/状态/CVE/CVSS/合规/证据/修复建议/修复详情/复现命令）"""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "漏洞名称",
                "URL",
                "危害等级",
                "状态",
                "CVE",
                "CVSS",
                "合规映射",
                "证据",
                "修复建议",
                "修复详情",
                "复现命令",
            ]
        )
        for r in self._effective_results():
            # 合规映射拼接为字符串
            compliance_str = ";".join(f"{k}:{v}" for k, v in r.compliance.items()) if r.compliance else ""
            writer.writerow(
                [
                    r.name,
                    r.url,
                    SEVERITY_CN.get(r.severity, r.severity),
                    r.status,
                    r.cve or "",
                    f"{r.cvss_score:.1f}" if r.cvss_score > 0 else "",
                    compliance_str,
                    r.evidence,
                    r.fix,
                    getattr(r, "fix_detail", "") or "",
                    getattr(r, "reproduce", "") or "",
                ]
            )
        return buf.getvalue()

    def _render_risk_donut_svg(self, dist):
        """生成风险分布环形图 SVG（阶段六：纯 SVG，零外部依赖）

        三色弧（高=红/中=黄/低=绿）按占比拼接成环，中心显示总漏洞数。
        总数为 0 时仅显示灰色底环 + 0。颜色与表格 badge 保持一致。

        Args:
            dist: {'high': n, 'medium': n, 'low': n, 'total': n}
        Returns:
            SVG HTML 字符串（含外层 div 容器）
        """
        import math

        high = dist["high"]
        medium = dist["medium"]
        low = dist["low"]
        total = dist["total"]
        r = 80
        circumference = 2 * math.pi * r  # ≈ 502.65
        # 底环（灰色背景）
        base_circle = f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="#e0e0e0" stroke-width="20"/>'
        if total == 0:
            arcs = base_circle
            center_num = "0"
            center_color = "#999"
        else:
            # 各段弧长（按占比）
            high_len = (high / total) * circumference
            medium_len = (medium / total) * circumference
            low_len = (low / total) * circumference
            # 三段弧：用 stroke-dasharray="弧长 间隙" 控制实线长度，
            # stroke-dashoffset 控制起点偏移（负值=向远离起点方向移动，让弧从上一段末尾开始）
            arcs = base_circle
            if high > 0:
                arcs += (
                    f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="#d9534f" '
                    f'stroke-width="20" stroke-dasharray="{high_len:.2f} {circumference - high_len:.2f}" '
                    f'stroke-dashoffset="0"/>'
                )
            if medium > 0:
                arcs += (
                    f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="#f0ad4e" '
                    f'stroke-width="20" stroke-dasharray="{medium_len:.2f} {circumference - medium_len:.2f}" '
                    f'stroke-dashoffset="{-high_len:.2f}"/>'
                )
            if low > 0:
                arcs += (
                    f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="#5cb85c" '
                    f'stroke-width="20" stroke-dasharray="{low_len:.2f} {circumference - low_len:.2f}" '
                    f'stroke-dashoffset="{-high_len - medium_len:.2f}"/>'
                )
            center_num = str(total)
            center_color = "#333"
        return (
            '<div style="margin:15px 0">'
            '<svg viewBox="0 0 200 200" width="200" height="200" role="img" '
            'aria-label="风险分布环形图">'
            # 旋转 -90° 让弧从顶部 12 点方向开始绘制
            f'<g transform="rotate(-90 100 100)">{arcs}</g>'
            f'<text x="100" y="95" text-anchor="middle" dominant-baseline="central" '
            f'font-size="28" font-weight="bold" fill="{center_color}">{center_num}</text>'
            '<text x="100" y="120" text-anchor="middle" font-size="12" fill="#999">确认漏洞</text>'
            "</svg>"
            "</div>"
        )

    def to_html(self, confirmed_only=False):
        """HTML 格式（风险着色 + 修复建议，标准库 string 模板，无 jinja2）

        Args:
            confirmed_only: True 时仅展示 CONFIRMED 行（SAFE/UNKNOWN 隐藏），默认展示全部
        """
        dist = self.risk_distribution()
        # 排序：CONFIRMED 优先，同安全度 high→medium→low
        sorted_list = self.sorted_results(confirmed_first=True)
        rows_html = []
        sev_color = {
            SEVERITY_HIGH: "#d9534f",
            SEVERITY_MEDIUM: "#f0ad4e",
            SEVERITY_LOW: "#5cb85c",
        }
        sev_cn = SEVERITY_CN
        for r in sorted_list:
            color = sev_color.get(r.severity, "#999")
            sev_text = sev_cn.get(r.severity, r.severity)
            status_cn = {"CONFIRMED": "确认存在", "SAFE": "不存在", "UNKNOWN": "未知"}.get(r.status, r.status)
            # CSS class 用于 show/hide 过滤
            row_class = "confirmed" if r.status == STATUS_CONFIRMED else "not-confirmed"
            # D7: WAF 绕过徽标（extra.waf_bypass 含 strategy_used 或 bypass_attempted）
            bypass_badge = ""
            extra = getattr(r, "extra", None) or {}
            waf_info = extra.get("waf_bypass") if isinstance(extra, dict) else None
            if waf_info:
                if waf_info.get("strategy_used"):
                    sid = html_module.escape(str(waf_info.get("strategy_used", "")))
                    sname = html_module.escape(str(waf_info.get("strategy_name", "")))
                    bypass_badge = f' <span class="bypass-badge" title="{sname}">WAF绕过:{sid}</span>'
                elif waf_info.get("bypass_attempted"):
                    bypass_badge = ' <span class="bypass-failed-badge">WAF绕过失败</span>'
            # D12：CVE/CVSS/合规列
            cve_text = html_module.escape(r.cve) if r.cve else "—"
            cvss_text = f"{r.cvss_score:.1f}" if r.cvss_score > 0 else "—"
            compliance_parts = []
            if r.compliance:
                for std, clause in r.compliance.items():
                    compliance_parts.append(f"{html_module.escape(std)}:{html_module.escape(clause)}")
            compliance_text = "<br>".join(compliance_parts) if compliance_parts else "—"
            # D18/D24：修复详情 + 复现命令（保留换行，转义 HTML）
            fix_detail_text = html_module.escape(getattr(r, "fix_detail", "") or "").replace("\n", "<br>") or "—"
            reproduce_text = html_module.escape(getattr(r, "reproduce", "") or "").replace("\n", "<br>") or "—"
            rows_html.append(
                f'<tr class="{row_class}">'
                f'<td class="sev-{r.severity}"><span class="badge" style="background:{color}">{html_module.escape(sev_text)}</span></td>'
                f"<td>{html_module.escape(r.name)}</td>"
                f'<td class="url">{html_module.escape(r.url)}</td>'
                f"<td>{html_module.escape(status_cn)}</td>"
                f'<td class="cve">{cve_text}</td>'
                f'<td class="cvss">{cvss_text}</td>'
                f'<td class="evidence">{html_module.escape(r.evidence)}{bypass_badge}</td>'
                f'<td class="fix">{html_module.escape(r.fix)}</td>'
                f'<td class="fix-detail">{fix_detail_text}</td>'
                f'<td class="reproduce">{reproduce_text}</td>'
                f'<td class="compliance">{compliance_text}</td>'
                "</tr>"
            )
        rows = "\n".join(rows_html) if rows_html else '<tr><td colspan="11" class="empty">无扫描结果</td></tr>'

        # 摘要区 + CMS 感知标题
        started = html_module.escape(str(self.summary.get("started_at", "")))
        duration = self.summary.get("duration", 0)
        req_count = self.summary.get("request_count", 0)
        fp = self.summary.get("fingerprint", {}) or {}
        fp_cms = html_module.escape(str(fp.get("cms", "")))
        fp_conf = fp.get("confidence", 0)
        mode = html_module.escape(str(self.summary.get("mode", "")))

        # 标题：多 CMS 感知（若识别到 CMS 则显示，否则默认 Ruoyi-Scan）
        cms_display = fp_cms.capitalize() if fp_cms else ""
        title_main = f"扫描报告 - {cms_display}" if cms_display else "Ruoyi-Scan 扫描报告"

        # 仅确认模式开关（CSS + checkbox）
        filter_html = ""
        any_non = any(r.status != STATUS_CONFIRMED for r in self._effective_results())
        if any_non and not confirmed_only:
            filter_html = (
                '<div style="margin:10px 0">'
                '<label style="cursor:pointer;font-size:13px;color:#555">'
                '<input type="checkbox" id="filter-confirmed" checked onchange="toggleFilter()">'
                " 仅显示确认存在的漏洞（隐藏 不存在/未知 行）"
                "</label></div>"
            )

        # 阶段六：风险分布环形图（纯 SVG，零外部依赖）
        donut_svg = self._render_risk_donut_svg(dist)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>{title_main} - {html_module.escape(self.target)}</title>
<style>
  body {{ font-family: "Microsoft YaHei", Arial, sans-serif; margin: 20px; background: #f7f7f9; color: #333; }}
  h1 {{ color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 8px; }}
  h2 {{ color: #34495e; margin-top: 24px; }}
  .summary {{ background: #fff; padding: 12px 18px; border-radius: 4px; border: 1px solid #e0e0e0; margin-bottom: 16px; }}
  .summary span {{ display: inline-block; margin-right: 24px; }}
  .risk-box {{ display: inline-block; padding: 4px 12px; border-radius: 3px; color: #fff; margin-right: 8px; }}
  .risk-high {{ background: #d9534f; }}
  .risk-medium {{ background: #f0ad4e; }}
  .risk-low {{ background: #5cb85c; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #2c3e50; color: #fff; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  td.url {{ word-break: break-all; color: #2980b9; font-family: Consolas, monospace; }}
  td.evidence {{ font-family: Consolas, monospace; font-size: 12px; color: #c0392b; }}
  td.fix {{ color: #27ae60; }}
  td.fix-detail {{ color: #27ae60; font-size: 12px; white-space: pre-wrap; max-width: 360px; }}
  td.reproduce {{ font-family: Consolas, monospace; font-size: 11px; color: #2c3e50; background: #f8f9fa; white-space: pre-wrap; max-width: 360px; }}
  td.cve {{ font-family: Consolas, monospace; font-size: 11px; color: #8e44ad; }}
  td.cvss {{ font-family: Consolas, monospace; font-size: 12px; font-weight: bold; text-align: center; }}
  td.compliance {{ font-size: 11px; color: #555; }}
  td.empty {{ text-align: center; color: #999; padding: 20px; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 12px; }}
  .bypass-badge {{ display: inline-block; background: #8e44ad; color: #fff; padding: 1px 6px; border-radius: 3px; font-size: 11px; margin-left: 4px; }}
  .bypass-failed-badge {{ display: inline-block; background: #7f8c8d; color: #fff; padding: 1px 6px; border-radius: 3px; font-size: 11px; margin-left: 4px; }}
  .footer {{ margin-top: 24px; color: #999; font-size: 12px; text-align: center; }}
  tr.not-confirmed {{ display: none; }}
  tr.not-confirmed.show {{ display: table-row; }}
</style>
<script>
function toggleFilter() {{
  var show = document.getElementById("filter-confirmed").checked;
  var rows = document.querySelectorAll("tr.not-confirmed");
  for (var i=0; i<rows.length; i++) {{
    rows[i].className = show ? "not-confirmed" : "not-confirmed show";
  }}
}}
</script>
</head>
<body>
<h1>{title_main}</h1>
<div class="summary">
  <span><b>目标：</b>{html_module.escape(self.target)}</span>
  <span><b>CMS：</b>{fp_cms or "未识别"}（置信度 {fp_conf:.2f}）</span>
  <span><b>扫描模式：</b>{mode}</span>
  <span><b>扫描时间：</b>{started}</span>
  <span><b>耗时：</b>{duration:.2f} 秒</span>
  <span><b>请求数：</b>{req_count}</span>
</div>
<h2>风险分布（仅统计确认存在的漏洞）</h2>
<div>
  <span class="risk-box risk-high">高 {dist["high"]}</span>
  <span class="risk-box risk-medium">中 {dist["medium"]}</span>
  <span class="risk-box risk-low">低 {dist["low"]}</span>
  <span>合计：{dist["total"]} 个漏洞</span>
</div>
{donut_svg}
{filter_html}
<h2>详细结果</h2>
<table>
  <thead>
    <tr>
      <th>危害等级</th><th>漏洞名称</th><th>URL</th><th>状态</th><th>CVE</th><th>CVSS</th><th>证据</th><th>修复建议</th><th>修复详情</th><th>复现命令</th><th>合规映射</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>
<div class="footer">由 Ruoyi-Scan 自动生成 · 仅用于授权范围内的安全测试</div>
</body>
</html>"""

    def render_all(self, out_dir, formats=None):
        """渲染多格式到 out_dir，返回生成的文件路径列表

        formats: 默认 ['html','json','csv']；D8 起新增 'pdf','docx','xlsx'；'all'=全部 6 种
        未安装可选依赖时自动降级（跳过 PDF/Word/Excel 并打印警告）。
        文件名：report.json / report.html / report.csv / report.pdf / report.docx / report.xlsx
        """
        if not out_dir:
            out_dir = settings.REPORT_DIR
        os.makedirs(out_dir, exist_ok=True)

        if formats is None:
            formats = ["html", "json", "csv"]
        elif formats == "all":
            formats = ["html", "json", "csv", "pdf", "docx", "xlsx", "sarif"]

        paths = []
        if "json" in formats:
            json_path = os.path.join(out_dir, "report.json")
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(self.to_json())
            paths.append(json_path)
        if "html" in formats:
            html_path = os.path.join(out_dir, "report.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(self.to_html())
            paths.append(html_path)
        if "csv" in formats:
            csv_path = os.path.join(out_dir, "report.csv")
            # CSV 用 utf-8-sig 便于 Excel 正确显示中文
            with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
                f.write(self.to_csv())
            paths.append(csv_path)
        # D8.2-D8.4: PDF/Word/Excel 惰性 import + 降级友好
        if "pdf" in formats:
            try:
                from core.report_pdf import render_pdf

                pdf_path = os.path.join(out_dir, "report.pdf")
                render_pdf(self, pdf_path)
                paths.append(pdf_path)
            except ImportError:
                print("[警告] reportlab 未安装，跳过 PDF 报告（pip install reportlab）")
        if "docx" in formats:
            try:
                from core.report_docx import render_docx

                docx_path = os.path.join(out_dir, "report.docx")
                render_docx(self, docx_path)
                paths.append(docx_path)
            except ImportError:
                print("[警告] python-docx 未安装，跳过 Word 报告（pip install python-docx）")
        if "xlsx" in formats:
            try:
                from core.report_xlsx import render_xlsx

                xlsx_path = os.path.join(out_dir, "report.xlsx")
                render_xlsx(self, xlsx_path)
                paths.append(xlsx_path)
            except ImportError:
                print("[警告] openpyxl 未安装，跳过 Excel 报告（pip install openpyxl）")
        # D22: SARIF 报告格式（GitHub Code Scanning）
        if "sarif" in formats:
            try:
                from core.report_sarif import render_sarif

                sarif_path = os.path.join(out_dir, "report.sarif")
                render_sarif(self, sarif_path)
                paths.append(sarif_path)
            except Exception as e:
                print(f"[警告] SARIF 报告生成失败: {e}")
        return paths


class BatchReport:
    """批量扫描汇总报告：聚合多个 ReportBuilder，输出 batch_report.html + batch_report.csv"""

    def __init__(self, builders=None):
        self.builders = builders or []  # list of ReportBuilder

    def add(self, builder):
        self.builders.append(builder)

    @property
    def total_targets(self):
        return len(self.builders)

    def total_confirmed(self):
        return sum(b.risk_distribution()["total"] for b in self.builders)

    def to_csv(self):
        """CSV：目标,CMS,高,中,低,合计,请求数,耗时(秒)"""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["目标", "CMS", "高", "中", "低", "合计", "请求数", "耗时秒"])
        for b in self.builders:
            dist = b.risk_distribution()
            fp = (b.summary or {}).get("fingerprint", {}) or {}
            writer.writerow(
                [
                    b.target,
                    fp.get("cms", "未识别"),
                    dist["high"],
                    dist["medium"],
                    dist["low"],
                    dist["total"],
                    (b.summary or {}).get("request_count", 0),
                    round((b.summary or {}).get("duration", 0), 1),
                ]
            )
        return buf.getvalue()

    def _render_targets_bar_svg(self):
        """生成各目标确认漏洞数柱状图 SVG（阶段六：纯 SVG rect，堆叠三色）

        每个目标一根柱，从底部向上堆叠 高(红)/中(黄)/低(绿)，柱顶标注总数，
        底部标目标序号（与表格行对应）。零漏洞目标显示空位 + 序号。
        无目标时返回空字符串。
        """
        if not self.builders:
            return ""
        # 预计算各目标分布
        items = []
        for b in self.builders:
            d = b.risk_distribution()
            items.append((b.target, d["high"], d["medium"], d["low"], d["total"]))
        max_total = max((it[4] for it in items), default=1) or 1
        bar_width = 40
        gap = 20
        chart_h = 120  # SVG 内坐标高度（viewBox 高度 = chart_h + 20 留底部标签）
        bar_area_h = 100  # 柱子最大高度
        base_y = chart_h  # 底部基线（柱子从 base_y 向上生长）
        n = len(items)
        svg_w = n * (bar_width + gap) + gap
        bars = []
        for i, (_target, hi, me, lo, total) in enumerate(items):
            x = gap + i * (bar_width + gap)
            # 三段堆叠：从底部开始 高 → 中 → 低
            h_high = int((hi / max_total) * bar_area_h) if max_total > 0 else 0
            h_med = int((me / max_total) * bar_area_h) if max_total > 0 else 0
            h_low = int((lo / max_total) * bar_area_h) if max_total > 0 else 0
            y_high = base_y - h_high
            y_med = y_high - h_med
            y_low = y_med - h_low
            if h_high > 0:
                bars.append(f'<rect x="{x}" y="{y_high}" width="{bar_width}" height="{h_high}" fill="#d9534f"/>')
            if h_med > 0:
                bars.append(f'<rect x="{x}" y="{y_med}" width="{bar_width}" height="{h_med}" fill="#f0ad4e"/>')
            if h_low > 0:
                bars.append(f'<rect x="{x}" y="{y_low}" width="{bar_width}" height="{h_low}" fill="#5cb85c"/>')
            # 柱顶标注总数
            if total > 0:
                bars.append(
                    f'<text x="{x + bar_width // 2}" y="{y_low - 5}" text-anchor="middle" '
                    f'font-size="11" fill="#333">{total}</text>'
                )
            # 底部序号（与表格行对应）
            bars.append(
                f'<text x="{x + bar_width // 2}" y="{base_y + 15}" text-anchor="middle" '
                f'font-size="11" fill="#666">{i + 1}</text>'
            )
        bars_str = "\n      ".join(bars)
        view_h = chart_h + 20
        return (
            f'<svg viewBox="0 0 {svg_w} {view_h}" width="{svg_w}" height="{view_h}" '
            f'style="margin:10px 0" role="img" aria-label="各目标漏洞数柱状图">\n      '
            f"{bars_str}\n    </svg>"
        )

    def to_html(self):
        """HTML 批量汇总：概览表 + 各目标摘要"""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        bar_svg = self._render_targets_bar_svg()
        rows = []
        total_high = total_medium = total_low = total_vuln = total_req = 0.0
        total_dur = 0.0
        for b in self.builders:
            dist = b.risk_distribution()
            fp = (b.summary or {}).get("fingerprint", {}) or {}
            cms = html_module.escape(str(fp.get("cms", "未识别")))
            dur = round((b.summary or {}).get("duration", 0), 1)
            req = (b.summary or {}).get("request_count", 0)
            total_high += dist["high"]
            total_medium += dist["medium"]
            total_low += dist["low"]
            total_vuln += dist["total"]
            total_req += req
            total_dur += dur
            rows.append(
                f"<tr>"
                f'<td class="url">{html_module.escape(b.target)}</td>'
                f"<td>{cms}</td>"
                f"<td>{dist['high']}</td><td>{dist['medium']}</td><td>{dist['low']}</td>"
                f"<td><b>{dist['total']}</b></td>"
                f"<td>{req}</td><td>{dur}s</td>"
                "</tr>"
            )
        rows_html = "\n".join(rows) if rows else '<tr><td colspan="8" class="empty">无扫描目标</td></tr>'
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>批量扫描汇总报告</title>
<style>
  body {{ font-family: "Microsoft YaHei", Arial, sans-serif; margin: 20px; background: #f7f7f9; color: #333; }}
  h1 {{ color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 8px; }}
  h2 {{ color: #34495e; margin-top: 24px; }}
  .summary {{ background: #fff; padding: 12px 18px; border-radius: 4px; border: 1px solid #e0e0e0; margin-bottom: 16px; }}
  .summary span {{ display: inline-block; margin-right: 24px; }}
  .risk-box {{ display: inline-block; padding: 4px 12px; border-radius: 3px; color: #fff; margin-right: 8px; }}
  .risk-high {{ background: #d9534f; }}
  .risk-medium {{ background: #f0ad4e; }}
  .risk-low {{ background: #5cb85c; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #2c3e50; color: #fff; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  td.url {{ word-break: break-all; color: #2980b9; font-family: Consolas, monospace; }}
  td.empty {{ text-align: center; color: #999; padding: 20px; }}
  .footer {{ margin-top: 24px; color: #999; font-size: 12px; text-align: center; }}
</style>
</head>
<body>
<h1>批量扫描汇总报告</h1>
<div class="summary">
  <span><b>扫描目标数：</b>{self.total_targets}</span>
  <span><b>总耗时：</b>{total_dur:.1f} 秒</span>
  <span><b>总请求数：</b>{total_req}</span>
  <span><b>生成时间：</b>{now}</span>
</div>
<h2>风险概览</h2>
<div>
  <span class="risk-box risk-high">高 {total_high}</span>
  <span class="risk-box risk-medium">中 {total_medium}</span>
  <span class="risk-box risk-low">低 {total_low}</span>
  <span>合计确认漏洞：{total_vuln}</span>
</div>
{bar_svg}
<h2>各目标详情</h2>
<table>
  <thead>
    <tr>
      <th>目标</th><th>CMS</th><th>高</th><th>中</th><th>低</th><th>合计漏洞</th><th>请求数</th><th>耗时</th>
    </tr>
  </thead>
  <tbody>
{rows_html}
  </tbody>
</table>
<div class="footer">由 Ruoyi-Scan 批量扫描自动生成 · 仅用于授权范围内的安全测试</div>
</body>
</html>"""

    def render_all(self, out_dir):
        """输出 batch_report.html + batch_report.csv"""
        if not out_dir:
            out_dir = settings.REPORT_DIR
        os.makedirs(out_dir, exist_ok=True)
        paths = []
        html_path = os.path.join(out_dir, "batch_report.html")
        csv_path = os.path.join(out_dir, "batch_report.csv")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(self.to_html())
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            f.write(self.to_csv())
        paths.extend([html_path, csv_path])
        return paths
