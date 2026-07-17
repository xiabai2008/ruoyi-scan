# 报告渲染：HTML / JSON / CSV（标准库 json/csv/string 模板，无第三方依赖）
import csv
import datetime
import html as html_module
import io
import json
import os

from config import settings
from core.models import (STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN,
                          SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_CN)


class ReportBuilder:
    """扫描报告构建器：HTML（风险着色+修复建议）/ JSON（供 CI）/ CSV

    字段：漏洞名称、URL、危害等级（高/中/低）、证据、修复建议
    摘要：目标、耗时、请求数、风险分布、扫描时间
    """

    def __init__(self, results=None, target='', summary=None):
        self.results = results or []
        self.target = target
        # summary: {duration, request_count, started_at, ended_at, mode, fingerprint}
        self.summary = summary or {}

    def add(self, result):
        self.results.append(result)

    # 风险分布：仅统计 CONFIRMED 漏洞
    def risk_distribution(self):
        dist = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        for r in self.results:
            if r.status != STATUS_CONFIRMED:
                continue
            dist['total'] += 1
            if r.severity in dist:
                dist[r.severity] += 1
        return dist

    # 仅保留确认存在的漏洞条目（UNKNOWN/SAFE 不计入漏洞数，见开发方案 §三 Step 4）
    def confirmed_results(self):
        return [r for r in self.results if r.status == STATUS_CONFIRMED]

    def sorted_results(self, confirmed_first=True):
        """排序结果：CONFIRMED 在前，同状态按危害度 high→medium→low→其他排序"""
        sev_order = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
        status_order = {STATUS_CONFIRMED: 0, STATUS_UNKNOWN: 1, STATUS_SAFE: 2}

        def key(r):
            s = status_order.get(r.status, 99)
            v = sev_order.get(r.severity, 99)
            return (s if confirmed_first else 0, v, r.name)
        return sorted(self.results, key=key)

    def to_dict(self):
        """整体报告字典（JSON 用）"""
        dist = self.risk_distribution()
        return {
            'target': self.target,
            'scan_time': self.summary.get('started_at', ''),
            'duration_sec': round(self.summary.get('duration', 0), 2),
            'request_count': self.summary.get('request_count', 0),
            'mode': self.summary.get('mode', ''),
            'fingerprint': self.summary.get('fingerprint', {}),
            'risk_distribution': dist,
            'vuln_count': dist['total'],
            'results': [r.to_dict() for r in self.results],
        }

    def to_json(self):
        """JSON 格式（供 CI 解析，UTF-8，缩进 2）"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def to_csv(self):
        """CSV 格式（漏洞名称/URL/危害等级/状态/证据/修复建议）"""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['漏洞名称', 'URL', '危害等级', '状态', '证据', '修复建议'])
        for r in self.results:
            writer.writerow([
                r.name,
                r.url,
                SEVERITY_CN.get(r.severity, r.severity),
                r.status,
                r.evidence,
                r.fix,
            ])
        return buf.getvalue()

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
            SEVERITY_HIGH: '#d9534f',
            SEVERITY_MEDIUM: '#f0ad4e',
            SEVERITY_LOW: '#5cb85c',
        }
        sev_cn = SEVERITY_CN
        for r in sorted_list:
            color = sev_color.get(r.severity, '#999')
            sev_text = sev_cn.get(r.severity, r.severity)
            status_cn = {'CONFIRMED': '确认存在', 'SAFE': '不存在', 'UNKNOWN': '未知'}.get(r.status, r.status)
            # CSS class 用于 show/hide 过滤
            row_class = 'confirmed' if r.status == STATUS_CONFIRMED else 'not-confirmed'
            rows_html.append(
                f'<tr class="{row_class}">'
                f'<td class="sev-{r.severity}"><span class="badge" style="background:{color}">{html_module.escape(sev_text)}</span></td>'
                f'<td>{html_module.escape(r.name)}</td>'
                f'<td class="url">{html_module.escape(r.url)}</td>'
                f'<td>{html_module.escape(status_cn)}</td>'
                f'<td class="evidence">{html_module.escape(r.evidence)}</td>'
                f'<td class="fix">{html_module.escape(r.fix)}</td>'
                '</tr>'
            )
        rows = '\n'.join(rows_html) if rows_html else '<tr><td colspan="6" class="empty">无扫描结果</td></tr>'

        # 摘要区 + CMS 感知标题
        started = html_module.escape(str(self.summary.get('started_at', '')))
        duration = self.summary.get('duration', 0)
        req_count = self.summary.get('request_count', 0)
        fp = self.summary.get('fingerprint', {}) or {}
        fp_cms = html_module.escape(str(fp.get('cms', '')))
        fp_conf = fp.get('confidence', 0)
        mode = html_module.escape(str(self.summary.get('mode', '')))

        # 标题：多 CMS 感知（若识别到 CMS 则显示，否则默认 Ruoyi-Scan）
        cms_display = fp_cms.capitalize() if fp_cms else ''
        title_main = f'扫描报告 - {cms_display}' if cms_display else 'Ruoyi-Scan 扫描报告'

        # 仅确认模式开关（CSS + checkbox）
        filter_html = ''
        any_non = any(r.status != STATUS_CONFIRMED for r in self.results)
        if any_non and not confirmed_only:
            filter_html = (
                '<div style="margin:10px 0">'
                '<label style="cursor:pointer;font-size:13px;color:#555">'
                '<input type="checkbox" id="filter-confirmed" checked onchange="toggleFilter()">'
                ' 仅显示确认存在的漏洞（隐藏 不存在/未知 行）'
                '</label></div>'
            )

        return f'''<!DOCTYPE html>
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
  td.empty {{ text-align: center; color: #999; padding: 20px; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 12px; }}
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
  <span><b>CMS：</b>{fp_cms or '未识别'}（置信度 {fp_conf:.2f}）</span>
  <span><b>扫描模式：</b>{mode}</span>
  <span><b>扫描时间：</b>{started}</span>
  <span><b>耗时：</b>{duration:.2f} 秒</span>
  <span><b>请求数：</b>{req_count}</span>
</div>
<h2>风险分布（仅统计确认存在的漏洞）</h2>
<div>
  <span class="risk-box risk-high">高 {dist['high']}</span>
  <span class="risk-box risk-medium">中 {dist['medium']}</span>
  <span class="risk-box risk-low">低 {dist['low']}</span>
  <span>合计：{dist['total']} 个漏洞</span>
</div>
{filter_html}
<h2>详细结果</h2>
<table>
  <thead>
    <tr>
      <th>危害等级</th><th>漏洞名称</th><th>URL</th><th>状态</th><th>证据</th><th>修复建议</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>
<div class="footer">由 Ruoyi-Scan 自动生成 · 仅用于授权范围内的安全测试</div>
</body>
</html>'''

    def render_all(self, out_dir):
        """渲染三种格式到 out_dir，返回生成的文件路径列表

        文件名：report.json / report.html / report.csv（已存在则覆盖）
        """
        if not out_dir:
            out_dir = settings.REPORT_DIR
        os.makedirs(out_dir, exist_ok=True)
        paths = []
        json_path = os.path.join(out_dir, 'report.json')
        html_path = os.path.join(out_dir, 'report.html')
        csv_path = os.path.join(out_dir, 'report.csv')
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(self.to_json())
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(self.to_html())
        # CSV 用 utf-8-sig 便于 Excel 正确显示中文
        with open(csv_path, 'w', encoding='utf-8-sig', newline='') as f:
            f.write(self.to_csv())
        paths.extend([json_path, html_path, csv_path])
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
        return sum(b.risk_distribution()['total'] for b in self.builders)

    def to_csv(self):
        """CSV：目标,CMS,高,中,低,合计,请求数,耗时(秒)"""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['目标', 'CMS', '高', '中', '低', '合计', '请求数', '耗时秒'])
        for b in self.builders:
            dist = b.risk_distribution()
            fp = (b.summary or {}).get('fingerprint', {}) or {}
            writer.writerow([
                b.target,
                fp.get('cms', '未识别'),
                dist['high'], dist['medium'], dist['low'], dist['total'],
                (b.summary or {}).get('request_count', 0),
                round((b.summary or {}).get('duration', 0), 1),
            ])
        return buf.getvalue()

    def to_html(self):
        """HTML 批量汇总：概览表 + 各目标摘要"""
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        rows = []
        total_high = total_medium = total_low = total_vuln = total_req = 0.0
        total_dur = 0.0
        for b in self.builders:
            dist = b.risk_distribution()
            fp = (b.summary or {}).get('fingerprint', {}) or {}
            cms = html_module.escape(str(fp.get('cms', '未识别')))
            dur = round((b.summary or {}).get('duration', 0), 1)
            req = (b.summary or {}).get('request_count', 0)
            total_high += dist['high']
            total_medium += dist['medium']
            total_low += dist['low']
            total_vuln += dist['total']
            total_req += req
            total_dur += dur
            rows.append(
                f'<tr>'
                f'<td class="url">{html_module.escape(b.target)}</td>'
                f'<td>{cms}</td>'
                f'<td>{dist["high"]}</td><td>{dist["medium"]}</td><td>{dist["low"]}</td>'
                f'<td><b>{dist["total"]}</b></td>'
                f'<td>{req}</td><td>{dur}s</td>'
                '</tr>'
            )
        rows_html = '\n'.join(rows) if rows else '<tr><td colspan="8" class="empty">无扫描目标</td></tr>'
        return f'''<!DOCTYPE html>
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
</html>'''

    def render_all(self, out_dir):
        """输出 batch_report.html + batch_report.csv"""
        if not out_dir:
            out_dir = settings.REPORT_DIR
        os.makedirs(out_dir, exist_ok=True)
        paths = []
        html_path = os.path.join(out_dir, 'batch_report.html')
        csv_path = os.path.join(out_dir, 'batch_report.csv')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(self.to_html())
        with open(csv_path, 'w', encoding='utf-8-sig', newline='') as f:
            f.write(self.to_csv())
        paths.extend([html_path, csv_path])
        return paths
