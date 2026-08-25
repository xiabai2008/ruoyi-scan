# D20：增量扫描与差异对比
#
# 保存历史扫描结果，对比两次扫描输出新增/修复/未变漏洞
#
# 使用场景：
#   1. 安全运维：定期扫描同一目标，跟踪漏洞修复进度
#   2. CI/CD：代码合并前后对比，检测是否引入新漏洞
#   3. 合规审计：对比基线扫描与当前状态
#
# 使用方式：
#   # 保存当前扫描结果为基线
#   python main.py -u http://target/ --report reports/ --save-baseline
#
#   # 与基线对比
#   python main.py -u http://target/ --report reports/ --diff reports/report.json
#
#   # 仅输出差异报告（不重新扫描）
#   python main.py --diff-only reports/old.json reports/new.json
#
# 差异类型：
#   - new（新增）：新基线有，旧基线无 → 新引入的漏洞
#   - fixed（已修复）：旧基线有，新基线无 → 已修复的漏洞
#   - persisted（未变）：两次都有 → 仍未修复的漏洞
#   - changed（变化）：状态/严重度变化 → 漏洞状态改变
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class VulnFingerprint:
    """漏洞指纹（用于对比两次扫描中的同一漏洞）

    指纹由 name + url 路径组成，不包含 status/severity（这些是比较维度）
    """

    name: str
    url: str

    def key(self) -> str:
        """生成唯一 key"""
        # URL 去除查询参数中的随机 token（保留路径结构）
        url = self.url.split("?")[0]  # 去查询参数
        return f"{self.name}|{url}"


@dataclass
class DiffEntry:
    """差异条目"""

    diff_type: str  # new / fixed / persisted / changed
    name: str
    url: str
    old_status: str = ""  # 旧状态（fixed/changed 时有值）
    new_status: str = ""  # 新状态（new/persisted/changed 时有值）
    old_severity: str = ""
    new_severity: str = ""
    cve: str = ""


@dataclass
class DiffReport:
    """差异报告"""

    old_scan_time: str = ""
    new_scan_time: str = ""
    target: str = ""
    old_total: int = 0
    new_total: int = 0
    new_vulns: List[DiffEntry] = field(default_factory=list)  # 新增漏洞
    fixed_vulns: List[DiffEntry] = field(default_factory=list)  # 已修复漏洞
    persisted_vulns: List[DiffEntry] = field(default_factory=list)  # 未变漏洞
    changed_vulns: List[DiffEntry] = field(default_factory=list)  # 状态变化漏洞

    @property
    def total_new(self) -> int:
        return len(self.new_vulns)

    @property
    def total_fixed(self) -> int:
        return len(self.fixed_vulns)

    @property
    def total_persisted(self) -> int:
        return len(self.persisted_vulns)

    @property
    def total_changed(self) -> int:
        return len(self.changed_vulns)

    def to_dict(self) -> Dict[str, Any]:
        """转为字典"""
        return {
            "old_scan_time": self.old_scan_time,
            "new_scan_time": self.new_scan_time,
            "target": self.target,
            "old_total": self.old_total,
            "new_total": self.new_total,
            "summary": {
                "new": self.total_new,
                "fixed": self.total_fixed,
                "persisted": self.total_persisted,
                "changed": self.total_changed,
            },
            "new_vulns": [e.__dict__ for e in self.new_vulns],
            "fixed_vulns": [e.__dict__ for e in self.fixed_vulns],
            "persisted_vulns": [e.__dict__ for e in self.persisted_vulns],
            "changed_vulns": [e.__dict__ for e in self.changed_vulns],
        }

    def to_json(self) -> str:
        """转为 JSON"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def to_html(self) -> str:
        """转为 HTML 差异报告"""
        import html as html_module

        def render_entries(entries: List[DiffEntry], color: str, icon: str) -> str:
            """渲染某分类（new/fixed/persisted/changed）的差异表格行；名称/URL 经 HTML 转义防注入"""
            if not entries:
                return '<tr><td colspan="5" class="empty">无</td></tr>'
            rows = []
            for e in entries:
                rows.append(
                    f"<tr>"
                    f"<td>{html_module.escape(e.name)}</td>"
                    f'<td class="url">{html_module.escape(e.url)}</td>'
                    f"<td>{html_module.escape(e.old_status or '—')}</td>"
                    f"<td>{html_module.escape(e.new_status or '—')}</td>"
                    f"<td>{html_module.escape(e.cve or '—')}</td>"
                    f"</tr>"
                )
            return "\n".join(rows)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>差异报告 - {html_module.escape(self.target)}</title>
<style>
  body {{ font-family: "Microsoft YaHei", Arial, sans-serif; margin: 20px; background: #f7f7f9; color: #333; }}
  h1 {{ color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 8px; }}
  .summary {{ background: #fff; padding: 12px 18px; border-radius: 4px; border: 1px solid #e0e0e0; margin-bottom: 16px; }}
  .summary span {{ display: inline-block; margin-right: 24px; padding: 4px 12px; border-radius: 3px; color: #fff; }}
  .new {{ background: #d9534f; }}
  .fixed {{ background: #5cb85c; }}
  .persisted {{ background: #f0ad4e; }}
  .changed {{ background: #5bc0de; }}
  h2 {{ color: #34495e; margin-top: 24px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; margin-bottom: 16px; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #2c3e50; color: #fff; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  td.url {{ word-break: break-all; color: #2980b9; font-family: Consolas, monospace; }}
  td.empty {{ text-align: center; color: #999; padding: 20px; }}
</style>
</head>
<body>
<h1>差异报告</h1>
<div class="summary">
  <strong>目标：</strong>{html_module.escape(self.target)}<br>
  <strong>旧扫描：</strong>{html_module.escape(self.old_scan_time)}（{self.old_total} 个漏洞）<br>
  <strong>新扫描：</strong>{html_module.escape(self.new_scan_time)}（{self.new_total} 个漏洞）<br><br>
  <span class="new">新增 {self.total_new}</span>
  <span class="fixed">已修复 {self.total_fixed}</span>
  <span class="persisted">未变 {self.total_persisted}</span>
  <span class="changed">变化 {self.total_changed}</span>
</div>

<h2>🆕 新增漏洞（{self.total_new}）</h2>
<table>
<tr><th>漏洞名称</th><th>URL</th><th>旧状态</th><th>新状态</th><th>CVE</th></tr>
{render_entries(self.new_vulns, "new", "🆕")}
</table>

<h2>✅ 已修复漏洞（{self.total_fixed}）</h2>
<table>
<tr><th>漏洞名称</th><th>URL</th><th>旧状态</th><th>新状态</th><th>CVE</th></tr>
{render_entries(self.fixed_vulns, "fixed", "✅")}
</table>

<h2>⚠️ 状态变化（{self.total_changed}）</h2>
<table>
<tr><th>漏洞名称</th><th>URL</th><th>旧状态</th><th>新状态</th><th>CVE</th></tr>
{render_entries(self.changed_vulns, "changed", "⚠️")}
</table>

<h2>⏳ 未变漏洞（{self.total_persisted}）</h2>
<table>
<tr><th>漏洞名称</th><th>URL</th><th>旧状态</th><th>新状态</th><th>CVE</th></tr>
{render_entries(self.persisted_vulns, "persisted", "⏳")}
</table>
</body>
</html>"""


def _extract_vulns(report_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """从报告字典中提取漏洞，以指纹 key 为键

    仅提取 CONFIRMED 状态的漏洞（SAFE/UNKNOWN 不计入差异对比）
    """
    from common.models import STATUS_CONFIRMED

    vulns = {}
    results = report_data.get("results", [])
    for r in results:
        if r.get("status") != STATUS_CONFIRMED:
            # SAFE/UNKNOWN 多为探测过程态、复现波动大，计入差异会制造大量假新增/假修复
            continue
        fp = VulnFingerprint(name=r.get("name", ""), url=r.get("url", ""))
        vulns[fp.key()] = {
            "name": r.get("name", ""),
            "url": r.get("url", ""),
            "status": r.get("status", ""),
            "severity": r.get("severity", ""),
            "cve": r.get("cve", ""),
        }
    return vulns


def load_report(filepath: str) -> Dict[str, Any]:
    """加载 JSON 报告文件"""
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def diff_reports(old_report: Dict[str, Any], new_report: Dict[str, Any]) -> DiffReport:
    """对比两个扫描报告

    Args:
        old_report: 旧扫描报告字典（JSON 解析后）
        new_report: 新扫描报告字典（JSON 解析后）
    Returns:
        DiffReport 差异报告
    """
    old_vulns = _extract_vulns(old_report)
    new_vulns = _extract_vulns(new_report)

    report = DiffReport(
        old_scan_time=old_report.get("scan_time", ""),
        new_scan_time=new_report.get("scan_time", ""),
        target=new_report.get("target", old_report.get("target", "")),
        old_total=len(old_vulns),
        new_total=len(new_vulns),
    )

    # 先转成集合再求差集/交集，把三类对比从嵌套循环降为线性扫描
    old_keys = set(old_vulns.keys())
    new_keys = set(new_vulns.keys())

    # 新增漏洞：新有旧无
    for key in new_keys - old_keys:
        v = new_vulns[key]
        report.new_vulns.append(
            DiffEntry(
                diff_type="new",
                name=v["name"],
                url=v["url"],
                new_status=v["status"],
                new_severity=v["severity"],
                cve=v.get("cve", ""),
            )
        )

    # 已修复漏洞：旧有新无
    for key in old_keys - new_keys:
        v = old_vulns[key]
        report.fixed_vulns.append(
            DiffEntry(
                diff_type="fixed",
                name=v["name"],
                url=v["url"],
                old_status=v["status"],
                old_severity=v["severity"],
                cve=v.get("cve", ""),
            )
        )

    # 对比共有的漏洞
    for key in old_keys & new_keys:
        old_v = old_vulns[key]
        new_v = new_vulns[key]
        # 状态或严重度变化
        if old_v["status"] != new_v["status"] or old_v["severity"] != new_v["severity"]:
            report.changed_vulns.append(
                DiffEntry(
                    diff_type="changed",
                    name=new_v["name"],
                    url=new_v["url"],
                    old_status=old_v["status"],
                    new_status=new_v["status"],
                    old_severity=old_v["severity"],
                    new_severity=new_v["severity"],
                    cve=new_v.get("cve", ""),
                )
            )
        else:
            # 未变
            report.persisted_vulns.append(
                DiffEntry(
                    diff_type="persisted",
                    name=new_v["name"],
                    url=new_v["url"],
                    old_status=old_v["status"],
                    new_status=new_v["status"],
                    old_severity=old_v["severity"],
                    new_severity=new_v["severity"],
                    cve=new_v.get("cve", ""),
                )
            )

    return report


def save_baseline(report_data: Dict[str, Any], filepath: str):
    """保存扫描结果为基线文件

    Args:
        report_data: 扫描报告字典
        filepath: 基线文件路径（.json）
    """
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)


def render_diff_report(diff: DiffReport, out_dir: str) -> List[str]:
    """输出差异报告到目录

    Args:
        diff: DiffReport 对象
        out_dir: 输出目录
    Returns:
        生成的文件路径列表
    """
    os.makedirs(out_dir, exist_ok=True)
    paths = []

    # JSON 差异报告
    json_path = os.path.join(out_dir, "diff_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(diff.to_json())
    paths.append(json_path)

    # HTML 差异报告
    html_path = os.path.join(out_dir, "diff_report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(diff.to_html())
    paths.append(html_path)

    return paths
