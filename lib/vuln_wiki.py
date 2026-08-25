# D29：漏洞知识库（离线 Wiki）
#
# 从所有 POC 插件的元数据生成离线 HTML 知识库，可搜索、可浏览
#
# 使用场景：
#   1. 安全团队快速查阅漏洞信息（描述/修复/复现/合规映射）
#   2. 离线环境下的漏洞知识参考
#   3. 培训材料（含修复代码和复现命令）
#
# 使用方式：
#   # 生成知识库
#   python main.py --wiki --report docs/
#   # → 生成 docs/vuln_wiki.html
#
#   # 指定输出路径
#   python main.py --wiki -o wiki.html
#
# 知识库内容：
#   - 漏洞列表（可按严重度/CVE/合规筛选）
#   - 每个漏洞的详情页（描述/修复建议/修复详情/复现命令/合规映射）
#   - 搜索框（前端 JS 实现，无需后端）
#   - 统计图表（按严重度/类别/CVE 分布）
import html as html_module
from typing import Any, Dict, List


def build_wiki_data(plugins: List[Dict[str, Any]]) -> Dict[str, Any]:
    """构建知识库数据

    Args:
        plugins: 插件元数据列表（来自 plugin_sdk.list_all_plugins）
    Returns:
        知识库数据字典
    """
    # 统计
    by_severity = {"high": 0, "medium": 0, "low": 0}
    by_category = {}
    by_compliance = {"OWASP": 0, "等保": 0}
    with_cve = 0
    with_fix_detail = 0
    with_reproduce = 0

    for p in plugins:
        # 严重度统计
        sev = p.get("severity", "")
        if sev in by_severity:
            by_severity[sev] += 1

        # 类别统计
        cat = p.get("category", "")
        by_category[cat] = by_category.get(cat, 0) + 1

        # 合规统计
        compliance = p.get("compliance", "") or ""
        if "OWASP" in compliance:
            by_compliance["OWASP"] += 1
        if "等保" in compliance:
            by_compliance["等保"] += 1

        # CVE 统计
        # 空值与 'N/A' 占位不计入 CVE 统计（插件模板默认 cve='N/A'）
        if p.get("cve", "") and p["cve"] != "N/A":
            with_cve += 1

        # 修复详情/复现命令
        if p.get("has_fix_detail"):
            with_fix_detail += 1
        if p.get("has_reproduce"):
            with_reproduce += 1

    return {
        "plugins": plugins,
        "stats": {
            "total": len(plugins),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_compliance": by_compliance,
            "with_cve": with_cve,
            "with_fix_detail": with_fix_detail,
            "with_reproduce": with_reproduce,
        },
    }


def render_wiki_html(plugins: List[Dict[str, Any]]) -> str:
    """渲染知识库 HTML

    Args:
        plugins: 插件元数据列表
    Returns:
        HTML 字符串
    """
    data = build_wiki_data(plugins)
    stats = data["stats"]

    # 漏洞卡片 HTML
    cards = []
    for p in plugins:
        sev = p.get("severity", "low")
        sev_color = {"high": "#d9534f", "medium": "#f0ad4e", "low": "#5cb85c"}.get(sev, "#999")
        cve = p.get("cve", "") or "N/A"
        cve_display = cve if cve != "N/A" else "—"
        compliance = p.get("compliance", "") or "—"
        fix_badge = "✓" if p.get("has_fix_detail") else "✗"
        reproduce_badge = "✓" if p.get("has_reproduce") else "✗"

        # 转义
        name = html_module.escape(p.get("name", ""))
        category = html_module.escape(p.get("category", ""))
        cve_esc = html_module.escape(cve_display)
        compliance_esc = html_module.escape(compliance)

        # data-* 属性统一存小写，配合前端 toLowerCase 搜索/筛选，避免大小写不一致漏匹配
        cards.append(f'''
        <div class="vuln-card" data-severity="{sev}" data-category="{category}"
             data-cve="{cve_esc}" data-name="{name.lower()}"
             data-compliance="{compliance_esc.lower()}">
            <div class="card-header">
                <span class="badge severity-{sev}" style="background:{sev_color}">{sev.upper()}</span>
                <span class="vuln-name">{name}</span>
                <span class="vuln-cve">{cve_esc}</span>
            </div>
            <div class="card-meta">
                <span class="meta-item">类别: {category}</span>
                <span class="meta-item">合规: {compliance_esc}</span>
                <span class="meta-item">修复详情: {fix_badge}</span>
                <span class="meta-item">复现命令: {reproduce_badge}</span>
            </div>
            <div class="card-module">{html_module.escape(p.get("module", ""))}</div>
        </div>
        ''')

    cards_html = "\n".join(cards) if cards else '<p class="empty">暂无漏洞数据</p>'

    # 统计区域
    stats_html = f"""
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-num">{stats["total"]}</div>
            <div class="stat-label">漏洞总数</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#d9534f">{stats["by_severity"]["high"]}</div>
            <div class="stat-label">高危</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#f0ad4e">{stats["by_severity"]["medium"]}</div>
            <div class="stat-label">中危</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:#5cb85c">{stats["by_severity"]["low"]}</div>
            <div class="stat-label">低危</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{stats["with_cve"]}</div>
            <div class="stat-label">含 CVE</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{stats["with_fix_detail"]}</div>
            <div class="stat-label">含修复详情</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{stats["with_reproduce"]}</div>
            <div class="stat-label">含复现命令</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{stats["by_compliance"]["OWASP"]}</div>
            <div class="stat-label">OWASP 映射</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{stats["by_compliance"]["等保"]}</div>
            <div class="stat-label">等保映射</div>
        </div>
    </div>
    """

    # 类别统计
    category_stats = ""
    for cat, count in sorted(stats["by_category"].items()):
        category_stats += f'<span class="cat-badge">{cat}: {count}</span>'

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ruoyi-Scan 漏洞知识库</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: "Microsoft YaHei", Arial, sans-serif; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); color: #fff; padding: 30px 20px; text-align: center; }}
  .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
  .header p {{ opacity: 0.9; font-size: 14px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 15px; margin-bottom: 24px; }}
  .stat-card {{ background: #fff; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  .stat-num {{ font-size: 32px; font-weight: bold; color: #2c3e50; }}
  .stat-label {{ font-size: 13px; color: #7f8c8d; margin-top: 5px; }}
  .toolbar {{ background: #fff; padding: 16px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  .search-box {{ width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: 6px; font-size: 14px; outline: none; transition: border 0.3s; }}
  .search-box:focus {{ border-color: #3498db; }}
  .filters {{ margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
  .filter-label {{ font-size: 13px; color: #7f8c8d; margin-right: 5px; }}
  .filter-btn {{ padding: 4px 12px; border: 1px solid #ddd; background: #fff; border-radius: 4px; cursor: pointer; font-size: 12px; transition: all 0.3s; }}
  .filter-btn:hover {{ background: #f0f0f0; }}
  .filter-btn.active {{ background: #3498db; color: #fff; border-color: #3498db; }}
  .cat-badges {{ margin-top: 8px; }}
  .cat-badge {{ display: inline-block; padding: 2px 10px; background: #ecf0f1; border-radius: 3px; font-size: 12px; color: #7f8c8d; margin-right: 5px; margin-bottom: 4px; }}
  .vuln-list {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 15px; }}
  .vuln-card {{ background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); transition: transform 0.2s, box-shadow 0.2s; cursor: pointer; }}
  .vuln-card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 16px rgba(0,0,0,0.12); }}
  .card-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }}
  .vuln-name {{ font-weight: bold; font-size: 14px; flex: 1; }}
  .vuln-cve {{ font-size: 11px; color: #8e44ad; font-family: Consolas, monospace; }}
  .card-meta {{ font-size: 12px; color: #7f8c8d; display: flex; flex-wrap: wrap; gap: 12px; }}
  .meta-item {{ white-space: nowrap; }}
  .card-module {{ font-size: 11px; color: #bdc3c7; margin-top: 8px; font-family: Consolas, monospace; }}
  .empty {{ text-align: center; color: #999; padding: 40px; }}
  .footer {{ text-align: center; padding: 20px; color: #95a5a6; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
    <h1>Ruoyi-Scan 漏洞知识库</h1>
    <p>共 {stats["total"]} 个漏洞 · {stats["with_cve"]} 个含 CVE · {stats["with_fix_detail"]} 个含修复详情 · {stats["with_reproduce"]} 个含复现命令</p>
</div>

<div class="container">
    {stats_html}

    <div class="toolbar">
        <input type="text" class="search-box" id="searchBox" placeholder="搜索漏洞名称、CVE、类别..." oninput="filterCards()">
        <div class="filters">
            <span class="filter-label">严重度:</span>
            <button class="filter-btn active" data-filter="severity" data-value="all" onclick="toggleFilter(this)">全部</button>
            <button class="filter-btn" data-filter="severity" data-value="high" onclick="toggleFilter(this)">高危</button>
            <button class="filter-btn" data-filter="severity" data-value="medium" onclick="toggleFilter(this)">中危</button>
            <button class="filter-btn" data-filter="severity" data-value="low" onclick="toggleFilter(this)">低危</button>
        </div>
        <div class="filters" style="margin-top: 8px">
            <span class="filter-label">合规:</span>
            <button class="filter-btn active" data-filter="compliance" data-value="all" onclick="toggleFilter(this)">全部</button>
            <button class="filter-btn" data-filter="compliance" data-value="OWASP" onclick="toggleFilter(this)">OWASP</button>
            <button class="filter-btn" data-filter="compliance" data-value="等保" onclick="toggleFilter(this)">等保 2.0</button>
        </div>
        <div class="cat-badges">
            <span class="filter-label">类别分布:</span>
            {category_stats}
        </div>
    </div>

    <div class="vuln-list" id="vulnList">
        {cards_html}
    </div>
</div>

<div class="footer">
    Generated by Ruoyi-Scan · {stats["total"]} vulnerabilities
</div>

<script>
// 前端筛选（无需后端）
const activeFilters = {{ severity: 'all', compliance: 'all' }};

function toggleFilter(btn) {{
    const filterType = btn.dataset.filter;
    const filterValue = btn.dataset.value;

    // 更新按钮状态
    document.querySelectorAll(`[data-filter="${{filterType}}"]`).forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    activeFilters[filterType] = filterValue;
    filterCards();
}}

function filterCards() {{
    const searchTerm = document.getElementById('searchBox').value.toLowerCase();
    const cards = document.querySelectorAll('.vuln-card');

    cards.forEach(card => {{
        const name = card.dataset.name || '';
        const cve = card.dataset.cve || '';
        const severity = card.dataset.severity || '';
        const category = card.dataset.category || '';
        const compliance = card.dataset.compliance || '';

        // 搜索匹配
        const matchSearch = !searchTerm ||
            name.includes(searchTerm) ||
            cve.toLowerCase().includes(searchTerm) ||
            category.toLowerCase().includes(searchTerm);

        // 严重度筛选
        const matchSeverity = activeFilters.severity === 'all' || severity === activeFilters.severity;

        // 合规筛选
        const matchCompliance = activeFilters.compliance === 'all' ||
            compliance.includes(activeFilters.compliance.toLowerCase());

        if (matchSearch && matchSeverity && matchCompliance) {{
            card.style.display = '';
        }} else {{
            card.style.display = 'none';
        }}
    }});
}}
</script>
</body>
</html>"""


def render_wiki_json(plugins: List[Dict[str, Any]]) -> str:
    """渲染知识库 JSON（供 API 调用）

    Args:
        plugins: 插件元数据列表
    Returns:
        JSON 字符串
    """
    import json

    data = build_wiki_data(plugins)
    return json.dumps(data, ensure_ascii=False, indent=2)


def generate_wiki(output_path: str, formats: List[str] = None) -> List[str]:
    """生成漏洞知识库

    Args:
        output_path: 输出文件路径（HTML）或目录
        formats: 输出格式列表（['html', 'json']）
    Returns:
        生成的文件路径列表
    """
    from lib.plugin_sdk import list_all_plugins

    if formats is None:
        formats = ["html"]

    plugins = list_all_plugins()
    generated = []

    # HTML 知识库
    if "html" in formats:
        html_content = render_wiki_html(plugins)
        html_path = output_path
        if not html_path.endswith(".html"):
            import os

            os.makedirs(html_path, exist_ok=True)
            html_path = os.path.join(html_path, "vuln_wiki.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        generated.append(html_path)

    # JSON 知识库
    if "json" in formats:
        json_content = render_wiki_json(plugins)
        import os

        # 按 output_path 是文件还是目录推导 JSON 输出路径，兼容 HTML 文件/目录两种传参
        json_dir = os.path.dirname(output_path) or "."
        os.makedirs(json_dir, exist_ok=True)
        if output_path.endswith(".html"):
            json_path = output_path.replace(".html", ".json")
        elif os.path.isdir(output_path):
            json_path = os.path.join(output_path, "vuln_wiki.json")
        else:
            json_path = output_path if output_path.endswith(".json") else output_path + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_content)
        generated.append(json_path)

    return generated
