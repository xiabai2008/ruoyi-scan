# D19：扫描模板（预设策略）
#
# 提供预置扫描模板，用户通过 --template <name> 选择：
#   quick       快速扫描（仅高危插件 + 目录扫描，约 1-2 分钟）
#   deep        深度扫描（全插件 + 爬虫 + JS 提取 + 子域名，约 10-30 分钟）
#   compliance  合规扫描（仅含 OWASP 映射的插件，输出合规报告）
#   dengbao     等保扫描（仅含等保 2.0 映射的插件，输出等保报告）
#
# 模板可覆盖：
#   1. 插件过滤规则（severity/category/compliance 筛选）
#   2. CLI 默认参数（crawl/subdomain/js_extract/threads 等）
#   3. 报告模式标签
#
# 设计原则：
#   - 模板不破坏现有 CLI 参数，仅作为"预设组合"
#   - 用户显式指定的 CLI 参数优先于模板默认值
#   - 模板可叠加（如 --template quick --subdomain）
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class ScanTemplate:
    """扫描模板定义

    Attributes:
        name: 模板标识（CLI 用 --template <name>）
        display_name: 中文显示名
        description: 模板描述
        severity_filter: 插件严重度过滤（空=不过滤；{'high'} 只跑高危）
        category_filter: 插件类别过滤（空=不过滤；{'vuln'} 只跑漏洞类）
        compliance_filter: 合规映射过滤（空=不过滤；{'OWASP'} 只跑含 OWASP 的）
        default_args: 模板默认 CLI 参数（用户未显式指定时生效）
        estimated_time: 预估耗时（描述性字符串）
        report_label: 报告模式标签（覆盖默认 mode 标签）
    """

    name: str
    display_name: str
    description: str
    severity_filter: Set[str] = field(default_factory=set)
    category_filter: Set[str] = field(default_factory=set)
    compliance_filter: Set[str] = field(default_factory=set)
    default_args: Dict[str, Any] = field(default_factory=dict)
    estimated_time: str = ""
    report_label: str = ""


# ============================================================
# 预置模板定义
# ============================================================

TEMPLATES: Dict[str, ScanTemplate] = {
    "quick": ScanTemplate(
        name="quick",
        display_name="快速扫描",
        description=("仅执行高危漏洞检测 + 目录扫描，跳过低危和信息泄露类插件。适合快速评估目标是否存在严重漏洞。"),
        severity_filter={"high"},  # 只跑高危
        category_filter=set(),  # 不限类别（vuln + recon + brute 都跑）
        compliance_filter=set(),
        default_args={
            "threads": 5,
            "timeout": 8,
            "crawl": False,
            "subdomain": False,
            "js_extract": False,
        },
        estimated_time="1-3 分钟",
        report_label="快速扫描",
    ),
    "deep": ScanTemplate(
        name="deep",
        display_name="深度扫描",
        description=("全量插件扫描 + 主动爬虫（深度 3）+ JS 端点提取 + 子域名枚举。发现面最广，适合全面安全评估。"),
        severity_filter=set(),  # 不过滤严重度
        category_filter=set(),  # 不过滤类别
        compliance_filter=set(),
        default_args={
            "threads": 3,
            "timeout": 15,
            "crawl": True,
            "crawl_depth": 3,
            "crawl_max_pages": 100,
            "subdomain": True,
            "js_extract": True,
        },
        estimated_time="10-30 分钟",
        report_label="深度扫描",
    ),
    "compliance": ScanTemplate(
        name="compliance",
        display_name="OWASP 合规扫描",
        description=("仅执行含 OWASP Top 10 映射的漏洞插件，生成 OWASP 合规报告。适合合规审计场景。"),
        severity_filter=set(),
        category_filter={"vuln"},  # 只跑漏洞类
        compliance_filter={"OWASP"},  # 只跑含 OWASP 映射的
        default_args={
            "threads": 3,
            "timeout": 10,
            "crawl": False,
            "subdomain": False,
            "js_extract": False,
        },
        estimated_time="5-10 分钟",
        report_label="OWASP 合规扫描",
    ),
    "dengbao": ScanTemplate(
        name="dengbao",
        display_name="等保 2.0 合规扫描",
        description=("仅执行含等保 2.0 映射的漏洞插件，生成等保合规报告。适合等级保护测评场景。"),
        severity_filter=set(),
        category_filter={"vuln"},
        compliance_filter={"等保"},  # 只跑含等保映射的
        default_args={
            "threads": 3,
            "timeout": 10,
            "crawl": False,
            "subdomain": False,
            "js_extract": False,
        },
        estimated_time="5-10 分钟",
        report_label="等保 2.0 合规扫描",
    ),
}


def get_template(name: str) -> Optional[ScanTemplate]:
    """按名称获取模板

    Args:
        name: 模板名称（quick/deep/compliance/dengbao）
    Returns:
        ScanTemplate 或 None（未找到）
    """
    return TEMPLATES.get(name)


def list_templates() -> List[ScanTemplate]:
    """列出所有可用模板"""
    return list(TEMPLATES.values())


def apply_template(args, template_name: str, verbose: bool = True) -> Optional[ScanTemplate]:
    """将模板默认参数应用到 args 对象

    规则：用户显式指定的 CLI 参数优先，模板仅填充未指定的参数。

    判定"用户是否显式指定"的逻辑：
        - argparse 的 default 值视为"未显式指定"
        - 布尔 flag（store_true）：default=False 时，值为 True 视为显式指定
        - 数值参数：与 default 相同视为未显式指定

    Args:
        args: argparse.Namespace 对象
        template_name: 模板名称
        verbose: 是否打印应用日志
    Returns:
        应用的 ScanTemplate，或 None（模板不存在）
    """
    tmpl = get_template(template_name)
    if tmpl is None:
        return None

    if verbose:
        print(f"  [*]应用模板: {tmpl.display_name}（{tmpl.estimated_time}）")
        print(f"      {tmpl.description}")

    # 应用模板默认参数（仅填充未显式指定的）
    parser_defaults = _get_parser_defaults()
    for key, tmpl_value in tmpl.default_args.items():
        current_value = getattr(args, key, None)
        default_value = parser_defaults.get(key)
        # 当前值与默认值相同 → 用户未显式指定 → 应用模板值
        if current_value == default_value:
            setattr(args, key, tmpl_value)
            if verbose:
                print(f"      {key}: {current_value} → {tmpl_value}")

    return tmpl


def filter_plugins(plugins: List, template: ScanTemplate) -> List:
    """按模板规则过滤插件列表

    Args:
        plugins: 插件类列表
        template: 扫描模板
    Returns:
        过滤后的插件类列表
    """
    if not template:
        return plugins

    filtered = []
    for cls in plugins:
        # 按严重度过滤
        if template.severity_filter:
            severity = getattr(cls, "severity", "")
            if severity not in template.severity_filter:
                continue

        # 按类别过滤
        if template.category_filter:
            category = getattr(cls, "category", "")
            if category not in template.category_filter:
                continue

        # 按合规映射过滤
        if template.compliance_filter:
            # compliance 可能为 None，用 or '' 兜底，避免后续 std in compliance 抛 TypeError
            compliance = getattr(cls, "compliance", "") or ""
            # compliance 格式：'等保2.0:8.1.4;OWASP:A01:2021'
            # 检查是否包含目标合规标准
            matched = False
            for std in template.compliance_filter:
                # 子串匹配而非全等：'OWASP' 可命中 'OWASP:A01:2021' 这类带编号的映射
                if std in compliance:
                    matched = True
                    break
            if not matched:
                continue

        filtered.append(cls)

    return filtered


# ============================================================
# 内部工具
# ============================================================

# 缓存 argparse 默认值（用于判断用户是否显式指定参数）
_parser_defaults_cache: Optional[Dict[str, Any]] = None


def _get_parser_defaults() -> Dict[str, Any]:
    """获取 main.py build_parser() 的默认值映射

    通过导入 main 模块的 build_parser 来获取默认值。
    缓存避免重复构建。
    """
    global _parser_defaults_cache
    if _parser_defaults_cache is not None:
        return _parser_defaults_cache

    try:
        # 延迟导入避免循环依赖
        import main as _main

        parser = _main.build_parser()
        _parser_defaults_cache = dict(vars(parser.parse_args([])))
    except Exception:
        # 回退：空映射（所有参数视为"未显式指定"）
        _parser_defaults_cache = {}

    return _parser_defaults_cache


def set_parser_defaults(defaults: Dict[str, Any]):
    """注入 argparse 默认值（测试用）

    测试时可不依赖 main.py 直接注入默认值映射。
    """
    global _parser_defaults_cache
    _parser_defaults_cache = dict(defaults)
