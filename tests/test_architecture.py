"""架构约束门禁：把"新人必须靠口头传承的规则"变成 CI 断言。

覆盖三类规则：
1. 依赖方向：common 不依赖上层；core/lib/plugins/chains 不反向依赖 cli/api。
2. 函数规模：新增函数不得超过 150 行（存量巨函数按 qualname 记录上限，只减不增）。
3. 帮助文本：--help 必须按选项行覆盖 parser 里的每个 action（别名只需显示一个）。
"""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAYER_DIRS = ("common", "core", "lib", "cli", "api", "plugins", "chains")
MAX_FUNC_LINES = 150

# 存量超限函数：key = "相对路径:qualname"，value = 当前行数上限。
# 只允许缩小；拆分完成后必须从表中删除，否则 test_no_new_god_functions 会报 stale。
LEGACY_LONG_FUNCTIONS = {
    "main.py:build_parser": 382,
    "core/engine.py:ScanEngine.run": 219,
    "core/orchestrator.py:ScanOrchestrator._run": 317,
    "core/orchestrator.py:ScanOrchestrator._run_recon": 151,
    "core/report.py:ReportBuilder.to_html": 279,
    "core/report_docx.py:render_docx": 238,
    "core/report_pdf.py:render_pdf": 206,
    "lib/vuln_wiki.py:render_wiki_html": 228,
    "cli/dispatcher.py:dispatch": 166,
    "cli/runner.py:_cli_event_handler": 194,
    "cli/runner.py:run_mode": 219,
    "cli/runner.py:run_mode_batch": 153,
    "plugins/ruoyi/cve_2025_70986_select_dept_tree.py:Cve202570986SelectDeptTreePlugin.verify": 209,
    "plugins/ruoyi/default_password.py:DefaultPasswordPlugin.verify": 228,
    "plugins/ruoyi/job_invoke_target.py:JobInvokeTargetPlugin.verify": 158,
    "plugins/ruoyi/job_rce.py:JobRcePlugin.verify": 207,
    "plugins/ruoyi/sql_inject_role.py:SqlInjectRolePlugin.verify": 160,
}

# 依赖方向：key 不得 import value 中的顶层包（除自身）
FORBIDDEN = {
    "common": {"core", "lib", "cli", "api", "plugins", "chains", "config"},
    "core": {"cli", "api"},
    "lib": {"cli", "api"},
    "plugins": {"cli", "api"},
    "chains": {"cli", "api"},
}


def _iter_py(layer: str):
    for p in (ROOT / layer).rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        yield p


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # 相对导入：按层级解析到顶层包名，否则 from ..cli import x 会漏网
                parts = list(path.relative_to(ROOT).parent.parts)
                keep = len(parts) - (node.level - 1)
                base = parts[:keep] if keep > 0 else []
                if node.module:
                    base += node.module.split(".")
                if base:
                    yield base[0]
                else:
                    for alias in node.names:
                        yield alias.name.split(".")[0]
                continue
            if node.module:
                yield node.module.split(".")[0]
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in ("import_module", "__import__") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    yield arg.value.split(".")[0]


def _long_functions(path: Path):
    """产出 (qualname, 行数)，包含类方法与嵌套函数。"""
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))

    def walk(node, prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = prefix + child.name
                yield qualname, child.end_lineno - child.lineno + 1
                yield from walk(child, qualname + ".")
            elif isinstance(child, ast.ClassDef):
                yield from walk(child, prefix + child.name + ".")
            else:
                yield from walk(child, prefix)

    yield from walk(tree)


def _all_source_files():
    for layer in LAYER_DIRS:
        yield from _iter_py(layer)
    yield ROOT / "main.py"


def test_layer_dependency_direction():
    violations = []
    for layer, forbidden in FORBIDDEN.items():
        for path in _iter_py(layer):
            for mod in _imports(path):
                if mod in forbidden:
                    violations.append(f"{path.relative_to(ROOT).as_posix()} -> {mod}")
    assert not violations, "依赖方向违规（下层反向依赖上层）：\n" + "\n".join(sorted(violations))


def test_no_new_god_functions():
    offenders = {}
    for path in _all_source_files():
        rel = path.relative_to(ROOT).as_posix()
        try:
            for qualname, size in _long_functions(path):
                if size > MAX_FUNC_LINES:
                    offenders[f"{rel}:{qualname}"] = size
        except SyntaxError:
            continue

    new = sorted(
        f"{key}（{size} 行）"
        for key, size in offenders.items()
        if size > LEGACY_LONG_FUNCTIONS.get(key, MAX_FUNC_LINES)
    )
    stale = sorted(key for key in LEGACY_LONG_FUNCTIONS if key not in offenders)
    assert not new, "新增或变长的巨函数，请拆分（或仅存量可登记精确上限）：\n" + "\n".join(new)
    assert not stale, "以下存量巨函数已拆分到 150 行以内，请从 LEGACY_LONG_FUNCTIONS 删除：\n" + "\n".join(stale)


def test_help_covers_every_long_option(capsys):
    """帮助文本由 parser 生成后，每个 action 至少有一个长选项出现在 --help 中。

    用行首锚定而不是子串匹配：否则 --report 会因 --report-format 那一行而假通过。
    同一 action 的别名（如 --framework/--category）只要求显示其中一个。
    """
    from main import build_parser, print_help

    parser = build_parser()
    print_help()
    out = capsys.readouterr().out
    missing = []
    for action in parser._actions:
        longs = [o for o in action.option_strings if o.startswith("--")]
        if not longs or action.dest in ("help", "version"):
            continue
        if not any(re.search(r"(?m)^\s*" + re.escape(o) + r"(?:\s|$)", out) for o in longs):
            missing.extend(longs)
    assert not missing, "以下长选项未出现在 --help 中：%s" % sorted(missing)
