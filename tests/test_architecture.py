"""架构约束门禁：把"新人必须靠口头传承的规则"变成 CI 断言。

覆盖三类规则：
1. 依赖方向：common 不依赖上层；core/lib/plugins/chains 不反向依赖 cli/api。
2. 函数规模：新增函数不得超过 150 行（存量巨函数列在白名单，只减不增）。
3. 帮助文本：--help 必须覆盖 parser 里的全部长选项（防止手写表再次漂移）。
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAYER_DIRS = ("common", "core", "lib", "cli", "api", "plugins", "chains")
MAX_FUNC_LINES = 150

# 存量超限函数白名单：重构完成一项就删一项，不允许新增。
LEGACY_LONG_FUNCTIONS = {
    "cli/runner.py:run_mode",
    "core/orchestrator.py:_run",
    "core/report.py:to_html",
    "core/report_docx.py:render_docx",
    "plugins/ruoyi/default_password.py:verify",
    "lib/vuln_wiki.py:render_wiki_html",
    "core/report_pdf.py:render_pdf",
    "plugins/ruoyi/job_rce.py:verify",
    "plugins/ruoyi/cve_2025_70986_select_dept_tree.py:verify",
    "core/orchestrator.py:_stage_load_plugins",
    "cli/runner.py:_cli_event_handler",
    "core/engine.py:run",
    "cli/dispatcher.py:dispatch",
    "plugins/ruoyi/sql_inject_role.py:verify",
    "plugins/ruoyi/job_invoke_target.py:verify",
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
            for a in node.names:
                yield a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            yield node.module.split(".")[0]


def test_layer_dependency_direction():
    violations = []
    for layer, forbidden in FORBIDDEN.items():
        for path in _iter_py(layer):
            for mod in _imports(path):
                if mod in forbidden:
                    violations.append(f"{path.relative_to(ROOT).as_posix()} -> {mod}")
    assert not violations, "依赖方向违规（下层反向依赖上层）：\n" + "\n".join(sorted(violations))


def test_no_new_god_functions():
    offenders = set()
    for layer in LAYER_DIRS:
        for path in _iter_py(layer):
            rel = path.relative_to(ROOT).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                size = node.end_lineno - node.lineno + 1
                if size > MAX_FUNC_LINES:
                    offenders.add(f"{rel}:{node.name}")
    new_offenders = sorted(offenders - LEGACY_LONG_FUNCTIONS)
    assert not new_offenders, "新增函数超过 %d 行，请拆分为多个函数，或（仅存量）加入 LEGACY_LONG_FUNCTIONS：\n%s" % (
        MAX_FUNC_LINES,
        "\n".join(new_offenders),
    )


def test_help_covers_every_long_option(capsys):
    """帮助文本由 parser 生成后，每个长选项都必须出现在 --help 输出中。"""
    from main import build_parser, print_help

    parser = build_parser()
    print_help()
    out = capsys.readouterr().out
    long_options = sorted(o for o in parser._option_string_actions if o.startswith("--"))
    missing = [o for o in long_options if o not in ("--help", "--version") and o not in out]
    assert not missing, "以下长选项未出现在 --help 中：%s" % missing
