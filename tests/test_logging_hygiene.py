# -*- coding: utf-8 -*-
"""输出规范门禁：库代码不得直接 print，必须走 lib/reporter.emit()。

存在意义
========
插件与 core 原先在 `verify()` 内直接 `print()` 进度行。这在 CLI 下没问题，
但在 API sidecar / 桌面端 / 测试中会污染输出：误报基线测试单次执行
51 插件 × 多条语料，此前向 stdout 倾倒约 2.39 MB 文本，把真正的失败信息淹没。

本文件把「输出必须走单一出口」固化为可回归的门禁：

  1. AST 静态门禁：`plugins/**`、`lib/**`、`core/**` 中出现**隐式写 stdout 的裸 `print()`** 即失败。
     （docstring / 字符串字面量里的 print 不算；显式 `print(..., file=<流>)` 也不算——
     它按调用方提供的流输出，不污染 stdout）
  2. 行为门禁：静默模式下 `emit()` 不写 stdout；CLI 模式下保持原样输出。
  3. 端到端门禁：静默模式下真正跑一遍全插件基线，stdout 必须为空——
     用于兜住「有人绕过 emit() 直接写 sys.stdout」这类情况。

关于函数名
==========
桥函数名是 `emit` 而非 `report`：`report` 在本项目里是高频局部变量名
（扫描结果字典，见 lib/ai_generator、lib/cve_sync、lib/distributed、core/dedup 等
7 个文件 9 处绑定）。若命名为 `report`，这些文件里 `report = ...` 之后的
`report(...)` 会抛 `TypeError: 'dict' object is not callable`。
`test_reporter_does_not_export_ambiguous_report_name` 会拦住重新引入该别名。

维护约定
========
- 新增插件/库/核心模块需要输出进度时，`from lib.reporter import emit` 后调用 `emit(...)`。
- `cli/**` 是 stdout 呈现层（banner、结果表格、帮助），允许并应当直接 print，
  因此不在本门禁的检查范围内。
"""

import ast
import logging
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# 需强制「不得直接 print」的目录（相对仓库根）
GUARDED_DIRS = ("plugins", "lib", "core")

# 允许例外：{相对路径: 原因}。目标状态是仅剩输出桥自身。
ALLOWED_DIRECT_PRINT: dict[str, str] = {
    "lib/reporter.py": "输出桥的实现本体：CLI 模式必须真正写 stdout，这是唯一的合法 print",
}


def _guarded_files() -> list[pathlib.Path]:
    """收集受检查的 Python 源文件"""
    files = []
    for d in GUARDED_DIRS:
        files.extend(sorted((ROOT / d).rglob("*.py")))
    return files


def _find_print_calls(path: pathlib.Path) -> list[int]:
    """返回文件中「隐式写 stdout 的 print()」调用行号列表

    基于 AST 而非文本匹配，两条精确规则：
      1. docstring / 字符串字面量中出现的 `print(` 不是调用节点，不会误报
         （例如 plugins/common/redis_unauth.py 的 PoC 字符串、
         core/portscan.py 的用法示例）。
      2. 显式带 `file=` 的 print 不写 stdout——它是「按调用方提供的流输出」，
         属合法用法（如 lib/star_cta.py 的 stream 参数契约）。
         本门禁只针对隐式写 stdout 的裸 print。
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return []
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
            if any(kw.arg == "file" for kw in node.keywords):
                continue  # 写往显式指定的流，不污染 stdout
            hits.append(node.lineno)
    return hits


@pytest.mark.parametrize("path", _guarded_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_library_code_does_not_call_print_directly(path):
    """库代码（plugins / lib / core）不得直接调用 print()，必须走 lib/reporter.emit()"""
    rel = str(path.relative_to(ROOT)).replace("\\", "/")
    if rel in ALLOWED_DIRECT_PRINT:
        pytest.skip(f"已在白名单登记：{ALLOWED_DIRECT_PRINT[rel]}")
    lines = _find_print_calls(path)
    assert not lines, (
        f"{rel} 存在直接 print() 调用，行号 {lines}。\n"
        f"库代码必须使用 lib/reporter.emit()，否则会污染 API 服务日志与测试输出。"
    )


def test_reporter_does_not_export_ambiguous_report_name():
    """护栏：不得重新引入 `report` 别名

    `report` 在 lib/ 与 core/ 中被广泛用作局部变量（扫描结果字典）。
    一旦把桥函数命名为 report（或以别名形式导出），
    `report = master.aggregate_results(...)` 之后的 `report(...)` 会立即抛
    TypeError: 'dict' object is not callable。此护栏防止该命名被重新引入。
    """
    import lib.reporter as reporter_module

    assert hasattr(reporter_module, "emit"), "输出桥必须提供 emit()"
    assert not hasattr(reporter_module, "report"), (
        "lib.reporter 不得导出 report 名称：它会与 lib/ 中大量名为 report 的局部变量冲突，"
        "导致 'dict' object is not callable 运行时错误。请使用 emit()。"
    )


# ── 行为门禁 ────────────────────────────────────────────────────


@pytest.fixture
def reporter_mode():
    """保存并恢复 reporter 模式，避免用例之间相互影响"""
    from lib.reporter import is_quiet, set_quiet

    saved = is_quiet()

    def _switch(quiet: bool) -> None:
        set_quiet(quiet)

    yield _switch
    set_quiet(saved)


def test_quiet_mode_writes_nothing_to_stdout(capsys, reporter_mode):
    """静默模式：emit() 不得写 stdout"""
    from lib.colors import ok
    from lib.reporter import emit

    reporter_mode(True)
    emit(ok("存在测试漏洞"))
    assert capsys.readouterr().out == ""


def test_cli_mode_preserves_stdout_and_colors(capsys, reporter_mode):
    """CLI 模式（默认）：输出形态与迁移前的 print() 完全一致（含 ANSI 与 [*] 前缀）"""
    from lib.colors import ok
    from lib.reporter import emit

    reporter_mode(False)
    emit(ok("存在测试漏洞"))
    out = capsys.readouterr().out
    assert "[*]" in out, "CLI 模式必须保留 [*] 前缀"
    assert "存在测试漏洞" in out
    assert "\033[" in out, "CLI 模式必须保留 ANSI 颜色"


def test_quiet_mode_routes_to_logger_without_ansi(caplog, reporter_mode):
    """静默模式：内容以 DEBUG 级别进日志，且 ANSI 转义必须被剥离"""
    from lib.colors import ok
    from lib.reporter import emit

    reporter_mode(True)
    with caplog.at_level(logging.DEBUG, logger="lib.reporter"):
        emit(ok("存在测试漏洞"))

    messages = [r.getMessage() for r in caplog.records]
    assert any("存在测试漏洞" in m for m in messages), f"静默模式下应仍可从日志读到内容，实际 {messages}"
    assert not any("\033[" in m for m in messages), "日志中不得混入 ANSI 转义序列"


def test_emit_is_print_compatible_multiple_args(capsys, reporter_mode):
    """emit() 签名与 print 兼容：支持多参数与 sep"""
    from lib.reporter import emit

    reporter_mode(False)
    emit("a", "b", sep="-")
    assert capsys.readouterr().out == "a-b\n"


# ── 端到端门禁 ──────────────────────────────────────────────────


def test_full_plugin_baseline_produces_no_stdout(capsys, reporter_mode):
    """端到端：静默模式下真正执行全部插件，stdout 必须为空

    覆盖 AST 门禁无法发现的情况——例如有人直接写 `sys.stdout.write(...)`，
    或第三方库向 stdout 打印。这是「输出单一出口」的最后一道保险。
    """
    from lib.reporter import emit  # noqa: F401  确保模块已加载
    from tests.test_fp_baseline import BENIGN_CASES, _run_baseline

    reporter_mode(True)
    capsys.readouterr()  # 清空既有缓冲
    _run_baseline(BENIGN_CASES["generic_html"])
    out = capsys.readouterr().out
    assert out == "", f"静默模式下执行全部插件不得产生 stdout 输出，实际前 300 字符：{out[:300]!r}"
