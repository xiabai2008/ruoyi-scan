"""CLI 开关可达性门禁（v1.8 清理）。

背景：项目曾一次性新增 31 个参数组 / 127 个开关，其中 --lang、--cache*、
--no-components、--oast、--web-ui*、--proxy-rotate 等**没有任何消费方**，
只有测试在跑——用户按文档传参却什么也不发生。本测试把"每个开关必须有
消费方"固化为门禁，防止同类债再次长出来。

允许的例外：
- help / version：argparse 内建动作，不需要业务消费方；
- 模式开关 u/m/p/l：dispatcher 通过 _MODE_ARGS 元组统一处理（非逐名读取）。
"""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOW = {"help", "version", "u", "m", "p", "l"}
SOURCE_DIRS = ("cli", "core", "lib", "api", "common", "config", "plugins", "chains")


def _parser_dests():
    """解析 main.py 的 add_argument，返回 {dest: lineno}。"""
    tree = ast.parse((ROOT / "main.py").read_text(encoding="utf-8"))
    dests = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "add_argument":
            continue
        opts = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        dest = None
        for kw in node.keywords:
            if kw.arg == "dest" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                dest = kw.value.value
        if dest is None:
            longs = [o for o in opts if o.startswith("--")]
            if longs:
                dest = longs[0][2:].replace("-", "_")
            else:
                shorts = [o for o in opts if re.fullmatch(r"-[A-Za-z]", o)]
                if shorts:
                    dest = shorts[0][1:]
        if dest:
            dests[dest] = node.lineno
    return dests


def _source_files():
    for d in SOURCE_DIRS:
        yield from (ROOT / d).rglob("*.py")
    yield ROOT / "main.py"


def _consumed(dest):
    pats = (
        re.compile(r"\bargs\." + re.escape(dest) + r"\b"),
        re.compile(r"getattr\(\s*args\s*,\s*['\"]" + re.escape(dest) + r"['\"]"),
        re.compile(r"vars\(args\)"),
    )
    for path in _source_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(p.search(text) for p in pats):
            return True
    return False


def test_every_cli_flag_has_a_consumer():
    missing = {dest: line for dest, line in _parser_dests().items() if dest not in ALLOW and not _consumed(dest)}
    assert not missing, "以下 CLI 开关没有任何消费方（用户传了也不会生效）：%s" % missing


def test_category_choices_are_derived_from_plugin_packages():
    """--category 必须接受所有已发现的插件包（v1.6 曾因写死三元组拒绝 jeecgboot）。"""
    from core.loader import known_categories
    from main import build_parser

    cats = known_categories()
    assert cats, "未发现任何插件包"
    parser = build_parser()
    for cat in cats:
        ns = parser.parse_args(["--plugin-init", "demo", "--category", cat])
        assert ns.category == cat
