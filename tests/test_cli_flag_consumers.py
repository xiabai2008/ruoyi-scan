"""CLI 开关可达性门禁（v1.8 清理）。

背景：项目曾一次性新增 31 个参数组 / 127 个开关，其中 --lang、--cache*、
--no-components、--oast、--web-ui*、--proxy-rotate 等没有任何消费方，
只有测试在跑——用户按文档传参却什么也不发生。本测试把"每个开关必须有
消费方"固化为门禁，防止同类债再次长出来。

判定用 AST 而不是文本正则：
- 注释/文档字符串里的 args.xxx 不算消费；
- vars(args) 整体转储是调试写法，不算某个开关被消费；
- 支持 args.x、getattr(args, "x")、hasattr(args, "x")、vars(args)["x"]。

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


def _is_args(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "args"


def _consumed_in(paths, dest: str) -> bool:
    """在给定文件集合中查找 dest 的真实消费点（AST 级）。"""
    for path in paths:
        try:
            tree = ast.parse(Path(path).read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == dest and _is_args(node.value):
                return True
            if isinstance(node, ast.Call) and len(node.args) >= 2:
                func = node.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                if name in ("getattr", "hasattr") and _is_args(node.args[0]):
                    arg = node.args[1]
                    if isinstance(arg, ast.Constant) and arg.value == dest:
                        return True
            if isinstance(node, ast.Subscript):
                value = node.value
                slice_node = node.slice
                if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "vars":
                    if value.args and _is_args(value.args[0]):
                        if isinstance(slice_node, ast.Constant) and slice_node.value == dest:
                            return True
    return False


def _consumed(dest: str) -> bool:
    return _consumed_in(_source_files(), dest)


def test_every_cli_flag_has_a_consumer():
    missing = {dest: line for dest, line in _parser_dests().items() if dest not in ALLOW and not _consumed(dest)}
    assert not missing, "以下 CLI 开关没有任何消费方（用户传了也不会生效）：%s" % missing


def test_consumer_gate_ignores_comments_and_vars_dump(tmp_path):
    """门禁自身的回归：注释提及和 vars(args) 整体转储都不算消费。"""
    f = tmp_path / "fake.py"
    f.write_text(
        "def dump(args):\n"
        "    # TODO: args.brand_new_flag 还没实现\n"
        "    return vars(args)\n",
        encoding="utf-8",
    )
    assert not _consumed_in([f], "brand_new_flag")

    f.write_text("def use(args):\n    return getattr(args, 'brand_new_flag')\n", encoding="utf-8")
    assert _consumed_in([f], "brand_new_flag")


def test_framework_choices_are_derived_from_plugin_packages():
    """--framework（兼容别名 --category）必须接受所有已发现的插件包。

    v1.6 曾因写死三元组拒绝 jeecgboot；v1.8 清理后规范名为 --framework。
    """
    from core.loader import known_categories
    from main import build_parser

    cats = known_categories()
    assert cats, "未发现任何插件包"
    parser = build_parser()
    for cat in cats:
        ns = parser.parse_args(["--plugin-init", "demo", "--framework", cat])
        assert ns.framework == cat
        # 旧别名仍可用
        assert parser.parse_args(["--plugin-init", "demo", "--category", cat]).framework == cat

def test_getattr_args_names_match_parser_dests():
    """getattr(args, "literal") 的字面量必须是 parser 的 dest，防止改名后静默回退。"""
    dests = set(_parser_dests())
    stale = set()
    for path in _source_files():
        try:
            tree = ast.parse(Path(path).read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            if node.func.id != "getattr" or len(node.args) < 2:
                continue
            if not _is_args(node.args[0]):
                continue
            arg = node.args[1]
            if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                continue
            # 下划线开头是运行期内部属性（如 args._crawl_endpoints），不是 parser dest
            if arg.value.startswith("_"):
                continue
            if arg.value not in dests:
                stale.add(arg.value)
    assert not stale, "getattr(args, ...) 读取了 parser 不存在的 dest（改名后的静默回退）：%s" % sorted(stale)
