# 顶层包名冲突检测（namespace collision guard）
#
# 背景：本项目以非 src-layout 分发，pyproject 的 packages.find.include 覆盖
# common / cli / core / lib / api / plugins / config / chains 共 8 个顶层包名，
# 外加 py-modules = ["main"]。pip install ruoyi-scan 会把这些名字直接放进
# site-packages，与用户项目里同名的顶层包（core / common / lib / cli 这类
# 名字在 Python 生态里极其常见）产生**导入劫持**。
#
# 危害实测（2026-10-29）：
#   用户项目根目录下有 core/http.py 时，`from core.http import join_url`
#   会导入**用户的** core.http 而非本项目的 —— 若签名恰好兼容，
#   扫描器会静默调用错误的函数，行为诡异且无任何报错。
#   若签名不兼容，则在调用处抛 TypeError，栈信息指向用户代码而非本项目，
#   排查成本极高。
#
# 为什么不做「收进 ruoyi_scan/ 单包」的重构：
#   - 1380 处绝对导入（core 307 / lib 548 / plugins 227 / common 217 / 其余 81），
#     且 0 处相对导入，全量机械改写风险高
#   - plugins.base.PluginBase 与 common.models.ScanResult 是 docs/plugin_dev.md
#     公开承诺的第三方插件契约，改包名等于破坏已发布的插件生态
#   - 两个 PyInstaller spec（终端版 + 桌面端引擎）硬编码 8 个顶层包名与
#     plugins/ chains/ web/ assets/ data/ 的磁盘目录，配置错了不报错、
#     只在 exe 运行时才炸，其中「插件自动发现失效 → 扫出 0 个漏洞」最危险
#   - 真实用户多在独立 venv 或桌面端 exe 中运行，本就隔离了命名空间
#
# 因此采取低成本方案：**检测冲突并明确告知用户怎么规避**，而不是改包结构。
#
# 检测原理（关键）：
#   不是「环境里有没有同名包」——那样会误报（用户同名包排在 sys.path 后面时
#   根本不会被导入）。而是**检查实际被解析到的模块是否来自本项目自己的包**。
#   用 importlib.util.find_spec 拿每个顶层名当前解析到的位置，
#   与本项目自身的包根目录比对；不一致即说明发生了劫持。

from __future__ import annotations

import os
import sys
from typing import List, NamedTuple, Optional

# 本项目会放进 site-packages 的顶层包名（与 pyproject packages.find.include 一致）
# main 是 py-modules，同样会被暴露
PROJECT_TOP_LEVEL = ("common", "cli", "core", "lib", "api", "plugins", "config", "chains", "main")

# 用户生态里最常见、最容易与本项目撞名的前缀
# 这些名字在真实项目里出现频率极高，是冲突的主要来源
COMMON_USER_NAMES = frozenset({"core", "common", "lib", "cli", "api", "config", "plugins", "chains", "main"})


class Conflict(NamedTuple):
    """一处顶层包名冲突"""

    name: str  # 顶层包名（如 "core"）
    expected: str  # 本项目自己的该包位置（应解析到的路径）
    actual: str  # 实际解析到的位置（被劫持时指向用户包）


def _project_root() -> str:
    """本项目自身的根目录（core/ 的父目录）

    必须**不依赖任何可被劫持的顶层包**来定位——本模块自己就住在 lib/ 里，
    如果用 `import core` 来推断根目录，而 core 恰好被用户同名包劫持，
    推出来的根目录就是用户的目录，后续比对全部失真（实测会误报 7 个冲突）。
    因此改用本文件的物理路径：<root>/lib/namespace_guard.py → <root>。
    """
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve(name: str) -> Optional[str]:
    """返回顶层名**按当前 sys.path 顺序**实际会被解析到的路径。

    必须自己按 sys.path 顺序查找，不能直接用 importlib.util.find_spec：
    find_spec 对已存在于 sys.modules 的模块直接返回缓存结果，对未导入的模块
    也可能因为 sys.path 顺序与真实 import 行为不一致而给出误导性结论
    （实测：sys.path 里项目路径在前时 find_spec 返回项目自己的包，
    但真实的 pip 安装场景是 site-packages 在后、用户工作目录在前）。

    这里用 PathFinder.find_spec(name, path) 传 None 作为 path，
    让它按 sys.path 的完整顺序逐项查找——这正是 CPython import 机制的行为。
    """
    from importlib.machinery import PathFinder

    try:
        spec = PathFinder.find_spec(name, None)
    except (ImportError, ValueError, AttributeError, TypeError):
        spec = None

    if spec is not None:
        if spec.origin:
            return os.path.abspath(spec.origin)
        locations = list(getattr(spec, "submodule_search_locations", None) or [])
        if locations:
            return os.path.abspath(locations[0])

    # PathFinder 找不到（命名空间包等边缘情况）时退回 sys.modules
    mod = sys.modules.get(name)
    if mod is not None:
        origin = getattr(mod, "__file__", None)
        if origin:
            return os.path.abspath(origin)
        locations = list(getattr(mod, "__path__", None) or [])
        if locations:
            return os.path.abspath(locations[0])
    return None


def _is_project_copy(path: str, name: str, src_root: str) -> bool:
    """path 指向的顶层包是否是**本项目自己的**一份副本。

    判据不能用「内容相同」：pip 安装的副本与源码树可能不是同一版本
    （用户装的是 1.5.0、源码是 1.5.2），逐字节比必然不等 → 会把本项目的
    正常安装副本误判成冲突（实测误报 7 个）。

    也不宜只看「单个目录」：site-packages 里本项目的副本与用户自己的同名包
    会同时存在，光看目录结构无法区分谁是谁。

    采用组合判据——路径下必须**同时存在本项目的多个标志性顶层包**：
    本项目固定包含 core / lib / plugins / common / cli 五个，用户自己的
    同名包（core、lib 之类）几乎不可能凑齐这五套。
    """
    if _is_under(path, src_root):
        return True

    # path 形如 <root>/<name>/__init__.py 或 <root>/<name>.py，
    # 需要定位到 <root>（包含全部顶层包的目录）：
    #   - <root>/<name>/__init__.py → 去掉两层
    #   - <root>/<name>.py         → 去掉一层
    parent = os.path.dirname(path)  # <root>/<name>  或  <root>
    if os.path.basename(parent) == name:
        parent = os.path.dirname(parent)
    if not parent or not os.path.isdir(parent):
        return False

    signatures = ("core", "lib", "plugins", "common", "cli")
    present = 0
    for sig in signatures:
        sig_dir = os.path.join(parent, sig)
        if os.path.isdir(sig_dir) and os.path.isfile(os.path.join(sig_dir, "__init__.py")):
            present += 1
    # 五个标志性包中至少 4 个在此目录 → 是本项目的安装副本
    return present >= 4


def detect_conflicts(names: Optional[List[str]] = None) -> List[Conflict]:
    """检测顶层包名冲突。

    判据是「实际解析到的模块是不是本项目自己的」——**不是**「环境里有没有
    同名包」。后者会误报：用户的同名包排在 sys.path 后面时根本不会被导入。

    Args:
        names: 要检查的顶层名，默认检查全部 PROJECT_TOP_LEVEL

    Returns:
        冲突列表；无冲突时返回空列表
    """
    if names is None:
        names = list(PROJECT_TOP_LEVEL)

    src_root = _project_root()
    conflicts: List[Conflict] = []

    for name in names:
        actual = _resolve(name)
        if actual is None:
            continue

        # 情况一：解析到本项目源码树内 → 正常（源码运行）
        if _is_under(actual, src_root):
            continue

        # 情况二：解析到 site-packages 等其他位置 → 需要判断那是不是本项目的副本
        if _is_project_copy(actual, name, src_root):
            continue

        # 情况三：解析到了别处，且不是本项目的副本 → 劫持
        conflicts.append(Conflict(name=name, expected=os.path.join(src_root, name), actual=actual))

    return conflicts


def _is_under(path: str, root: str) -> bool:
    """path 是否位于 root 之下（含 root 本身）"""
    try:
        path = os.path.abspath(path)
        root = os.path.abspath(root)
    except (OSError, ValueError):
        return False
    if path == root:
        return True
    return path.startswith(root + os.sep)


def format_conflict_warning(conflicts: List[Conflict]) -> str:
    """把冲突列表格式化成给用户看的告警文本（纯文本，无 ANSI 色）"""
    if not conflicts:
        return ""

    names = sorted({c.name for c in conflicts})
    lines = [
        "",
        "=" * 68,
        "[!] 检测到顶层包名冲突：ruoyi-scan 的内部模块可能被同名包劫持",
        "=" * 68,
    ]

    for c in sorted(conflicts, key=lambda x: x.name):
        lines.append(f"    包名 {c.name}")
        lines.append(f"      应解析到：{c.expected}")
        lines.append(f"      实际解析到：{c.actual}")
    lines.append("")
    lines.append(f"    受影响的顶层名：{', '.join(names)}")
    lines.append("")
    lines.append("    可能后果：")
    lines.append("      · 扫描器内部 from core.xxx / lib.xxx 导入到的是别人的模块")
    lines.append("      · 轻则调用时报难以定位的 TypeError，重则静默调用到错误实现")
    lines.append("")
    lines.append("    解决办法（任选其一，推荐第一条）：")
    lines.append("      1. 用独立虚拟环境安装（最推荐）：")
    lines.append("           python -m venv .venv")
    lines.append("           .venv/Scripts/pip install ruoyi-scan     # Windows")
    lines.append("           .venv/bin/pip install ruoyi-scan         # Linux / macOS")
    lines.append("      2. 确认当前工作目录（以及你运行脚本的目录）下没有 core/ common/ lib/ 等同名目录")
    lines.append("      3. 桌面端单文件版不受影响（引擎已内嵌，无命名空间暴露问题）")
    lines.append("")
    lines.append("=" * 68)
    lines.append("")
    return "\n".join(lines)


def check_and_warn(stream=None) -> List[Conflict]:
    """执行检测，有冲突则打印告警。

    Args:
        stream: 输出流，默认 sys.stderr（告警走 stderr，不污染 stdout 的报告输出）

    Returns:
        冲突列表（无冲突时为空）
    """
    # 冻结环境（PyInstaller exe）：所有模块已内嵌，不存在 site-packages 冲突
    if getattr(sys, "frozen", False):
        return []

    conflicts = detect_conflicts()
    if not conflicts:
        return []

    text = format_conflict_warning(conflicts)
    if stream is None:
        stream = sys.stderr
    try:
        stream.write(text)
        stream.flush()
    except Exception:
        pass
    return conflicts


def check_early() -> List[Conflict]:
    """早期冲突检测（在 main.py 顶部调用）。

    与 check_and_warn 的区别：不走 `from lib.namespace_guard import ...`，
    因此即使 lib/ 已被同名包劫持也能正常工作（检测本身就是为这种场景准备的）。

    Returns:
        冲突列表；无冲突、加载失败或冻结环境时返回空列表
    """
    return check_and_warn()


def main() -> int:
    """命令行入口：python -m lib.namespace_guard"""
    conflicts = check_and_warn()
    if conflicts:
        return 1
    # 库代码禁裸 print()（test_logging_hygiene 门禁）：统一走 lib.reporter.emit。
    # 这里必须**延迟导入且容错**——本模块在早期检测时是按文件路径独立加载的
    # （此时 lib/ 可能已被同名包劫持，from lib.reporter import emit 会失败），
    # 加载失败不能连带把冲突检测也废掉。
    try:
        from lib.reporter import emit

        emit("[+] 未检测到顶层包名冲突")
    except Exception:
        sys.stdout.write("[+] 未检测到顶层包名冲突\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
