"""CLI submodule — 插件管理"""

from __future__ import annotations

from argparse import Namespace
from typing import Optional

from common.logger import get_logger
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW

logger = get_logger(__name__)


def run_plugin_init_mode(args: Namespace) -> None:
    """生成插件模板（D25）"""
    from lib.plugin_sdk import init_plugin_file

    name = args.plugin_init
    category = args.category
    print(f"{YELLOW}[*]生成插件模板{RESET}")
    print(f"    名称: {name}")
    print(f"    类别: {category}")
    try:
        filepath = init_plugin_file(name, category=category)
        print(f"{GREEN}[+]插件已生成: {filepath}{RESET}")
        print(f"{YELLOW}[*]下一步:{RESET}")
        print(f"    1. 编辑 {filepath} 完善检测逻辑")
        print(f"    2. 运行 python main.py --plugin-check {filepath} 验证")
        print("    3. 运行 python main.py -u http://target/ 扫描")
    except FileExistsError as e:
        print(f"{RED}[!]{e}{RESET}")


def run_plugin_check_mode(args: Namespace) -> None:
    """验证插件文件（D25）"""
    from lib.plugin_sdk import check_plugin, check_plugin_by_import

    filepath = args.plugin_check
    print(f"{YELLOW}[*]验证插件: {filepath}{RESET}")

    # 静态检查：仅解析插件文件结构，不执行插件代码（捕获元数据/AST 级别问题）
    ok1, errors1, warnings1 = check_plugin(filepath)
    print(f"{SEPARATOR}")
    print("静态检查:")
    if ok1:
        print(f"  {GREEN}[OK] 通过{RESET}")
    else:
        print(f"  {RED}[X] 失败{RESET}")
    for e in errors1:
        print(f"  {RED}错误: {e}{RESET}")
    for w in warnings1:
        print(f"  {YELLOW}警告: {w}{RESET}")

    # 导入检查：动态加载插件模块，捕获仅运行时才暴露的错误
    ok2, errors2, warnings2 = check_plugin_by_import(filepath)
    print("导入检查:")
    if ok2:
        print(f"  {GREEN}[OK] 通过{RESET}")
    else:
        print(f"  {RED}[X] 失败{RESET}")
    for e in errors2:
        print(f"  {RED}错误: {e}{RESET}")
    for w in warnings2:
        print(f"  {YELLOW}警告: {w}{RESET}")

    print(f"{SEPARATOR}")
    # 两层检查全部通过才算验证成功；任一失败即判定插件不合法
    if ok1 and ok2:
        print(f"{GREEN}[+]插件验证通过{RESET}")
    else:
        print(f"{RED}[!]插件验证失败{RESET}")


def run_plugin_list_mode(_args: Optional[Namespace] = None) -> None:
    """列出所有插件元数据（D25）"""
    from lib.plugin_sdk import list_all_plugins

    plugins = list_all_plugins()
    print(f"{SEPARATOR}")
    print(f"{YELLOW}[*]已加载插件列表（{len(plugins)} 个）{RESET}")
    print(f"{SEPARATOR}")
    print(f"{'#':<3} {'漏洞名称':<25} {'类别':<10} {'严重度':<8} {'CVE':<18} {'修复':<4} {'复现':<4}")
    print(f"{'-' * 80}")
    for i, p in enumerate(plugins, 1):
        # 布尔字段映射为 [Y]/[N] 列展示；长名称/CVE 截断到列宽，避免表格错位
        has_fix = "[Y]" if p["has_fix_detail"] else "[N]"
        has_reproduce = "[Y]" if p["has_reproduce"] else "[N]"
        print(
            f"{i:<3} {p['name'][:25]:<25} {p['category']:<10} "
            f"{p['severity']:<8} {(p['cve'] or 'N/A')[:18]:<18} "
            f"{has_fix:<4} {has_reproduce:<4}"
        )
    print(f"{SEPARATOR}")


def run_plugin_new_mode(args: Namespace) -> None:
    """P3: 创建新插件脚手架"""
    from lib.plugin_sdk import generate_plugin_template

    name = args.plugin_new
    category = getattr(args, "category", "ruoyi")
    print(f"{YELLOW}[*]创建新插件脚手架{RESET}")
    print(f"    名称: {name}")
    print(f"    类别: {category}")
    # FileExistsError 单独捕获：同名插件已存在属预期情况；其余异常统一归为创建失败
    try:
        filepath = generate_plugin_template(name, category=category)
        print(f"{GREEN}[+]插件已创建: {filepath}{RESET}")
        print(f"{YELLOW}[*]下一步:{RESET}")
        print("    1. 编辑插件文件实现 verify() 方法")
        print(f"    2. 运行 python main.py --plugin-check {filepath} 验证")
        print("    3. 运行 python main.py -u http://target/ 扫描")
    except FileExistsError as e:
        print(f"{RED}[!]{e}{RESET}")
    except Exception as e:
        print(f"{RED}[!]创建插件失败: {e}{RESET}")
