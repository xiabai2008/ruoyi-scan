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
    category = args.framework
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
    except Exception as e:
        # 无效名称/类别、目录/文件权限等错误给友好提示，
        # 同时保留 traceback 供排查
        logger.warning("生成插件模板失败: %s", name, exc_info=True)
        print(f"{RED}[!]生成插件模板失败: {e}{RESET}")


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


def run_plugin_export_mode(out_dir: str) -> None:
    """导出插件源码与元信息到目录（模板仓库）"""
    from lib.plugin_repo import export_plugins

    try:
        hashes = export_plugins(out_dir)
        print(f"{GREEN}[*]导出完成: {out_dir}（{len(hashes)} 个文件）{RESET}")
        print(f"{YELLOW}[*]下一步: --plugin-manifest {out_dir} 生成 manifest.json{RESET}")
    except Exception as e:
        print(f"{RED}[!]导出失败: {e}{RESET}")


def run_plugin_manifest_mode(out_dir: str) -> None:
    """生成/校验 manifest.json（Ed25519 签名，cryptography 可选）"""
    from lib.plugin_repo import build_manifest, verify_manifest

    try:
        import json
        import os

        manifest_path = os.path.join(out_dir, "manifest.json")
        if os.path.isfile(manifest_path):
            # 校验模式
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            errors = verify_manifest(manifest, out_dir)
            if errors:
                print(f"{RED}[!]manifest 校验失败:{RESET}")
                for e in errors:
                    print(f"{RED}    - {e}{RESET}")
            else:
                print(f"{GREEN}[*]manifest 校验通过: {manifest_path}{RESET}")
                if manifest.get("signature"):
                    print(f"{GREEN}[*]签名验证通过（Ed25519）{RESET}")
                else:
                    print(f"{YELLOW}[*]manifest 未签名（需 cryptography + 私钥才可签名）{RESET}")
        else:
            manifest = build_manifest(out_dir)
            print(f"{GREEN}[*]manifest 已生成: {manifest_path}（{len(manifest['files'])} 个文件）{RESET}")
            if manifest.get("signature"):
                print(f"{GREEN}[*]已签名（Ed25519）{RESET}")
            else:
                print(
                    f"{YELLOW}[*]未签名（仅摘要校验；生成私钥: cryptography 库 + --plugin-manifest 重复执行自动创建签名密钥）{RESET}"
                )
    except Exception as e:
        print(f"{RED}[!]manifest 处理失败: {e}{RESET}")


def run_plugin_update_mode(url: str) -> None:
    """从模板仓库更新插件（下载 → 强制验签 → 安装到 ~/.ruoyi-scan/plugins/）

    供应链安全：远程安装强制 Ed25519 验签（fail-closed）。公钥默认取自
    ~/.ruoyi-scan/signing.pub（首次可通过 --plugin-manifest 生成并人工确认指纹）。
    """
    from config import settings
    from lib.plugin_repo import download_and_install

    # "default" 关键字回退到配置的默认仓库地址；未配置时直接拒绝（fail-closed）
    if url == "default":
        url = settings.PLUGIN_REPO_URL
    if not url:
        print(f"{RED}[!]未配置插件仓库地址（config/settings.py PLUGIN_REPO_URL）{RESET}")
        return
    print(f"{YELLOW}[*]插件仓库更新: {url} ...{RESET}")
    try:
        installed = download_and_install(url)
        print(f"{GREEN}[*]更新完成：安装 {len(installed)} 个文件到 ~/.ruoyi-scan/plugins/{RESET}")
        for rel in installed:
            print(f"{GREEN}  [*] {rel}{RESET}")
    # 验签/校验失败抛 ValueError 且不安装任何文件：远程插件更新默认失败关闭
    except ValueError as e:
        print(f"{RED}[!]更新失败（已拒绝安装）: {e}{RESET}")
        print(f"{YELLOW}[*]安全提示：远程插件安装要求 Ed25519 签名 + cryptography 库{RESET}")
        print(
            f"{YELLOW}[*]请安装依赖并确认可信公钥：pip install cryptography；"
            f"并用 --plugin-manifest 生成/校验 manifest 后人工确认 ~/.ruoyi-scan/signing.pub 指纹{RESET}"
        )
