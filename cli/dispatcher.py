"""CLI 分发器 — 从 main.py 提取的模式分发逻辑

P1 重构：将 main() 中的 if-elif 分发链提取为独立函数，
main.py 保留参数解析 + Banner，调用 dispatch() 执行。
"""

from __future__ import annotations

from argparse import Namespace

from cli.runner import (
    final_prompt,
    run_chain_mode,
    run_ci_init_mode,
    run_diff_only_mode,
    run_mode,
    run_mode_batch,
    run_passive_mode,
    run_plugin_check_mode,
    run_plugin_init_mode,
    run_plugin_list_mode,
    run_plugin_new_mode,
    run_serve_mode,
    run_template_list_mode,
    run_wiki_mode,
)
from lib.colors import RED, RESET


def dispatch(args: Namespace) -> None:
    """根据 CLI args 分发到对应模式执行器

    Args:
        args: argparse 解析后的 Namespace
    """
    # ── 纯工具模式（不涉及扫描）──
    if args.diff_only:
        run_diff_only_mode(args.diff_only[0], args.diff_only[1])
        return
    if args.template_list:
        run_template_list_mode()
        return
    if args.plugin_new:
        run_plugin_new_mode(args)
        return
    if args.plugin_init:
        run_plugin_init_mode(args)
        return
    if args.plugin_check:
        run_plugin_check_mode(args)
        return
    if args.plugin_list:
        run_plugin_list_mode()
        return
    if args.ci_init:
        run_ci_init_mode(args)
        return
    if args.wiki:
        run_wiki_mode(args)
        return
    if args.oast_server:
        from lib.oast import run_oast_mode

        run_oast_mode(args)
        return
    if args.cve_sync or args.cve_id:
        from lib.cve_sync import run_cve_sync_mode

        run_cve_sync_mode(args)
        return
    if args.web_ui:
        from lib.web_ui import run_web_ui_mode

        run_web_ui_mode(args)
        return
    if args.cache_stats:
        from lib.cache import run_cache_stats_mode

        run_cache_stats_mode(args)
        return
    if args.cache_clear:
        from lib.cache import run_cache_clear_mode

        run_cache_clear_mode(args)
        return

    # ── 服务/链/代理模式（独立进程）──
    if args.serve:
        run_serve_mode(args)
        return
    if args.chain_list or (args.chain == "list"):
        run_chain_mode("list", args)
        return
    if args.chain:
        run_chain_mode(args.chain, args)
        return
    if args.passive:
        run_passive_mode(args)
        return

    # ── 标准扫描模式 ──
    def _mode_flag(val):
        return val is not None and val != "__flag__"

    target_for = {}
    flag_for = {}
    for k in ("u", "m", "p", "l"):
        val = getattr(args, k, None)
        if val is not None:
            if val == "__flag__":
                flag_for[k] = True
            else:
                target_for[k] = val

    if args.file:
        mode = None
        for k in ("u", "m", "p", "l"):
            if k in flag_for:
                mode = k
                break
        if not mode:
            print(f"{RED}[!]-f 批量扫描需配合 -u/-m/-p/-l 指定扫描模式，如：main.py -f targets.txt -p{RESET}")
            return
        run_mode_batch(args.file, mode, args)
    elif target_for:
        for k in ("u", "m", "p", "l"):
            if k in target_for:
                run_mode(k, target_for[k], args)
                break

    final_prompt()
