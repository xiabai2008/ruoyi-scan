"""CLI 分发器 — 从 main.py 提取的模式分发逻辑

P1 重构：将 main() 中的 if-elif 分发链提取为独立函数，
main.py 保留参数解析 + Banner，调用 dispatch() 执行。
"""

from __future__ import annotations

import sys
from argparse import Namespace

from cli.preflight import EXIT_UNREACHABLE, preflight_target
from cli.runner import (
    final_prompt,
    run_chain_mode,
    run_ci_init_mode,
    run_diff_only_mode,
    run_mode,
    run_mode_batch,
    run_nuclei_validate_mode,
    run_passive_mode,
    run_plugin_check_mode,
    run_plugin_export_mode,
    run_plugin_init_mode,
    run_plugin_list_mode,
    run_plugin_manifest_mode,
    run_plugin_new_mode,
    run_plugin_update_mode,
    run_serve_mode,
    run_template_list_mode,
    run_wiki_mode,
)

# 标准扫描的模式参数：裸开关（不带 target）时值为 "__flag__"（见 main.py nargs="?" const）
_MODE_ARGS = ("u", "m", "p", "l")


def _has_scan_target(args: Namespace) -> bool:
    """是否携带真实扫描目标（忽略只作开关用的 "__flag__" 占位符）"""
    return any(getattr(args, k, None) not in (None, "__flag__") for k in _MODE_ARGS)


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
    if args.cve_sync or args.cve_id or getattr(args, "cve_offline", None) is not None:
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
    if args.cache_clear or args.cache_clear_all:
        from lib.cache import run_cache_clear_mode

        run_cache_clear_mode(args)
        return
    # E4：nuclei 模板校验（不扫描）
    if args.nuclei_validate:
        run_nuclei_validate_mode(args.nuclei_validate)
        return
    # E5：插件模板仓库（导出/清单/更新）
    if args.plugin_export:
        run_plugin_export_mode(args.plugin_export)
        return
    if args.plugin_manifest:
        run_plugin_manifest_mode(args.plugin_manifest)
        return
    if args.plugin_update:
        run_plugin_update_mode(args.plugin_update)
        return
    # G3：生成即验证——对已有插件独立验证（--ai-validate <path>）
    if args.ai_validate is not None and args.ai_validate is not True:
        from lib.ai_validate import run_ai_validate_mode

        sys.exit(run_ai_validate_mode(args))
    # G3：--ai-triage 仅在扫描模式中联动处理（runner 内），独立调用无意义。
    # 用 _has_scan_target 而非真值判断：裸 -u 的值为 "__flag__"，不构成可执行的扫描目标
    if args.ai_triage and not _has_scan_target(args) and not args.file:
        from lib.colors import RED, RESET

        print(f"{RED}[!]--ai-triage 需配合扫描模式使用（如 -u <url> --ai-triage）{RESET}")
        return
    # E7：AI POC 生成器（--ai）
    if args.ai:
        from lib.ai_generator import run_ai_generate_mode

        run_ai_generate_mode(args)
        return

    # ── 服务/链/代理模式（独立进程）──
    if args.serve:
        run_serve_mode(args)
        return
    # --chain-list 与 --chain list 两种写法等价，均进入链列表模式
    if args.chain_list or (args.chain == "list"):
        run_chain_mode("list", args)
        return
    if args.chain:
        run_chain_mode(args.chain, args)
        return
    if args.passive:
        run_passive_mode(args)
        return

    # D36：分布式扫描（master 分发 / worker 执行 / standalone 本机分发）
    # 必须排在标准扫描之前：master 与 standalone 同样接受 -f + 模式开关，
    # 落到下面的批量分支会把任务当成单机批量扫描，分布式参数全部失效。
    if getattr(args, "distributed", None):
        from cli.distributed_runner import run_distributed_mode

        code = run_distributed_mode(args)
        if code:
            sys.exit(code)
        return

    # ── 标准扫描模式 ──
    # 分别收集"真实目标值"与"纯开关标记"：值为 __flag__ 时仅标记模式，无实际目标
    target_for = {}
    flag_for = {}
    for k in _MODE_ARGS:
        val = getattr(args, k, None)
        if val is not None:
            if val == "__flag__":
                flag_for[k] = True
            else:
                target_for[k] = val

    # 目标未带协议（如 127.0.0.1:8080）：在入口补 http://。
    # 否则 requests 抛 InvalidSchema，插件只看到"请求异常"，可能写出 SAFE，
    # 违反"网络异常绝不冒充 SAFE"。
    if target_for:
        from core.http import ensure_scheme
        from lib.colors import RESET, YELLOW

        for _k in list(target_for):
            _fixed, _added = ensure_scheme(target_for[_k])
            if _added:
                print(f"{YELLOW}[*]目标未带协议，按 {_fixed} 处理{RESET}")
            target_for[_k] = _fixed

    # 批量模式：-f 需配合 -u/-m/-p/-l 开关指定扫描类型，开关位的值本身无意义
    if args.file:
        mode = None
        for k in _MODE_ARGS:
            if k in flag_for:
                mode = k
                break
        if not mode:
            from lib.colors import RED, RESET  # 与上方 --ai-triage 分支一致的延迟导入

            print(f"{RED}[!]-f 批量扫描需配合 -u/-m/-p/-l 指定扫描模式，如：main.py -f targets.txt -p{RESET}")
            return
        run_mode_batch(args.file, mode, args)
    # 单目标模式按 u→m→p→l 顺序取第一个有效目标执行（优先级隐含在元组顺序中）
    elif target_for:
        for k in _MODE_ARGS:
            if k in target_for:
                if not preflight_target(target_for[k], args):
                    sys.exit(EXIT_UNREACHABLE)
                run_mode(k, target_for[k], args)
                break
    # 只给了模式开关（如裸 -p）却没有目标：明确报错并返回非 0 退出码。
    # 此前这种调用会走完全部分支、只留一个 banner 后 exit 0，使用者以为扫过了。
    elif flag_for:
        from lib.colors import RED, RESET, YELLOW  # 与其余分支一致的延迟导入

        modes = "/".join(f"-{k}" for k in _MODE_ARGS if k in flag_for)
        first_mode = next(k for k in _MODE_ARGS if k in flag_for)
        print(f"{RED}[!]{modes} 缺少扫描目标{RESET}")
        print(f"{YELLOW}[*]单目标: main.py -{first_mode} http://target:8080{RESET}")
        print(f"{YELLOW}[*]批量:   main.py -f targets.txt {modes}{RESET}")
        sys.exit(2)  # 与 argparse 参数错误一致的退出码

    final_prompt(no_pause=getattr(args, "no_pause", False) or getattr(args, "ci", False))
