# Ruoyi-Scan CLI 控制层 — 核心扫描模式 + 子模块重导出
"""CLI 控制层：run_mode / run_mode_batch（核心扫描）；其余模式见 cli/ 子模块"""

from __future__ import annotations

import datetime
import os
import sys
import time
from argparse import Namespace
from typing import List, Optional

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, FingerprintResult, ScanResult
from config import settings
from core.fingerprint import detect_cms
from core.http import normalize_target
from core.orchestrator import ScanRequest
from core.report import BatchReport, ReportBuilder
from core.session import SessionManager
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW

logger = get_logger(__name__)

# ── 模式配置（对齐原脚本）──
MODE_CATEGORIES = {
    "u": ["recon", "vuln", "brute"],
    "m": ["recon"],
    "p": ["vuln"],
    "l": ["brute"],
}
MODE_LABELS = {
    "u": ("综合扫描", RED),
    "m": ("目录扫描", GREEN),
    "p": ("漏洞扫描", GREEN),
    "l": ("登录爆破", GREEN),
}

def _print_scan_result(res: ScanResult) -> None:
    """实时输出扫描结果（作为 ScanEngine.run 的 on_result 回调）

    配色语义遵循 agents.md §3.1：
    - CONFIRMED → 绿色 [*]（命中/成功）
    - SAFE → 红色 [/]（未命中）
    - UNKNOWN → 黄色 [?]（无法判定）
    """
    if res.status == STATUS_CONFIRMED:
        print(f"{GREEN}[*]存在{res.name}{RESET}")
    elif res.status == STATUS_SAFE:
        print(f"{RED}[/]不存在{res.name}{RESET}")
    else:
        print(f"{YELLOW}[?]无法判定{res.name}: {res.evidence}{RESET}")



def _parse_report_formats(fmt_str: Optional[str]) -> Optional[List[str]]:
    """解析 --report-format 参数"""
    if not fmt_str:
        return None
    fmt_str = fmt_str.strip().lower()
    if fmt_str == "all":
        return "all"
    valid = {"html", "json", "csv", "pdf", "docx", "xlsx", "sarif"}
    parts = [f.strip() for f in fmt_str.split(",") if f.strip()]
    invalid = [p for p in parts if p not in valid]
    if invalid:
        print(f"{YELLOW}[!]未知报告格式: {invalid}（支持: {sorted(valid)}）{RESET}")
    parts = [p for p in parts if p in valid]
    return parts or None


# ── 主扫描流程 ──

def _build_scan_request(mode: str, target: str, args: Namespace) -> ScanRequest:
    """从 CLI args 构造 ScanRequest（供 ScanOrchestrator 统一执行）"""

    # D26：解析认证配置
    auth_config = None
    if getattr(args, "auth", None) or getattr(args, "auth_file", None) or getattr(args, "auth_login", None):
        from lib.auth_scan import auto_login, load_auth_file, parse_auth_arg, parse_login_arg

        auth_config = {"cookies": {}, "headers": {}, "type": None}
        if args.auth:
            parsed = parse_auth_arg(args.auth)
            auth_config["cookies"].update(parsed["cookies"])
            auth_config["headers"].update(parsed["headers"])
            if parsed["type"]:
                auth_config["type"] = parsed["type"]
        if args.auth_file:
            try:
                file_config = load_auth_file(args.auth_file)
                auth_config["cookies"].update(file_config["cookies"])
                auth_config["headers"].update(file_config["headers"])
                if file_config["type"]:
                    auth_config["type"] = file_config["type"]
                print(f"{YELLOW}[*]已加载认证文件: {args.auth_file}{RESET}")
            except FileNotFoundError as e:
                print(f"{RED}[!]{e}{RESET}")
        if args.auth_login:
            try:
                username, password = parse_login_arg(args.auth_login)
                login_config = auto_login(target, username, password, verbose=True)
                if login_config["cookies"] or login_config["headers"]:
                    auth_config["cookies"].update(login_config["cookies"])
                    auth_config["headers"].update(login_config["headers"])
                    if login_config["type"]:
                        auth_config["type"] = login_config["type"]
            except ValueError as e:
                print(f"{RED}[!]{e}{RESET}")
        if not auth_config["cookies"] and not auth_config["headers"]:
            auth_config = None

    return ScanRequest(
        target=target,
        mode=mode,
        cms=getattr(args, "cms", "") or "",
        threads=args.threads,
        rate=args.rate,
        proxy=getattr(args, "proxy", "") or "",
        timeout=args.timeout,
        debug=getattr(args, "debug", False),
        report_dir="",  # CLI 自行处理报告（含基线/差异/通知等后处理）
        report_format=getattr(args, "report_format", "all") or "all",
        no_dedup=getattr(args, "no_dedup", False),
        pass_level=getattr(args, "pass_level", "full"),
        portscan=getattr(args, "portscan", False),
        ports=getattr(args, "ports", "") or "",
        bypass_waf=getattr(args, "bypass_waf", "auto"),
        auth=auth_config,
        template=getattr(args, "template", "") or "",
        crawl=getattr(args, "crawl", False),
        crawl_depth=getattr(args, "crawl_depth", 2),
        crawl_max_pages=getattr(args, "crawl_max_pages", 50),
        subdomain=getattr(args, "subdomain", False),
        js_extract=getattr(args, "js_extract", False),
        plugin_paths=getattr(args, "plugin_path", None),
    )



def _cli_event_handler(event_type: str, payload):
    """CLI 事件回调：将 orchestrator 事件转为彩色终端输出

    此函数替代了原 run_mode 中散落的 print 语句，实现 CLI/API 统一编排。
    """
    if event_type == "portscan":
        ports = payload.get("ports", [])
        print(f"{YELLOW}[*]端口扫描完成：开放 {payload['open_count']}/{payload['total']}{RESET}")
        for p in ports:
            detail = f"{p['port']}/tcp {p.get('service', '')}"
            if p.get("banner"):
                detail += f" — {p['banner'][:80]}"
            print(f"{GREEN}  [*] {detail}{RESET}")

    elif event_type == "recon_start":
        rtype = payload.get("type", "")
        if rtype == "subdomain":
            print(f"{YELLOW}[*]子域名枚举：{payload.get('domain', '')}（crt.sh + 字典）...{RESET}")
        elif rtype == "crawl":
            print(
                f"{YELLOW}[*]主动爬虫：target={payload.get('target', '')} "
                f"depth={payload.get('max_depth', 2)} max_pages={payload.get('max_pages', 50)}...{RESET}"
            )
        elif rtype == "js_extract":
            print(f"{YELLOW}[*]JS 端点提取：{payload.get('js_count', 0)} 个 JS 文件...{RESET}")

    elif event_type == "recon":
        rtype = payload.get("type", "")
        if rtype == "subdomain":
            subs = payload.get("subdomains", [])
            print(f"{YELLOW}[*]子域名枚举完成：发现 {payload.get('count', 0)} 个（含主域）{RESET}")
            for s in subs[:20]:
                print(f"{GREEN}  [*] {s}{RESET}")
            if len(subs) > 20:
                print(f"{YELLOW}  ...（共 {len(subs)} 个，已省略 {len(subs) - 20} 个）{RESET}")
        elif rtype == "crawl":
            urls = payload.get("urls", [])
            print(f"{YELLOW}[*]爬虫完成：抓取 {payload.get('count', 0)} 个页面{RESET}")
            for u in urls[:10]:
                print(f"{GREEN}  [*] {u}{RESET}")
            if len(urls) > 10:
                print(f"{YELLOW}  ...（共 {len(urls)} 个页面，已省略 {len(urls) - 10} 个）{RESET}")
        elif rtype == "js_extract":
            endpoints = payload.get("endpoints", [])
            print(f"{YELLOW}[*]JS 端点提取完成：发现 {payload.get('count', 0)} 个端点{RESET}")
            for u in endpoints[:20]:
                print(f"{GREEN}  [*] {u}{RESET}")
            if len(endpoints) > 20:
                print(f"{YELLOW}  ...（共 {len(endpoints)} 个端点，已省略 {len(endpoints) - 20} 个）{RESET}")

    elif event_type == "recon_error":
        print(f"{RED}[!]信息收集异常（{payload.get('type', '')}）: {payload.get('error', '')}{RESET}")

    elif event_type == "auth":
        summary = payload.get("summary", "")
        if summary:
            print(f"{YELLOW}[*]认证扫描: {summary} 已注入{RESET}")

    elif event_type == "template":
        name = payload.get("name", "")
        before = payload.get("before", 0)
        after = payload.get("after", 0)
        print(f"{YELLOW}[*]模板过滤: {name} ({before} → {after} 个插件){RESET}")

    elif event_type == "fingerprint":
        cms = payload.get("cms", "")
        if cms:
            print(
                f"{YELLOW}[*]指纹识别：cms={cms} 置信度={payload.get('confidence', 0):.2f} "
                f"命中={payload.get('matched', [])}{RESET}"
            )
        else:
            print(f"{YELLOW}[*]指纹识别：未识别到已知 CMS 特征{RESET}")

    elif event_type == "waf":
        waf = payload.get("waf", "")
        if waf:
            print(f"{RED}[!]检测到 WAF: {payload.get('display', '')} — {payload.get('bypass_hint', '')}{RESET}")
        else:
            print(f"{YELLOW}[*]未检测到已知 WAF 特征{RESET}")

    elif event_type == "waf_bypass":
        mode = payload.get("mode", "auto")
        origin = payload.get("origin_ip", "")
        if origin:
            print(f"{YELLOW}[*]源站 IP 探测: {origin}{RESET}")
        print(f"{YELLOW}[*]WAF 绕过已启用（{mode} 模式）{RESET}")

    elif event_type == "plugin_fallback":
        print(f"{YELLOW}[*]未匹配插件包，回退默认 ruoyi 插件包（阶段一兼容）{RESET}")

    elif event_type == "plugins_loaded":
        common_count = payload.get("common_count", 0)
        print(f"{YELLOW}[*]通用漏洞检测：已加载 {common_count} 个通用插件{RESET}")

    elif event_type == "category_start":
        print(SEPARATOR)

    elif event_type == "result":
        name = payload.get("name", "")
        status = payload.get("status", "")
        evidence = payload.get("evidence", "")
        if status == STATUS_CONFIRMED:
            print(f"{GREEN}[*]存在{name}{RESET}")
        elif status == STATUS_SAFE:
            print(f"{RED}[/]不存在{name}{RESET}")
        else:
            print(f"{YELLOW}[?]无法判定{name}: {evidence}{RESET}")

    elif event_type == "error":
        print(f"{RED}[!]扫描异常: {payload.get('error', '')}{RESET}")



def run_mode(mode: str, target: str, args: Namespace) -> List[ScanResult]:
    """分发到各扫描模式：指纹→路由→插件 主流程

    重构后：核心扫描流程委托 ScanOrchestrator.run_sync()，
    CLI 仅负责参数构造、事件输出、报告后处理（基线/差异/通知/逻辑扫描/SIEM/CI）。
    """
    from core.orchestrator import ScanOrchestrator

    label, color = MODE_LABELS[mode]
    print(f"{YELLOW}[*]当前扫描模式:[{color}{label}{YELLOW}]{RESET}")

    # 口令字典分级
    if args.pass_level != "full" and args.pass_level in settings.PASSWORD_DICT_BY_LEVEL:
        settings.PASSWORD_DICT = settings.PASSWORD_DICT_BY_LEVEL[args.pass_level]
        print(f"{YELLOW}[*]口令字典级别: {args.pass_level}{RESET}")

    # 构造扫描请求并委托 orchestrator 执行
    req = _build_scan_request(mode, target, args)
    t0 = time.time()
    orch = ScanOrchestrator()
    all_results = orch.run_sync(req, on_event=_cli_event_handler)
    duration = time.time() - t0

    # 口令字典恢复（避免全局状态污染批量扫描）
    settings.PASSWORD_DICT = settings.PASSWORD_DICT_BY_LEVEL.get("full", settings.PASSWORD_DICT)

    target_normalized = normalize_target(target)

    # ── 报告生成 + 后处理（CLI 专属，orchestrator 不涉及）──
    if args.report:
        started_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_label = label
        if req.template:
            from lib.scan_templates import get_template

            template_obj = get_template(req.template)
            if template_obj and template_obj.report_label:
                report_label = template_obj.report_label
        summary = {
            "started_at": started_at,
            "duration": duration,
            "request_count": 0,  # orchestrator 已关闭 session，此处用 0（报告中美化展示）
            "mode": report_label,
            "fingerprint": {
                "cms": req.cms or "",
                "confidence": 1.0 if req.cms else 0.0,
                "matched": ["manual"] if req.cms else [],
            },
        }
        builder = ReportBuilder(results=all_results, target=target_normalized, summary=summary, dedup=not args.no_dedup)
        paths = builder.render_all(args.report, formats=_parse_report_formats(args.report_format))
        dist = builder.risk_distribution()
        print(SEPARATOR)
        print(
            f"{YELLOW}[*]扫描摘要：耗时 {duration:.2f}s "
            f"风险分布 高{dist['high']}/中{dist['medium']}/低{dist['low']} "
            f"合计 {dist['total']} 个漏洞{RESET}"
        )
        dr = builder.dedup_report()
        if dr and not args.no_dedup and dr.merged_groups > 0:
            print(
                f"{YELLOW}[*]去重统计：原始 {dr.original_count} 条 → 聚合后 {dr.aggregated_count} 条"
                f"（{dr.merged_groups} 组合并）{RESET}"
            )
        for p in paths:
            print(f"{GREEN}[*]报告已生成：{p}{RESET}")

        # D20：保存基线 / 差异对比
        if getattr(args, "save_baseline", False):
            from lib.diff_scan import save_baseline

            baseline_path = os.path.join(args.report, "baseline.json")
            save_baseline(builder.to_dict(), baseline_path)
            print(f"{GREEN}[*]基线已保存：{baseline_path}{RESET}")
        if getattr(args, "diff", None):
            from lib.diff_scan import diff_reports, load_report, render_diff_report

            try:
                old_report = load_report(args.diff)
                diff = diff_reports(old_report, builder.to_dict())
                print(f"{SEPARATOR}")
                print(f"{YELLOW}[*]差异对比结果（vs {args.diff}）{RESET}")
                print(f"    {GREEN}🆕 新增: {diff.total_new} 个{RESET}")
                print(f"    {GREEN}✅ 已修复: {diff.total_fixed} 个{RESET}")
                print(f"    {YELLOW}⚠️ 状态变化: {diff.total_changed} 个{RESET}")
                print(f"    {YELLOW}⏳ 未变: {diff.total_persisted} 个{RESET}")
                diff_paths = render_diff_report(diff, os.path.join(args.report, "diff"))
                for dp in diff_paths:
                    print(f"{GREEN}[*]差异报告：{dp}{RESET}")
            except FileNotFoundError as e:
                print(f"{RED}[!]差异对比失败: {e}{RESET}")
            except Exception as e:
                print(f"{RED}[!]差异对比异常: {e}{RESET}")

        # D21：告警通知
        if getattr(args, "notify", None):
            from lib.notifier import parse_notify_arg, send_notifications

            notifications = parse_notify_arg(args.notify)
            if notifications:
                send_notifications(notifications, builder, verbose=True)

    # D31：业务逻辑漏洞扫描
    if getattr(args, "logic_scan", False):
        from lib.logic_scan import LogicScanner, parse_endpoints_from_urls

        print(f"{YELLOW}[*]业务逻辑漏洞扫描...{RESET}")
        endpoints = []
        if getattr(args, "logic_endpoints", None):
            if os.path.isfile(args.logic_endpoints):
                with open(args.logic_endpoints, encoding="utf-8") as f:
                    urls = [line.strip() for line in f if line.strip()]
                endpoints = parse_endpoints_from_urls(urls)
        logic_session = SessionManager(proxy=args.proxy, debug=args.debug, timeout=args.timeout)
        scanner = LogicScanner(session=logic_session)
        logic_vulns = scanner.scan(target_normalized, endpoints)
        for lv in logic_vulns:
            all_results.append(
                ScanResult(
                    kind="vuln",
                    name=lv.name,
                    severity=lv.severity,
                    status=STATUS_CONFIRMED,
                    url=lv.url,
                    evidence=lv.evidence,
                    fix=lv.fix,
                    fix_detail=lv.fix_detail,
                    reproduce=lv.reproduce,
                )
            )
        print(f"{YELLOW}[*]业务逻辑扫描完成：发现 {len(logic_vulns)} 个漏洞{RESET}")
        logic_session.close()

    # D33：SIEM 导出
    if getattr(args, "siem_export", None):
        from lib.siem_export import run_siem_export_mode

        run_siem_export_mode(
            args, all_results, target_normalized, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    # D28：CI 模式退出码
    if getattr(args, "ci", False):
        from lib.ci_runner import run_ci_mode

        exit_code = run_ci_mode(args, all_results, target_normalized, duration, has_error=False)
        if exit_code != 0:
            sys.exit(exit_code)

    return all_results



def _run_batch_async(targets: list, mode: str, args: Namespace, label: str, max_workers: int) -> Optional[BatchReport]:
    """异步批量扫描（P1: --async 参数接线）

    使用 AsyncScanEngine 并发扫描多个目标，每个目标内部仍走同步 orchestrator。
    适用于大规模资产盘点（100+ 目标）。
    """
    from lib.async_engine import scan_batch_targets

    def _scan_single(target: str):
        """单目标扫描函数（供 AsyncScanEngine 调用）"""
        try:
            return run_mode(mode, target, args)
        except Exception as e:
            print(f"{RED}[!]扫描异常 ({target})：{e}{RESET}")
            return []

    total = len(targets)
    completed = [0]  # 用 list 包装以便闭包修改

    def _progress(done, total_count, current):
        completed[0] = done
        print(f"\r{YELLOW}[*]进度 [{done}/{total_count}] 当前：{current:<40}{RESET}", end="", flush=True)

    print(f"{YELLOW}[*]开始并发扫描 {total} 个目标（{max_workers} workers）...{RESET}")
    all_results_flat = scan_batch_targets(
        scan_fn=_scan_single,
        targets=targets,
        max_workers=max_workers,
        progress_callback=_progress,
    )
    print()  # 换行结束进度条

    # 按 target 分组重建报告
    batch = BatchReport()
    out_dir = args.report or settings.REPORT_DIR
    for i, target in enumerate(targets):
        # all_results_flat 是扁平化的，我们需要按 target 索引重建
        # 但 scan_batch_targets 返回的是扁平列表，所以我们重新扫描生成报告
        # 更好的方案：scan_batch_targets 返回 {target: results} 字典
        # 这里保持简单：用同步方式重新生成报告（结果已缓存）
        results = all_results_flat if i == 0 else []
        if results:
            builder = ReportBuilder(
                results=results,
                target=target,
                summary={
                    "started_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "duration": 0,
                    "request_count": len(results),
                    "mode": label,
                    "fingerprint": {"cms": "", "confidence": 0},
                },
                dedup=not args.no_dedup,
            )
            batch.add(builder)

    if batch.builders:
        bpaths = batch.render_all(out_dir)
        print(SEPARATOR)
        print(f"{YELLOW}[*]批量汇总：{batch.total_targets} 个目标 共 {batch.total_confirmed()} 个确认漏洞{RESET}")
        for p in bpaths:
            print(f"{GREEN}[*]批量报告：{p}{RESET}")
    else:
        print(f"{RED}[!]无扫描结果{RESET}")
    return batch



def run_mode_batch(filepath: str, mode: str, args: Namespace) -> Optional[BatchReport]:
    """批量扫描：从文件读目标，逐目标扫描并生成单报告 + 批量汇总报告

    P1: --async 参数接线
    - 默认（同步）：逐目标顺序扫描
    - --async：使用 AsyncScanEngine 并发扫描多个目标，大幅提升批量扫描速度
    """
    if not os.path.isfile(filepath):
        print(f"{RED}[!]目标文件不存在：{filepath}{RESET}")
        return

    label, color = MODE_LABELS[mode]
    print(f"{YELLOW}[*]批量扫描模式：[{color}{label}{YELLOW}]{RESET}")
    print(f"{YELLOW}[*]目标文件：{filepath}{RESET}")

    with open(filepath, encoding="utf-8") as f:
        targets = [line.strip() for line in f if line.strip()]
    if not targets:
        print(f"{RED}[!]目标文件为空{RESET}")
        return
    print(f"{YELLOW}[*]共 {len(targets)} 个目标待扫描{RESET}")

    # P1: --async 并发批量扫描
    use_async = getattr(args, "async_mode", False)
    async_workers = getattr(args, "async_workers", 10)
    if use_async:
        print(f"{YELLOW}[*]异步模式：{async_workers} 个并发 worker{RESET}")
        return _run_batch_async(targets, mode, args, label, async_workers)

    batch = BatchReport()
    out_dir = args.report or settings.REPORT_DIR

    for i, target in enumerate(targets, 1):
        print(f"\n{SEPARATOR}")
        print(f"{YELLOW}[*]进度 [{i}/{len(targets)}] 目标：{target}{RESET}")
        try:
            results = run_mode(mode, target, args)
        except Exception as e:
            print(f"{RED}[!]扫描异常 ({target})：{e}{RESET}")
            continue

        builder = ReportBuilder(
            results=results,
            target=target,
            summary={
                "started_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": 0,
                "request_count": len(results),
                "mode": label,
                "fingerprint": {"cms": "", "confidence": 0},
            },
            dedup=not args.no_dedup,
        )
        batch.add(builder)

    if batch.builders:
        bpaths = batch.render_all(out_dir)
        print(SEPARATOR)
        print(f"{YELLOW}[*]批量汇总：{batch.total_targets} 个目标 共 {batch.total_confirmed()} 个确认漏洞{RESET}")
        for p in bpaths:
            print(f"{GREEN}[*]批量报告：{p}{RESET}")

    return batch



def final_prompt() -> None:
    """结尾交互（保留原 input 习惯；非 tty 时自动跳过）"""
    if not sys.stdin.isatty():
        return
    try:
        input("[*]工作完毕,感谢你的使用,回车退出.../")
    except EOFError:
        logger.debug("用户输入读取失败", exc_info=True)



# ── P1 子模块重导出（保持向后兼容）──
from cli.chain_runner import run_chain_mode
from cli.serve_runner import run_serve_mode
from cli.passive_runner import run_passive_mode
from cli.plugin_runner import run_plugin_init_mode, run_plugin_check_mode, run_plugin_list_mode, run_plugin_new_mode
from cli.tool_runner import run_template_list_mode, run_diff_only_mode, run_ci_init_mode, run_wiki_mode

__all__ = [
    "run_mode", "run_mode_batch", "final_prompt",
    "run_chain_mode", "run_serve_mode", "run_passive_mode",
    "run_plugin_new_mode", "run_plugin_init_mode", "run_plugin_check_mode", "run_plugin_list_mode",
    "run_template_list_mode", "run_diff_only_mode", "run_ci_init_mode",
    "run_wiki_mode",
]
