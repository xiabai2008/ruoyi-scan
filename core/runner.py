# Ruoyi-Scan 扫描编排器 — 各模式执行逻辑（从 main.py 拆分，P0 瘦身）
"""扫描编排器：run_mode / run_mode_batch / run_chain_mode / run_serve_mode / run_passive_mode 等"""

from __future__ import annotations

import datetime
import os
import sys
import time
from argparse import Namespace
from typing import List, Optional

from config import settings
from core.fingerprint import detect_cms
from core.models import STATUS_CONFIRMED, STATUS_SAFE, FingerprintResult, ScanResult
from core.orchestrator import ScanRequest
from core.report import BatchReport, ReportBuilder
from core.session import SessionManager
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW
from lib.http import normalize_target

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


def run_mode_batch(filepath: str, mode: str, args: Namespace) -> Optional[BatchReport]:
    """批量扫描：从文件读目标，逐目标扫描并生成单报告 + 批量汇总报告"""
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
        pass


def run_chain_mode(chain_name: str, args: Namespace) -> None:
    """漏洞利用链执行模式（D6）：按链定义编排多插件"""
    from chains.registry import get_chain, list_chains
    from core.chain import ChainEngine

    if chain_name == "list" or getattr(args, "chain_list", False):
        print(f"{SEPARATOR}")
        print(f"{YELLOW}[*]可用漏洞利用链{RESET}")
        print(f"{SEPARATOR}")
        for c in list_chains():
            print(f"{GREEN}  {c['name']}{RESET}")
            print(f"    名称：{c['display_name']}")
            print(f"    描述：{c['description']}")
            print(f"    严重度：{c['severity']}")
            print()
        return

    target = args.u
    if not target or target == "__flag__":
        print(f"{RED}[!]--chain 需配合 -u <target> 指定目标{RESET}")
        return

    chain_def = get_chain(chain_name)
    if chain_def is None:
        print(f"{RED}[!]未找到链: {chain_name}（用 --chain list 查看可用链）{RESET}")
        return

    print(f"{YELLOW}[*]执行漏洞利用链: {chain_def.display_name}{RESET}")
    print(f"{YELLOW}[*]链描述: {chain_def.description}{RESET}")
    print(f"{YELLOW}[*]影响版本: {chain_def.affected_versions or '全版本'}{RESET}")
    print(f"{SEPARATOR}")

    errors = chain_def.validate()
    if errors:
        print(f"{RED}[!]链定义校验失败:{RESET}")
        for e in errors:
            print(f"{RED}  - {e}{RESET}")
        return

    target = normalize_target(target)
    session = SessionManager(proxy=args.proxy, debug=args.debug, timeout=args.timeout)

    if args.cms:
        fp_result = FingerprintResult(cms=args.cms, version="", confidence=1.0, matched=["manual"])
        print(f"{YELLOW}[*]手动指定 CMS: {args.cms}（跳过指纹识别）{RESET}")
    else:
        fp_result = detect_cms(target, session)
        if fp_result.cms:
            print(f"{YELLOW}[*]指纹识别：cms={fp_result.cms} 置信度={fp_result.confidence:.2f}{RESET}")
        else:
            print(f"{YELLOW}[*]指纹识别：未识别到已知 CMS{RESET}")

    engine = ChainEngine()
    started_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    t0 = time.time()

    def _on_chain_result(res):
        if res.status == STATUS_CONFIRMED:
            print(f"{GREEN}[*]节点成功: {res.name}{RESET}")
        elif res.status == STATUS_SAFE:
            print(f"{RED}[/]节点失败: {res.name}{RESET}")
        else:
            print(f"{YELLOW}[?]节点未知: {res.name} - {res.evidence}{RESET}")

    chain_result = engine.run(chain_def, target, session, fp_result, on_result=_on_chain_result)
    duration = time.time() - t0
    session.close()

    print(f"{SEPARATOR}")
    status_color = (
        GREEN if chain_result.status == "CONFIRMED" else (YELLOW if chain_result.status == "UNKNOWN" else RED)
    )
    print(f"{YELLOW}[*]链执行状态: {status_color}{chain_result.status}{YELLOW}{RESET}")
    print(f"{YELLOW}[*]耗时: {duration:.2f}s{RESET}")

    for step_id, status in chain_result.node_status.items():
        color = GREEN if status == "success" else (YELLOW if status == "skipped" else RED)
        print(f"  {color}{step_id}: {status}{RESET}")

    if chain_result.facts:
        print(f"{YELLOW}[*]提取事实:{RESET}")
        for k, v in chain_result.facts.items():
            print(f"  {k} = {v}")

    chain_scan_result = chain_result.to_scan_result(chain_def)
    all_results = [chain_scan_result]

    if args.report:
        summary = {
            "started_at": started_at,
            "duration": duration,
            "request_count": session.request_count,
            "mode": f"链执行: {chain_def.display_name}",
            "fingerprint": {"cms": fp_result.cms, "confidence": fp_result.confidence, "matched": fp_result.matched},
        }
        builder = ReportBuilder(results=all_results, target=target, summary=summary, dedup=not args.no_dedup)
        paths = builder.render_all(args.report, formats=_parse_report_formats(args.report_format))
        print(f"{SEPARATOR}")
        for p in paths:
            print(f"{GREEN}[*]报告已生成：{p}{RESET}")


def run_serve_mode(args: Namespace) -> None:
    """Web API 服务模式（D9 + D11）：启动 FastAPI + WebSocket + Web 控制台"""
    print(f"{YELLOW}[*]启动 Web API 服务模式（D9 + D11）{RESET}")
    print(f"{YELLOW}[*]监听地址: {args.host}:{args.port}{RESET}")
    print(f"{YELLOW}[*]API 文档: http://{args.host}:{args.port}/docs{RESET}")
    print(f"{YELLOW}[*]Web 控制台: http://{args.host}:{args.port}/{RESET}")

    api_key = getattr(args, "api_key", None) or ""
    if not api_key:
        api_key = os.environ.get("RUOYI_SCAN_API_KEY", "")
    if api_key:
        print(f"{GREEN}[*]API 鉴权: 已启用（X-API-Key 头）{RESET}")
    else:
        print(f"{YELLOW}[*]API 鉴权: 未设置 API Key，仅允许 127.0.0.1 访问{RESET}")

    db_path = args.db_path or "data/tasks.db"
    print(f"{YELLOW}[*]任务持久化: {db_path}{RESET}")
    print(f"{SEPARATOR}")

    try:
        import uvicorn

        from api.app import create_app

        cors_origins = None
        if args.cors_origins:
            cors_origins = [o.strip() for o in args.cors_origins.split(",") if o.strip()]
        app = create_app(api_key=api_key, cors_origins=cors_origins, db_path=args.db_path or "")
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    except ImportError as e:
        print(f"{RED}[!]启动 API 服务需要 fastapi + uvicorn，请安装：pip install fastapi uvicorn[standard]{RESET}")
        print(f"{RED}[!]缺失模块: {e}{RESET}")


def run_passive_mode(args: Namespace) -> None:
    """被动代理模式：启动 HTTP/HTTPS 代理，捕获流量 URL 自动扫描"""
    from core.proxy_server import ProxyServer, ScanQueue

    queue = ScanQueue()
    host = args.passive_host
    port = args.passive_port
    proxy = ProxyServer(host=host, port=port, queue=queue)
    proxy.start()

    print(f"{SEPARATOR}")
    print(f"{GREEN}[*]被动扫描模式启动{RESET}")
    print(f"{YELLOW}[*]代理监听: http://{host}:{port}")
    print(f"{YELLOW}[*]请将浏览器/工具代理设为 http://{host}:{port}")
    print(f"{YELLOW}[*]所有经过代理的 HTTP/HTTPS 请求目标会自动加入扫描队列")
    print(f"{YELLOW}[*]按 Ctrl+C 停止被动扫描{RESET}")
    print(f"{SEPARATOR}")

    scanned = set()
    try:
        while True:
            time.sleep(3)
            urls = queue.drain()
            if not urls:
                continue
            for url in urls:
                if url in scanned:
                    continue
                scanned.add(url)
                print(f"\n{SEPARATOR}")
                print(f"{YELLOW}[*]被动捕获: {url}{RESET}")
                try:
                    run_mode("p", url, args)
                except Exception as e:
                    print(f"{RED}[!]扫描异常 ({url}): {e}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*]被动扫描已停止，共扫描 {len(scanned)} 个目标{RESET}")
    finally:
        proxy.stop()


def run_template_list_mode() -> None:
    """列出所有可用的扫描模板（D19）"""
    from lib.scan_templates import list_templates

    print(f"{SEPARATOR}")
    print(f"{YELLOW}[*]可用扫描模板{RESET}")
    print(f"{SEPARATOR}")
    for t in list_templates():
        print(f"{GREEN}  {t.name}{RESET}")
        print(f"    名称：{t.display_name}")
        print(f"    描述：{t.description}")
        print(f"    预估耗时：{t.estimated_time}")
        if t.severity_filter:
            print(f"    严重度过滤：{', '.join(sorted(t.severity_filter))}")
        if t.category_filter:
            print(f"    类别过滤：{', '.join(sorted(t.category_filter))}")
        if t.compliance_filter:
            print(f"    合规过滤：{', '.join(sorted(t.compliance_filter))}")
        if t.default_args:
            defaults_str = ", ".join(f"{k}={v}" for k, v in t.default_args.items())
            print(f"    默认参数：{defaults_str}")
        print()
    print(f"{YELLOW}用法：python main.py --template <name> -u <target>{RESET}")
    print(f"{SEPARATOR}")


def run_diff_only_mode(old_path: str, new_path: str) -> None:
    """仅对比两个 JSON 报告（D20）"""
    import json as _json

    from lib.diff_scan import diff_reports, load_report, render_diff_report

    print(f"{YELLOW}[*]差异对比模式{RESET}")
    print(f"    旧报告: {old_path}")
    print(f"    新报告: {new_path}")
    try:
        old_report = load_report(old_path)
        new_report = load_report(new_path)
    except FileNotFoundError as e:
        print(f"{RED}[!]{e}{RESET}")
        return
    except _json.JSONDecodeError as e:
        print(f"{RED}[!]JSON 解析失败: {e}{RESET}")
        return

    diff = diff_reports(old_report, new_report)
    print(f"{SEPARATOR}")
    print(f"{YELLOW}[*]差异结果{RESET}")
    print(f"    旧扫描: {diff.old_scan_time}（{diff.old_total} 个漏洞）")
    print(f"    新扫描: {diff.new_scan_time}（{diff.new_total} 个漏洞）")
    print(f"    {GREEN}🆕 新增: {diff.total_new} 个{RESET}")
    print(f"    {GREEN}✅ 已修复: {diff.total_fixed} 个{RESET}")
    print(f"    {YELLOW}⚠️ 状态变化: {diff.total_changed} 个{RESET}")
    print(f"    {YELLOW}⏳ 未变: {diff.total_persisted} 个{RESET}")

    out_dir = os.path.dirname(new_path) or "."
    paths = render_diff_report(diff, os.path.join(out_dir, "diff"))
    print(f"{SEPARATOR}")
    print(f"{GREEN}[+]差异报告已生成:{RESET}")
    for p in paths:
        print(f"    {p}")
    print(f"{SEPARATOR}")


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

    ok1, errors1, warnings1 = check_plugin(filepath)
    print(f"{SEPARATOR}")
    print("静态检查:")
    if ok1:
        print(f"  {GREEN}✓ 通过{RESET}")
    else:
        print(f"  {RED}✗ 失败{RESET}")
    for e in errors1:
        print(f"  {RED}错误: {e}{RESET}")
    for w in warnings1:
        print(f"  {YELLOW}警告: {w}{RESET}")

    ok2, errors2, warnings2 = check_plugin_by_import(filepath)
    print("导入检查:")
    if ok2:
        print(f"  {GREEN}✓ 通过{RESET}")
    else:
        print(f"  {RED}✗ 失败{RESET}")
    for e in errors2:
        print(f"  {RED}错误: {e}{RESET}")
    for w in warnings2:
        print(f"  {YELLOW}警告: {w}{RESET}")

    print(f"{SEPARATOR}")
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
        has_fix = "✓" if p["has_fix_detail"] else "✗"
        has_reproduce = "✓" if p["has_reproduce"] else "✗"
        print(
            f"{i:<3} {p['name'][:25]:<25} {p['category']:<10} "
            f"{p['severity']:<8} {(p['cve'] or 'N/A')[:18]:<18} "
            f"{has_fix:<4} {has_reproduce:<4}"
        )
    print(f"{SEPARATOR}")


def run_ci_init_mode(args: Namespace) -> None:
    """生成 CI 配置文件（D28）"""
    from lib.ci_runner import generate_ci_config

    platform = args.ci_init
    output_paths = {
        "github": ".github/workflows/security-scan.yml",
        "gitlab": ".gitlab-ci-security.yml",
        "jenkins": "Jenkinsfile.security",
    }
    output_path = output_paths.get(platform, f"ci-{platform}.yml")
    print(f"{YELLOW}[*]生成 CI 配置: {platform}{RESET}")
    try:
        generate_ci_config(platform, output_path)
        print(f"{GREEN}[+]CI 配置已生成: {output_path}{RESET}")
        if platform == "github":
            print(f"{YELLOW}[*]使用方法:{RESET}")
            print("    1. 将文件提交到仓库")
            print("    2. 在 GitHub Secrets 中设置 SCAN_TARGET")
            print("    3. 推送代码触发扫描")
            print("    4. 在 GitHub → Security → Code scanning 查看结果")
    except ValueError as e:
        print(f"{RED}[!]{e}{RESET}")


def run_wiki_mode(args: Namespace) -> None:
    """生成漏洞知识库（D29）"""
    from lib.vuln_wiki import generate_wiki

    output_path = args.wiki_output or "vuln_wiki.html"
    print(f"{YELLOW}[*]生成漏洞知识库{RESET}")
    paths = generate_wiki(output_path, formats=["html", "json"])
    print(f"{GREEN}[+]知识库已生成:{RESET}")
    for p in paths:
        print(f"    {p}")
    print(f"{YELLOW}[*]用浏览器打开 HTML 文件查看{RESET}")
