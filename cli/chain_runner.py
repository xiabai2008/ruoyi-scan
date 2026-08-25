"""CLI submodule — 漏洞利用链执行"""

from __future__ import annotations

import datetime
import time
from argparse import Namespace

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, FingerprintResult
from core.session import SessionManager
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW

logger = get_logger(__name__)


def run_chain_mode(chain_name: str, args: Namespace) -> None:
    """漏洞利用链执行模式（D6）：按链定义编排多插件"""
    from chains.registry import get_chain, list_chains
    from core.chain import ChainEngine

    # 链列表模式：--chain list 与 --chain-list 等价，仅列出可用链不执行
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
    # "__flag__" 是开关占位符（-u 只作开关传递时），此时视为未指定目标
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

    from core.fingerprint import detect_cms
    from core.http import normalize_target

    target = normalize_target(target)
    session = SessionManager(proxy=args.proxy, debug=args.debug, timeout=args.timeout)

    # 手动指定 CMS 时跳过指纹识别：confidence=1.0 / matched=["manual"] 标记为人工确认
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
    # started_at 用于报告时间戳，t0 用于耗时统计；均在链执行前记下起点
    started_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    t0 = time.time()

    # 节点结果回调：CONFIRMED=节点成功 / SAFE=节点失败 / 其余视为未知并带出证据
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
    # 链状态配色与扫描结果一致：CONFIRMED 绿 / UNKNOWN 黄 / 其余状态红
    status_color = (
        GREEN if chain_result.status == "CONFIRMED" else (YELLOW if chain_result.status == "UNKNOWN" else RED)
    )
    print(f"{YELLOW}[*]链执行状态: {status_color}{chain_result.status}{YELLOW}{RESET}")
    print(f"{YELLOW}[*]耗时: {duration:.2f}s{RESET}")

    # 逐节点回放执行结果（success 绿 / skipped 黄 / 其余失败红），便于定位断链环节
    for step_id, status in chain_result.node_status.items():
        color = GREEN if status == "success" else (YELLOW if status == "skipped" else RED)
        print(f"  {color}{step_id}: {status}{RESET}")

    if chain_result.facts:
        print(f"{YELLOW}[*]提取事实:{RESET}")
        for k, v in chain_result.facts.items():
            print(f"  {k} = {v}")

    # 整条链汇总为一个 ScanResult 进入报告；节点级详情保留在 node_status/facts 中
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
        from cli.runner import _parse_report_formats
        from core.report import ReportBuilder

        builder = ReportBuilder(results=all_results, target=target, summary=summary, dedup=not args.no_dedup)
        paths = builder.render_all(args.report, formats=_parse_report_formats(args.report_format))
        print(f"{SEPARATOR}")
        for p in paths:
            print(f"{GREEN}[*]报告已生成：{p}{RESET}")
