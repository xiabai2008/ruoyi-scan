"""CLI 报告生成与后处理（从 run_mode 抽出，保持 CLI/API 分工清晰）。

层：控制层（cli）｜上游：runner.run_mode｜下游：core.report / lib.*
先读：docs/CONCEPTS.md#12-报告管线
"""

from __future__ import annotations

import datetime
import os
from argparse import Namespace
from typing import Any, Dict, List

from common.models import ScanResult
from core.report import ReportBuilder
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW


def run_cli_report(
    args: Namespace,
    req: Any,
    all_results: List[ScanResult],
    target_normalized: str,
    label: str,
    duration: float,
    detected_fingerprint: Dict[str, Any],
    orch: Any,
    surface_status: str,
    formats: Any,
) -> None:
    """生成 CLI 报告并执行全部后处理（模板/整改/降噪/基线/差异/通知/AI 解读）。"""
    started_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_label = label
    if req.template:
        from lib.scan_profiles import get_template

        template_obj = get_template(req.template)
        if template_obj and template_obj.report_label:
            report_label = template_obj.report_label
    # E3：版本对照矩阵（检测版本 vs 各插件适用性）
    # CLI 传 report_dir="" 由自己出报告，orchestrator 的矩阵分支被整体跳过——
    # 若不在此补算，报告的 version_matrix 恒为空、版本对照表不显示（2026-09-19 修复）。
    version_matrix = []
    try:
        fp_cms = req.cms or detected_fingerprint.get("cms", "")
        fp_version = detected_fingerprint.get("version", "")
        if fp_cms and fp_version:
            from common.models import FingerprintResult
            from core.loader import load_plugins
            from core.router import Router
            from core.ruoyi_versions import build_version_matrix

            fp_obj = FingerprintResult(
                cms=fp_cms,
                version=fp_version,
                confidence=detected_fingerprint.get("confidence", 0.0),
                matched=list(detected_fingerprint.get("matched", [])),
                variant=detected_fingerprint.get("variant", ""),
            )
            # 用未过滤候选集：矩阵要展示「哪些插件因版本被跳过」
            cands = Router().candidates(fp_obj) or load_plugins("plugins.ruoyi")
            version_matrix = build_version_matrix(fp_version, cands)
    except Exception:
        version_matrix = []  # 矩阵生成失败不影响报告主体

    summary = {
        "started_at": started_at,
        "duration": duration,
        "request_count": getattr(orch, "last_request_count", 0),
        "blocked": getattr(orch, "last_block_info", {}),
        "mode": report_label,
        "auth_status": {
            "admin": req.auth_status,
            "surface": surface_status,
        },
        "version_matrix": version_matrix,
        "fingerprint": {
            "cms": req.cms or detected_fingerprint.get("cms", ""),
            "version": detected_fingerprint.get("version", ""),
            "variant": detected_fingerprint.get("variant", ""),
            "confidence": 1.0 if req.cms else detected_fingerprint.get("confidence", 0.0),
            "matched": ["manual"] if req.cms else detected_fingerprint.get("matched", []),
        },
    }
    builder = ReportBuilder(results=all_results, target=target_normalized, summary=summary, dedup=not args.no_dedup)
    paths = builder.render_all(args.report, formats=formats)
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

    _run_report_postprocess(args, builder)


def _run_report_postprocess(args: Namespace, builder: ReportBuilder) -> None:
    """报告生成后的可选后处理（模板/整改/降噪/基线/差异/通知/AI 解读）。"""
    # G5：合规报告模板渲染（安服交付物定制）
    if getattr(args, "report_template", None):
        from lib.report_docx_template import render_docx_template

        tpl_out = os.path.join(args.report, "report_custom.docx")
        tpl_path = render_docx_template(args.report_template, builder, tpl_out)
        if tpl_path:
            print(f"{GREEN}[*]模板报告已生成：{tpl_path}{RESET}")

    # G5：整改复测工作流（--remediation 基线对比 → 整改验证报告）
    if getattr(args, "remediation", None):
        from lib.remediation import run_remediation

        rem_paths = run_remediation(args, builder)
        for rp in rem_paths:
            print(f"{GREEN}[*]整改验证报告已生成：{rp}{RESET}")

    # G3：UNKNOWN 智能降噪（--ai-triage 聚类分流，三态纪律不受影响）
    if getattr(args, "ai_triage", False):
        from lib.ai_triage import run_ai_triage_mode

        run_ai_triage_mode(args, builder=builder)

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

    # E8：AI 报告解读（--ai-report zh|en）
    if getattr(args, "ai_report", None):
        from lib.ai_report import run_ai_report_mode

        lang = args.ai_report
        if lang not in ("zh", "en"):
            lang = "zh"
        print(f"{YELLOW}[*]AI 漏洞分析生成中（%s）...{RESET}" % lang)
        try:
            analysis_path = run_ai_report_mode(args.report, builder.to_dict(), lang=lang)
            print(f"{GREEN}[*]AI 分析已生成：{analysis_path}{RESET}")
        except Exception as e:
            print(f"{RED}[!]AI 分析生成失败: {e}{RESET}")
