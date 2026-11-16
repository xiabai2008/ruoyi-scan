#!/usr/bin/env python
"""v1.7 WP-1：盲测报告 UNKNOWN 归因审计。

用途
====
把 artifacts/blind_v4 下所有 report.json 的 UNKNOWN 结果按 `unknown_reason` 归类，
输出逐类计数与覆盖率；回答「567 条 UNKNOWN 里，多少是外部条件测不了、多少是
插件证据不足、多少无法解释」。

归因路径与运行时一致：
  1. extra 结构化标记（auth_wall / no_evidence / blocked / denied / unreachable）
  2. lib/unknown_reasons.py 的受控历史证据前缀白名单
  3. unclassified（必须可计数，目标 <5%）

用法
====
    python scripts/unknown_audit.py
    python scripts/unknown_audit.py --reports-dir artifacts/blind_v4 --check
    python scripts/unknown_audit.py --emit docs/unknown_audit_v1.7.md
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List, Tuple

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from common.models import (  # noqa: E402
    ALL_UNKNOWN_REASONS,
    STATUS_UNKNOWN,
    ScanResult,
    UnknownReason,
    unknown_reason_label,
)
from core.orchestrator import fill_unknown_reasons  # noqa: E402

# 归因大类的展示顺序
_GROUP_OF = {
    UnknownReason.AUTH_WALL.value: "缺少外部条件（登录/权限/预算）",
    UnknownReason.NO_SESSION.value: "缺少外部条件（登录/权限/预算）",
    UnknownReason.NO_LOWPRIV.value: "缺少外部条件（登录/权限/预算）",
    UnknownReason.DENIED.value: "缺少外部条件（登录/权限/预算）",
    UnknownReason.BLOCKED.value: "缺少外部条件（登录/权限/预算）",
    UnknownReason.BUDGET_EXCEEDED.value: "缺少外部条件（登录/权限/预算）",
    UnknownReason.UNREACHABLE.value: "目标/网络不可达",
    UnknownReason.NO_EVIDENCE.value: "判定证据不足",
    UnknownReason.INSUFFICIENT_EVIDENCE.value: "判定证据不足",
    UnknownReason.ENDPOINT_ABSENT.value: "端点不存在（正确行为）",
    UnknownReason.UNCLASSIFIED.value: "未归类",
}


def _load_unknowns(reports_dir: str) -> Tuple[List[Tuple[str, ScanResult]], List[str]]:
    files = sorted(glob.glob(os.path.join(reports_dir, "**", "report.json"), recursive=True))
    if not files:
        raise SystemExit(f"[ERROR] 未找到报告：{reports_dir}/**/report.json")
    results: List[Tuple[str, ScanResult]] = []
    for path in files:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for row in data.get("results", []):
            if row.get("status") != STATUS_UNKNOWN:
                continue
            results.append(
                (
                    path,
                    ScanResult(
                        kind=row.get("kind", "info"),
                        name=row.get("name", ""),
                        severity=row.get("severity", "low"),
                        status=STATUS_UNKNOWN,
                        url=row.get("url", ""),
                        evidence=row.get("evidence", ""),
                        extra=row.get("extra") or {},
                        unknown_reason=row.get("unknown_reason", ""),
                    ),
                )
            )
    return results, files


def audit(reports_dir: str) -> Dict[str, Any]:
    pairs, files = _load_unknowns(reports_dir)
    fill_unknown_reasons([r for _, r in pairs])
    counts = Counter(r.unknown_reason for _, r in pairs)
    total = len(pairs)
    unclassified = counts.get(UnknownReason.UNCLASSIFIED.value, 0)
    coverage = (total - unclassified) / total if total else 1.0
    groups = Counter(_GROUP_OF.get(code, "未归类") for code, n in counts.items() for _ in range(n))
    examples = [
        {
            "report": os.path.relpath(path, _PROJECT_ROOT).replace(os.sep, "/"),
            "name": r.name,
            "evidence": (r.evidence or "")[:160],
        }
        for path, r in pairs
        if r.unknown_reason == UnknownReason.UNCLASSIFIED.value
    ]
    return {
        "reports": len(files),
        "unknown_total": total,
        "coverage": coverage,
        "unclassified": unclassified,
        "counts": dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "groups": dict(sorted(groups.items(), key=lambda kv: (-kv[1], kv[0]))),
        "unclassified_examples": examples,
        "unknown_reasons_valid": all(code in ALL_UNKNOWN_REASONS for code in counts),
    }


def render_markdown(result: Dict[str, Any]) -> str:
    lines = [
        "# v1.7 WP-1 · UNKNOWN 归因审计",
        "",
        f"- 报告数：**{result['reports']}**",
        f"- UNKNOWN 总数：**{result['unknown_total']}**",
        f"- 归因覆盖率：**{result['coverage']:.2%}**",
        f"- unclassified：**{result['unclassified']}**（目标 <5%）",
        "",
        "## 逐类计数",
        "",
        "| 原因码 | 中文 | 条数 | 占比 |",
        "|---|---|---:|---:|",
    ]
    total = result["unknown_total"] or 1
    for code, n in result["counts"].items():
        lines.append(f"| `{code}` | {unknown_reason_label(code)} | {n} | {n / total:.1%} |")
    lines += [
        "",
        "## 归因大类",
        "",
        "| 大类 | 条数 | 占比 |",
        "|---|---:|---:|",
    ]
    for group, n in result["groups"].items():
        lines.append(f"| {group} | {n} | {n / total:.1%} |")
    examples = result.get("unclassified_examples") or []
    if examples:
        lines += [
            "",
            f"## unclassified 明细（{len(examples)} 条，逐条可列出）",
            "",
            "| # | 报告 | 结果名 | 证据前缀 |",
            "|---:|---|---|---|",
        ]
        for i, ex in enumerate(examples, 1):
            evidence = str(ex["evidence"]).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {i} | `{ex['report']}` | {ex['name']} | {evidence} |")
    lines += [
        "",
        "> 说明：本表回答「为什么无法判定」，不改变任何 status。",
        "> 「有多少 UNKNOWN 其实是 GT 真漏洞」属于 WP-2 的假阴性藏匿率，需结合 ground truth 计算。",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Ruoyi-Scan UNKNOWN 归因审计")
    parser.add_argument("--reports-dir", default=os.path.join(_PROJECT_ROOT, "artifacts", "blind_v4"))
    parser.add_argument("--emit", default="", help="输出 Markdown 路径（空则不写文件）")
    parser.add_argument("--check", action="store_true", help="覆盖率 <95% 或 unclassified >=5% 时退出 1")
    args = parser.parse_args()

    result = audit(args.reports_dir)
    md = render_markdown(result)
    print(md)
    if args.emit:
        with open(args.emit, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[OK] 已写入 {args.emit}")

    if args.check and (result["coverage"] < 0.95 or result["unclassified"] / max(1, result["unknown_total"]) >= 0.05):
        print("[FAIL] 归因覆盖率不达标", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
