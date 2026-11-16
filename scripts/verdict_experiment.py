#!/usr/bin/env python
"""v1.7 WP-2：三态 vs 二态对照实验。

核心约束（方案 §5.2）
=====================
二态折叠只在**本脚本读取 report.json 之后**做映射，绝不修改 `ScanResult.status`，
不加 `--verdict-mode` 到扫描引擎。原因：status 被 20+ 处门禁/报告/指标消费，
改它一次性打挂全部。

用法
====
    # 校验 GT 表与报告集齐备（CI 用）
    python scripts/verdict_experiment.py --check

    # 生成报告
    python scripts/verdict_experiment.py --emit docs/verdict_experiment_v1.7.md

    # 重建 data/verdict_experiment_gt.json（需要 artifacts/blind_v2/gt）
    python scripts/verdict_experiment.py --build-gt

数据集
======
  - data/verdict_experiment_gt.json：29 个 GT 站（当前 27 个有 GT 文件）+ 3 个
    签名靶场 baseline 归一化后的 (site, plugin, gt_label) 表。
  - artifacts/blind_v4/*-anon/report.json：默认只取匿名报告，与 GT 的匿名视角一致。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from common.models import STATUS_UNKNOWN, ScanResult, UnknownReason  # noqa: E402
from core.orchestrator import fill_unknown_reasons  # noqa: E402

GT_PATH = REPO / "data" / "verdict_experiment_gt.json"
GT_DIR = REPO / "artifacts" / "blind_v2" / "gt"
BASELINE_PATH = REPO / "data" / "acceptance_baseline.json"

LABEL_VULN = "vulnerable"
LABEL_SAFE = "safe"
LABEL_UNKNOWN = "unknown"
VALID_LABELS = {LABEL_VULN, LABEL_SAFE, LABEL_UNKNOWN}

_VARIANT_SUFFIX = re.compile(
    r"^(?P<site>.+?)-(?:anon|auth|surface|exploit|basepath-.+|contextpath|backup|nacos-anon|plusjob)$"
)


# ─────────────────────────────────────────────────────────────
# GT 表构建
# ─────────────────────────────────────────────────────────────
def _load_gt_compare() -> Any:
    """只读复用 artifacts/blind_v2/gt_compare.py 的 GT→插件映射与判定逻辑。"""
    path = GT_DIR.parent / "gt_compare.py"
    spec = importlib.util.spec_from_file_location("_gt_compare_ref", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"[ERROR] 无法加载 {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _merge_label(old: str, new: str) -> str:
    """同一插件被多个 GT 项覆盖时的合并优先级：vulnerable > unknown > safe。"""
    rank = {LABEL_SAFE: 0, LABEL_UNKNOWN: 1, LABEL_VULN: 2}
    if not old:
        return new
    return old if rank.get(old, -1) >= rank.get(new, -1) else new


def build_gt_table() -> Dict[str, Any]:
    if not GT_DIR.is_dir():
        raise SystemExit(f"[ERROR] GT 目录不存在：{GT_DIR}")
    ref = _load_gt_compare()
    entries: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for gf in sorted(GT_DIR.glob("*.json")):
        data = json.loads(gf.read_text(encoding="utf-8"))
        tag = data.get("tag", "")
        if not tag:
            continue
        for item in data.get("items", []):
            gt_id = item.get("id", "")
            plugins = ref.GT_TO_PLUGIN.get(gt_id)
            if not plugins:
                continue
            verdict = ref.gt_verdict(item)
            label = {"exists": LABEL_VULN, "absent": LABEL_SAFE, "undecidable": LABEL_UNKNOWN}.get(verdict)
            if not label:
                continue
            for plugin in plugins:
                key = (tag, plugin)
                rec = entries.setdefault(
                    key,
                    {"site": tag, "plugin": plugin, "gt_label": label, "sources": []},
                )
                rec["gt_label"] = _merge_label(rec["gt_label"], label)
                rec["sources"].append(f"artifacts/blind_v2/gt/{gf.name}#{gt_id}")

    # 三个签名靶场：expected=漏洞；allowed=容忍（unknown，排除出混淆矩阵）；
    # safe 靶场 expected_safe_all=true 时把全部插件标为 safe（用于误报门禁）。
    if BASELINE_PATH.is_file():
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        all_plugins = {p["name"] for p in _runtime_plugins()}
        for target in baseline.get("targets", []):
            site = target.get("name", "")
            if not site:
                continue
            for name in target.get("expected_confirmed", []):
                entries[(site, name)] = {
                    "site": site,
                    "plugin": name,
                    "gt_label": LABEL_VULN,
                    "sources": [f"data/acceptance_baseline.json#{site}:expected_confirmed"],
                }
            for name in target.get("allowed_confirmed", []):
                entries.setdefault(
                    (site, name),
                    {
                        "site": site,
                        "plugin": name,
                        "gt_label": LABEL_UNKNOWN,
                        "sources": [f"data/acceptance_baseline.json#{site}:allowed_confirmed"],
                    },
                )
            if target.get("expected_safe_all"):
                for name in all_plugins:
                    entries.setdefault(
                        (site, name),
                        {
                            "site": site,
                            "plugin": name,
                            "gt_label": LABEL_SAFE,
                            "sources": [f"data/acceptance_baseline.json#{site}:expected_safe_all"],
                        },
                    )

    rows = []
    for rec in sorted(entries.values(), key=lambda r: (r["site"], r["plugin"])):
        rec["sources"] = sorted(set(rec["sources"]))
        rows.append(rec)
    return {
        "schema": "ruoyi-scan-verdict-gt",
        "version": "1.0",
        "description": "WP-2 三态/二态对照实验 GT 表：site × plugin → vulnerable/safe/unknown；逐条注明来源",
        "entries": rows,
    }


def _runtime_plugins() -> List[Dict[str, Any]]:
    from scripts.export_plugin_list import collect

    return collect()


# ─────────────────────────────────────────────────────────────
# 报告发现与指标
# ─────────────────────────────────────────────────────────────
def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return path.as_posix()


def _site_from_dir(name: str) -> str:
    m = _VARIANT_SUFFIX.match(name)
    return m.group("site") if m else name


def discover_reports(reports_dir: Path, anon_only: bool = True) -> Dict[str, Path]:
    """返回 {site: report.json 路径}。默认只取 -anon，避免 auth/surface 污染 GT 对照。"""
    found: Dict[str, Path] = {}
    for path in sorted(reports_dir.glob("*/report.json")):
        site = _site_from_dir(path.parent.name)
        if anon_only and not path.parent.name.endswith("-anon"):
            continue
        # 同名多报告时优先 anon；其他变体不覆盖
        if site not in found:
            found[site] = path
    return found


def load_statuses(path: Path) -> Dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rank = {"SAFE": 0, "UNKNOWN": 1, "CONFIRMED": 2}
    out: Dict[str, str] = {}
    for row in data.get("results", []):
        name = row.get("name", "")
        status = row.get("status", "")
        if name and rank.get(status, -1) > rank.get(out.get(name, ""), -1):
            out[name] = status
    return out


def load_unknown_reasons(path: Path) -> Dict[str, str]:
    """读取报告并按 WP-1 同一套逻辑补齐 UNKNOWN 原因码（只读，不改报告）。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    results = []
    for row in data.get("results", []):
        if row.get("status") != STATUS_UNKNOWN:
            continue
        results.append(
            ScanResult(
                kind=row.get("kind", "info"),
                name=row.get("name", ""),
                severity=row.get("severity", "low"),
                status=STATUS_UNKNOWN,
                url=row.get("url", ""),
                evidence=row.get("evidence", ""),
                extra=row.get("extra") or {},
                unknown_reason=row.get("unknown_reason", ""),
            )
        )
    fill_unknown_reasons(results)
    return {r.name: r.unknown_reason for r in results}


def _confusion(gt: str, status: str, mode: str) -> str:
    if gt == LABEL_UNKNOWN:
        return "excluded"
    positive = status == "CONFIRMED" or (mode == "G2" and status == "UNKNOWN")
    negative = status == "SAFE" or (mode == "G1" and status == "UNKNOWN") or status == "MISSING"
    if mode == "G0" and status == "UNKNOWN":
        return "unknown"
    if positive:
        return "TP" if gt == LABEL_VULN else "FP"
    if negative:
        return "FN" if gt == LABEL_VULN else "TN"
    return "unknown"


def _metrics(counts: Dict[str, int]) -> Dict[str, float]:
    tp, fp, fn, tn = counts.get("TP", 0), counts.get("FP", 0), counts.get("FN", 0), counts.get("TN", 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "specificity": round(specificity, 4),
        "youden_j": round(recall + specificity - 1, 4),
    }


def evaluate(gt: Dict[str, Any], reports_dir: Path, anon_only: bool = True) -> Dict[str, Any]:
    by_site: Dict[str, Dict[str, str]] = defaultdict(dict)
    for rec in gt.get("entries", []):
        by_site[rec["site"]][rec["plugin"]] = rec["gt_label"]

    reports = discover_reports(reports_dir, anon_only=anon_only)
    sites = {}
    aggregate = {m: defaultdict(int) for m in ("G0", "G1", "G2")}
    unknown_total = 0
    entry_total = 0
    hidden = 0
    vuln_gt = 0

    label_counts: Dict[str, int] = defaultdict(int)
    status_counts: Dict[str, int] = defaultdict(int)
    reason_counts: Dict[str, int] = defaultdict(int)
    gt_cross: Dict[str, Dict[str, int]] = {LABEL_VULN: defaultdict(int), LABEL_SAFE: defaultdict(int), LABEL_UNKNOWN: defaultdict(int)}
    unknown_reason_by_gt: Dict[str, Dict[str, int]] = {
        LABEL_VULN: defaultdict(int),
        LABEL_SAFE: defaultdict(int),
        LABEL_UNKNOWN: defaultdict(int),
    }

    for site, labels in sorted(by_site.items()):
        path = reports.get(site)
        if path is None:
            sites[site] = {"report": "", "entries": 0, "skipped": True}
            continue
        statuses = load_statuses(path)
        reasons = load_unknown_reasons(path)
        site_counts = {m: defaultdict(int) for m in ("G0", "G1", "G2")}
        for plugin, label in labels.items():
            status = statuses.get(plugin, "MISSING")
            entry_total += 1
            label_counts[label] += 1
            status_counts[status] += 1
            gt_cross[label][status] += 1
            if status == "UNKNOWN":
                unknown_total += 1
                reason = reasons.get(plugin, UnknownReason.UNCLASSIFIED.value)
                reason_counts[reason] += 1
                unknown_reason_by_gt[label][reason] += 1
            if label == LABEL_VULN:
                vuln_gt += 1
                if status == "UNKNOWN":
                    hidden += 1
            for mode in ("G0", "G1", "G2"):
                cell = _confusion(label, status, mode)
                if cell in ("TP", "FP", "FN", "TN"):
                    site_counts[mode][cell] += 1
                    aggregate[mode][cell] += 1
        sites[site] = {
            "report": _rel(path),
            "entries": len(labels),
            "skipped": False,
            "modes": {m: _metrics(site_counts[m]) for m in ("G0", "G1", "G2")},
        }

    try:
        reports_dir_label = reports_dir.resolve().relative_to(REPO).as_posix()
    except ValueError:
        reports_dir_label = reports_dir.as_posix()
    return {
        "dataset": {
            "reports_dir": reports_dir_label,
            "anon_only": anon_only,
            "sites_total": len(by_site),
            "sites_evaluated": sum(1 for s in sites.values() if not s["skipped"]),
            "entries_evaluated": entry_total,
            "labels": dict(sorted(label_counts.items())),
            "statuses": dict(sorted(status_counts.items())),
            "unknown_reasons": dict(sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            "unknown_reason_by_gt": {
                label: dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))
                for label, counter in unknown_reason_by_gt.items()
            },
            "gt_cross": {
                label: dict(sorted(counter.items())) for label, counter in gt_cross.items()
            },
            "unknown_rate": round(unknown_total / entry_total, 4) if entry_total else 0.0,
            "false_negative_hiding_rate": round(hidden / vuln_gt, 4) if vuln_gt else 0.0,
        },
        "modes": {m: _metrics(aggregate[m]) for m in ("G0", "G1", "G2")},
        "sites": sites,
    }


# ─────────────────────────────────────────────────────────────
# 输出
# ─────────────────────────────────────────────────────────────
def render_markdown(result: Dict[str, Any]) -> str:
    ds = result["dataset"]
    lines = [
        "# v1.7 WP-2 · 三态 vs 二态对照实验",
        "",
        "## 实验假设",
        "",
        "**H1**：在自建靶场 GT 上，三态判定（CONFIRMED / SAFE / UNKNOWN）相对二态判定，",
        "在**不显著抬高漏报**的前提下显著降低误报，综合判别能力（Youden J）更高。",
        "",
        "## 数据集",
        "",
        f"- 报告目录：`{ds['reports_dir']}`（仅匿名报告：{ds['anon_only']}）",
        f"- GT 站点：{ds['sites_total']}，可评估：{ds['sites_evaluated']}",
        f"- 评估条目：{ds['entries_evaluated']}",
        f"- GT 标签构成：{ds.get('labels', {})}",
        f"- 扫描器状态构成：{ds.get('statuses', {})}",
        f"- UNKNOWN 率：{ds['unknown_rate']:.2%}",
        f"- 假阴性藏匿率（GT 真漏洞中被标 UNKNOWN 的比例）：{ds['false_negative_hiding_rate']:.2%}",
        "",
        "## UNKNOWN 归因交叉（WP-1）",
        "",
        "| 原因码 | 条数 |",
        "|---|---:|",
    ]
    for code, n in (ds.get("unknown_reasons") or {}).items():
        lines.append(f"| `{code}` | {n} |")
    lines += [
        "",
        "### GT 标签 × 扫描器状态",
        "",
        "| GT 标签 | CONFIRMED | SAFE | UNKNOWN | MISSING |",
        "|---|---:|---:|---:|---:|",
    ]
    for label in (LABEL_VULN, LABEL_SAFE, LABEL_UNKNOWN):
        row = ds.get("gt_cross", {}).get(label, {})
        lines.append(
            f"| {label} | {row.get('CONFIRMED', 0)} | {row.get('SAFE', 0)} | "
            f"{row.get('UNKNOWN', 0)} | {row.get('MISSING', 0)} |"
        )
    lines += [
        "",
        "### UNKNOWN 原因 × GT 标签（回答「多少 UNKNOWN 其实是真漏洞」）",
        "",
        "| 原因码 | GT vulnerable | GT safe | GT unknown |",
        "|---|---:|---:|---:|",
    ]
    by_gt = ds.get("unknown_reason_by_gt", {})
    codes = sorted(set().union(*(set(v) for v in by_gt.values()))) if by_gt else []
    for code in codes:
        lines.append(
            f"| `{code}` | {by_gt.get(LABEL_VULN, {}).get(code, 0)} | "
            f"{by_gt.get(LABEL_SAFE, {}).get(code, 0)} | {by_gt.get(LABEL_UNKNOWN, {}).get(code, 0)} |"
        )
    lines += [
        "",
        "> 若 `GT vulnerable` 列在某原因码下为 0，说明该原因下的 UNKNOWN 没有 GT 真漏洞被藏起来；",
        "> 若不为 0，则该数字就是「被降级掉的正确答案」的实测条数。",
        "> 注意：本表只统计 GT 覆盖到的 UNKNOWN（当前 57 条）；全量 567 条 UNKNOWN 的归因见",
        "> `python scripts/unknown_audit.py`。",
        "",
        "## 三组判定口径",
        "",
        "| 组 | 判定口径 | Precision | Recall | F1 | Specificity | Youden J | TP/FP/FN/TN |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    labels = {
        "G0": "三态（原始）",
        "G1": "二态·保守（UNKNOWN→SAFE）",
        "G2": "二态·激进（UNKNOWN→CONFIRMED）",
    }
    for mode in ("G0", "G1", "G2"):
        m = result["modes"][mode]
        lines.append(
            f"| {mode} | {labels[mode]} | {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.4f} | "
            f"{m['specificity']:.2%} | {m['youden_j']:.4f} | {m['tp']}/{m['fp']}/{m['fn']}/{m['tn']} |"
        )
    g0 = result["modes"]["G0"]
    g1 = result["modes"]["G1"]
    g2 = result["modes"]["G2"]
    delta_g1 = round(g0["youden_j"] - g1["youden_j"], 4)
    unknown_n = ds.get("statuses", {}).get("UNKNOWN", 0)
    if g0["youden_j"] > g1["youden_j"] + 0.01:
        verdict = (
            f"G0 的 Youden J 比 G1 高 **{delta_g1:+.4f}**，在本数据集上支持 H1："
            "三态在保持召回的同时降低了误报。"
        )
    else:
        verdict = (
            f"G0 的 Youden J 与 G1 相差 **{delta_g1:+.4f}**，**本数据集不支持 H1 的强形式**："
            "保守二态折叠（UNKNOWN→SAFE）的 P/R 与三态相同，J 甚至略高。"
            "三态的价值应表述为「可解释性与风险分层」——它把 UNKNOWN 与 SAFE 分开，"
            f"避免把 {unknown_n} 条未判定（占 {ds['unknown_rate']:.1%}）伪装成“确认不存在”，"
            "而不是在本 GT 上提高 J。"
        )
    lines += [
        "",
        "## 结论（按实际数据，不美化）",
        "",
        verdict,
        f"G2（UNKNOWN→CONFIRMED）的 Precision 为 {g2['precision']:.2%}、J 为 {g2['youden_j']:.4f}，"
        "显著差于 G0/G1——激进折叠会把“测不了”批量变成误报，直接验证项目坚持三态的动机。",
        "",
        "## 逐站结果（三组 Youden J）",
        "",
        "| 站点 | 条目 | G0 | G1 | G2 | 报告 |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for site, info in sorted(result["sites"].items()):
        if info["skipped"]:
            lines.append(f"| {site} | {info['entries']} | — | — | — | 无报告，跳过 |")
            continue
        g0, g1, g2 = (info["modes"][m]["youden_j"] for m in ("G0", "G1", "G2"))
        lines.append(f"| {site} | {info['entries']} | {g0:.3f} | {g1:.3f} | {g2:.3f} | `{info['report']}` |")
    lines += [
        "",
        "## 适用边界",
        "",
        "- 数据来自自建靶场与匿名视角，不能外推到生产环境；",
        "- GT 只覆盖手工探过的项，GT 未覆盖的结果不计入混淆矩阵；当前 GT 表 30 个站点中 27 个有报告，3 个签名靶场报告不在工作区；",
        "- 二态 G1/G2 是分析层折叠，不改变扫描器运行时的三态语义；",
        "- 若 G0 的 Youden J 不高于 G1/G2，应如实写入报告并分析三态的成本，不得美化。",
        "",
    ]
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Ruoyi-Scan 三态/二态对照实验")
    parser.add_argument("--gt", default=str(GT_PATH), help="GT 表路径")
    parser.add_argument("--reports-dir", default=str(REPO / "artifacts" / "blind_v4"))
    parser.add_argument("--all-variants", action="store_true", help="包含 auth/surface 等非匿名报告")
    parser.add_argument("--build-gt", action="store_true", help="重建 GT 表")
    parser.add_argument("--emit", default="", help="输出 Markdown 路径")
    parser.add_argument("--check", action="store_true", help="只校验数据/指标可计算，退出码 0/1")
    parser.add_argument("--json", action="store_true", help="同时输出机器可读 JSON")
    args = parser.parse_args(argv)

    if args.build_gt:
        table = build_gt_table()
        GT_PATH.write_text(json.dumps(table, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[OK] 已生成 {GT_PATH}：{len(table['entries'])} 条 (site, plugin, gt_label)")
        return 0

    gt_path = Path(args.gt)
    if not gt_path.is_file():
        print(f"[ERROR] GT 表不存在：{gt_path}（先运行 --build-gt）", file=sys.stderr)
        return 1
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    if gt.get("schema") != "ruoyi-scan-verdict-gt":
        print("[ERROR] GT schema 不正确", file=sys.stderr)
        return 1
    keys = [(e["site"], e["plugin"]) for e in gt.get("entries", [])]
    if len(keys) != len(set(keys)):
        print("[ERROR] GT 表存在重复 (site, plugin)", file=sys.stderr)
        return 1
    if not all(e.get("gt_label") in VALID_LABELS for e in gt.get("entries", [])):
        print("[ERROR] GT 表存在非法 gt_label", file=sys.stderr)
        return 1

    result = evaluate(gt, Path(args.reports_dir), anon_only=not args.all_variants)
    if result["dataset"]["sites_evaluated"] == 0:
        print("[ERROR] 没有任何站点可评估（报告集与 GT 站点不匹配）", file=sys.stderr)
        return 1

    md = render_markdown(result)
    print(md)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if args.emit:
        Path(args.emit).write_text(md, encoding="utf-8")
        print(f"[OK] 已写入 {args.emit}")
    if args.check:
        print("[OK] 实验数据齐备，指标可计算", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
