"""v1.7 WP-2：三态/二态对照实验的指标计算。"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.verdict_experiment import evaluate


def _write_report(tmp_path, site, rows):
    d = tmp_path / f"{site}-anon"
    d.mkdir(parents=True)
    (d / "report.json").write_text(
        json.dumps({"target": f"http://{site}/", "results": rows}, ensure_ascii=False),
        encoding="utf-8",
    )


def test_confusion_metrics_are_hand_verifiable(tmp_path):
    _write_report(
        tmp_path,
        "S1",
        [
            {"name": "A", "status": "CONFIRMED", "evidence": "ok", "extra": {}},
            {"name": "B", "status": "CONFIRMED", "evidence": "fp", "extra": {}},
            {"name": "C", "status": "UNKNOWN", "evidence": "缺少低权账号", "extra": {}},
            {"name": "D", "status": "UNKNOWN", "evidence": "登录墙", "extra": {}},
        ],
    )
    gt = {
        "schema": "ruoyi-scan-verdict-gt",
        "entries": [
            {"site": "S1", "plugin": "A", "gt_label": "vulnerable", "sources": ["x"]},
            {"site": "S1", "plugin": "B", "gt_label": "safe", "sources": ["x"]},
            {"site": "S1", "plugin": "C", "gt_label": "safe", "sources": ["x"]},
            {"site": "S1", "plugin": "D", "gt_label": "vulnerable", "sources": ["x"]},
        ],
    }
    result = evaluate(gt, tmp_path, anon_only=True)
    ds = result["dataset"]
    assert ds["sites_evaluated"] == 1
    assert ds["entries_evaluated"] == 4
    assert ds["statuses"]["UNKNOWN"] == 2
    assert abs(ds["unknown_rate"] - 0.5) < 1e-9
    # GT 真漏洞 A/D 中 D 被标 UNKNOWN → 藏匿率 1/2
    assert abs(ds["false_negative_hiding_rate"] - 0.5) < 1e-9

    # G0：A TP；B FP；C/D 的 UNKNOWN 被排除出混淆矩阵（另由藏匿率统计）
    g0 = result["modes"]["G0"]
    assert (g0["tp"], g0["fp"], g0["fn"], g0["tn"]) == (1, 1, 0, 0)
    assert abs(g0["precision"] - 0.5) < 1e-9
    assert abs(g0["recall"] - 1.0) < 1e-9
    assert abs(g0["f1"] - 0.6667) < 1e-4

    # G1：UNKNOWN→SAFE：D 变 FN、C 变 TN；B 仍 FP
    g1 = result["modes"]["G1"]
    assert (g1["tp"], g1["fp"], g1["fn"], g1["tn"]) == (1, 1, 1, 1)
    assert abs(g1["recall"] - 0.5) < 1e-9

    # G2：UNKNOWN→CONFIRMED：C 变 FP、D 变 TP；B 仍 FP
    g2 = result["modes"]["G2"]
    assert (g2["tp"], g2["fp"], g2["fn"], g2["tn"]) == (2, 2, 0, 0)
    assert abs(g2["precision"] - 0.5) < 1e-9


def test_missing_report_is_skipped(tmp_path):
    gt = {
        "schema": "ruoyi-scan-verdict-gt",
        "entries": [{"site": "NOPE", "plugin": "A", "gt_label": "vulnerable", "sources": ["x"]}],
    }
    result = evaluate(gt, tmp_path, anon_only=True)
    assert result["dataset"]["sites_evaluated"] == 0
    assert result["sites"]["NOPE"]["skipped"] is True
