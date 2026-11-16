"""v1.7 WP-1：UNKNOWN 归因覆盖率。

数据来源优先级：
  1. artifacts/blind_v4/**/report.json（本地完整盲测产物，gitignore 不入库）
  2. tests/fixtures/blind_v4_unknowns.json（从上述 51 份报告提取的 567 条 UNKNOWN，
     不含 URL/CVE/账号，专供 CI 复跑；由 artifacts 生成，内容稳定）
"""

import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

from common.models import ALL_UNKNOWN_REASONS, STATUS_UNKNOWN, ScanResult, UnknownReason
from core.orchestrator import fill_unknown_reasons

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_GLOB = os.path.join(ROOT, "artifacts", "blind_v4", "**", "report.json")
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "blind_v4_unknowns.json")


def _load_from_reports(files):
    results = []
    for path in files:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
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
    return results


def _load_from_fixture():
    with open(FIXTURE, encoding="utf-8") as f:
        data = json.load(f)
    return [
        ScanResult(
            kind="info",
            name=row.get("name", ""),
            status=STATUS_UNKNOWN,
            evidence=row.get("evidence", ""),
            extra=row.get("extra") or {},
        )
        for row in data.get("results", [])
    ]


def _load_unknowns():
    files = sorted(glob.glob(REPORT_GLOB, recursive=True))
    if files:
        return _load_from_reports(files), f"reports:{len(files)}"
    assert os.path.isfile(FIXTURE), "缺少 artifacts/blind_v4 与 tests/fixtures/blind_v4_unknowns.json"
    return _load_from_fixture(), "fixture"


def _assert_coverage(unknown, source):
    assert len(unknown) >= 500, f"UNKNOWN 样本不足：{len(unknown)}（source={source}）"
    fill_unknown_reasons(unknown)
    unclassified = [r for r in unknown if r.unknown_reason == UnknownReason.UNCLASSIFIED.value]
    classified = len(unknown) - len(unclassified)
    coverage = classified / len(unknown)
    assert coverage >= 0.95, f"归因覆盖率 {coverage:.1%} < 95%（unclassified={len(unclassified)}）"
    assert len(unclassified) / len(unknown) < 0.05
    assert all(r.unknown_reason in ALL_UNKNOWN_REASONS for r in unknown)
    # 不改变任何三态语义
    assert all(r.status == STATUS_UNKNOWN for r in unknown)


def test_blind_v4_unknown_attribution_coverage():
    unknown, source = _load_unknowns()
    _assert_coverage(unknown, source)


def test_committed_fixture_covers_ci_without_artifacts():
    # CI checkout 不含 gitignored 的 artifacts/，必须用 fixture 复跑同一覆盖率
    _assert_coverage(_load_from_fixture(), "fixture")
