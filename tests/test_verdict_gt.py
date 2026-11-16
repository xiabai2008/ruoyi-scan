"""v1.7 WP-2：GT 表的 schema 与唯一性。"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path

GT = Path(__file__).resolve().parent.parent / "data" / "verdict_experiment_gt.json"


def test_gt_table_schema_and_uniqueness():
    assert GT.is_file(), "缺少 data/verdict_experiment_gt.json"
    data = json.loads(GT.read_text(encoding="utf-8"))
    assert data["schema"] == "ruoyi-scan-verdict-gt"
    entries = data["entries"]
    assert len(entries) >= 200, f"GT 条目过少：{len(entries)}"

    keys = [(e["site"], e["plugin"]) for e in entries]
    assert len(keys) == len(set(keys)), "GT 表存在重复 (site, plugin)"
    for e in entries:
        assert e["site"] and e["plugin"]
        assert e["gt_label"] in {"vulnerable", "safe", "unknown"}
        assert e["sources"] and all(isinstance(s, str) and s for s in e["sources"])

    sites = {e["site"] for e in entries}
    assert len(sites) >= 25
    # 三个签名靶场也在表里（报告可能缺席，但 GT 必须先登记）
    assert {"lab-ruoyi-vuln", "lab-ruoyi-safe", "lab-spring-vuln"} <= sites
