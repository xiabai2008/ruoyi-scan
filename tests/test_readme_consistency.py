"""v1.7 WP-2：README 对外口径的轻量一致性检查。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"


def test_readme_declares_coverage_proxy_not_detection_rate():
    text = README.read_text(encoding="utf-8")
    assert "覆盖率代理指标" in text
    assert "不是检出率" in text
    # v1.7 的 GT 指标与实验报告必须可追溯
    assert "verdict_experiment_v1.7.md" in text
    assert "Youden J" in text
    assert "75.00%" in text and "81.82%" in text


def test_readme_keeps_historical_snapshots():
    text = README.read_text(encoding="utf-8")
    # 历史盲测快照必须保留，不能为了 SSOT 机械替换
    assert "29 / 54" in text
    assert "46 / 54" in text
    assert "48 / 54" in text
