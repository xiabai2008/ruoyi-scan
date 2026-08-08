# F4 验收基线测试：schema 校验 + 插件元信息对照（无靶场也能跑）
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _baseline_path():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "acceptance_baseline.json")


def test_baseline_schema():
    """基线 schema 完整（schema/version/targets）"""
    with open(_baseline_path(), encoding="utf-8") as f:
        baseline = json.load(f)
    assert baseline["schema"] == "ruoyi-scan-acceptance-baseline"
    assert baseline["version"]
    assert len(baseline["targets"]) >= 2, "应至少含 vuln + safe 两个目标"
    for t in baseline["targets"]:
        assert t["url"], "目标缺少 url"
        assert t["mode"] in ("vuln", "safe")
        assert "expected_confirmed" in t
    print("PASS test_baseline_schema")


def test_baseline_confirmed_matches_plugins():
    """vuln 基线预期命中项都能在 ruoyi 插件包中找到对应插件名"""
    from core.loader import load_plugins

    plugin_names = {getattr(cls, "name", "") for cls in load_plugins("plugins.ruoyi")}
    with open(_baseline_path(), encoding="utf-8") as f:
        baseline = json.load(f)
    vuln = [t for t in baseline["targets"] if t["mode"] == "vuln"][0]
    for name in vuln["expected_confirmed"]:
        assert name in plugin_names, f"基线预期项 {name} 不在 ruoyi 插件包中（插件已改名/删除？）"
    print("PASS test_baseline_confirmed_matches_plugins: %d 项全部匹配" % len(vuln["expected_confirmed"]))


def test_baseline_safe_zero():
    """safe 基线开启零误报门禁"""
    with open(_baseline_path(), encoding="utf-8") as f:
        baseline = json.load(f)
    safe = [t for t in baseline["targets"] if t["mode"] == "safe"][0]
    assert safe.get("expected_safe_all") is True, "safe 模式应开启 expected_safe_all 门禁"
    assert safe["expected_confirmed"] == []
    print("PASS test_baseline_safe_zero")


def test_check_target_logic():
    """对拍判定逻辑：漏报/误报检测 + allowed_confirmed 豁免"""
    from lab.run_acceptance import check_target

    cfg = {"name": "t", "url": "http://x/", "mode": "vuln",
           "expected_confirmed": ["A", "B"], "allowed_confirmed": ["C"]}
    # 完全命中 → 通过
    r = check_target(cfg, ["A", "B"])
    assert r["passed"] and r["missing"] == [] and r["unexpected"] == [], r
    # 预期外但豁免命中 → 通过
    r = check_target(cfg, ["A", "B", "C"])
    assert r["passed"], r
    # 非豁免误报 → 失败
    r = check_target(cfg, ["A", "B", "X"])
    assert not r["passed"] and r["unexpected"] == ["X"], r
    # 漏报 → 失败
    r = check_target(cfg, ["A"])
    assert not r["passed"] and r["missing"] == ["B"], r
    # safe 模式：豁免外任何命中都是误报
    cfg_safe = {"name": "s", "url": "http://x/", "mode": "safe",
                "expected_confirmed": [], "allowed_confirmed": ["C"], "expected_safe_all": True}
    r = check_target(cfg_safe, ["A"])
    assert not r["passed"] and r["unexpected"] == ["A"], r
    r = check_target(cfg_safe, ["C"])
    assert r["passed"], r
    r = check_target(cfg_safe, [])
    assert r["passed"], r
    print("PASS test_check_target_logic")


if __name__ == "__main__":
    test_baseline_schema()
    test_baseline_confirmed_matches_plugins()
    test_baseline_safe_zero()
    test_check_target_logic()
    print("ALL_F4_TESTS_PASS")
