"""弱指纹不该排他 —— 否则整包插件被跳过。

背景（2026-11-01 盲测 v2 实测）
==============================
`spring` 的 `root_json_keys` 特征（根路径返回
`{"timestamp","status","error","path"}`）在 `core/fingerprint.py` 里被算作
**强特征**（`strong_hits += 1`），单独命中就给 0.5 置信度。

但「返回 Spring Boot 默认错误 JSON」只说明这是个 Spring 应用 ——
它完全可能同时也是若依 / JeecgBoot。

后果实测（C4-4 / C4-5 靶场）：

    GET / → {"timestamp","status","error","path"}
    → cms=spring，置信度 0.50
    → Router.resolve() 只返回 plugins.spring（14 个插件）
    → plugins.jeecgboot / plugins.ruoyi **整包不加载**
    → freemarker_ssti / ruoyi_gen_rce 根本没被调用
    → 0 CONFIRMED（而靶场真有 SSTI，手工验证 ${7*7} → 49）

**一个错误的指纹判定，屏蔽掉整个插件包的漏洞面**，比单个插件判定不准严重得多。

修复
====
`core/orchestrator.py` 增加弱证据扩展：cms 非空但置信度 ≤ 0.5 时，
保留原包并补加载 ruoyi / spring / jeecgboot。强证据（> 0.5）行为不变。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import FingerprintResult  # noqa: E402
from core.orchestrator import (  # noqa: E402
    _EXPANDED_PACKAGES,
    _WEAK_FINGERPRINT_CONFIDENCE,
    _is_weak_fingerprint,
)


def _fp(cms: str, confidence: float) -> FingerprintResult:
    return FingerprintResult(cms=cms, version="", confidence=confidence, matched=[])


# ── 弱证据判定 ────────────────────────────────────────────


def test_spring_at_half_confidence_is_weak():
    """cms=spring + 0.50（只有 root_json 强特征）→ 弱证据。

    这正是 C4-4/C4-5 的实测指纹。
    """
    assert _is_weak_fingerprint(_fp("spring", 0.5)) is True


def test_ruoyi_at_high_confidence_is_strong():
    """若依 favicon + keyword 命中是 0.70，属强证据，不该触发补加载。"""
    assert _is_weak_fingerprint(_fp("ruoyi", 0.7)) is False


def test_jeecgboot_at_high_confidence_is_strong():
    assert _is_weak_fingerprint(_fp("jeecgboot", 1.0)) is False


def test_empty_cms_is_not_weak_but_unmatched():
    """cms 为空走的是另一条回退路径，不该被这里处理。"""
    assert _is_weak_fingerprint(_fp("", 0.0)) is False


def test_low_confidence_variants_are_weak():
    """任何 cms 只要置信度不超过阈值，都算弱证据。"""
    for conf in (0.2, 0.3, 0.5):
        assert _is_weak_fingerprint(_fp("spring", conf)) is True, f"conf={conf} 应判弱"


def test_just_above_threshold_is_strong():
    """刚超过阈值算强证据 —— 边界要明确。"""
    assert _is_weak_fingerprint(_fp("spring", _WEAK_FINGERPRINT_CONFIDENCE + 0.01)) is False


def test_malformed_confidence_falls_back_to_strong():
    """置信度字段异常时不触发补加载（避免误伤正常扫描）。"""
    fp = FingerprintResult(cms="ruoyi", version="", confidence=0.7, matched=[])
    fp.confidence = "not-a-number"  # type: ignore[assignment]
    assert _is_weak_fingerprint(fp) is False


# ── 扩展包列表 ────────────────────────────────────────────


def test_expanded_packages_cover_all_spring_ecosystem():
    """弱证据时要覆盖 ruoyi / spring / jeecgboot 三个包。

    C4-4 需要 jeecgboot、C4-5 需要 ruoyi，两个都必须在列表里。
    """
    assert "plugins.ruoyi" in _EXPANDED_PACKAGES
    assert "plugins.spring" in _EXPANDED_PACKAGES
    assert "plugins.jeecgboot" in _EXPANDED_PACKAGES


def test_expanded_packages_loadable():
    """三个包都必须能真的加载出插件（否则扩展是空的）。"""
    from core.loader import load_plugins

    for pkg in _EXPANDED_PACKAGES:
        bundle = load_plugins(pkg)
        assert bundle, f"{pkg} 加载不出任何插件"
