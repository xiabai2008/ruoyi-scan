"""v1.7 WP-1：UNKNOWN 原因码的结构化归因。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import (
    ALL_UNKNOWN_REASONS,
    STATUS_CONFIRMED,
    STATUS_SAFE,
    STATUS_UNKNOWN,
    ComponentVersionResult,
    ScanResult,
    UnknownReason,
    unknown_reason_label,
)
from core.engine import ScanEngine
from core.orchestrator import fill_unknown_reasons
from lib.component_detect import to_scan_result
from lib.reachability import (
    downgrade_auth_wall_safe,
    downgrade_evidence_less_safe,
    downgrade_safe_results,
    upgrade_denied_safe_to_unknown,
)


def test_unknown_reason_enum_is_stable():
    assert set(ALL_UNKNOWN_REASONS) == {
        "auth_wall",
        "no_session",
        "no_lowpriv",
        "denied",
        "unreachable",
        "no_evidence",
        "blocked",
        "budget_exceeded",
        "endpoint_absent",
        "insufficient_evidence",
        "unclassified",
    }
    assert UnknownReason.AUTH_WALL.value == "auth_wall"
    assert unknown_reason_label("auth_wall") == "登录墙拦截"
    assert unknown_reason_label("not_registered") == "not_registered"


def test_scan_result_field_is_additive_and_defaults_empty():
    r = ScanResult(kind="vuln", name="x", status=STATUS_CONFIRMED)
    assert r.unknown_reason == ""
    assert r.to_dict()["unknown_reason"] == ""

    r2 = ScanResult(kind="info", name="y", status=STATUS_UNKNOWN, unknown_reason=UnknownReason.DENIED.value)
    assert r2.to_dict()["unknown_reason"] == "denied"


def test_component_result_field_and_conversion():
    c = ComponentVersionResult(component="fastjson", status=STATUS_UNKNOWN, evidence="网络异常")
    assert c.to_dict()["unknown_reason"] == ""
    sr = to_scan_result(c)
    assert sr.status == STATUS_UNKNOWN
    assert sr.unknown_reason == UnknownReason.UNREACHABLE.value

    c2 = ComponentVersionResult(component="fastjson", status=STATUS_UNKNOWN, evidence="版本无法识别")
    assert to_scan_result(c2).unknown_reason == UnknownReason.INSUFFICIENT_EVIDENCE.value

    c3 = ComponentVersionResult(
        component="fastjson", status=STATUS_UNKNOWN, evidence="x", unknown_reason="endpoint_absent"
    )
    assert to_scan_result(c3).unknown_reason == "endpoint_absent"


def test_reachability_downgrades_write_reason():
    wall_results = [ScanResult(kind="info", name="a", status=STATUS_SAFE, evidence="无特征")]
    downgrade_auth_wall_safe(wall_results, {"wall": True, "reason": "302 -> /login"})
    assert wall_results[0].status == STATUS_UNKNOWN
    assert wall_results[0].unknown_reason == UnknownReason.AUTH_WALL.value

    no_ev = [ScanResult(kind="info", name="b", status=STATUS_SAFE, evidence="")]
    downgrade_evidence_less_safe(no_ev)
    assert no_ev[0].unknown_reason == UnknownReason.NO_EVIDENCE.value

    blocked = [ScanResult(kind="info", name="c", status=STATUS_SAFE, evidence="404")]
    downgrade_safe_results(blocked, {"blocked": True, "reason": "WAF", "status": 403})
    assert blocked[0].unknown_reason == UnknownReason.BLOCKED.value

    denied = [ScanResult(kind="info", name="d", status=STATUS_SAFE, evidence="状态码=401")]
    upgrade_denied_safe_to_unknown(denied)
    assert denied[0].unknown_reason == UnknownReason.DENIED.value

    unreachable = [ScanResult(kind="info", name="e", status=STATUS_SAFE, evidence="连接失败")]
    upgrade_denied_safe_to_unknown(unreachable)
    assert unreachable[0].unknown_reason == UnknownReason.UNREACHABLE.value


class _Session:
    authenticated = False


class _AuthSafePlugin:
    name = "需会话 SAFE"
    requires_auth = True

    def verify(self, target, session):
        return ScanResult(kind="info", name=self.name, status=STATUS_SAFE, evidence="无特征")


def test_engine_auth_downgrade_reason():
    results = ScanEngine(threads=1).run([_AuthSafePlugin], "http://target/", _Session())
    assert results[0].status == STATUS_UNKNOWN
    assert results[0].unknown_reason == UnknownReason.NO_SESSION.value


def test_engine_budget_reason():
    engine = ScanEngine(threads=1, deadline=-1.0)
    results = engine.run([_AuthSafePlugin], "http://target/", _Session())
    assert results[0].status == STATUS_UNKNOWN
    assert results[0].unknown_reason == UnknownReason.BUDGET_EXCEEDED.value


def test_engine_exception_reason():
    class BoomPlugin:
        name = "异常插件"

        def verify(self, target, session):
            raise ValueError("boom")

    class NetPlugin:
        name = "网络异常插件"

        def verify(self, target, session):
            raise ConnectionError("connection reset")

    boom = ScanEngine(threads=1).run([BoomPlugin], "http://target/", _Session())[0]
    assert boom.unknown_reason == UnknownReason.INSUFFICIENT_EVIDENCE.value
    net = ScanEngine(threads=1).run([NetPlugin], "http://target/", _Session())[0]
    assert net.unknown_reason == UnknownReason.UNREACHABLE.value


def test_fill_unknown_reasons_maps_extra_flags_and_only_fills_empty():
    results = [
        ScanResult(kind="info", name="a", status=STATUS_UNKNOWN, extra={"auth_wall": True}),
        ScanResult(kind="info", name="b", status=STATUS_UNKNOWN, extra={"denied": True}, unknown_reason="denied"),
        ScanResult(kind="info", name="c", status=STATUS_UNKNOWN, evidence="彻底无法解释"),
        ScanResult(kind="vuln", name="d", status=STATUS_CONFIRMED),
    ]
    filled, unclassified = fill_unknown_reasons(results)
    assert filled == 2
    assert unclassified == 1
    assert results[0].unknown_reason == UnknownReason.AUTH_WALL.value
    assert results[1].unknown_reason == "denied"  # 不覆盖显式值
    assert results[2].unknown_reason == UnknownReason.UNCLASSIFIED.value
    assert results[3].unknown_reason == ""


def test_plugin_scaffold_contains_unknown_reason(monkeypatch, tmp_path):
    import lib.plugin_sdk as sdk

    monkeypatch.chdir(tmp_path)
    os.makedirs("plugins/common", exist_ok=True)
    import core.loader as loader

    monkeypatch.setattr(loader, "known_categories", lambda: ["common"])
    path = sdk.generate_plugin_template("v17_demo", "common")
    text = open(path, encoding="utf-8").read()
    assert "UnknownReason" in text
    assert "unknown_reason=UnknownReason.INSUFFICIENT_EVIDENCE.value" in text


def test_report_column_present():
    from core.report import ReportBuilder

    rb = ReportBuilder(
        results=[
            ScanResult(
                kind="info",
                name="登录墙项",
                status=STATUS_UNKNOWN,
                evidence="请求被登录墙拦截",
                unknown_reason=UnknownReason.AUTH_WALL.value,
            )
        ],
        target="http://x/",
        summary={"target": "http://x/"},
    )
    assert "未判定原因" in rb.to_csv()
    assert "登录墙拦截" in rb.to_csv()
    html = rb.to_html()
    assert "未判定原因" in html
    assert "登录墙拦截" in html
