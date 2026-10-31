"""认证状态门禁：需会话插件在 auth_status != ok 时不得输出 CONFIRMED/SAFE。

这是 P0-2 的统一入口回归：只有一处 downgrade_auth_required_results，
避免十个插件各写一遍「登录失败就降级」。
"""
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.orchestrator import downgrade_auth_required_results
from core.report import ReportBuilder


def _result(name: str, status: str) -> ScanResult:
    return ScanResult(kind="vuln", name=name, status=status, evidence="原始证据")


def test_failed_auth_downgrades_confirmed_and_safe():
    results = [
        _result("需要会话", STATUS_CONFIRMED),
        _result("需要会话-安全", STATUS_SAFE),
        _result("匿名插件", STATUS_CONFIRMED),
    ]
    changed = downgrade_auth_required_results(
        results, "failed", {"需要会话", "需要会话-安全"}
    )
    assert changed == 2
    assert results[0].status == STATUS_UNKNOWN
    assert "auth_status=failed" in results[0].evidence
    assert results[1].status == STATUS_UNKNOWN
    # 未标记 requires_auth 的插件不受影响
    assert results[2].status == STATUS_CONFIRMED


def test_ok_auth_keeps_results():
    results = [_result("需要会话", STATUS_CONFIRMED), _result("需要会话-安全", STATUS_SAFE)]
    changed = downgrade_auth_required_results(results, "ok", {"需要会话", "需要会话-安全"})
    assert changed == 0
    assert results[0].status == STATUS_CONFIRMED
    assert results[1].status == STATUS_SAFE


def test_not_attempted_is_treated_as_not_authenticated():
    results = [_result("需要会话", STATUS_SAFE)]
    changed = downgrade_auth_required_results(results, "not_attempted", {"需要会话"})
    assert changed == 1
    assert results[0].status == STATUS_UNKNOWN


def _builder(admin: str, surface: str) -> ReportBuilder:
    summary = {
        "started_at": "2026-10-31 00:00:00",
        "duration": 0,
        "request_count": 0,
        "mode": "u",
        "fingerprint": {},
        "version_matrix": [],
        "blocked": {},
        "auth_status": {"admin": admin, "surface": surface},
    }
    results = [
        ScanResult(
            kind="vuln",
            name="surface-confirmed",
            severity="high",
            status=STATUS_CONFIRMED,
            evidence="surface 独立会话产出的确认结果",
        )
    ]
    return ReportBuilder(results=results, target="http://target/", summary=summary, dedup=False)


def test_html_banner_splits_admin_and_surface():
    """admin 失败 + surface 成功时，横幅必须分别说明，不能宣称所有需会话结论都降级。"""
    html = _builder("failed", "ok").to_html()
    assert "主扫描（--auth-login）高权登录失败" in html
    assert "--auth-surface 使用独立会话成功完成" in html
    assert "surface 结论（CONFIRMED）未降级" in html
    assert "需要会话的插件结论已统一降级为 UNKNOWN" not in html


def test_json_meta_auth_status_is_split():
    data = _builder("failed", "ok").to_dict()
    assert data["meta"]["auth_status"] == {"admin": "failed", "surface": "ok"}


def test_html_banner_surface_failure_only():
    """主扫描 ok、surface 失败时，只提示 surface，不要把主扫描说成未认证。"""
    html = _builder("ok", "failed").to_html()
    assert "--auth-surface 高权登录失败" in html
    assert "主扫描（--auth-login）高权登录失败" not in html
