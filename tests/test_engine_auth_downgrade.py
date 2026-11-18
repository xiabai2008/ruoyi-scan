"""F13：需会话插件在 CLI 打印前降级，终端与报告口径一致。

2026-11-02 D1 实测：-u 扫描 gen SSTI 的差分证据成立（引擎返回 CONFIRMED），
CLI 打印「存在 RuoYi 代码生成模块 SSTI」，但 orchestrator 随后按 auth_status
降级为 UNKNOWN —— 终端与 report.json 说法不一致。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult  # noqa: E402
from core.engine import ScanEngine  # noqa: E402


class FakeSession:
    def __init__(self, authenticated):
        self.authenticated = authenticated


class AuthRequiredPlugin:
    name = "F13 需会话插件"
    requires_auth = True

    def verify(self, target, session):
        return ScanResult(kind="vuln", name=self.name, status=STATUS_CONFIRMED, url=target, evidence="差分成立")


class AnonPlugin:
    name = "F13 匿名插件"
    requires_auth = False

    def verify(self, target, session):
        return ScanResult(kind="vuln", name=self.name, status=STATUS_CONFIRMED, url=target, evidence="匿名可证")


def test_auth_required_result_downgraded_before_callback():
    printed = []
    engine = ScanEngine(threads=1)
    results = engine.run(
        [AuthRequiredPlugin], "http://target/", FakeSession(authenticated=False), on_result=printed.append
    )
    assert results[0].status == STATUS_UNKNOWN, results[0].evidence
    assert "降级" in results[0].evidence
    # 回调即 CLI 打印口：必须看到 UNKNOWN，而不是 CONFIRMED
    assert printed[0].status == STATUS_UNKNOWN


def test_auth_required_result_kept_when_authenticated():
    engine = ScanEngine(threads=1)
    results = engine.run([AuthRequiredPlugin], "http://target/", FakeSession(authenticated=True))
    assert results[0].status == STATUS_CONFIRMED


def test_anon_plugin_not_downgraded():
    engine = ScanEngine(threads=1)
    results = engine.run([AnonPlugin], "http://target/", FakeSession(authenticated=False))
    assert results[0].status == STATUS_CONFIRMED


def test_safe_downgraded_to_unknown_when_unauthenticated():
    class SafeRequiredPlugin:
        name = "F13 需会话 SAFE"
        requires_auth = True

        def verify(self, target, session):
            return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=target, evidence="不可达")

    engine = ScanEngine(threads=1)
    results = engine.run([SafeRequiredPlugin], "http://target/", FakeSession(authenticated=False))
    assert results[0].status == STATUS_UNKNOWN
