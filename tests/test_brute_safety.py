"""爆破安全：锁定/429/验证码停止与默认 top100 字典。"""

from types import SimpleNamespace

from common.models import STATUS_CONFIRMED, STATUS_UNKNOWN
from lib.brute_safety import BruteGuard, classify_brute_block


def _resp(status=200, body="", headers=None):
    return SimpleNamespace(status_code=status, text=body, headers=headers or {}, json=lambda: {})


def test_classify_http_429_is_soft_block():
    blocked, reason, hard = classify_brute_block(_resp(429, "too many requests"))
    assert blocked is True
    assert hard is False
    assert "429" in reason or "限流" in reason


def test_classify_lock_keyword_is_hard_block():
    blocked, reason, hard = classify_brute_block(_resp(200, '{"msg":"密码错误5次，账户已锁定10分钟"}'))
    assert blocked is True
    assert hard is True
    assert "锁定" in reason


def test_classify_normal_failure_is_not_block():
    blocked, _, _ = classify_brute_block(_resp(200, "error"))
    assert blocked is False


def test_guard_stops_after_three_soft_blocks():
    guard = BruteGuard()
    for _ in range(2):
        assert guard.observe(_resp(429, "too many requests")) is False
    assert guard.observe(_resp(429, "too many requests")) is True
    assert guard.stopped
    assert "限流" in guard.stop_reason


def test_guard_hard_block_stops_immediately():
    guard = BruteGuard()
    assert guard.observe(_resp(200, "账户已锁定")) is True
    assert guard.attempts == 1


def test_guard_normal_response_resets_soft_counter():
    guard = BruteGuard()
    guard.observe(_resp(429, "too many requests"))
    guard.observe(_resp(200, "error"))
    assert guard.observe(_resp(429, "too many requests")) is False
    assert not guard.stopped


def test_scan_request_default_pass_level_is_safe():
    from core.orchestrator import ScanRequest

    assert ScanRequest(target="http://example.com/").pass_level == "top100"


def test_druid_brute_stops_on_lockout_and_returns_unknown():
    from plugins.ruoyi.druid_brute import DruidBrutePlugin

    class _Session:
        password_dict = None

        def post(self, url, data=None, **kwargs):
            return _resp(200, "账户已锁定，请稍后重试")

    result = DruidBrutePlugin().verify("http://target/", _Session())
    assert result.status == STATUS_UNKNOWN
    assert result.unknown_reason == "brute_blocked"
    assert result.status != STATUS_CONFIRMED
