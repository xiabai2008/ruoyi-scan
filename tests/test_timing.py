"""lib/timing 时序差分判定 + 时间盲注插件的纯函数测试。

纪律：禁止真实 sleep、禁止真实网络请求（全部用假 session / monkeypatch 计时）。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import lib.timing as timing  # noqa: E402
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN  # noqa: E402
from plugins.ruoyi.sql_blind_time import PROBE, SqlBlindTimePlugin  # noqa: E402

TARGET = "http://target/"


class FakeResp:
    """最小响应对象（登录墙/业务码检查只用到 status_code / text / headers）。"""

    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}
        self.content = text.encode()


class RecordingSession:
    """记录请求；有 deadline 属性以便插件做预算检查。"""

    deadline = None

    def __init__(self, resp=None):
        self.calls = []
        self.resp = resp if resp is not None else FakeResp('{"code":200,"rows":[]}', 200)

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.resp


# === classify：三态判定 ===


def test_classify_confirmed():
    assert timing.classify(0.2, [3.2, 3.1, 3.3]) == "confirmed"


def test_classify_slow_site_not_confirmed():
    """最重要负样本：慢站同样慢。绝对值 4.1s 很大，但相对基线只差 0.1s → safe。"""
    assert timing.classify(4.0, [4.1, 4.0, 4.2]) == "safe"


def test_classify_timeout_unknown():
    """超时不等于「没延迟」：不能把 None 当 0 秒算进中位数。"""
    assert timing.classify(0.2, [3.2, None, 3.1]) == "unknown"


def test_classify_jitter_unknown():
    """有延迟但不够（0.4s << 3s）：不得 confirmed。

    ⚠ 指令 §6 该行期望 "unknown"，与 §5.1 规则 4 冲突：中位数 0.6 - 基线 0.2 = 0.4s，
    小于 delay*0.3 = 0.9s，按「逐条严格实现」的规则 4 应判 "safe"。这里按规范算法断言，
    冲突已在交付报告「未做 / 存疑」中记录（未擅自改动安全判定阈值）。
    """
    assert timing.classify(0.2, [0.5, 0.6, 0.9]) == "safe"


def test_classify_single_spike_unknown():
    """仅 1 次成立：中位数只有 0.3s，不得 confirmed。"""
    assert timing.classify(0.2, [3.2, 0.3, 0.3]) != "confirmed"


def test_classify_middle_band_unknown():
    """延迟落在 0.3*delay ~ 0.7*delay 之间（0.9s~2.1s）→ unknown。"""
    assert timing.classify(0.2, [1.2, 1.1, 1.3]) == "unknown"


# === median ===


def test_median_odd_even_empty():
    assert timing.median([3]) == 3.0
    assert timing.median([1, 3]) == 2.0
    assert timing.median([]) == 0.0


# === measure ===


class _ExplodingSession:
    def post(self, url, **kwargs):
        raise RuntimeError("connection reset")


def test_measure_returns_none_on_exception():
    assert timing.measure(_ExplodingSession(), "POST", TARGET, data={}) is None


def test_measure_uses_monotonic(monkeypatch):
    """必须用 time.monotonic；time.time 被系统时钟调整会污染差值。"""

    class _FakeClock:
        def __init__(self):
            self._values = iter([100.0, 100.5])

        def monotonic(self):
            return next(self._values)

        def time(self):
            raise AssertionError("measure 不得使用 time.time")

    class _NoopSession:
        def post(self, url, **kwargs):
            return FakeResp("ok", 200)

    monkeypatch.setattr(timing, "time", _FakeClock())
    assert abs(timing.measure(_NoopSession(), "POST", TARGET, data={}) - 0.5) < 1e-9


# === 插件：预算前置 ===


def test_plugin_budget_guard(monkeypatch):
    """预算不足：直接 UNKNOWN(budget_exceeded)，且一个请求都不许发。"""

    class _NoRequestAllowed(RecordingSession):
        def post(self, url, **kwargs):  # pragma: no cover - 命中即失败
            raise AssertionError("预算不足时不得发出任何请求")

    sess = _NoRequestAllowed()
    # 最坏一轮约 25s（8 次请求 × sleep(3) + 余量）：剩 20s 也必须判预算不足
    sess.deadline = timing.time.monotonic() + 20
    r = SqlBlindTimePlugin().verify(TARGET, sess)
    assert r.status == STATUS_UNKNOWN, r.evidence
    assert r.unknown_reason == "budget_exceeded", r.unknown_reason
    assert sess.calls == []


# === 插件：判定接线（measure 被替换，仍然零 sleep、零网络）===


def _fake_measure(reading):
    """构造 measure 替身：按 payload 是否含 if(1=1,...) 返回预设耗时。"""

    def _measure(session, method, url, **kwargs):
        data = (kwargs.get("data") or {}).get("params[dataScope]", "")
        return reading(data == PROBE)

    return _measure


def test_plugin_confirmed_on_differential(monkeypatch):
    import plugins.ruoyi.sql_blind_time as mod

    monkeypatch.setattr(mod, "measure", _fake_measure(lambda is_probe: 3.2 if is_probe else 0.18))
    sess = RecordingSession()
    r = SqlBlindTimePlugin().verify(TARGET, sess)
    assert r.status == STATUS_CONFIRMED, r.evidence
    assert "3.20" in r.evidence and "0.18" in r.evidence, r.evidence
    assert r.extra.get("vuln_type") == "sqli"
    assert r.extra.get("payload_class") == "time_if"


def test_plugin_slow_site_is_safe(monkeypatch):
    """慢站负样本（插件级）：基线 4.0s、探测 4.1s → SAFE，绝不 CONFIRMED。"""
    import plugins.ruoyi.sql_blind_time as mod

    monkeypatch.setattr(mod, "measure", _fake_measure(lambda is_probe: 4.1 if is_probe else 4.0))
    r = SqlBlindTimePlugin().verify(TARGET, RecordingSession())
    assert r.status == STATUS_SAFE, r.evidence


def test_plugin_login_wall_is_unknown(monkeypatch):
    """登录墙：UNKNOWN(auth_wall)，且不进入 20 秒探测（measure 一次都不调用）。"""

    def _must_not_measure(session, method, url, **kwargs):  # pragma: no cover - 命中即失败
        raise AssertionError("登录墙时不得进入时序采样")

    import plugins.ruoyi.sql_blind_time as mod

    monkeypatch.setattr(mod, "measure", _must_not_measure)
    wall = FakeResp('<html><title>若依后台管理</title><input name="password"><div id="loginForm"></div></html>', 200)
    r = SqlBlindTimePlugin().verify(TARGET, RecordingSession(resp=wall))
    assert r.status == STATUS_UNKNOWN, r.evidence
    assert r.unknown_reason == "auth_wall", r.unknown_reason


def test_plugin_denied_is_unknown(monkeypatch):
    """HTTP 200 + {"code":401}（若依鉴权失败的真实形态）→ UNKNOWN(denied)。"""

    def _must_not_measure(session, method, url, **kwargs):  # pragma: no cover - 命中即失败
        raise AssertionError("被拒绝时不得进入时序采样")

    import plugins.ruoyi.sql_blind_time as mod

    monkeypatch.setattr(mod, "measure", _must_not_measure)
    r = SqlBlindTimePlugin().verify(TARGET, RecordingSession(resp=FakeResp('{"code":401,"msg":"认证失败"}', 200)))
    assert r.status == STATUS_UNKNOWN, r.evidence
    assert r.unknown_reason == "denied", r.unknown_reason
