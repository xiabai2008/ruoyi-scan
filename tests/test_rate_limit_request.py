# 请求级限速（--rate 语义修正）单测
#
# 全部使用假时钟：TokenBucket(rate, clock=fake.tick, sleeper=fake.sleep)，
# 不产生任何真实 sleep，整套用例应在一秒内跑完。
import os
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.session import SessionManager
from lib.rate_limit import TokenBucket


class FakeClock:
    """线程安全的假时钟：tick() 读时间，sleep() 推进时间并记账。"""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps = 0
        self._lock = threading.Lock()
        # (线程 id, 事件类型, 值)：事件按线程内顺序可还原「拿到令牌」的调用
        self._events: List[Tuple[int, str, float]] = []

    def tick(self) -> float:
        with self._lock:
            self._events.append((threading.get_ident(), "tick", self.now))
            return self.now

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self._events.append((threading.get_ident(), "sleep", float(seconds)))
            self.sleeps += 1
            self.now += max(0.0, float(seconds))

    def grants(self) -> List[float]:
        """还原每次真正拿到令牌的时刻。

        每次 acquire 迭代都以 tick 开始：tick 之后紧跟 sleep 说明被拒（无令牌），
        没有紧跟 sleep（直接返回或下一轮 tick）说明拿到令牌并写入了该时刻。
        """
        with self._lock:
            events = list(self._events)
        by_thread: Dict[int, List[Tuple[str, float]]] = {}
        for ident, kind, value in events:
            by_thread.setdefault(ident, []).append((kind, value))
        granted: List[float] = []
        for seq in by_thread.values():
            for idx, (kind, value) in enumerate(seq):
                if kind != "tick":
                    continue
                nxt = seq[idx + 1][0] if idx + 1 < len(seq) else ""
                if nxt != "sleep":
                    granted.append(value)
        return sorted(granted)


class _FakeResponse:
    status_code = 200
    content = b""


def _max_in_any_window(times: List[float], window: float = 1.0) -> int:
    """任意半开窗口 [t, t+window) 内的最大放行数（与实现的 now - t < 1.0 口径一致）"""
    ordered = sorted(times)
    best = 0
    j = 0
    for i, start in enumerate(ordered):
        while j < len(ordered) and ordered[j] < start + window:
            j += 1
        best = max(best, j - i)
    return best


def test_no_rate_means_no_sleep():
    """rate=0：acquire 立即返回，不取时、不加锁、不 sleep"""
    fake = FakeClock()
    bucket = TokenBucket(0, clock=fake.tick, sleeper=fake.sleep)
    for _ in range(10):
        bucket.acquire()
    assert fake.sleeps == 0
    assert fake.grants() == []  # 连 clock 都没调用过（短路发生在取时之前）


def test_rate_limits_per_second():
    """rate=5 申请 20 次：任意 1 秒窗口内放行数 <= 5"""
    fake = FakeClock()
    bucket = TokenBucket(5, clock=fake.tick, sleeper=fake.sleep)
    for _ in range(20):
        bucket.acquire()
    granted = fake.grants()
    assert len(granted) == 20
    assert _max_in_any_window(granted) <= 5
    # 20 个令牌至少跨 3 个窗口（初始满桶 + 两次补充）
    assert fake.now >= 3.0


def test_no_burst_at_boundary():
    """窗口边界不允许「同一时刻挤满下一批」的预约式突发"""
    fake = FakeClock()
    bucket = TokenBucket(5, clock=fake.tick, sleeper=fake.sleep)
    for _ in range(12):
        bucket.acquire()
    granted = fake.grants()
    assert len(granted) == 12
    # 同一时刻最多放行 rate 个（旧实现锁内预约时间戳会突破这个上限）
    assert max(Counter(granted).values()) <= 5
    # 第 2 批起必须落在首批之后：醒来是重新竞争，而不是沿用预约时刻
    assert all(t > granted[0] for t in granted[5:])
    # 每个新放行必然替换窗口内最老的一个令牌
    for i in range(5, len(granted)):
        assert granted[i] > granted[i - 5]


def test_thread_safe():
    """8 线程各申请 10 次：总放行 80 次，窗口约束仍成立"""
    fake = FakeClock()
    bucket = TokenBucket(5, clock=fake.tick, sleeper=fake.sleep)
    granted_count = 0
    count_lock = threading.Lock()

    def worker() -> None:
        nonlocal granted_count
        for _ in range(10):
            bucket.acquire()
            with count_lock:
                granted_count += 1

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(worker) for _ in range(8)]
        for fut in futures:
            fut.result()

    assert granted_count == 80
    granted = fake.grants()
    assert len(granted) == 80
    assert _max_in_any_window(granted) <= 5


def test_session_manager_wires_limiter():
    """request 作用域自带桶；plugin 作用域与 rate=0 时 SessionManager 不建桶"""
    request_scope = SessionManager(rate=5, rate_scope="request")
    assert request_scope._limiter is not None
    assert request_scope._limiter.rate == 5

    plugin_scope = SessionManager(rate=5, rate_scope="plugin")
    assert plugin_scope._limiter is None

    unlimited = SessionManager(rate=0, rate_scope="request")
    assert unlimited._limiter is None

    for mgr in (request_scope, plugin_scope, unlimited):
        mgr.close()


def test_session_shares_limiter():
    """两个 SessionManager 传同一个 limiter：合计请求受同一个桶约束"""
    fake = FakeClock()
    bucket = TokenBucket(3, clock=fake.tick, sleeper=fake.sleep)
    first = SessionManager(rate=3, rate_scope="request", limiter=bucket)
    second = SessionManager(rate=3, rate_scope="request", limiter=bucket)
    assert first._limiter is bucket
    assert second._limiter is bucket

    try:
        # 不走真实网络：替换底层 requests.Session.request 的出口
        first.session.request = lambda *a, **k: _FakeResponse()
        second.session.request = lambda *a, **k: _FakeResponse()
        for i in range(6):
            first.get(f"http://example.com/a{i}")
        for i in range(6):
            second.get(f"http://example.com/b{i}")
    finally:
        first.close()
        second.close()

    granted = fake.grants()
    assert len(granted) == 12
    assert _max_in_any_window(granted) <= 3
    # 两个会话合计仍只按一个桶的速率放行（各建桶会让实际 QPS 翻倍）
    assert fake.now >= 3.0


def test_anonymous_session_shares_parent_limiter():
    """匿名探测会话必须复用父会话的同一个令牌桶，rate=0 时不建桶

    回归点：anonymous() 曾只复制代理/超时/UA 等配置，未传 rate/rate_scope/limiter，
    导致攻击面盘点等未授权探测路径的请求完全绕过请求级限速（一次扫描内实际 QPS
    不再受 --rate 约束）。
    """
    fake = FakeClock()
    bucket = TokenBucket(3, clock=fake.tick, sleeper=fake.sleep)
    parent = SessionManager(rate=3, rate_scope="request", limiter=bucket)
    anon = parent.anonymous()
    assert anon._limiter is bucket
    assert anon._limiter is parent._limiter
    assert anon.rate == parent.rate == 3
    assert anon.rate_scope == parent.rate_scope == "request"

    try:
        # 匿名会话的请求与父会话共用一个桶：合计受同一速率约束
        parent.session.request = lambda *a, **k: _FakeResponse()
        anon.session.request = lambda *a, **k: _FakeResponse()
        for i in range(3):
            parent.get(f"http://example.com/p{i}")
        for i in range(3):
            anon.get(f"http://example.com/a{i}")
    finally:
        anon.close()
        parent.close()

    granted = fake.grants()
    assert len(granted) == 6
    assert _max_in_any_window(granted) <= 3

    # 不限速时匿名会话同样不建桶
    unlimited = SessionManager(rate=0, rate_scope="request")
    unlimited_anon = unlimited.anonymous()
    try:
        assert unlimited._limiter is None
        assert unlimited_anon._limiter is None
    finally:
        unlimited_anon.close()
        unlimited.close()


def test_engine_rate_zero_in_request_scope(monkeypatch):
    """request 模式下 orchestrator 传给引擎的 rate 必须为 0（否则双重限速）"""
    import core.orchestrator as orch_mod

    captured: Dict[str, object] = {}

    class _Stop(Exception):
        pass

    def fake_engine_init(self, threads=1, rate=0, deadline=None):
        captured["rate"] = rate
        raise _Stop

    monkeypatch.setattr(orch_mod.ScanEngine, "__init__", fake_engine_init)
    monkeypatch.setattr(orch_mod, "preflight", lambda *a, **k: (True, "tcp", ""))

    orch = orch_mod.ScanOrchestrator()

    orch.run_sync(orch_mod.ScanRequest(target="http://example.com/", rate=9, rate_scope="request"))
    assert captured.get("rate") == 0

    # plugin 作用域仍把 rate 交给引擎（会话层不限速）
    captured.clear()
    orch.run_sync(orch_mod.ScanRequest(target="http://example.com/", rate=9, rate_scope="plugin"))
    assert captured.get("rate") == 9


def test_isolated_auth_session_shares_parent_limiter(monkeypatch):
    """扫描中创建的隔离登录会话必须复用父会话的同一个令牌桶

    回归点：isolated_auth_session 曾直接 SessionManager(timeout=...)，没传
    rate/rate_scope/limiter，插件在扫描中登录及其后的取证请求完全绕过请求级
    限速（同 anonymous() 此前的缺口）。不传 parent 时保持不限速的兼容行为。
    """
    import core.login_chain as auth_chain

    # 登录链打桩为成功：本用例不发起任何真实网络请求
    monkeypatch.setattr(
        auth_chain.RuoYiAuthChain,
        "login",
        lambda self, *a, **k: (True, auth_chain.LOGIN_OK),
    )

    fake = FakeClock()
    bucket = TokenBucket(3, clock=fake.tick, sleeper=fake.sleep)
    parent = SessionManager(rate=3, rate_scope="request", limiter=bucket)
    try:
        with auth_chain.isolated_auth_session("http://example.com", "u", "p", parent=parent) as (iso, ok, _reason):
            assert ok is True
            assert iso._limiter is parent._limiter
            assert iso._limiter is bucket
            assert iso.rate == parent.rate == 3
            assert iso.rate_scope == parent.rate_scope == "request"

        # 不传 parent：保持向后兼容，不建桶
        with auth_chain.isolated_auth_session("http://example.com", "u", "p") as (
            detached,
            ok_detached,
            _reason,
        ):
            assert ok_detached is True
            assert detached._limiter is None
    finally:
        parent.close()
