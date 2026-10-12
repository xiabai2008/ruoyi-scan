"""方案 A E2E：验证 WafBypassCoordinator 是否真能选到 BP-ENG-1，以及 attempts 截断问题

回答两个问题：
  ① 编排器真的会选到 BP-ENG-1 吗？
  ② attempts（默认 3）会不会把它截断？

方法：使用**真实** WafBypassCoordinator / StrategyRegistry / BypassSession，
配一个记录「实际尝试了哪些策略」的桩插件，跑两个场景对照：
  - 场景 A（接入前）：注册表移除 L5 引擎策略 → 观察编排器只尝试廉价策略，结果 UNKNOWN
  - 场景 B（接入后）：默认注册表（含 L5）+ 保底选择 → 观察 BP-ENG-1 被选中并突破 → CONFIRMED

外部依赖（重要）：场景 B 的通过判定要求目标站点可达且 Cloudflare 挑战正常——默认目标是
公有站点 scrapingcourse.com，其可用性与挑战策略不受本仓控制。站点不可达/策略变化时
B_status 必然非 CONFIRMED，脚本以退出码 2 报告「结论未达预期」：这属于环境问题，不是
编排器逻辑回归；需要稳定可复现的结果时，用位置参数指定自建/可控的 CF 靶站。

用法：python e2e_coordinator.py [目标URL]
"""
from __future__ import annotations

import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from common.models import STATUS_CONFIRMED, STATUS_UNKNOWN, ScanResult  # noqa: E402
from lib.waf_bypass import StrategyRegistry, WafBypassCoordinator  # noqa: E402

DEFAULT_TARGET = "https://scrapingcourse.com/cloudflare-challenge"


class StubPlugin:
    """GET 型探测插件桩（真实 RuoYi 插件逻辑不适用于公有 CF 测试页，故用桩）。

    只实现编排器所需的接口：vuln_type / bypass_max_attempts / verify_with_bypass。
    verify_with_bypass 用传入的 bypass_session（真实 BypassSession）发一次 GET，
    由引擎策略决定这次 GET 走 requests 还是更高级传输层。
    """

    vuln_type = "sqli"
    supports_waf_bypass = True
    bypass_max_attempts = 3

    def __init__(self) -> None:
        self.attempted: list[str] = []

    def verify(self, target: str, session) -> ScanResult:  # noqa: ANN001
        return ScanResult(kind="vuln", name="stub", status=STATUS_UNKNOWN, url=target)

    def verify_with_bypass(self, target: str, bypass_session, ctx) -> ScanResult:  # noqa: ANN001
        sid = getattr(getattr(ctx, "strategy", None), "strategy_id", "?")
        self.attempted.append(sid)
        try:
            resp = bypass_session.get(target)
        except Exception as exc:  # noqa: BLE001
            return ScanResult(kind="vuln", name="stub", status=STATUS_UNKNOWN, url=target,
                              evidence=f"{sid} 异常: {type(exc).__name__}")
        body = resp.text.lower()
        blocked = ("just a moment" in body) or (resp.status_code in (403, 429, 503))
        if resp.status_code == 200 and not blocked:
            return ScanResult(kind="vuln", name="stub", status=STATUS_CONFIRMED, url=target,
                              evidence=f"{sid} 绕过成功 HTTP {resp.status_code}")
        return ScanResult(kind="vuln", name="stub", status=STATUS_UNKNOWN, url=target,
                          evidence=f"{sid} 仍被拦 HTTP {resp.status_code}")


def _base_session():
    """构造编排器所需的基础会话（真实 SessionManager，失败则退化为 requests 包装）"""
    try:
        from core.session import SessionManager

        return SessionManager(timeout=20), "core.session.SessionManager（真实）"
    except Exception:  # noqa: BLE001
        import requests

        class _Wrap:
            request_count = 0

            def __init__(self) -> None:
                self.s = requests.Session()

            def get(self, url, **k):  # noqa: ANN001
                return self.s.get(url, timeout=20, **k)

            def post(self, url, **k):  # noqa: ANN001
                return self.s.post(url, timeout=20, **k)

            def request(self, method, url, **k):  # noqa: ANN001
                return self.s.request(method, url, timeout=20, **k)

            def close(self) -> None:
                self.s.close()

        return _Wrap(), "requests 包装（SessionManager 依赖不可用）"


def run_scenario(target: str, use_engine: bool) -> tuple[str, list[str], float]:
    reg = StrategyRegistry()
    if not use_engine:
        # 模拟接入前：移除 L5 引擎策略
        reg._strategies = [s for s in reg._strategies if s.layer != "L5"]  # noqa: SLF001

    coordinator = WafBypassCoordinator(
        waf_type="cloudflare", registry=reg, enable_engine_fallback=use_engine
    )
    plugin = StubPlugin()
    session, sess_desc = _base_session()
    print(f"  session: {sess_desc}")

    # 原结果：被 WAF 拦截 → 非 CONFIRMED，触发 maybe_bypass
    original = ScanResult(kind="vuln", name="stub", status=STATUS_UNKNOWN, url=target,
                          evidence="基线被 CF 拦截")

    t0 = time.monotonic()
    result = coordinator.maybe_bypass(plugin, target, session, original)
    dt = time.monotonic() - t0
    return result.status, plugin.attempted, dt


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    print("=" * 78)
    print(f"方案 A E2E | 目标: {target} | WAF: cloudflare | vuln_type: sqli")
    print("=" * 78)

    print("\n【场景 A】接入前：注册表无 L5 引擎策略（模拟原状）")
    a_status, a_tried, a_dt = run_scenario(target, use_engine=False)
    print(f"  编排器实际尝试策略: {a_tried}")
    print(f"  结果: {a_status} | 耗时 {a_dt:.1f}s")
    a_engine_hit = "BP-ENG-1" in a_tried
    print(f"  ① 是否选到 BP-ENG-1: {'是' if a_engine_hit else '否'}  "
          f"② 是否被 attempts 截断: {'否' if a_engine_hit else '是（L5 不在可选集中）'}")

    print("\n【场景 B】接入后：默认注册表含 L5 + 保底选择（本次修复）")
    b_status, b_tried, b_dt = run_scenario(target, use_engine=True)
    print(f"  编排器实际尝试策略: {b_tried}")
    print(f"  结果: {b_status} | 耗时 {b_dt:.1f}s")
    b_engine_hit = "BP-ENG-1" in b_tried
    print(f"  ① 是否选到 BP-ENG-1: {'是' if b_engine_hit else '否'}  "
          f"② 是否被 attempts 截断: {'否' if b_engine_hit else '是'}")

    print("\n" + "=" * 78)
    # 注意：b_status 来自对公有 Cloudflare 站点的真实请求，外部不可用时本行必然为假
    ok = (not a_engine_hit) and b_engine_hit and b_status == STATUS_CONFIRMED
    if ok:
        print("[验证通过] 修复前 L5 不可达；修复后 BP-ENG-1 被选中并突破 → CONFIRMED")
        return 0
    print(f"[注意] 结论未达预期：A_engine={a_engine_hit} B_engine={b_engine_hit} B_status={b_status}")
    if b_engine_hit and b_status != STATUS_CONFIRMED:
        print("[环境] 目标不可达 / CF 挑战变化属外部依赖问题，非编排器逻辑回归（见模块 docstring）")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
