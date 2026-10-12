"""真实 ScanEngine 端到端：Cloudflare 保护目标的「完整扫描」链路验证。

走的是生产链路本体（无 Mock）：
    ScanOrchestrator.run_sync(ScanRequest)
      → detect_cms / detect_waf        （真实指纹 + WAF 探测）
      → _build_waf_bypass              （--adversarial-transport 开启 L5 引擎兜底）
      → ScanEngine.run                 （逐插件 verify；被 CF 拦 → UNKNOWN）
      → WafBypassCoordinator.maybe_bypass
            BP-CF-2（payload/UA 伪装）等廉价策略无效
            → BP-ENG-1（Scrapling 隐身浏览器解挑战 + cf_clearance 注入 requests 复用）
      → 重放插件 → CONFIRMED

两个场景：
    场景 A（仅探针）：完整走「原始 verify 被拦 → 策略序列 → BP-ENG-1 解挑战 →
                      verify_with_bypass 重放 → CONFIRMED」，证明 L5 链路自身可用。
    场景 B（真实插件 + 探针）：证明解挑战产物（cf_clearance + UA）跨插件复用——
                      同一 SessionManager 下 prime 只发生一次，后置插件在 requests
                      快速路径上直接拿到源站真实内容。

运行：
    <scrapling-venv>/python.exe lab/scrapling_poc/e2e_scanengine_cf.py
"""

import logging
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TARGET = "https://scrapingcourse.com/cloudflare-challenge"
EXT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ext_plugins")

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
for _name in ("lib.waf_bypass", "lib.scrapling_transport", "core.orchestrator", "core.engine"):
    logging.getLogger(_name).setLevel(logging.INFO)

# ---------------------------------------------------------------- 插桩（测试侧，不改生产码）
import lib.scrapling_transport as st  # noqa: E402
import lib.waf_bypass as wb  # noqa: E402

ATTEMPTS = []   # 每次策略尝试：(strategy_id, layer, name)
TRANSPORTS = []  # 每次 BypassSession 的 transport 配置
PRIME_CALLS = []  # ScraplingTransport.prime 调用记录
APPLY_CALLS = []  # ScraplingTransport.apply_clearance 调用记录


def reset_counters() -> None:
    ATTEMPTS.clear()
    TRANSPORTS.clear()
    PRIME_CALLS.clear()
    APPLY_CALLS.clear()


_ctx_init = wb.BypassContext.__init__


def _ctx_init_patched(self, *a, **kw):
    _ctx_init(self, *a, **kw)
    s = getattr(self, "strategy", None)
    ATTEMPTS.append(
        (getattr(s, "strategy_id", "?"), getattr(s, "layer", "?"), getattr(s, "name", ""))
    )


wb.BypassContext.__init__ = _ctx_init_patched

_bs_init = wb.BypassSession.__init__


def _bs_init_patched(self, *args, **kwargs):
    # *args/**kwargs 透传：生产签名若增删参数，插桩仍生效而不是 TypeError/静默丢参
    _bs_init(self, *args, **kwargs)
    transport_config = kwargs.get("transport_config")
    if transport_config is None and len(args) >= 2:
        transport_config = args[1]
    TRANSPORTS.append(dict(transport_config or {}))


wb.BypassSession.__init__ = _bs_init_patched

_prime = st.ScraplingTransport.prime


def _prime_patched(self, *args, **kwargs):
    url = kwargs.get("url", args[0] if args else "")
    t0 = time.time()
    out = _prime(self, *args, **kwargs)
    PRIME_CALLS.append({"url": url, "secs": round(time.time() - t0, 1)})
    print(f"      [插桩] 隐身浏览器解挑战 prime() → {url}  ({PRIME_CALLS[-1]['secs']}s)")
    return out


st.ScraplingTransport.prime = _prime_patched

_apply = st.ScraplingTransport.apply_clearance


def _apply_patched(self, *args, **kwargs):
    out = _apply(self, *args, **kwargs)
    APPLY_CALLS.append(1)
    print(f"      [插桩] 注入 cf_clearance → 基础会话（第 {len(APPLY_CALLS)} 次）")
    return out


st.ScraplingTransport.apply_clearance = _apply_patched

# ---------------------------------------------------------------- 事件回调
EVENTS = []


def on_event(event_type, payload):
    EVENTS.append((event_type, payload))
    if event_type == "fingerprint":
        print(f"    [事件] 指纹：cms={payload.get('cms')!r} version={payload.get('version')!r}")
    elif event_type == "waf":
        print(f"    [事件] WAF 探测：waf={payload.get('waf')!r} display={payload.get('display')!r}")
    elif event_type == "waf_bypass":
        print(f"    [事件] WAF 绕过：mode={payload.get('mode')!r} enabled={payload.get('enabled')} "
              f"origin_ip={payload.get('origin_ip')!r}")
    elif event_type == "plugin_fallback":
        print("    [事件] 插件回退到 plugins.ruoyi 全量加载")
    elif event_type == "category_start":
        print(f"    [事件] 分类开始：{payload.get('category')} ({payload.get('count')} 个插件)")
    elif event_type == "result":
        print(f"    [事件] 结果：{payload.get('name')} → {payload.get('status')} | {payload.get('evidence')}")
    elif event_type == "complete":
        print(f"    [事件] 完成：{payload}")
    elif event_type == "error":
        print(f"    [事件] 错误：{payload}")


# ---------------------------------------------------------------- 场景执行
def run_scenario(title: str, plugins: list) -> dict:
    from core.orchestrator import ScanOrchestrator, ScanRequest

    print("\n" + "=" * 80)
    print(f"{title}")
    print(f"  目标: {TARGET}")
    print(f"  插件: {plugins}")
    print("=" * 80)

    EVENTS.clear()
    reset_counters()

    req = ScanRequest(
        target=TARGET,
        mode="p",  # 漏洞验证模式
        threads=1,
        timeout=30,
        bypass_waf="on",  # 显式开启绕过
        adversarial_transport=True,  # 方案 A：启用 L5 引擎兜底
        plugins=plugins,
        plugin_paths=[EXT_DIR],
    )

    t0 = time.time()
    results = ScanOrchestrator().run_sync(req, on_event=on_event)
    elapsed = time.time() - t0

    waf_evt = next((p for t, p in EVENTS if t == "waf"), {})
    bp_evt = next((p for t, p in EVENTS if t == "waf_bypass"), None)

    print("\n  --- 插桩汇总 ---")
    print(f"    策略尝试序列        : {[a[0] for a in ATTEMPTS]}")
    for sid, layer, nm in ATTEMPTS:
        print(f"        - {sid:10s} layer={layer}  {nm}")
    print(f"    transport 序列      : {TRANSPORTS}")
    print(f"    prime() 次数        : {len(PRIME_CALLS)}  {PRIME_CALLS}")
    print(f"    apply_clearance 次数: {len(APPLY_CALLS)}")

    print("\n  --- 扫描结果 ---")
    for r in results:
        print(f"    {r.status:9s} | {r.name} | {r.url}")
        print(f"              evidence: {r.evidence}")
        extra = r.extra if isinstance(r.extra, dict) else {}
        if extra.get("waf_bypass"):
            print(f"              waf_bypass: {extra['waf_bypass']}")
    print(f"\n    本场景耗时: {elapsed:.1f}s")

    return {
        "results": results,
        "attempts": [a[0] for a in ATTEMPTS],
        "transports": list(TRANSPORTS),
        "prime_calls": list(PRIME_CALLS),
        "apply_calls": len(APPLY_CALLS),
        "waf": waf_evt.get("waf"),
        "coordinator_enabled": bool(bp_evt and bp_evt.get("enabled")),
        "elapsed": elapsed,
    }


def main() -> int:
    print("=" * 80)
    print("真实 ScanEngine 端到端扫描（Cloudflare 保护目标）")
    print(f"  目标      : {TARGET}")
    print("  bypass_waf: on    adversarial_transport: True")
    print("=" * 80)

    checks = []

    # ---------------- 场景 A：仅探针 → 必须走完整绕过链 ----------------
    a = run_scenario("场景 A：仅探针插件（验证 L5 链路自身可穿透）", ["CF 挑战穿透探针"])
    a_probe = next((r for r in a["results"] if r.name == "CF 挑战穿透探针"), None)
    a_extra = (
        (a_probe.extra if isinstance(a_probe.extra, dict) else {}).get("waf_bypass", {}) if a_probe else {}
    )
    checks += [
        ("A① detect_waf 识别出 Cloudflare", a["waf"] == "cloudflare"),
        ("A② 编排器构建了绕过协调器", a["coordinator_enabled"]),
        ("A③ 引擎尝试了 L5 引擎策略 BP-ENG-1", "BP-ENG-1" in a["attempts"]),
        ("A④ 真正执行了隐身浏览器解挑战", len(a["prime_calls"]) >= 1),
        ("A⑤ 探针经 BP-ENG-1 重放后 CONFIRMED",
         bool(a_probe and a_probe.status == "CONFIRMED" and "穿透成功" in (a_probe.evidence or ""))),
        ("A⑥ CONFIRMED 的 extra 标注 strategy_used=BP-ENG-1",
         a_extra.get("strategy_used") == "BP-ENG-1"),
    ]

    # ---------------- 场景 B：真实插件 + 探针 → 跨插件复用 ----------------
    b = run_scenario(
        "场景 B：真实插件 + 探针（验证解挑战产物跨插件复用）",
        ["RuoYi Swagger 未授权访问", "CF 挑战穿透探针"],
    )
    b_probe = next((r for r in b["results"] if r.name == "CF 挑战穿透探针"), None)
    checks += [
        ("B① 同一 host 只解一次挑战（prime 次数 = 1）", len(b["prime_calls"]) == 1),
        ("B② 两个插件均拿到源站真实内容（无 UNKNOWN）",
         all(r.status != "UNKNOWN" for r in b["results"])),
        ("B③ 后置探针在快速路径上直接 CONFIRMED",
         bool(b_probe and b_probe.status == "CONFIRMED" and "穿透成功" in (b_probe.evidence or ""))),
        ("B④ 真实插件未被误判（SAFE 而非 UNKNOWN）",
         any(r.name == "RuoYi Swagger 未授权访问" and r.status == "SAFE" for r in b["results"])),
    ]

    print("\n" + "=" * 80)
    print("总体链路校验")
    print("=" * 80)
    ok = True
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok = ok and bool(passed)
    print("\n>>> 结论:", "端到端链路全部通过" if ok else "存在未通过项，见上")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
