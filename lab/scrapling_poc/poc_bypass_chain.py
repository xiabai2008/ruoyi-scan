"""方案 A PoC：验证「requests 被 Cloudflare 拦截 → Scrapling 对抗传输突破 → 三态 CONFIRMED」

本脚本直接使用 ruoyi-scan 的真实集成组件（lib.waf_bypass.BypassSession + lib.scrapling_transport），
不使用任何 mock，验证以下链路：

    ┌─ 基线：plain requests（≈ SessionManager 传输层） ──→ 被 CF 403 拦死
    └─ 方案 A：BypassSession(engine="scrapling").get() ──→ 200 突破 ──→ 三态判定 CONFIRMED

用法：
    python poc_bypass_chain.py [目标URL]
    默认目标：https://scrapingcourse.com/cloudflare-challenge（专用 CF 挑战测试页）

退出码：0=链路验证成功；1=目标本身未拦截（无法验证）；2=突破失败（属正常，记 UNKNOWN）；
        3=基线请求异常（网络/传输错误，与「未拦截」区分）
"""
from __future__ import annotations

import os
import re
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

DEFAULT_TARGET = "https://scrapingcourse.com/cloudflare-challenge"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def classify(status: int, text: str) -> str:
    """判定响应是「被拦」还是「通过」——对齐 ruoyi-scan 三态语义"""
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    title = (m.group(1).strip() if m else "")
    tlow = title.lower()
    if "just a moment" in tlow or "verifying connection" in tlow or "attention required" in tlow:
        return "BLOCKED"
    if status in (403, 429, 503):
        return "BLOCKED"
    if status == 200:
        return "OK"
    return f"HTTP{status}"


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    print("=" * 74)
    print(f"方案 A PoC | 目标: {target}")
    print("=" * 74)

    # ---------- 阶段 1：基线（plain requests ≈ 现有 SessionManager 传输层）----------
    import requests

    t0 = time.monotonic()
    try:
        r = requests.get(target, timeout=20, headers={"User-Agent": UA})
        base_status, base_text = r.status_code, r.text
    except Exception as exc:  # noqa: BLE001
        base_status, base_text = 0, f"ERR {type(exc).__name__}: {exc}"
    base_dt = time.monotonic() - t0
    base_verdict = classify(base_status, base_text)
    print(f"[阶段1] plain requests          -> HTTP {base_status} | {base_verdict} | "
          f"{len(base_text)}b | {base_dt:.2f}s")

    if base_status == 0:
        # 传输异常（DNS/连接/超时）不等于「目标未被拦截」：必须显式区分，否则结论误导
        print(f"\n[跳过] 基线请求异常，无法判定目标是否被拦截：{base_text}")
        return 3

    if base_verdict != "BLOCKED":
        print("\n[跳过] 基线未被拦截，该目标无法验证「突破」链路。")
        return 1

    # ---------- 阶段 2：方案 A 对抗传输（真实 BypassSession + Scrapling 引擎）----------
    from lib.waf_bypass import BypassSession
    from lib.scrapling_transport import ScraplingTransport  # noqa: F401  (触发导入校验)

    class _StubSession:
        """底层会话桩：engine=scrapling 时不应被触达，触达即报错（证明路由生效）"""
        request_count = 0

        def get(self, *a, **k):  # noqa: ANN002, ANN003
            raise AssertionError("engine=scrapling 时不应触达底层 requests session")

        post = request = get

        def close(self) -> None:
            pass

    bypass = BypassSession(_StubSession(), {"engine": "scrapling", "scrapling_mode": "stealth"})
    t0 = time.monotonic()
    try:
        resp = bypass.get(target)
        adv_dt = time.monotonic() - t0
    except Exception as exc:  # noqa: BLE001
        print(f"[阶段2] ScraplingTransport     -> 异常 {type(exc).__name__}: {exc}")
        print("\n[结论] 突破失败 -> 三态判定 UNKNOWN（对齐纪律：绝不降级 SAFE）")
        return 2

    adv_verdict = classify(resp.status_code, resp.text)
    print(f"[阶段2] BypassSession(scrapling) -> HTTP {resp.status_code} | {adv_verdict} | "
          f"{len(resp.text)}b | {adv_dt:.2f}s | server={resp.headers.get('server')}")

    # 契约校验：返回值必须兼容插件消费的字段
    assert hasattr(resp, "status_code") and hasattr(resp, "text"), "返回类型不符合插件契约"
    assert resp.elapsed is not None, "elapsed 缺失"

    # ---------- 阶段 3：三态判定 ----------
    print("-" * 74)
    if adv_verdict == "OK":
        print("[结论] 对抗传输突破成功 -> 三态判定 CONFIRMED")
        print(f"       基线被拦({base_dt:.1f}s) → 对抗突破({adv_dt:.1f}s) | 契约字段: "
              f"status_code/text/headers/url/elapsed ✓")
        title_m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.I | re.S)
        title = title_m.group(1).strip() if title_m else "N/A"
        print(f"       抓取内容标题: {title[:60]}")
        return 0

    print("[结论] 对抗传输仍未突破 -> 三态判定 UNKNOWN（不降级 SAFE）")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
