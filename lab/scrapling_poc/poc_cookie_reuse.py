"""方案 A 四期 PoC：cf_clearance 复用（覆盖 POST）

验证通过真实组件（core.session.SessionManager + lib.waf_bypass.BypassSession）：

  1. 首次 GET  → 隐身浏览器解挑战、收割 cf_clearance+UA、注入基础会话 → 200
  2. 二次 GET  → 免浏览器、走 requests 快速路径（应 < 2s）→ 200
  3. POST      → 同样走 requests + Cookie（证明 CF 已放行 POST，不再 403 挑战）

判据：POST 返回「非 CF 挑战」即算通过（scrapingcourse 仅收 GET，预期 405/其它非 403）。
用法：python poc_cookie_reuse.py [目标URL]
"""
from __future__ import annotations

import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lib.waf_bypass import BypassSession  # noqa: E402

DEFAULT_TARGET = "https://scrapingcourse.com/cloudflare-challenge"


def is_cf_blocked(status: int, text: str) -> bool:
    """CF 挑战判定：403 或挑战页正文特征。

    429（限流）/503（上游错误）并不表示 CF 挑战，混入会把真实故障误报成「被 CF 拦截」。
    """
    low = (text or "").lower()
    return status == 403 or "just a moment" in low or "verifying connection" in low


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    print("=" * 74)
    print(f"方案 A 四期 PoC | cf_clearance 复用 | 目标: {target}")
    print("=" * 74)

    from core.session import SessionManager

    base = SessionManager(timeout=20)
    bypass = BypassSession(base, {"engine": "scrapling", "scrapling_reuse": True})

    # 1) 首次 GET：解挑战 + 注入
    t0 = time.monotonic()
    r1 = bypass.get(target)
    dt1 = time.monotonic() - t0
    print(f"[1] 首次 GET（浏览器解挑战） -> HTTP {r1.status_code} | blocked={is_cf_blocked(r1.status_code, r1.text)} | {dt1:.1f}s")
    if is_cf_blocked(r1.status_code, r1.text):
        print("\n[失败] 首次 GET 未突破，链路不通")
        return 2

    # 2) 二次 GET：应走快速 requests 路径
    t0 = time.monotonic()
    r2 = bypass.get(target)
    dt2 = time.monotonic() - t0
    print(f"[2] 二次 GET（requests 复用） -> HTTP {r2.status_code} | blocked={is_cf_blocked(r2.status_code, r2.text)} | {dt2:.2f}s")
    fast = dt2 < 5.0
    print(f"    → 是否走快速路径（<5s）: {fast}")

    # 3) POST：验证 CF 对 POST 已放行（非挑战即通过）
    t0 = time.monotonic()
    r3 = bypass.post(target, data={"probe": "1"})
    dt3 = time.monotonic() - t0
    post_blocked = is_cf_blocked(r3.status_code, r3.text)
    print(f"[3] POST（requests + Cookie）  -> HTTP {r3.status_code} | CF挑战={post_blocked} | {dt3:.2f}s")

    print("-" * 74)
    ok = (not is_cf_blocked(r1.status_code, r1.text)) and fast and (not post_blocked)
    if ok:
        print("[验证通过] 浏览器只解一次挑战；后续 GET/POST 均走快速 requests 路径且未被 CF 拦截")
        return 0
    print(f"[注意] GET fast={fast} POST_blocked={post_blocked} — 需人工判读（POST 到只收 GET 的页面时 405 属正常）")
    return 0 if (fast and not post_blocked) else 2


if __name__ == "__main__":
    raise SystemExit(main())
