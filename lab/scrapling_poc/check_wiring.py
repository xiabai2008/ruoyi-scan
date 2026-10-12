"""方案 A 三期接线验证：CLI --adversarial-transport → ScanRequest → WafBypassCoordinator

验证链路：
  1. main.build_parser() 能解析 --adversarial-transport（默认 False）
  2. cli.runner._build_scan_request() 把它映射进 ScanRequest.adversarial_transport
  3. core.orchestrator._build_waf_bypass() 据此设置 enable_engine_fallback，
     并在 Scrapling 未安装时安全降级为 False（不产生永远失败的空尝试）

在「无 scrapling」的 venv（如项目 .venv）中运行 → 期望降级为 False；
在「装了 scrapling」的 venv 中运行 → 期望为 True。无需联网。
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ---- 1. CLI 解析 ----
from main import build_parser  # noqa: E402

parser = build_parser()
args_on = parser.parse_args(["-u", "http://x/", "--adversarial-transport"])
args_off = parser.parse_args(["-u", "http://x/"])
assert getattr(args_on, "adversarial_transport", None) is True, "CLI 未识别 --adversarial-transport"
assert getattr(args_off, "adversarial_transport", None) is False, "默认应为 False"
print("[1] CLI 解析 OK：--adversarial-transport 开/默认为 True/False")

# ---- 2. 映射进 ScanRequest ----
from cli.runner import _build_scan_request  # noqa: E402

req_on = _build_scan_request("u", "http://x/", args_on)
req_off = _build_scan_request("u", "http://x/", args_off)
assert req_on.adversarial_transport is True, "ScanRequest 未透传开关"
assert req_off.adversarial_transport is False, "默认应为 False"
print("[2] cli.runner 映射 OK：ScanRequest.adversarial_transport 透传正确")

# ---- 3. scrapling 可用性 ----
try:
    import scrapling

    have, ver = True, getattr(scrapling, "__version__", "?")
except ImportError:
    have, ver = False, "-"
print(f"[3] 环境 scrapling 可用: {have}（版本 {ver}）")

# ---- 4. _build_waf_bypass 传递 enable_engine_fallback ----
import lib.origin_finder as of  # noqa: E402


class _NoNetFinder:  # 避免源站 IP 探测联网
    def __init__(self, *a, **k):  # noqa: ANN002, ANN003
        pass

    def find_origin_ip(self, *a, **k):  # noqa: ANN002, ANN003
        return []


_orig_origin_ip_finder = of.OriginIPFinder
of.OriginIPFinder = _NoNetFinder  # type: ignore[assignment]

from core.orchestrator import ScanOrchestrator  # noqa: E402
from core.session import SessionManager  # noqa: E402

try:
    sess = SessionManager(timeout=1)

    coord_on = ScanOrchestrator._build_waf_bypass(object(), req_on, {"waf": "cloudflare"}, "http://x/", sess)
    got = getattr(coord_on, "enable_engine_fallback", None)
    print(f"[4] 开关开启 → 协调器 enable_engine_fallback={got}（期望 {have}）")
    assert got == have, f"开关传递/降级异常：got={got} 期望 {have}"

    coord_off = ScanOrchestrator._build_waf_bypass(object(), req_off, {"waf": "cloudflare"}, "http://x/", sess)
    off_got = getattr(coord_off, "enable_engine_fallback", None)
    print(f"[5] 开关关闭 → 协调器 enable_engine_fallback={off_got}（期望 False）")
    assert off_got is False
finally:
    # 恢复原类：monkeypatch 是本脚本的临时手段，不得污染后续 import/测试
    of.OriginIPFinder = _orig_origin_ip_finder

print("\n接线验证通过 " + ("（含真实启用）" if have else "（含安全降级）"))
