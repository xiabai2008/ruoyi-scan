import math
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# 1) ResponseAdapter：Scrapling .status -> 插件契约 .status_code
from lib.scrapling_transport import ResponseAdapter, ScraplingStealthStrategy

class _FakeResp:
    status = 200
    reason = "OK"
    headers = {"Server": "cloudflare"}
    url = "https://example.com/"
    cookies = {}
    history = []
    body = b"<html><title>T</title></html>"


def check(cond, msg):
    """契约校验用显式异常：assert 在 -O/PYTHONOPTIMIZE 下会被剥离成空操作，静默失去校验能力"""
    if not cond:
        raise AssertionError(msg)


a = ResponseAdapter(_FakeResp(), 1.23)
check(a.status_code == 200, "status_code 映射失败")
check(a.text == "<html><title>T</title></html>", "text 解码失败")
check(
    a.headers["Server"] == "cloudflare"
    and a.ok
    and math.isclose(a.elapsed.total_seconds(), 1.23, abs_tol=1e-6),
    "headers/ok/elapsed 契约失败",
)
print("[1] ResponseAdapter 契约: status_code/text/headers/ok/elapsed 全通过")

# 2) 策略层
s = ScraplingStealthStrategy()
check(s.apply_transport(None)["engine"] == "scrapling", "apply_transport 未返回 scrapling 引擎")
check(s.is_applicable("cloudflare", "sqli") and not s.is_applicable("safedog", "sqli"), "is_applicable 判定错误")
print("[2] ScraplingStealthStrategy: apply_transport/is_applicable 通过")

# 3) 向后兼容：BypassSession 默认引擎 = requests，不触碰 scrapling
from lib.waf_bypass import BypassSession

class _Recorder:
    def __init__(self): self.called = []
    def get(self, url, **k): self.called.append(("GET", url)); return "RAW"
    def post(self, url, **k): self.called.append(("POST", url)); return "RAW"
    def request(self, m, url, **k): self.called.append((m, url)); return "RAW"
    def close(self): pass

rec = _Recorder()
bs = BypassSession(rec, {"headers": {"X-Test": "1"}})  # 无 engine 键
out = bs.get("http://t/x")
check(out == "RAW" and rec.called == [("GET", "http://t/x")], "默认引擎未走底层 session")
check(bs._engine == "requests", "未指定 engine 时应默认 requests")
print("[3] 向后兼容: 未指定 engine 时默认走底层 requests session，行为零变化")

# 4) engine=scrapling 时路由到对抗层（底层不被触达）
bs2 = BypassSession(_Recorder(), {"engine": "scrapling"})
check(bs2._engine == "scrapling", "engine=scrapling 未生效")
engine = bs2._resolve_engine()
print(f"[4] 引擎路由: engine=scrapling -> {type(engine).__name__}(mode={engine.mode}, "
      f"solve_cloudflare={engine.solve_cloudflare}, timeout={engine.timeout}s)")
print("\n全部通过 ✓")
