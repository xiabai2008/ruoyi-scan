#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab/prod 冒烟探针：确认真实 RuoYi 4.7.8 栈已就绪，并核对三档代理行为。

它只做**无破坏性的未认证请求**：
  GET  /login
  GET  /captcha/captchaImage
  GET  /druid/index.html
  POST /system/role/list
  GET  /common/download/resource?resource=../../../../etc/passwd

设计要点
========
* 真实 RuoYi 4.7.8 的 ShiroConfig 把 /** 交给 "user" 过滤器，未登录访问
  /system/**、/druid/**、/common/download/resource 会返回 **302 -> /login**。
  题目口径里的「未认证 401 JSON」是 RuoYi-Vue（前后端分离/JWT）的形态；
  本脚本两种都接受，并在输出里明确标注实际形态，绝不把 302 当成 401。
* stock 档 = 官方 4.7.8 原版（Druid 默认口令、admin/admin123、验证码开启）。
  4.7.8 已修复扫描器覆盖的 SQLi / 路径穿越 / 定时任务白名单，因此安全预期
  是「不出现 CONFIRMED」；真正带洞的对照需要按 lab/VULN-REINTRODUCE.md 回退。
* harden 档在 nginx 层对四个端点返回 403；waf 档由 CRS 在代理层拦截攻击载荷。
  这两档的 403 是**预期结果**，不是栈故障。

退出码
======
  0  所有检查符合该档预期（WARN 不影响退出码）
  1  依赖缺失 / 栈未就绪 / 参数错误（打印排查提示，不抛 traceback）
  2  至少一项检查不符合预期（例如 harden/waf 未拦截、app 返回 5xx）

用法
====
  python scripts/prod_smoke.py --help
  python scripts/prod_smoke.py --base-url https://127.0.0.1:8443 --insecure
  python scripts/prod_smoke.py --tier harden --base-url https://127.0.0.1:8444 --ca-cert lab/prod/certs/server.crt
  python scripts/prod_smoke.py --tier waf --base-url http://127.0.0.1:8085 --insecure --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover - exercised only without requirements
    print(
        "[FAIL] 缺少依赖 requests。\n"
        "       安装：pip install requests\n"
        "       仓库虚拟环境示例：.venv/Scripts/python.exe scripts/prod_smoke.py ...",
        file=sys.stderr,
    )
    raise SystemExit(1)

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass


# ---------------------------------------------------------------------------
# Expectations per tier
# ---------------------------------------------------------------------------
EXPECTED: dict[str, dict[str, set[int]]] = {
    # Official 4.7.8: Shiro gates all three paths behind a 302 to /login.
    "stock": {
        "login": {200},
        "captcha": {200},
        "druid": {302, 401},
        "role_list": {302, 401},
        "traversal": {302, 401},
    },
    # nginx-harden: 403 for /druid/*, /monitor/job/edit, /tool/gen/edit,
    # /common/download/resource. /system/role/list is not in the block list.
    "harden": {
        "login": {200},
        "captcha": {200},
        "druid": {403},
        "role_list": {302, 401},
        "traversal": {403},
    },
    # ModSecurity CRS @ paranoia 1: attack payloads should be rejected at the
    # proxy. Druid is not a CRS signature target, so its stock 302 is accepted.
    "waf": {
        "login": {200},
        "captcha": {200},
        "druid": {302, 401, 403},
        "role_list": {403},
        "traversal": {403},
    },
    # Best-effort readiness mode: accept any well-formed gate/403, never 5xx.
    "auto": {
        "login": {200},
        "captcha": {200},
        "druid": {200, 302, 401, 403},
        "role_list": {200, 302, 401, 403},
        "traversal": {200, 302, 401, 403},
    },
}

TIER_LABEL = {
    "stock": "stock / 官方 4.7.8（漏洞对照的“未加固”档）",
    "harden": "harden / nginx 403 代理层",
    "waf": "waf / OWASP CRS paranoia=1",
    "auto": "auto / 仅确认可用",
}

PASSWD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):[^:\n]*:(\d+):(\d+):", re.MULTILINE)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

ROLE_LIST_BODY = {
    "pageSize": "",
    "pageNum": "",
    "orderByColumn": "",
    "isAsc": "",
    "roleName": "",
    "roleKey": "",
    "status": "",
    "params[beginTime]": "",
    "params[endTime]": "",
    "params[dataScope]": "and extractvalue(1,concat(0x7e,(select database()),0x7e))",
}


@dataclass
class Result:
    key: str
    title: str
    method: str
    path: str
    expected: str
    status: Optional[int] = None
    content_type: str = ""
    location: str = ""
    snippet: str = ""
    verdict: str = "FAIL"
    note: str = ""


def clip(text: str, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def expected_text(tier: str, key: str) -> str:
    return "/".join(str(code) for code in sorted(EXPECTED[tier][key]))


def make_session(args: argparse.Namespace) -> requests.Session:
    session = requests.Session()
    session.trust_env = False  # do not route loopback through HTTP_PROXY
    session.headers.update(
        {
            "User-Agent": "ruoyi-scan-prod-smoke/1.0 (+https://github.com/xiabai2008/ruoyi-scan)",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
    )
    retry = Retry(total=2, connect=2, read=2, backoff_factor=0.3, status_forcelist=(502, 503, 504))
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if args.ca_cert:
        if not os.path.isfile(args.ca_cert):
            print(f"[FAIL] --ca-cert 文件不存在: {args.ca_cert}", file=sys.stderr)
            raise SystemExit(1)
        session.verify = os.path.abspath(args.ca_cert)
    elif args.insecure:
        session.verify = False
    else:
        session.verify = True
    return session


def url_of(base: str, path: str) -> str:
    return base + path if path.startswith("/") else base + "/" + path


def wait_for_stack(
    session: requests.Session,
    base: str,
    wait_seconds: int,
    timeout: float,
    as_json: bool,
) -> tuple[bool, str]:
    """Poll /login until the MVC stack answers, or the deadline expires."""
    deadline = time.monotonic() + max(wait_seconds, 0)
    last = "no attempt"
    attempt = 0
    hint_printed = False

    while True:
        attempt += 1
        try:
            resp = session.get(url_of(base, "/login"), timeout=timeout, allow_redirects=True)
            body = resp.text or ""
            if resp.status_code == 200 and any(k in body for k in ("RuoYi", "若依", "loginForm")):
                return True, f"HTTP 200 after {attempt} attempt(s)"
            last = f"HTTP {resp.status_code}"
        except requests.exceptions.SSLError as exc:
            last = f"TLS error: {exc.__class__.__name__}"
            if not hint_printed and not as_json:
                print(
                    "\n[HINT] TLS 校验失败（自签证书）。加 --insecure，"
                    "或 --ca-cert lab/prod/certs/server.crt。",
                    file=sys.stderr,
                )
                hint_printed = True
        except requests.exceptions.RequestException as exc:
            last = f"{exc.__class__.__name__}: {clip(str(exc), 120)}"
        except Exception as exc:  # never leak a traceback for a probe
            last = f"{exc.__class__.__name__}: {clip(str(exc), 120)}"

        if time.monotonic() >= deadline:
            return False, last

        if not as_json and (attempt == 1 or attempt % 5 == 0):
            elapsed = int(time.monotonic() - (deadline - max(wait_seconds, 0)))
            print(
                f"[WAIT] {elapsed:>3}s / {wait_seconds}s  {base}/login -> {last}",
                file=sys.stderr,
            )
        time.sleep(3)


def request(
    session: requests.Session,
    method: str,
    url: str,
    timeout: float,
    **kwargs,
) -> tuple[Optional[requests.Response], Optional[str]]:
    try:
        return session.request(method, url, timeout=timeout, **kwargs), None
    except requests.exceptions.SSLError:
        return None, "TLS 校验失败；使用 --insecure 或 --ca-cert certs/server.crt"
    except requests.exceptions.RequestException as exc:
        return None, f"{exc.__class__.__name__}: {clip(str(exc), 160)}"
    except Exception as exc:  # pragma: no cover
        return None, f"{exc.__class__.__name__}: {clip(str(exc), 160)}"


def check_login(session, base, tier, timeout) -> Result:
    r = Result(
        key="login",
        title="/login 登录页",
        method="GET",
        path="/login",
        expected=expected_text(tier, "login"),
    )
    resp, err = request(session, "GET", url_of(base, "/login"), timeout, allow_redirects=True)
    if err:
        r.note = err
        return r
    assert resp is not None
    r.status = resp.status_code
    r.content_type = resp.headers.get("Content-Type", "")
    body = resp.text or ""
    title = TITLE_RE.search(body)
    r.snippet = clip(title.group(1)) if title else clip(body)
    marker = any(k in body for k in ("RuoYi", "若依", "loginForm", "captchaImage"))
    if r.status in EXPECTED[tier]["login"] and marker:
        r.verdict = "PASS"
        r.note = "RuoYi 登录页 + 验证码入口可见"
    elif r.status in EXPECTED[tier]["login"]:
        r.note = "HTTP 200 但未找到 RuoYi 登录页特征"
    else:
        r.note = "登录页不可用；先确认 nginx -> ruoyi 链路与 JVM 启动"
    return r


def check_captcha(session, base, tier, timeout) -> Result:
    r = Result(
        key="captcha",
        title="/captcha/captchaImage",
        method="GET",
        path="/captcha/captchaImage",
        expected=expected_text(tier, "captcha"),
    )
    resp, err = request(session, "GET", url_of(base, "/captcha/captchaImage"), timeout, allow_redirects=False)
    if err:
        r.note = err
        return r
    assert resp is not None
    r.status = resp.status_code
    r.content_type = resp.headers.get("Content-Type", "")
    content = resp.content or b""
    magic = content[:3]
    is_jpeg = magic == b"\xff\xd8\xff"
    is_png = magic == b"\x89PNG"
    is_json = "json" in r.content_type.lower() and b'"code"' in content[:4096]
    r.snippet = f"{len(content)} bytes, magic={magic.hex()}, type={r.content_type or '?'}"
    if r.status in EXPECTED[tier]["captcha"] and (is_jpeg or is_png or is_json):
        r.verdict = "PASS"
        r.note = "验证码开启（4.7.8 默认 shiro.captchaEnabled=true）"
    elif r.status in EXPECTED[tier]["captcha"]:
        r.note = "HTTP 200 但不是图片/验证码 JSON；检查 Shiro captcha 配置"
    else:
        r.note = "验证码接口不可用"
    return r


def check_druid(session, base, tier, timeout) -> Result:
    path = "/druid/index.html"
    r = Result(key="druid", title="Druid 控制台", method="GET", path=path, expected=expected_text(tier, "druid"))
    resp, err = request(session, "GET", url_of(base, path), timeout, allow_redirects=False)
    if err:
        r.note = err
        return r
    assert resp is not None
    r.status = resp.status_code
    r.content_type = resp.headers.get("Content-Type", "")
    r.location = resp.headers.get("Location", "")
    body = resp.text or ""
    r.snippet = clip(r.location or body)

    if r.status in EXPECTED[tier]["druid"]:
        r.verdict = "PASS"
        if r.status == 403:
            r.note = "被 403 拦截（harden/waf 预期）"
        elif r.status in (302, 401):
            r.note = "Shiro 未认证拦截（真实 4.7.8：302 -> /login）"
        elif r.status == 200:
            r.note = "Druid 控制台未鉴权返回 200（真实发现）"
    elif tier == "stock" and r.status == 200 and ("druid" in body.lower() or "druid" in r.content_type.lower()):
        r.verdict = "WARN"
        r.note = "Druid 控制台未鉴权暴露（真实发现，不是栈故障）；记录后继续"
    elif r.status == 200:
        r.verdict = "WARN" if tier == "stock" else "FAIL"
        r.note = "200 但不是预期的拦截形态"
    else:
        r.note = "Druid 端点行为不符合该档预期；检查 nginx 模板 / Shiro 过滤链"
    return r


def check_role_list(session, base, tier, timeout) -> Result:
    path = "/system/role/list"
    r = Result(key="role_list", title="未认证 POST role/list", method="POST", path=path,
               expected=expected_text(tier, "role_list"))
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": url_of(base, "/system/role"),
    }
    resp, err = request(
        session, "POST", url_of(base, path), timeout,
        data=ROLE_LIST_BODY, headers=headers, allow_redirects=False,
    )
    if err:
        r.note = err
        return r
    assert resp is not None
    r.status = resp.status_code
    r.content_type = resp.headers.get("Content-Type", "")
    r.location = resp.headers.get("Location", "")
    body = resp.text or ""
    r.snippet = clip(body)
    is_json = "json" in r.content_type.lower()
    parsed = None
    if is_json:
        try:
            parsed = resp.json()
        except Exception:
            parsed = None

    if r.status in EXPECTED[tier]["role_list"]:
        r.verdict = "PASS"
        if r.status == 401:
            r.note = "401 JSON：符合 RuoYi-Vue 风格的未认证响应口径"
        elif r.status == 403:
            r.note = "403：代理/WAF 拦截"
        else:
            r.note = "302 -> /login：真实 RuoYi 4.7.8 的 Shiro user filter 行为（非 401 JSON）"
    elif r.status == 200:
        code = parsed.get("code") if isinstance(parsed, dict) else None
        has_rows = isinstance(parsed, dict) and ("rows" in parsed or "total" in parsed)
        if code in (401, 403):
            r.verdict = "PASS"
            r.note = f"HTTP 200 但 JSON code={code}，按未认证处理"
        elif has_rows:
            r.verdict = "WARN" if tier == "stock" else "FAIL"
            r.note = "未认证直接返回角色数据：鉴权绕过（真实发现）"
        else:
            r.verdict = "WARN" if tier == "stock" else "FAIL"
            r.note = "200 且不是已知未认证形态"
    elif r.status >= 500:
        r.note = "5xx：应用异常；检查 ruoyi 日志与数据库连接"
    else:
        r.note = "状态码不符合该档预期"
    return r


def check_traversal(session, base, tier, timeout) -> Result:
    path = "/common/download/resource?resource=../../../../etc/passwd"
    r = Result(key="traversal", title="路径穿越读取 passwd", method="GET", path=path,
               expected=expected_text(tier, "traversal"))
    resp, err = request(session, "GET", url_of(base, path), timeout, allow_redirects=False)
    if err:
        r.note = err
        return r
    assert resp is not None
    r.status = resp.status_code
    r.content_type = resp.headers.get("Content-Type", "")
    r.location = resp.headers.get("Location", "")
    body = resp.text or ""
    r.snippet = clip(body)

    if r.status in EXPECTED[tier]["traversal"]:
        r.verdict = "PASS"
        if r.status == 403:
            r.note = "403：harden/WAF 按预期拦截路径穿越"
        elif r.status in (302, 401):
            r.note = "Shiro 未认证拦截（真实 4.7.8：302 -> /login）"
        elif r.status == 200:
            accounts = PASSWD_RE.findall(body)
            if len(accounts) >= 2 and any(name == "root" and uid == "0" for name, uid, _ in accounts):
                r.verdict = "WARN" if tier == "stock" else "FAIL"
                r.note = f"/etc/passwd 特征命中（{', '.join(a[0] for a in accounts[:3])}）"
            else:
                r.note = "200 但未命中 /etc/passwd 特征"
    elif r.status == 200 and tier == "stock":
        accounts = PASSWD_RE.findall(body)
        if len(accounts) >= 2 and any(name == "root" and uid == "0" for name, uid, _ in accounts):
            r.verdict = "WARN"
            r.note = f"真实文件读取暴露（真实发现）：{', '.join(a[0] for a in accounts[:3])}"
        else:
            r.verdict = "WARN"
            r.note = "200 但未命中 /etc/passwd 特征（可能是业务错误页）"
    elif r.status >= 500:
        r.note = "5xx：路径穿越请求触发应用异常；检查 ruoyi 日志"
    else:
        r.note = "状态码不符合该档预期；确认目标端口/代理层是否正确"
    return r


CHECKS = (check_login, check_captcha, check_druid, check_role_list, check_traversal)


def print_result(result: Result) -> None:
    status = "ERR" if result.status is None else str(result.status)
    print(f"[{result.verdict:<4}] {result.title}")
    print(f"       {result.method} {result.path}")
    print(f"       期望 {result.expected:<12} 实际 HTTP {status}  {result.content_type or '-'}")
    if result.location:
        print(f"       Location: {clip(result.location, 120)}")
    if result.snippet:
        print(f"       片段: {result.snippet}")
    if result.note:
        print(f"       说明: {result.note}")
    print()


def print_not_ready(base: str, wait_seconds: int, last: str) -> None:
    print(f"\n[FAIL] 栈未就绪：{wait_seconds}s 内未能从 {base}/login 得到 RuoYi 登录页", file=sys.stderr)
    print(f"       最后一次结果：{last}", file=sys.stderr)
    print("", file=sys.stderr)
    print("排查顺序：", file=sys.stderr)
    print("  1) docker compose -f lab/prod/docker-compose.yml ps", file=sys.stderr)
    print("  2) docker compose -f lab/prod/docker-compose.yml logs --tail=120 ruoyi nginx mysql", file=sys.stderr)
    print("  3) 首次启动需 MySQL 初始化 + JVM 启动（约 60-180s）；首次构建 Maven 依赖 10-20 分钟", file=sys.stderr)
    print("  4) 自签证书：默认用 --insecure；或用 --ca-cert lab/prod/certs/server.crt", file=sys.stderr)
    print("  5) 端口冲突：检查 lab/prod/.env 中的 *PORT* 变量与 docker compose port", file=sys.stderr)
    print("  6) 离线环境：先在可联网机器 build，再 docker save/load，见 lab/prod/README.md", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prod_smoke.py",
        description=(
            "lab/prod 冒烟探针：等待真实 RuoYi 4.7.8 栈就绪，并核对 "
            "stock / harden / waf 三档对 5 个端点的响应。\n"
            "默认目标是 https://127.0.0.1:8443（nginx 自签 TLS）。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  python scripts/prod_smoke.py --insecure\n"
            "  python scripts/prod_smoke.py --tier harden --base-url https://127.0.0.1:8444 --insecure\n"
            "  python scripts/prod_smoke.py --tier waf --base-url http://127.0.0.1:8085 --insecure\n"
            "  python scripts/prod_smoke.py --json --wait 60 --insecure\n"
            "\n"
            "退出码：0=符合预期，1=未就绪/依赖缺失，2=行为不符合该档预期。\n"
            "注意：官方 4.7.8 未认证访问受保护端点返回 302 -> /login，\n"
            "      不是 401 JSON；脚本对两种形态都识别并标注。"
        ),
    )
    parser.add_argument("--base-url", default="https://127.0.0.1:8443",
                        help="目标根 URL（默认 %(default)s）")
    parser.add_argument("--tier", choices=("stock", "harden", "waf", "auto"), default="stock",
                        help="期望档位（默认 %(default)s）")
    parser.add_argument("--wait", type=int, default=240, metavar="SECONDS",
                        help="等待 /login 就绪的最长秒数（默认 %(default)s；0=只试一次）")
    parser.add_argument("--timeout", type=float, default=8.0, metavar="SECONDS",
                        help="单请求超时（默认 %(default)s）")
    parser.add_argument("--insecure", action="store_true",
                        help="关闭 TLS 校验（自签证书实验室；与 --ca-cert 互斥时以 --ca-cert 为准）")
    parser.add_argument("--ca-cert", metavar="PEM",
                        help="用指定 CA/证书校验 TLS（例如 lab/prod/certs/server.crt）")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="输出机器可读 JSON，便于 CI 消费")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    base = args.base_url.rstrip("/")
    if not re.match(r"^https?://", base):
        print(f"[FAIL] --base-url 必须以 http:// 或 https:// 开头: {args.base_url}", file=sys.stderr)
        return 1

    session = make_session(args)

    ready, last = wait_for_stack(session, base, args.wait, args.timeout, args.as_json)
    if not ready:
        if args.as_json:
            print(json.dumps({"ok": False, "reason": "stack_not_ready", "last": last,
                              "base_url": base}, ensure_ascii=False, indent=2))
        else:
            print_not_ready(base, args.wait, last)
        return 1

    if not args.as_json:
        print(f"目标: {base}")
        print(f"档位: {args.tier} — {TIER_LABEL[args.tier]}")
        print(f"TLS : {'verify=' + str(session.verify) if session.verify is not False else 'verify=False (--insecure)'}")
        print("")

    results: list[Result] = []
    for check in CHECKS:
        try:
            results.append(check(session, base, args.tier, args.timeout))
        except Exception as exc:  # a probe bug must not turn into a traceback
            results.append(
                Result(
                    key=check.__name__,
                    title=check.__name__,
                    method="?",
                    path="?",
                    expected="n/a",
                    note=f"探针内部错误: {exc.__class__.__name__}: {clip(str(exc), 160)}",
                )
            )

    if args.as_json:
        summary = {
            "pass": sum(r.verdict == "PASS" for r in results),
            "warn": sum(r.verdict == "WARN" for r in results),
            "fail": sum(r.verdict == "FAIL" for r in results),
        }
        print(json.dumps({
            "ok": summary["fail"] == 0,
            "tier": args.tier,
            "base_url": base,
            "summary": summary,
            "results": [asdict(r) for r in results],
        }, ensure_ascii=False, indent=2))
    else:
        for result in results:
            print_result(result)
        n_pass = sum(r.verdict == "PASS" for r in results)
        n_warn = sum(r.verdict == "WARN" for r in results)
        n_fail = sum(r.verdict == "FAIL" for r in results)
        print(f"结论: {n_pass} PASS / {n_warn} WARN / {n_fail} FAIL  "
              f"(tier={args.tier}, target={base})")
        if n_fail:
            print("提示: FAIL 表示与期望档位不符；WARN 多为 stock 档的真实安全发现，不改变退出码。",
                  file=sys.stderr)
        elif n_warn:
            print("提示: 有 WARN（通常是真实发现）。如用于 CI 门禁，请显式按 WARN 处理。",
                  file=sys.stderr)

    return 2 if any(r.verdict == "FAIL" for r in results) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[FAIL] 已中断", file=sys.stderr)
        raise SystemExit(1)
