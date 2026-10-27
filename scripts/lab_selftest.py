#!/usr/bin/env python3
# Ruoyi 靶场自测脚本 —— 对 lab/chaos 与 lab/realistic 的每个 profile 做端到端断言
#
# 用法：
#   python scripts/lab_selftest.py
#
# 设计：
#   1. 为每个 profile 选择随机空闲端口并启动真实子进程；
#   2. 轮询 /__lab/health 等待就绪；
#   3. 执行关键断言（HTTP 状态码 / 头 / 响应体特征 / 认证流程）；
#   4. 关闭进程并输出 PASS/FAIL 明细；失败时退出码 1。
#
# 仅依赖标准库 + requests；不修改任何靶场文件。
import contextlib
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
CHAOS_SERVER = ROOT / "lab" / "chaos" / "server.py"
REALISTIC_SERVER = ROOT / "lab" / "realistic" / "server.py"

# 官方若依 4.7.8 favicon 原始字节 md5（与 core/fingerprint_features.py 一致）
FAVICON_MD5 = "e49fd30ea870c7a820464ca56a113e6e"

CHAOS_PROFILES = [
    "normal",
    "slow",
    "tarpit",
    "flaky",
    "ratelimit",
    "js_challenge",
    "soft404",
    "block_all",
    "redirect_loop",
    "gzip_chunked",
    "bigbody",
    "reset",
]
REALISTIC_PROFILES = ["vuln", "safe"]

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    """记录一条断言结果"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  PASS  %s" % name)
    else:
        FAIL += 1
        suffix = ("  [%s]" % detail) if detail else ""
        print("  FAIL  %s%s" % (name, suffix))


def client():
    """创建忽略系统代理的 requests 会话（避免 HTTP_PROXY 干扰 127.0.0.1）"""
    sess = requests.Session()
    sess.trust_env = False
    return sess


def free_port():
    """申请一个当前空闲的本机端口"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def wait_health(base, proc, timeout=20.0):
    """轮询 /__lab/health 直到 200 或超时"""
    deadline = time.time() + timeout
    sess = client()
    while time.time() < deadline:
        if proc.poll() is not None:
            return None
        try:
            resp = sess.get(base + "/__lab/health", timeout=1.0)
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException:
            pass
        time.sleep(0.15)
    return None


def read_log_tail(path, limit=2500):
    """读取子进程日志尾部，失败时用于定位"""
    try:
        with open(path, "rb") as f:
            data = f.read()
        return data[-limit:].decode("utf-8", "replace")
    except Exception:
        return ""


@contextlib.contextmanager
def running(kind, profile):
    """启动靶场子进程，yield (base_url, health_json, log_path)，退出时强制回收"""
    port = free_port()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    if kind == "chaos":
        env["CHAOS_PROFILE"] = profile
        env["CHAOS_PORT"] = str(port)
        env.pop("CHAOS_HOST", None)
        script = CHAOS_SERVER
    else:
        env["LAB_PROFILE"] = profile
        env["LAB_PORT"] = str(port)
        env.pop("LAB_HOST", None)
        script = REALISTIC_SERVER

    log_path = os.path.join(
        tempfile.gettempdir(),
        "ruoyi-lab-selftest-%s-%s-%s.log" % (kind, profile, port),
    )
    log_file = open(log_path, "wb")
    proc = subprocess.Popen(
        [sys.executable, str(script)],
        cwd=str(ROOT),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    base = "http://127.0.0.1:%s" % port
    try:
        health = wait_health(base, proc)
        if health is None:
            raise RuntimeError("靶场启动失败（日志：%s）\n%s" % (log_path, read_log_tail(log_path)))
        yield base, health, log_path
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
        try:
            log_file.close()
        except Exception:
            pass


# ── chaos ──────────────────────────────────────────────────────────────────


def test_chaos(profile):
    """chaos 各 profile 的关键 HTTP 行为断言"""
    global FAIL
    print("\n=== chaos / %s ===" % profile)
    fail_before = FAIL
    log_path = ""
    try:
        with running("chaos", profile) as (base, health, log_path):
            check(
                "health 200 且 profile 正确",
                health.get("ok") is True and health.get("profile") == profile,
                str(health),
            )
            sess = client()

            if profile == "normal":
                resp = sess.get(base + "/", timeout=15)
                check("根路径 200 且含若依", resp.status_code == 200 and "若依" in resp.text)
                resp = sess.get(base + "/missing", timeout=15)
                check("未知路径 404", resp.status_code == 404, "status=%s" % resp.status_code)

            elif profile == "slow":
                start = time.time()
                resp = sess.get(base + "/", timeout=20)
                elapsed = time.time() - start
                check("每个响应延迟 >= 2s", elapsed >= 1.9, "actual=%.2fs" % elapsed)
                check("延迟后仍返回 200 且含若依", resp.status_code == 200 and "若依" in resp.text)

            elif profile == "tarpit":
                start = time.time()
                resp = sess.get(base + "/", timeout=5)
                elapsed = time.time() - start
                check("/ 正常快速返回", resp.status_code == 200 and elapsed < 2.0, "%.2fs" % elapsed)
                timed_out = False
                try:
                    sess.get(base + "/tarpit-probe", timeout=1.5)
                except requests.Timeout:
                    timed_out = True
                check("非 / 路径被挂起（客户端超时）", timed_out)

            elif profile == "flaky":
                codes = []
                for _ in range(30):
                    try:
                        codes.append(sess.get(base + "/", timeout=10).status_code)
                    except requests.RequestException:
                        codes.append(0)
                fails = [c for c in codes if 500 <= c < 600]
                check("30 次请求中出现 5xx", len(fails) > 0, "codes=%s" % codes)
                check("5xx 比例处于合理范围", len(fails) <= 20, "fails=%d" % len(fails))

            elif profile == "ratelimit":
                codes = [sess.get(base + "/", timeout=10).status_code for _ in range(5)]
                check("前 5 个请求正常", codes == [200] * 5, "codes=%s" % codes)
                resp = sess.get(base + "/", timeout=10)
                check("第 6 个请求 429", resp.status_code == 429, "status=%s" % resp.status_code)
                check(
                    "429 携带 Retry-After: 30",
                    resp.headers.get("Retry-After") == "30",
                    str(resp.headers.get("Retry-After")),
                )

            elif profile == "js_challenge":
                resp = sess.get(base + "/", timeout=10)
                check("JS 挑战返回 503", resp.status_code == 503, "status=%s" % resp.status_code)
                check(
                    "cf-mitigated: challenge",
                    resp.headers.get("cf-mitigated") == "challenge",
                    str(resp.headers.get("cf-mitigated")),
                )
                check("挑战页含 window.location", "window.location" in resp.text)

            elif profile == "soft404":
                resp = sess.get(base + "/this-path-does-not-exist-12345", timeout=10)
                check("未知路径返回 HTTP 200（软 404）", resp.status_code == 200, "status=%s" % resp.status_code)
                check("未知路径仍是 404 页面", "404 Not Found" in resp.text)
                check("软 404 body 约 300 字节", 200 <= len(resp.content) <= 400, "len=%d" % len(resp.content))
                root = sess.get(base + "/", timeout=10)
                check("根路径仍正常且含若依", root.status_code == 200 and "若依" in root.text)

            elif profile == "block_all":
                resp = sess.get(base + "/", timeout=10)
                check(
                    "全站 403 + 空 body",
                    resp.status_code == 403 and len(resp.content) == 0,
                    "status=%s len=%d" % (resp.status_code, len(resp.content)),
                )
                check("WAF 拦截头存在", resp.headers.get("X-WAF-Block") == "1")
                resp2 = sess.get(base + "/system/user/list", timeout=10)
                check("其它路径同样 403", resp2.status_code == 403, "status=%s" % resp2.status_code)

            elif profile == "redirect_loop":
                r1 = sess.get(base + "/", allow_redirects=False, timeout=10)
                r2 = sess.get(base + "/a", allow_redirects=False, timeout=10)
                r3 = sess.get(base + "/b", allow_redirects=False, timeout=10)
                loc1 = r1.headers.get("Location", "")
                loc2 = r2.headers.get("Location", "")
                loc3 = r3.headers.get("Location", "")
                check(
                    "重定向链 / -> /a -> /b -> /a",
                    [r1.status_code, r2.status_code, r3.status_code] == [302, 302, 302]
                    and loc1.endswith("/a")
                    and loc2.endswith("/b")
                    and loc3.endswith("/a"),
                    "%s %s %s" % (loc1, loc2, loc3),
                )

            elif profile == "gzip_chunked":
                resp = sess.get(base + "/", timeout=15)
                check(
                    "Content-Encoding: gzip",
                    resp.headers.get("Content-Encoding") == "gzip",
                    str(resp.headers.get("Content-Encoding")),
                )
                check(
                    "Transfer-Encoding: chunked",
                    "chunked" in resp.headers.get("Transfer-Encoding", "").lower(),
                    str(resp.headers.get("Transfer-Encoding")),
                )
                check("解压后含若依", "若依" in resp.text)

            elif profile == "bigbody":
                resp = sess.get(base + "/", timeout=60)
                check(
                    "大响应体 8-10MB",
                    8 * 1024 * 1024 <= len(resp.content) <= 10 * 1024 * 1024 + 1024,
                    "len=%d" % len(resp.content),
                )
                check("大响应体 status 200", resp.status_code == 200, "status=%s" % resp.status_code)

            elif profile == "reset":
                reset_symptom = False
                try:
                    resp = sess.get(base + "/", timeout=5)
                    if resp.status_code == 413:
                        reset_symptom = True
                except requests.RequestException:
                    reset_symptom = True
                check("读到请求后连接中断或返回 413", reset_symptom)

    except Exception as exc:
        check("%s 靶场启动/执行异常" % profile, False, str(exc))

    if FAIL > fail_before and log_path:
        print("  ---- server log tail (%s) ----" % log_path)
        print(read_log_tail(log_path))


# ── realistic ──────────────────────────────────────────────────────────────


def _login(base):
    """完整走一遍登录页 -> 验证码 -> POST /login，返回 (session, page, sid, captcha, login_resp)"""
    sess = client()
    page = sess.get(base + "/login", timeout=15)
    sid = sess.cookies.get("JSESSIONID")
    captcha = sess.get(base + "/captcha/captchaImage", timeout=15)
    state = sess.get(base + "/__lab/session", timeout=15).json()
    code = state.get("captcha")
    login = sess.post(
        base + "/login",
        data={"username": "admin", "password": "admin123", "code": code, "uuid": sid},
        timeout=15,
    )
    return sess, page, sid, captcha, login


def test_realistic(profile):
    """realistic vuln/safe 的行为级断言"""
    global FAIL
    print("\n=== realistic / %s ===" % profile)
    fail_before = FAIL
    log_path = ""
    try:
        with running("realistic", profile) as (base, health, log_path):
            check(
                "health 200 且 profile 正确",
                health.get("ok") is True and health.get("profile") == profile,
                str(health),
            )
            ua = client()
            exec_payload = "java.lang.Runtime.getRuntime().exec('id')"
            sqli_payload = "(select extractvalue(1,concat(0x7e,(select database()),0x7e)))"

            # ── 登录页 / 验证码 ──────────────────────────────────────────
            page = ua.get(base + "/login", timeout=15)
            check("登录页 200", page.status_code == 200, "status=%s" % page.status_code)
            check("登录页约 5KB", len(page.content) >= 5000, "len=%d" % len(page.content))
            check("登录页含若依关键字", "若依" in page.text)
            check("登录页引用 /captcha/captchaImage", "/captcha/captchaImage" in page.text)
            # 靶场默认伪装成 4.7.8（LAB_VERSION 可改）；版权年份 2023 对应的正是扫描器的 4.7.8 版本判定
            check("登录页版权 2018-2023", "Copyright © 2018-2023 ruoyi.vip" in page.text)
            check("响应下发 JSESSIONID", "JSESSIONID" in page.headers.get("Set-Cookie", ""))
            check(
                "Server: nginx/1.24.0 且不暴露 Flask",
                page.headers.get("Server") == "nginx/1.24.0"
                and "werkzeug" not in page.headers.get("Server", "").lower(),
                str(page.headers.get("Server")),
            )
            check(
                "登录页 gzip 压缩",
                page.headers.get("Content-Encoding") == "gzip",
                str(page.headers.get("Content-Encoding")),
            )

            sid = ua.cookies.get("JSESSIONID")
            captcha = ua.get(base + "/captcha/captchaImage", timeout=15)
            check(
                "验证码 Content-Type: image/png",
                captcha.headers.get("Content-Type", "").startswith("image/png"),
                str(captcha.headers.get("Content-Type")),
            )
            check("验证码是合法 PNG", captcha.content[:8] == b"\x89PNG\r\n\x1a\n", repr(captcha.content[:8]))
            state = ua.get(base + "/__lab/session", timeout=15).json()
            code = state.get("captcha")
            check(
                "服务端保存 4 位验证码",
                isinstance(code, str) and len(code) == 4 and code.isdigit(),
                str(code),
            )

            # ── 验证码 / 密码错误分支 ────────────────────────────────────
            wrong_sess = client()
            wrong_sess.get(base + "/login", timeout=15)
            wrong_sess.get(base + "/captcha/captchaImage", timeout=15)
            wrong_code = wrong_sess.get(base + "/__lab/session", timeout=15).json().get("captcha")
            if wrong_code == "1111":
                wrong_code = "2222"
            else:
                wrong_code = "1111"
            bad_captcha = wrong_sess.post(
                base + "/login",
                data={
                    "username": "admin",
                    "password": "admin123",
                    "code": wrong_code,
                    "uuid": wrong_sess.cookies.get("JSESSIONID"),
                },
                timeout=15,
            )
            check(
                "错误验证码 -> 验证码错误",
                bad_captcha.json().get("code") == 500 and bad_captcha.json().get("msg") == "验证码错误",
                bad_captcha.text[:160],
            )
            wrong_sess.get(base + "/captcha/captchaImage", timeout=15)
            fresh_code = wrong_sess.get(base + "/__lab/session", timeout=15).json().get("captcha")
            bad_password = wrong_sess.post(
                base + "/login",
                data={
                    "username": "admin",
                    "password": "wrong-password",
                    "code": fresh_code,
                    "uuid": wrong_sess.cookies.get("JSESSIONID"),
                },
                timeout=15,
            )
            check(
                "错误密码 -> 用户不存在/密码错误",
                bad_password.json().get("code") == 500 and "用户不存在" in bad_password.json().get("msg", ""),
                bad_password.text[:160],
            )

            # ── 正式登录 ────────────────────────────────────────────────
            sid = ua.cookies.get("JSESSIONID")
            login = ua.post(
                base + "/login",
                data={"username": "admin", "password": "admin123", "code": code, "uuid": sid},
                timeout=15,
            )
            check("admin/admin123 + 正确验证码 -> code 200", login.json().get("code") == 200, login.text[:160])
            state = ua.get(base + "/__lab/session", timeout=15).json()
            check("登录后会话标记为已认证", state.get("authenticated") is True, str(state))

            # ── 未认证访问受保护接口：vuln/safe 一致 401 ────────────────
            unauth = client()
            resp = unauth.post(
                base + "/system/role/list",
                data={"params[dataScope]": sqli_payload},
                timeout=15,
            )
            check(
                "未认证 role list -> code 401",
                resp.status_code == 200 and resp.json().get("code") == 401,
                resp.text[:160],
            )
            check("未认证 role list 不泄露业务数据", "XPATH" not in resp.text and "rows" not in resp.text)

            resp = unauth.post(base + "/tool/gen/edit", data={"template": "${7*7}"}, timeout=15)
            check(
                "未认证 gen edit -> code 401",
                resp.status_code == 200 and resp.json().get("code") == 401,
                resp.text[:160],
            )
            resp = unauth.post(
                base + "/common/upload",
                files={"file": ("shell.jsp", b"probe", "application/octet-stream")},
                timeout=15,
            )
            check(
                "未认证 upload -> code 401",
                resp.status_code == 200 and resp.json().get("code") == 401,
                resp.text[:160],
            )

            # ── 未认证 job edit / run（历史越权点）──────────────────────
            resp = unauth.post(
                base + "/monitor/job/edit",
                data={"jobId": "1", "invokeTarget": exec_payload, "status": "0"},
                timeout=15,
            )
            if profile == "vuln":
                check(
                    "vuln 未认证 job edit -> 200 操作成功",
                    resp.status_code == 200 and resp.json().get("code") == 200,
                    resp.text[:160],
                )
            else:
                check(
                    "safe 未认证 job edit -> code 401",
                    resp.status_code == 200 and resp.json().get("code") == 401,
                    resp.text[:160],
                )
            resp = unauth.post(base + "/monitor/job/run", data={"jobId": "1", "jobGroup": "DEFAULT"}, timeout=15)
            if profile == "vuln":
                check(
                    "vuln 未认证 job run -> 200 操作成功",
                    resp.status_code == 200 and resp.json().get("code") == 200,
                    resp.text[:160],
                )
            else:
                check(
                    "safe 未认证 job run -> code 401",
                    resp.status_code == 200 and resp.json().get("code") == 401,
                    resp.text[:160],
                )

            # ── 文件读取（真实若依该端点为 anon）────────────────────────
            resp = unauth.get(
                base + "/common/download/resource",
                params={"resource": "../../../../etc/passwd"},
                timeout=15,
            )
            if profile == "vuln":
                check(
                    "vuln ../ + /etc/passwd 读出 passwd",
                    resp.status_code == 200 and "root:x:0:0" in resp.text,
                    "status=%s %s" % (resp.status_code, resp.text[:100]),
                )
                check("passwd 为 5 行真实格式", len([ln for ln in resp.text.splitlines() if ln]) == 5)
            else:
                check(
                    "safe ../ + /etc/passwd -> 400 无特征",
                    resp.status_code == 400 and "root:x:0:0" not in resp.text,
                    "status=%s" % resp.status_code,
                )
            resp = unauth.get(
                base + "/common/download/resource",
                params={"resource": "../../../../2.txt"},
                timeout=15,
            )
            if profile == "vuln":
                check(
                    "vuln ../ + 2.txt 可读",
                    resp.status_code == 200 and "2.txt" in resp.text,
                    "status=%s" % resp.status_code,
                )
            else:
                check("safe ../ + 2.txt -> 400", resp.status_code == 400, "status=%s" % resp.status_code)
            resp = unauth.get(
                base + "/common/download/resource",
                params={"resource": "etc/passwd"},
                timeout=15,
            )
            check("无 ../ 的 resource -> 400", resp.status_code == 400, "status=%s" % resp.status_code)

            # ── Druid / Nacos ──────────────────────────────────────────
            resp = unauth.get(base + "/druid/index.html", allow_redirects=False, timeout=15)
            if profile == "vuln":
                check(
                    "vuln Druid 控制台可访问",
                    resp.status_code == 200 and "Druid" in resp.text,
                    "status=%s" % resp.status_code,
                )
            else:
                check(
                    "safe Druid index 302 到登录",
                    resp.status_code == 302 and resp.headers.get("Location", "").endswith("/login"),
                    "%s %s" % (resp.status_code, resp.headers.get("Location")),
                )
            resp = unauth.get(base + "/druid/websession.json", timeout=15)
            if profile == "vuln":
                check(
                    "vuln Druid websession 泄露 SESSIONID",
                    resp.status_code == 200 and "SESSIONID" in resp.text,
                    "status=%s" % resp.status_code,
                )
            else:
                check(
                    "safe Druid websession 401 且无 SESSIONID",
                    resp.status_code == 401 and "SESSIONID" not in resp.text,
                    "status=%s" % resp.status_code,
                )
            resp = unauth.get(
                base + "/nacos/v1/cs/configs",
                params={"dataId": "ruoyi-dev.yml", "group": "DEFAULT_GROUP"},
                timeout=15,
            )
            if profile == "vuln":
                # 真实 Nacos 配置接口返回的是 YAML 正文（spring:\n  datasource:\n    password: ...），
                # 不是扁平 key。两种形态都算泄露（插件侧同样两种都认）。
                _nacos_leak = "spring.datasource.password" in resp.text or (
                    "spring:" in resp.text and "datasource:" in resp.text and "password:" in resp.text
                )
                check(
                    "vuln Nacos 配置泄露（含 password）",
                    resp.status_code == 200 and _nacos_leak and "Ruoyi@2024" in resp.text,
                    resp.text[:200],
                )
            else:
                check(
                    "safe Nacos 403 且无 password",
                    resp.status_code == 403 and "password" not in resp.text.lower(),
                    "status=%s" % resp.status_code,
                )

            # ── 404 / favicon / 真实 HTTP 头 ────────────────────────────
            resp = unauth.get(base + "/definitely-not-a-real-path-abcxyz", timeout=15)
            check("未知路径 404", resp.status_code == 404, "status=%s" % resp.status_code)
            check(
                "nginx 风格 404 页面约 271 字节",
                "404 Not Found" in resp.text and 200 <= len(resp.content) <= 400,
                "len=%d" % len(resp.content),
            )
            check(
                "404 Server: nginx/1.24.0",
                resp.headers.get("Server") == "nginx/1.24.0",
                str(resp.headers.get("Server")),
            )

            fav = unauth.get(base + "/favicon.ico", timeout=15)
            check("favicon 200", fav.status_code == 200, "status=%s" % fav.status_code)
            check(
                "favicon md5 与若依官方一致",
                hashlib.md5(fav.content).hexdigest() == FAVICON_MD5,
                hashlib.md5(fav.content).hexdigest(),
            )

            # ── 已登录：SQLi 差分 / 上传 / 定时任务 / SSTI ──────────────
            baseline = ua.post(base + "/system/role/list", data={}, timeout=15)
            baseline_json = baseline.json()
            check(
                "role 基线返回正常列表（total=2）",
                baseline.status_code == 200
                and baseline_json.get("total") == 2
                and len(baseline_json.get("rows") or []) == 2,
                baseline.text[:160],
            )
            check("role 基线无 XPATH", "XPATH" not in baseline.text)

            injected = ua.post(
                base + "/system/role/list",
                data={"params[dataScope]": sqli_payload},
                timeout=15,
            )
            if profile == "vuln":
                check(
                    "vuln 带载荷 -> XPATH 报错",
                    injected.status_code == 200
                    and "XPATH" in injected.text
                    and "Error querying database" in injected.text,
                    injected.text[:200],
                )
            else:
                check(
                    "safe 带载荷 -> 正常列表且无 XPATH",
                    injected.status_code == 200
                    and "XPATH" not in injected.text
                    and injected.json().get("total") == 2,
                    injected.text[:200],
                )

            dept_baseline = ua.post(base + "/system/dept/list", data={}, timeout=15)
            check(
                "dept 基线返回正常列表（total=2）",
                dept_baseline.status_code == 200 and dept_baseline.json().get("total") == 2,
                dept_baseline.text[:160],
            )
            dept_injected = ua.post(
                base + "/system/dept/list",
                data={"params[dataScope]": sqli_payload.replace("extractvalue", "updatexml")},
                timeout=15,
            )
            if profile == "vuln":
                check("vuln dept 带载荷 -> XPATH", "XPATH" in dept_injected.text, dept_injected.text[:200])
            else:
                check("safe dept 带载荷无 XPATH", "XPATH" not in dept_injected.text, dept_injected.text[:200])

            upload = ua.post(
                base + "/common/upload",
                files={"file": ("shell.jsp", b"<%@ page language=\"java\" %>", "application/octet-stream")},
                timeout=15,
            )
            if profile == "vuln":
                upload_json = upload.json()
                check(
                    "vuln 上传 jsp -> code 0",
                    upload_json.get("code") == 0 and upload_json.get("fileName") == "shell.jsp",
                    upload.text[:200],
                )
                check(
                    "vuln 上传返回 /profile/upload/ URL",
                    str(upload_json.get("url", "")).startswith("/profile/upload/"),
                    str(upload_json.get("url")),
                )
            else:
                check(
                    "safe 上传 jsp -> 文件类型不允许",
                    upload.json().get("code") == 500 and "文件类型不允许" in upload.json().get("msg", ""),
                    upload.text[:200],
                )
            upload_txt = ua.post(
                base + "/common/upload",
                files={"file": ("note.txt", b"hello", "text/plain")},
                timeout=15,
            )
            check("非可执行扩展名 -> code 500", upload_txt.json().get("code") == 500, upload_txt.text[:160])

            before = ua.get(base + "/__lab/executed", timeout=15).json().get("count", 0)
            job_edit = ua.post(
                base + "/monitor/job/edit",
                data={"jobId": "1", "invokeTarget": exec_payload, "status": "0"},
                timeout=15,
            )
            if profile == "vuln":
                check(
                    "vuln 已登录 job edit -> 200",
                    job_edit.status_code == 200 and job_edit.json().get("code") == 200,
                    job_edit.text[:160],
                )
                after = ua.get(base + "/__lab/executed", timeout=15).json().get("count", 0)
                check("vuln 记录 invokeTarget 已执行", after > before, "before=%s after=%s" % (before, after))
            else:
                check(
                    "safe 已登录 job edit 执行载荷被拒",
                    job_edit.json().get("code") == 500,
                    job_edit.text[:160],
                )
                after = ua.get(base + "/__lab/executed", timeout=15).json().get("count", 0)
                check("safe 未记录任何执行", after == 0, "count=%s" % after)
            job_run = ua.post(
                base + "/monitor/job/run",
                data={"jobId": "1", "jobGroup": "DEFAULT"},
                timeout=15,
            )
            check("已登录 job run -> code 200", job_run.json().get("code") == 200, job_run.text[:160])

            gen_edit = ua.post(base + "/tool/gen/edit", data={"template": "${7*7}"}, timeout=15)
            if profile == "vuln":
                check(
                    "vuln gen edit -> 500 且回显 49",
                    gen_edit.status_code == 500 and "49" in gen_edit.text,
                    "status=%s %s" % (gen_edit.status_code, gen_edit.text[:200]),
                )
            else:
                check(
                    "safe gen edit -> 无 49 回显",
                    gen_edit.status_code == 200 and "49" not in gen_edit.text,
                    "status=%s %s" % (gen_edit.status_code, gen_edit.text[:200]),
                )
            gen_runtime = ua.post(
                base + "/tool/gen/edit",
                data={"content": "T(java.lang.Runtime).getRuntime().exec('id')"},
                timeout=15,
            )
            if profile == "vuln":
                check(
                    "vuln gen edit T() -> 500 且回显 49",
                    gen_runtime.status_code == 500 and "49" in gen_runtime.text,
                    "status=%s" % gen_runtime.status_code,
                )
            else:
                check("safe gen edit T() -> 无 49", "49" not in gen_runtime.text, gen_runtime.text[:200])

            # ── safe 全局特征扫描 ──────────────────────────────────────
            if profile == "safe":
                nacos_probe = unauth.get(
                    base + "/nacos/v1/cs/configs",
                    params={"dataId": "x", "group": "y"},
                    timeout=15,
                )
                probes = [
                    page,
                    injected,
                    unauth.get(
                        base + "/common/download/resource",
                        params={"resource": "../../../../etc/passwd"},
                        timeout=15,
                    ),
                    unauth.get(base + "/druid/websession.json", timeout=15),
                    nacos_probe,
                    gen_edit,
                ]
                blob = "\n".join(p.text for p in probes)
                check(
                    "safe 关键特征总体扫描（XPATH / passwd / SESSIONID）",
                    "XPATH" not in blob
                    and "root:x:0:0" not in blob
                    and "SESSIONID" not in blob,
                )
                check("safe 登录页无 49", "49" not in page.text)
                check("safe gen edit 无 49", "49" not in gen_edit.text)
                check("safe Nacos 无 password", "password" not in nacos_probe.text.lower())

    except Exception as exc:
        check("%s 靶场启动/执行异常" % profile, False, str(exc))

    if FAIL > fail_before and log_path:
        print("  ---- server log tail (%s) ----" % log_path)
        print(read_log_tail(log_path))


def main():
    """依次运行全部 profile，返回退出码"""
    print("=" * 72)
    print("RuoYi-Scan Lab Selftest — chaos / realistic")
    print("=" * 72)
    for profile in CHAOS_PROFILES:
        test_chaos(profile)
    for profile in REALISTIC_PROFILES:
        test_realistic(profile)
    print("\n" + "=" * 72)
    print("SUMMARY: PASS=%d FAIL=%d" % (PASS, FAIL))
    print("=" * 72)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
