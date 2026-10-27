# Ruoyi 漏洞扫描器 —— 对抗 / 干扰环境靶场（仅用于合法授权测试 / 教学验证）
#
# 设计目标：与 lab/server.py（签名应答靶场）互补，验证扫描器在「真实 HTTP 层异常」
# 下的判定质量：超时、限流、WAF 挑战、软 404、连接中断、超大响应等。
#
# 每个 profile 都真实改变 HTTP 行为（延迟 / 状态码 / 头 / 分块编码 / 连接关闭），
# 不返回「假错误页」来伪造结果。服务本身不含任何漏洞利用代码。
#
# 运行示例：
#   CHAOS_PROFILE=flaky CHAOS_PORT=8099 python lab/chaos/server.py
#   GET /__lab/health 永远 200，且不计入任何 profile 行为。
import gzip
import json
import os
import random
import socket
import sys
import threading
import time

from flask import Flask, Response, abort, g, request
from werkzeug.serving import WSGIRequestHandler

# 当前行为 profile：normal 为不带干扰的基线，便于人工对照
PROFILE = os.environ.get("CHAOS_PROFILE", "normal").strip().lower()
PORT = int(os.environ.get("CHAOS_PORT", "8099"))
HOST = os.environ.get("CHAOS_HOST", "127.0.0.1")

VALID_PROFILES = {
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
}
if PROFILE not in VALID_PROFILES:
    print(
        "[chaos] 非法 CHAOS_PROFILE=%r，可选值：%s" % (PROFILE, ", ".join(sorted(VALID_PROFILES))),
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(2)

# static_folder=None：避免 Flask 自动挂载 /static，所有路径统一走 dispatch
app = Flask(__name__, static_folder=None)


class _LabRequestHandler(WSGIRequestHandler):
    """覆盖 Werkzeug 默认 Server 头，避免暴露 Flask/Werkzeug 指纹"""

    def version_string(self):
        return "cloudflare" if PROFILE == "js_challenge" else "nginx/1.24.0"

# 线程安全随机源 + 限流计数器：Flask 开发服务器以 threaded=True 运行，
# 所有共享状态必须加锁，否则 ratelimit 的「第 6 个请求」会出现竞态。
_LOCK = threading.Lock()
_RNG = random.Random()
_RATE_COUNT = 0

# ── 拟真页面 ────────────────────────────────────────────────────────────────

_RUOYI_LOGIN_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RuoYi管理系统</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{font-family:"Helvetica Neue","PingFang SC","Microsoft YaHei",Arial,sans-serif;
background:linear-gradient(135deg,#14326e 0%,#1f4e9e 45%,#3a7bd5 100%);
display:flex;align-items:center;justify-content:center}
.card{width:420px;background:#fff;border-radius:8px;box-shadow:0 14px 44px rgba(0,21,41,.35);padding:36px 40px}
.logo{width:52px;height:52px;margin:0 auto 14px;border-radius:10px;background:linear-gradient(135deg,#e6a23c,#f06431);
color:#fff;font-size:30px;font-weight:700;line-height:52px;text-align:center}
h3{text-align:center;color:#707070;font-size:22px;margin:0 0 24px;font-weight:600}
.item{margin-bottom:18px}
.item input{width:100%;height:42px;border:1px solid #dcdfe6;border-radius:4px;padding:0 12px;font-size:14px;color:#606266}
button{width:100%;height:42px;border:0;border-radius:4px;background:linear-gradient(90deg,#409eff,#2f7ce0);
color:#fff;font-size:15px;letter-spacing:6px;text-indent:6px;cursor:pointer}
.tip{margin-top:16px;text-align:center;font-size:13px;color:#889aa4}
.copy{position:fixed;left:0;right:0;bottom:14px;text-align:center;color:rgba(255,255,255,.65);font-size:13px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">若</div>
  <h3>若依后台管理系统</h3>
  <form onsubmit="return false">
    <div class="item"><input name="username" placeholder="账号"></div>
    <div class="item"><input name="password" type="password" placeholder="密码"></div>
    <button type="submit">登录</button>
  </form>
  <div class="tip">RuoYi Chaos Lab</div>
</div>
<div class="copy">Copyright © 2018-2024 ruoyi.vip All Rights Reserved.</div>
</body>
</html>
"""

# 分块 + gzip profile 使用：足够大、含「若依」强关键字的后台首页
_GZIP_HOME_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>RuoYi管理系统</title>
<style>
body{font-family:Arial,"Microsoft YaHei",sans-serif;background:#f0f2f4;margin:0}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:200px;background:#304156}
.sidebar .logo{height:56px;line-height:56px;text-align:center;color:#fff;font-size:17px;font-weight:700;letter-spacing:3px;background:#2b3a4d}
.sidebar a{display:block;height:46px;line-height:46px;padding:0 20px;color:#bfcbd9;font-size:14px;text-decoration:none}
.sidebar a:hover{background:#263445}
.navbar{height:56px;margin-left:200px;background:#fff;box-shadow:0 1px 4px rgba(0,21,41,.08);
display:flex;align-items:center;justify-content:space-between;padding:0 20px;color:#606266;font-size:14px}
.main{margin-left:200px;padding:22px}
.card{background:#fff;border-radius:6px;padding:22px;box-shadow:0 1px 4px rgba(0,21,41,.06)}
h4{color:#303133;font-size:16px;margin:0 0 12px}
p{color:#606266;font-size:14px;line-height:1.9}
table{border-collapse:collapse;width:100%;margin-top:14px}
td{border:1px solid #ebeef4;padding:8px 14px;font-size:13px;color:#606266}
td:first-child{background:#fafafa;width:180px;color:#909399}
</style>
</head>
<body>
<div class="sidebar">
  <div class="logo">RuoYi</div>
  <a href="/">首页</a>
  <a href="/system/user">系统管理</a>
  <a href="/monitor/job">系统监控</a>
  <a href="/tool/gen">系统工具</a>
</div>
<div class="navbar"><span>☰ 首页</span><span>admin 超级管理员</span></div>
<div class="main">
  <div class="card">
    <h4>欢迎使用 若依 后台管理系统</h4>
    <p>当前站点为 RuoYi 对抗型传输层靶场（gzip_chunked profile），用于验证扫描器对分块传输与压缩响应的解析能力。</p>
    <table>
      <tr><td>框架版本</td><td>RuoYi 4.8.0（Spring Boot 2.5.15）</td></tr>
      <tr><td>运行环境</td><td>JDK 1.8.0_311 / MySQL 8.0.33 / Redis 6.2.6</td></tr>
      <tr><td>传输编码</td><td>Transfer-Encoding: chunked + Content-Encoding: gzip</td></tr>
    </table>
  </div>
</div>
</body>
</html>
"""

_JS_CHALLENGE_HTML = """<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=Edge">
<meta name="robots" content="noindex,nofollow">
<title>Just a moment...</title>
<style>
body{margin:0;padding:0;background:#fff;font-family:Arial,sans-serif;color:#313131}
.wrap{max-width:720px;margin:120px auto;padding:0 24px}
h1{font-size:28px;font-weight:400;margin:0 0 16px}
p{font-size:16px;line-height:1.6;color:#555}
.spinner{width:32px;height:32px;border:4px solid #f3f3f3;border-top:4px solid #f48120;border-radius:50%;
margin:28px 0;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.footer{margin-top:48px;font-size:12px;color:#999}
</style>
</head>
<body>
<div class="wrap">
  <h1>Checking your browser before accessing the site.</h1>
  <p>This process is automatic. Your browser will redirect to your requested content shortly.</p>
  <div class="spinner"></div>
  <p>Please allow up to 5 seconds&hellip;</p>
  <div class="footer">DDoS protection by Cloudflare &middot; Ray ID: __RAY__</div>
</div>
<script>
setTimeout(function () {
  window.location.reload();
}, 5000);
</script>
</body>
</html>
"""

_BAD_GATEWAY_HTML = """<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
"""

_TARPIT_OK_HTML = """<html>
<head><title>RuoYi</title></head>
<body><h1>若依管理系统</h1><p>request accepted</p></body>
</html>
"""

# 软 404：HTTP 200 + 普通 404 页面（约 300 字节），用于检验软 404 误判
_SOFT_404_BASE = (
    '<!DOCTYPE html><html><head><title>404 Not Found</title></head>'
    "<body><h1>404 Not Found</h1>"
    "<p>The requested URL was not found on this server.</p></body></html>"
)


def _pad_html(base, target_len):
    """在 </body> 前插入空白注释，把 HTML 填充到指定字节数（用于软 404 尺寸对拍）"""
    pad = target_len - len(base.encode("utf-8"))
    if pad > 7:
        base = base.replace("</body>", "<!--" + " " * (pad - 7) + "--></body>")
    return base


_SOFT_404_HTML = _pad_html(_SOFT_404_BASE, 300)


def _json_body(obj, status=200):
    """返回 UTF-8 JSON 响应（保留中文）"""
    return Response(
        json.dumps(obj, ensure_ascii=False),
        status=status,
        content_type="application/json; charset=utf-8",
    )


def _html_body(body, status=200):
    """返回 UTF-8 HTML 响应"""
    return Response(body, status=status, content_type="text/html; charset=utf-8")


def _rand():
    """线程安全随机数（0.0 <= x < 1.0）"""
    with _LOCK:
        return _RNG.random()


def _uniform(a, b):
    """线程安全均匀分布随机数"""
    with _LOCK:
        return _RNG.uniform(a, b)


def _randint(a, b):
    """线程安全整数随机数"""
    with _LOCK:
        return _RNG.randint(a, b)


def _normal_response(path):
    """基线响应：/ 返回若依登录页，其余路径返回普通 404"""
    if path == "/":
        return _html_body(_RUOYI_LOGIN_HTML)
    return _html_body(_SOFT_404_BASE, 404)


def _challenge_response():
    """Cloudflare 风格 JS 挑战：503 + cf-mitigated: challenge"""
    body = _JS_CHALLENGE_HTML.replace("__RAY__", "%016x" % _randint(0, 0xFFFFFFFFFFFFFFFF))
    resp = _html_body(body, 503)
    resp.headers["cf-mitigated"] = "challenge"
    resp.headers["cf-ray"] = "%016x-SJC" % _randint(0, 0xFFFFFFFFFFFFFFFF)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _flaky_response():
    """30% 概率返回 502/503，其余走基线响应"""
    if _rand() < 0.30:
        status = 502 if _rand() < 0.5 else 503
        return _html_body(_BAD_GATEWAY_HTML, status)
    return None


def _ratelimit_response():
    """全局请求计数：前 5 个放行，之后一律 429 + Retry-After: 30"""
    global _RATE_COUNT
    with _LOCK:
        _RATE_COUNT += 1
        n = _RATE_COUNT
    if n > 5:
        resp = Response("Too Many Requests", status=429, content_type="text/plain; charset=utf-8")
        resp.headers["Retry-After"] = "30"
        return resp
    return None


def _redirect_loop_response(path):
    """构造 / -> /a -> /b -> /a 的循环重定向"""
    if path == "/":
        location = "/a"
    elif path == "/a":
        location = "/b"
    elif path == "/b":
        location = "/a"
    else:
        return _html_body(_SOFT_404_BASE, 404)
    resp = Response("", status=302)
    resp.headers["Location"] = location
    return resp


def _gzip_chunked_response():
    """返回 Transfer-Encoding: chunked + gzip 的真实若依首页 HTML"""
    compressed = gzip.compress(_GZIP_HOME_HTML.encode("utf-8"), compresslevel=6)

    def _iter_chunks():
        # 小块输出，确保 WSGI 服务器使用 chunked 而不是一次性 Content-Length
        for i in range(0, len(compressed), 1024):
            yield compressed[i : i + 1024]

    resp = Response(_iter_chunks(), status=200, content_type="text/html; charset=utf-8")
    resp.headers["Content-Encoding"] = "gzip"
    # 不手动写 Transfer-Encoding：WSGI 服务器对无 Content-Length 的迭代响应自动使用 chunked
    resp.headers["Vary"] = "Accept-Encoding"
    return resp


def _bigbody_response():
    """返回 8–10 MB 的超大 HTML，用于大响应体抗压测试"""
    size = _randint(8 * 1024 * 1024, 10 * 1024 * 1024)
    head = '<!DOCTYPE html><html><head><title>RuoYi 若依</title></head><body><pre>'.encode("utf-8")
    tail = b"</pre></body></html>"
    filler_len = max(0, size - len(head) - len(tail))
    return Response(
        head + (b"A" * filler_len) + tail,
        status=200,
        content_type="text/html; charset=utf-8",
    )


def _reset_connection():
    """读取请求后直接关闭底层 socket；关闭失败时退回 abort(413)"""
    sock = request.environ.get("werkzeug.socket")
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
    abort(413)


@app.before_request
def _before():
    """记录请求到达时间 + stderr 访问日志"""
    g.start = time.time()
    print("[chaos:%s] -> %s %s" % (PROFILE, request.method, request.full_path), file=sys.stderr, flush=True)


@app.after_request
def _after(resp):
    """移除可能暴露框架的响应头并记录状态码（Server 头由 request_handler 统一覆盖）"""
    resp.headers.pop("X-Powered-By", None)
    elapsed = (time.time() - getattr(g, "start", time.time())) * 1000
    print(
        "[chaos:%s] <- %s %s %s (%.0fms)" % (PROFILE, request.method, request.path, resp.status_code, elapsed),
        file=sys.stderr,
        flush=True,
    )
    return resp


def dispatch(path):
    """按 profile 真实改变 HTTP 层行为；/__lab/health 永远豁免"""
    # 健康检查永远 200，且不计入限流 / flaky / 延迟等任何 profile 行为
    if path == "/__lab/health":
        return _json_body({"profile": PROFILE, "ok": True})

    if PROFILE == "slow":
        # 每个响应延迟 2–5 秒（health 已在上方豁免）
        time.sleep(_uniform(2.0, 5.0))
        return _normal_response(path)

    if PROFILE == "tarpit":
        # / 正常，其它路径挂起 30 秒后再返回 200
        if path != "/":
            time.sleep(30.0)
            return _html_body(_TARPIT_OK_HTML)
        return _normal_response(path)

    if PROFILE == "flaky":
        flaky = _flaky_response()
        return flaky if flaky is not None else _normal_response(path)

    if PROFILE == "ratelimit":
        limited = _ratelimit_response()
        return limited if limited is not None else _normal_response(path)

    if PROFILE == "js_challenge":
        return _challenge_response()

    if PROFILE == "soft404":
        # 已知根路径正常；所有未知路径 HTTP 200 + 普通 404 页面（软 404）
        if path == "/":
            return _normal_response(path)
        return _html_body(_SOFT_404_HTML, 200)

    if PROFILE == "block_all":
        # 空 body，仅保留 WAF 拦截头
        resp = Response(b"", status=403)
        resp.headers["X-WAF-Block"] = "1"
        resp.headers["X-WAF-Rule"] = "1001"
        resp.headers["X-WAF-Action"] = "deny"
        return resp

    if PROFILE == "redirect_loop":
        return _redirect_loop_response(path)

    if PROFILE == "gzip_chunked":
        if path == "/":
            return _gzip_chunked_response()
        return _html_body(_SOFT_404_BASE, 404)

    if PROFILE == "bigbody":
        if path == "/":
            return _bigbody_response()
        return _html_body(_SOFT_404_BASE, 404)

    if PROFILE == "reset":
        _reset_connection()
        return Response(b"", status=413)

    # normal：无干扰基线
    return _normal_response(path)


@app.route("/", defaults={"p": ""}, methods=["GET", "POST"])
@app.route("/<path:p>", methods=["GET", "POST"])
def _route(p):
    """Flask 统一入口：所有路径转交 dispatch"""
    return dispatch(request.path)


@app.errorhandler(404)
def _handle_404(_e):
    """兜底：特殊字符路径未命中路由时仍按 profile 处理"""
    return dispatch(request.path)


if __name__ == "__main__":
    print("[*] RuoYi Chaos Lab 启动：PROFILE=%s PORT=%s HOST=%s" % (PROFILE, PORT, HOST), file=sys.stderr)
    print("[*] 仅用于合法授权测试 / 教学验证；所有行为均为可控 HTTP 层干扰", file=sys.stderr)
    print("[!] 安全提示：请仅绑定本机回环，严禁部署到公网或未授权网络", file=sys.stderr)
    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        threaded=True,
        use_reloader=False,
        request_handler=_LabRequestHandler,
    )
