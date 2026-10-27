# Ruoyi 漏洞扫描器 —— 行为级若依仿真靶场（仅用于合法授权测试 / 教学验证）
#
# 与 lab/server.py（签名应答靶场）的根本差别：
#   1. 真实的会话 / 验证码 / 登录流程，未认证访问受保护接口一律返回 code=401；
#   2. 漏洞「条件成立才成立」——SQLi 只在载荷出现时报 XPATH，基线返回正常列表；
#   3. 响应具备真实 HTTP 层细节：nginx 404 / Server 头 / gzip / 20-80ms 抖动。
#
# 本服务不实现任何真实漏洞利用代码，所有「执行」仅记录在内存，供自测脚本断言。
#
# 运行示例：
#   LAB_PROFILE=vuln LAB_PORT=8090 python lab/realistic/server.py
#   LAB_PROFILE=safe LAB_PORT=8091 python lab/realistic/server.py
import base64
import gzip
import html
import io
import json
import os
import random
import secrets
import sys
import threading
import time

from flask import Flask, Response, g, request
from werkzeug.serving import WSGIRequestHandler

try:
    from PIL import Image, ImageDraw, ImageFont
except Exception:  # Pillow 是可选依赖：缺失时退回 1x1 PNG
    Image = None
    ImageDraw = None
    ImageFont = None

# 版本标识：扫描器会据此做版本感知过滤。4.7.8 视为存在 dataScope 注入/文件读取等
# 历史问题；4.8.0 视为已修复，仅用于检验「版本矩阵是否真的会筛插件」。
LAB_VERSION = os.environ.get("LAB_VERSION", "4.7.8").strip()
COPYRIGHT = "2018-2023" if LAB_VERSION.startswith("4.7") else "2018-2024"
PROFILE = os.environ.get("LAB_PROFILE", "vuln").strip().lower()
# 真实部署里常见「验证码被关闭 / 换成滑块」的变体：LAB_CAPTCHA=off 用来区分
# 「扫描器能力不足」与「验证码挡路」。关闭后仍下发验证码图片，但登录不校验。
CAPTCHA_REQUIRED = os.environ.get("LAB_CAPTCHA", "on").strip().lower() not in ("off", "0", "false", "no")
PORT = int(os.environ.get("LAB_PORT", "8090"))
HOST = os.environ.get("LAB_HOST", "127.0.0.1")

if PROFILE not in ("vuln", "safe"):
    print("[realistic] 非法 LAB_PROFILE=%r，可选值：vuln / safe" % PROFILE, file=sys.stderr, flush=True)
    raise SystemExit(2)

VULN = PROFILE == "vuln"

# static_folder=None：未知路径必须由我们的 nginx 风格 404 处理，不能落到 Flask 静态路由
app = Flask(__name__, static_folder=None)


class _LabRequestHandler(WSGIRequestHandler):
    """覆盖 Werkzeug 默认 Server 头，模拟 nginx 反代后的真实站点"""

    def version_string(self):
        return "nginx/1.24.0"


# ── 内存状态（线程安全）────────────────────────────────────────────────────
_SESSIONS = {}
_SESSION_LOCK = threading.Lock()

_JOB = {
    "jobId": 1,
    "jobName": "系统默认任务",
    "jobGroup": "DEFAULT",
    "invokeTarget": "ryTask.ryParams('ruoyi')",
    "cronExpression": "0/10 * * * * ?",
    "status": "0",
}
_JOB_LOCK = threading.Lock()

# vuln profile 下「已执行」的 invokeTarget 记录；safe profile 永远为空
_EXECUTED = []
_EXEC_LOCK = threading.Lock()

# /etc/passwd 特征内容（5 行真实格式）
_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
)

# 可执行扩展名：vuln 下允许上传，safe 下统一拒绝
_EXEC_EXTS = {
    "jsp",
    "jspx",
    "jspf",
    "jspa",
    "php",
    "php3",
    "php4",
    "php5",
    "phtml",
    "asp",
    "aspx",
    "asa",
    "cer",
    "war",
    "jar",
    "exe",
    "sh",
    "py",
}

# 1x1 PNG：Pillow 缺失或绘图失败时的降级图
_FALLBACK_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)

# ── 拟真页面 ────────────────────────────────────────────────────────────────

_LOGIN_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="renderer" content="webkit">
<title>RuoYi管理系统</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { height: 100%; }
body {
  font-family: "Helvetica Neue", Helvetica, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", Arial, sans-serif;
  background: linear-gradient(135deg, #14326e 0%, #1f4e9e 45%, #3a7bd5 100%);
  display: flex; align-items: center; justify-content: center;
  position: relative; overflow: hidden;
}
.deco { position: absolute; border-radius: 50%; background: rgba(255, 255, 255, .06); }
.deco.d1 { width: 420px; height: 420px; left: -140px; top: -120px; }
.deco.d2 { width: 300px; height: 300px; right: -80px; bottom: -60px; }
.deco.d3 { width: 160px; height: 160px; right: 18%; top: 12%; }
.login-card {
  width: 430px; background: #fff; border-radius: 8px;
  box-shadow: 0 14px 44px rgba(0, 21, 41, .35);
  padding: 34px 40px 24px; z-index: 2;
}
.logo-row { text-align: center; }
.logo {
  width: 52px; height: 52px; margin: 0 auto; border-radius: 10px;
  background: linear-gradient(135deg, #e6a23c, #f06431);
  color: #fff; font-size: 30px; font-weight: 700; line-height: 52px; text-align: center;
}
h3.title { text-align: center; color: #707070; font-size: 22px; margin: 14px 0 22px; font-weight: 600; }
.msg {
  display: none; margin-bottom: 14px; padding: 8px 12px;
  background: #fef0f0; color: #eb5757; border: 1px solid #fde2e2;
  border-radius: 4px; font-size: 13px;
}
.form-item { position: relative; margin-bottom: 16px; }
.form-item input {
  width: 100%; height: 42px; border: 1px solid #dcdfe6; border-radius: 4px;
  padding: 0 12px; font-size: 14px; color: #606266; outline: none; background: #fff;
}
.form-item input:focus { border-color: #409eff; }
.captcha-row { display: flex; gap: 10px; }
.captcha-row input { flex: 1; }
.captcha-row img {
  width: 112px; height: 42px; border: 1px solid #dcdfe6; border-radius: 4px;
  cursor: pointer; background: #f7f8fa; object-fit: cover;
}
.remember { display: flex; align-items: center; font-size: 14px; color: #606266; margin-bottom: 20px; user-select: none; }
.remember input { margin-right: 6px; }
.btn-login {
  width: 100%; height: 42px; border: none; border-radius: 4px; cursor: pointer;
  background: linear-gradient(90deg, #409eff, #2f7ce0); color: #fff;
  font-size: 15px; letter-spacing: 6px; text-indent: 6px;
}
.btn-login:disabled { opacity: .75; cursor: not-allowed; }
.tip { margin-top: 14px; text-align: center; font-size: 12px; color: #889aa4; line-height: 1.8; }
.copyright {
  position: fixed; left: 0; right: 0; bottom: 14px; z-index: 2;
  text-align: center; color: rgba(255, 255, 255, .65); font-size: 13px;
}
</style>
</head>
<body>
<div class="deco d1"></div><div class="deco d2"></div><div class="deco d3"></div>
<div class="login-card">
  <div class="logo-row"><div class="logo">若</div></div>
  <h3 class="title">若依后台管理系统</h3>
  <div class="msg" id="login-msg"></div>
  <form id="login-form" autocomplete="off">
    <input type="hidden" name="uuid" value="__UUID__">
    <div class="form-item">
      <input name="username" type="text" placeholder="账号" autocomplete="username">
    </div>
    <div class="form-item">
      <input name="password" type="password" placeholder="密码" autocomplete="current-password">
    </div>
    <div class="form-item captcha-row">
      <input name="code" type="text" placeholder="验证码" maxlength="4" autocomplete="off">
      <img id="captcha-img" src="/captcha/captchaImage" alt="验证码" title="点击刷新" onclick="refreshCaptcha()">
    </div>
    <label class="remember"><input type="checkbox" checked>记住密码</label>
    <button class="btn-login" id="btn-login" type="submit">登录</button>
  </form>
  <div class="tip">RuoYi __LAB_VERSION__ · Spring Boot 2.5.15<br>建议使用 Chrome / Edge 浏览器访问</div>
</div>
<div class="copyright">Copyright © 2018-2023 ruoyi.vip All Rights Reserved.</div>
<script>
function refreshCaptcha() {
  var img = document.getElementById('captcha-img');
  img.src = '/captcha/captchaImage?t=' + Date.now();
}
document.getElementById('login-form').addEventListener('submit', function (e) {
  e.preventDefault();
  var btn = document.getElementById('btn-login');
  var msg = document.getElementById('login-msg');
  btn.disabled = true; btn.textContent = '登录中...';
  msg.style.display = 'none';
  var body = new URLSearchParams(new FormData(e.target)).toString();
  fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d && d.code === 200) {
        location.href = '/index';
      } else {
        msg.textContent = (d && d.msg) ? d.msg : '登录失败，请重试';
        msg.style.display = 'block';
        refreshCaptcha();
      }
    })
    .catch(function () {
      msg.textContent = '网络异常，请稍后重试';
      msg.style.display = 'block';
      refreshCaptcha();
    })
    .finally(function () { btn.disabled = false; btn.textContent = '登录'; });
});
</script>
</body>
</html>
"""

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>RuoYi管理系统</title>
<style>
body { font-family: Arial, "Microsoft YaHei", sans-serif; background: #f0f2f4; margin: 0; }
.sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 200px; background: #304156; }
.sidebar .logo { height: 56px; line-height: 56px; text-align: center; color: #fff; font-size: 17px; font-weight: 700; background: #2b3a4d; }
.sidebar a { display: block; height: 46px; line-height: 46px; padding: 0 20px; color: #bfcbd9; font-size: 14px; text-decoration: none; }
.navbar { height: 56px; margin-left: 200px; background: #fff; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; color: #606266; font-size: 14px; }
.main { margin-left: 200px; padding: 22px; }
.panel { background: #fff; border-radius: 6px; padding: 22px; box-shadow: 0 1px 4px rgba(0, 21, 41, .06); }
h4 { color: #303133; font-size: 16px; margin: 0 0 12px; }
p { color: #606266; font-size: 14px; line-height: 1.9; }
</style>
</head>
<body>
<div class="sidebar"><div class="logo">RuoYi</div><a href="/index">首页</a><a href="/system/role">角色管理</a><a href="/monitor/job">定时任务</a><a href="/tool/gen">代码生成</a></div>
<div class="navbar"><span>☰ 首页</span><span>admin 超级管理员</span></div>
<div class="main"><div class="panel"><h4>欢迎使用 RuoYi 后台管理系统</h4><p>当前为行为级若依仿真靶场，登录会话已建立。</p></div></div>
<div style="text-align:center;color:#909399;font-size:13px;margin-top:24px">Copyright © 2018-2023 ruoyi.vip All Rights Reserved.</div>
</body>
</html>
"""

_DRUID_INDEX_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Druid Stat Index</title>
<style>
body { font-family: Arial, "Microsoft YaHei", sans-serif; background: #f5f7fa; margin: 0; }
.box { width: 360px; margin: 120px auto; background: #fff; border: 1px solid #dcdfe6; border-radius: 4px; padding: 28px; }
h3 { margin: 0 0 18px; color: #303133; }
input { width: 100%; height: 36px; margin-bottom: 12px; border: 1px solid #dcdfe6; border-radius: 4px; padding: 0 10px; }
button { width: 100%; height: 36px; border: 0; border-radius: 4px; background: #409eff; color: #fff; }
</style>
</head>
<body>
<div class="box">
  <h3>Druid Monitor</h3>
  <form method="post" action="/druid/submitLogin">
    <input name="loginUsername" placeholder="Username">
    <input name="loginPassword" type="password" placeholder="Password">
    <button type="submit">Sign in</button>
  </form>
</div>
</body>
</html>
"""

# ── 通用响应工具 ────────────────────────────────────────────────────────────


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


def _nginx_404_body():
    """真实 nginx 404 页面，填充到约 271 字节"""
    base = (
        "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
        "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
        "<hr><center>nginx/1.24.0</center>\r\n</body>\r\n</html>\r\n"
    )
    pad = 271 - len(base.encode("utf-8"))
    if pad > 7:
        base = base.replace("</body>", "<!--" + " " * (pad - 7) + "--></body>")
    return base


_NGINX_404 = _nginx_404_body()


def _nginx_404():
    """未知路径统一返回 nginx 风格 404"""
    return _html_body(_NGINX_404, 404)


# ── 会话 / 验证码 / 认证 ───────────────────────────────────────────────────


def _new_sid():
    """生成 JSESSIONID；刻意避开子串 49，保证 safe 响应体不出现 SSTI 回显特征"""
    while True:
        sid = secrets.token_hex(16).upper()
        if "49" not in sid:
            return sid


def _new_session():
    """创建服务端会话，返回 (sid, sess)"""
    sid = _new_sid()
    sess = {
        "authenticated": False,
        "username": None,
        "captcha": None,
        "perms": set(),
        "token": None,
        "created": time.time(),
    }
    with _SESSION_LOCK:
        _SESSIONS[sid] = sess
    return sid, sess


def _get_session(sid):
    """按 sid 读取会话；不存在返回 None"""
    if not sid:
        return None
    with _SESSION_LOCK:
        return _SESSIONS.get(sid)


def _ensure_session(sid):
    """读取已有会话，不存在则创建"""
    sess = _get_session(sid)
    if sess is not None:
        return sid, sess
    return _new_session()


def _set_session_cookie(resp, sid):
    """下发 JSESSIONID（HttpOnly，模拟 Java 容器会话）"""
    resp.set_cookie("JSESSIONID", sid, path="/", httponly=True, samesite="Lax")
    return resp


def _auth_session():
    """返回 (sid, sess)：优先 JSESSIONID，其次 Authorization: Bearer <token>"""
    sid = request.cookies.get("JSESSIONID")
    sess = _get_session(sid)
    if sess is not None and sess.get("authenticated"):
        return sid, sess
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if token:
            with _SESSION_LOCK:
                for sid2, sess2 in _SESSIONS.items():
                    if sess2.get("authenticated") and sess2.get("token") == token:
                        return sid2, sess2
    return None, None


def _require_auth():
    """受保护接口的统一鉴权门：失败返回若依风格 code=401（HTTP 200）"""
    sid, sess = _auth_session()
    if sess is None:
        return None, None, _json_body({"code": 401, "msg": "认证失败，无法访问系统资源"})
    return sid, sess, None


def _has_perm(sess, perm):
    """权限判断：admin 拥有 *:*:* 通配权限"""
    perms = sess.get("perms") or set()
    return "*:*:*" in perms or perm in perms


def _json_input():
    """读取 JSON body（非 dict 一律视为空）"""
    if not request.is_json:
        return {}
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def _param(name):
    """按 JSON -> form -> query 的顺序取参数"""
    body = _json_input()
    if name in body:
        return str(body.get(name) or "")
    return request.form.get(name) or request.args.get(name) or ""


def _data_scope_value():
    """读取 params[dataScope]（form / JSON 两种形态）"""
    body = _json_input()
    params = body.get("params")
    if isinstance(params, dict):
        return str(params.get("dataScope") or "")
    return request.form.get("params[dataScope]") or request.args.get("params[dataScope]") or ""


def _make_captcha_png(code):
    """用 Pillow 绘制 4 位数字验证码；失败时退回 1x1 PNG"""
    if Image is None:
        return _FALLBACK_PNG
    try:
        img = Image.new("RGB", (120, 40), (245, 247, 250))
        draw = ImageDraw.Draw(img)
        font = None
        for font_name in ("arial.ttf", "DejaVuSans.ttf", "simhei.ttf", "msyh.ttc"):
            try:
                font = ImageFont.truetype(font_name, 28)
                break
            except Exception:
                continue
        if font is None:
            font = ImageFont.load_default()
        for i, ch in enumerate(code):
            color = (random.randint(20, 120), random.randint(20, 120), random.randint(20, 120))
            draw.text((12 + i * 26, 4), ch, fill=color, font=font)
        for _ in range(6):
            draw.line(
                [
                    (random.randint(0, 119), random.randint(0, 39)),
                    (random.randint(0, 119), random.randint(0, 39)),
                ],
                fill=(random.randint(120, 220), random.randint(120, 220), random.randint(120, 220)),
                width=1,
            )
        for _ in range(60):
            draw.point(
                (random.randint(0, 119), random.randint(0, 39)),
                fill=(random.randint(120, 220), random.randint(120, 220), random.randint(120, 220)),
            )
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return _FALLBACK_PNG


def _make_favicon_png():
    """favicon.ico 资产缺失时生成 16x16 PNG（md5 与官方不一致）"""
    if Image is None:
        return _FALLBACK_PNG
    try:
        img = Image.new("RGB", (16, 16), (64, 158, 255))
        draw = ImageDraw.Draw(img)
        draw.rectangle([3, 3, 12, 12], fill=(255, 255, 255))
        draw.rectangle([6, 6, 9, 9], fill=(64, 158, 255))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return _FALLBACK_PNG


def _load_favicon():
    """优先加载与若依官方 md5 一致的 favicon.ico；缺失时退回生成图"""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "favicon.ico")
    try:
        with open(path, "rb") as f:
            return f.read(), "image/x-icon"
    except OSError:
        return _make_favicon_png(), "image/png"


_FAVICON_DATA, _FAVICON_MIME = _load_favicon()


# ── 业务端点 ────────────────────────────────────────────────────────────────


def _login_page():
    """GET / 与 GET /login：返回仿若依登录页，并下发/复用服务端会话"""
    sid, _sess = _ensure_session(request.cookies.get("JSESSIONID"))
    resp = _html_body(
        _LOGIN_HTML.replace("__UUID__", sid).replace("__LAB_VERSION__", LAB_VERSION).replace("__COPYRIGHT__", COPYRIGHT)
    )
    return _set_session_cookie(resp, sid)


def _captcha_image():
    """GET /captcha/captchaImage：默认 image/png，Accept/format=json 时返回 {code,img,uuid}"""
    sid, sess = _ensure_session(request.cookies.get("JSESSIONID"))
    code = "%04d" % random.randint(0, 9999)
    with _SESSION_LOCK:
        sess["captcha"] = code
    png = _make_captcha_png(code)
    accept = request.headers.get("Accept", "")
    want_json = (
        request.args.get("format") == "json"
        or "application/json" in accept
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )
    if want_json:
        img_b64 = base64.b64encode(png).decode("ascii")
        resp = _json_body({"code": 200, "msg": "操作成功", "img": img_b64, "uuid": sid})
    else:
        resp = Response(png, status=200, content_type="image/png")
    resp.headers["Cache-Control"] = "no-cache, no-store, max-age=0"
    return _set_session_cookie(resp, sid)


def _login_post():
    """POST /login：验证码 -> 账号密码 -> 标记会话已认证"""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    code = (request.form.get("code") or "").strip()
    uuid = (request.form.get("uuid") or "").strip()
    sid = uuid or request.cookies.get("JSESSIONID") or ""
    sess = _get_session(sid)
    if sess is None:
        return _json_body({"code": 500, "msg": "验证码错误"})
    with _SESSION_LOCK:
        expected = sess.get("captcha")
        sess["captcha"] = None
    if CAPTCHA_REQUIRED and (not code or not expected or code.lower() != str(expected).lower()):
        return _json_body({"code": 500, "msg": "验证码错误"})
    if username != "admin" or password != "admin123":
        return _json_body({"code": 500, "msg": "用户不存在/密码错误"})
    token = secrets.token_hex(16)
    with _SESSION_LOCK:
        sess["authenticated"] = True
        sess["username"] = "admin"
        sess["perms"] = {"*:*:*"}
        sess["token"] = token
    resp = _json_body({"code": 200, "msg": "操作成功", "token": token})
    return _set_session_cookie(resp, sid)


def _index_page():
    """GET /index：已登录返回后台首页，未登录 302 到登录页"""
    _sid, sess = _auth_session()
    if sess is None:
        resp = Response("", status=302)
        resp.headers["Location"] = "/login"
        return resp
    return _html_body(_DASHBOARD_HTML)


def _list_endpoint(path):
    """POST /system/role/list、/system/dept/list：条件成立的报错注入"""
    _sid, _sess, err = _require_auth()
    if err is not None:
        return err
    scope = _data_scope_value()
    low = scope.lower()
    if VULN and ("extractvalue" in low or "updatexml" in low):
        msg = (
            "### Error querying database.\n"
            "Cause: java.sql.SQLException: XPATH syntax error: '~ry~'\n"
            "### SQL: select ... from sys_role where data_scope = '" + scope + "'\n"
            "### Cause: java.sql.SQLException: XPATH syntax error: '~ry~'"
        )
        # 真实若依把业务异常包装成 HTTP 200 + code=500
        return _json_body({"code": 500, "msg": msg})
    if path == "/system/role/list":
        rows = [
            {"roleId": 1, "roleName": "超级管理员", "roleKey": "admin", "roleSort": 1, "status": "0"},
            {"roleId": 2, "roleName": "普通角色", "roleKey": "common", "roleSort": 2, "status": "0"},
        ]
    else:
        rows = [
            {"deptId": 100, "parentId": 0, "deptName": "若依科技", "orderNum": 0, "status": "0"},
            {"deptId": 101, "parentId": 100, "deptName": "深圳总公司", "orderNum": 1, "status": "0"},
        ]
    return _json_body({"code": 200, "msg": "查询成功", "total": len(rows), "rows": rows})


def _file_download():
    """GET /common/download/resource：vuln 下 ../ + /etc/passwd 或 2.txt 可读"""
    resource = request.args.get("resource", "")
    if VULN and "../" in resource and ("/etc/passwd" in resource or "2.txt" in resource):
        if "2.txt" in resource:
            return Response(
                "ruoyi scan test file 2.txt\n",
                status=200,
                content_type="text/plain; charset=utf-8",
            )
        return Response(_PASSWD, status=200, content_type="text/plain; charset=utf-8")
    return _json_body({"code": 400, "msg": "文件路径不合法"}, status=400)


def _file_upload():
    """POST /common/upload：vuln 下可执行扩展名通过，safe 下统一拒绝"""
    _sid, _sess, err = _require_auth()
    if err is not None:
        return err
    uploaded = request.files.get("file")
    if uploaded is None:
        return _json_body({"code": 500, "msg": "上传文件不能为空"})
    filename = uploaded.filename or ""
    ext = os.path.splitext(filename)[1].lower().lstrip(".")
    if not VULN or ext not in _EXEC_EXTS:
        return _json_body({"code": 500, "msg": "文件类型不允许"})
    new_name = secrets.token_hex(8) + "." + ext
    return _json_body(
        {
            "code": 0,
            "msg": "",
            "fileName": filename,
            "url": "/profile/upload/2026/10/27/" + new_name,
            "newFileName": new_name,
        }
    )


def _is_exec_payload(payload):
    """判断 invokeTarget 是否包含命令执行特征"""
    low = (payload or "").lower()
    return "getruntime().exec" in low or "new java.lang.processbuilder" in low


def _record_exec(payload, endpoint, authenticated):
    """记录一次「已执行」（仅内存，不产生真实副作用）"""
    with _EXEC_LOCK:
        _EXECUTED.append(
            {
                "endpoint": endpoint,
                "payload": payload,
                "authenticated": authenticated,
                "ts": time.time(),
            }
        )


def _job_edit():
    """GET|POST /monitor/job/edit：vuln 未认证也可写（历史越权点）"""
    _sid, sess = _auth_session()
    payload = _param("invokeTarget")
    status = _param("status")
    if VULN:
        with _JOB_LOCK:
            if payload:
                _JOB["invokeTarget"] = payload
            if status:
                _JOB["status"] = status
        if _is_exec_payload(payload):
            _record_exec(payload, "edit", sess is not None)
        return _json_body({"code": 200, "msg": "操作成功"})
    if sess is None:
        return _json_body({"code": 401, "msg": "认证失败，无法访问系统资源"})
    if not _has_perm(sess, "monitor:job:edit"):
        return _json_body({"code": 403, "msg": "权限不足"})
    if _is_exec_payload(payload):
        return _json_body({"code": 500, "msg": "调用目标字符串不在白名单内"})
    with _JOB_LOCK:
        if payload:
            _JOB["invokeTarget"] = payload
        if status:
            _JOB["status"] = status
    return _json_body({"code": 200, "msg": "操作成功"})


def _job_run():
    """GET|POST /monitor/job/run：vuln 未认证也可触发（历史越权点）"""
    _sid, sess = _auth_session()
    payload = _param("invokeTarget")
    with _JOB_LOCK:
        stored = _JOB.get("invokeTarget", "")
    target = payload or stored
    if VULN:
        if _is_exec_payload(target):
            _record_exec(target, "run", sess is not None)
        return _json_body({"code": 200, "msg": "操作成功"})
    if sess is None:
        return _json_body({"code": 401, "msg": "认证失败，无法访问系统资源"})
    if not _has_perm(sess, "monitor:job:edit"):
        return _json_body({"code": 403, "msg": "权限不足"})
    return _json_body({"code": 200, "msg": "操作成功"})


def _job_list():
    """POST /monitor/job/list：需登录"""
    _sid, _sess, err = _require_auth()
    if err is not None:
        return err
    with _JOB_LOCK:
        row = dict(_JOB)
    return _json_body({"code": 200, "msg": "查询成功", "rows": [row], "total": 1})


def _gen_edit():
    """GET|POST /tool/gen/edit：vuln 下模板表达式回显 49，safe 下原样转义"""
    _sid, _sess, err = _require_auth()
    if err is not None:
        return err
    payload = _param("template") or _param("content")
    low = payload.lower()
    triggered = "${7*7}" in payload or "t(java.lang.runtime)" in low
    if VULN:
        if triggered:
            return _json_body(
                {"code": 500, "msg": "模板渲染异常：49", "template": payload},
                status=500,
            )
        return _json_body({"code": 200, "msg": "操作成功"})
    if triggered:
        return _json_body({"code": 200, "msg": "操作成功", "template": html.escape(payload)})
    return _json_body({"code": 200, "msg": "操作成功"})


def _druid_index():
    """GET /druid/index.html：vuln 暴露 Druid 控制台，safe 302 到登录"""
    if VULN:
        return _html_body(_DRUID_INDEX_HTML)
    resp = Response("", status=302)
    resp.headers["Location"] = "/login"
    return resp


def _druid_websession():
    """GET /druid/websession.json：vuln 未认证可读会话列表，safe 401"""
    if VULN:
        return _json_body(
            {
                "ResultCode": 200,
                "Content": {
                    "SessionList": [
                        {
                            "SESSIONID": secrets.token_hex(16).upper(),
                            "Principal": "admin",
                            "RemoteAddr": "127.0.0.1",
                            "UserAgent": "Mozilla/5.0",
                        },
                        {
                            "SESSIONID": secrets.token_hex(16).upper(),
                            "Principal": "ruoyi",
                            "RemoteAddr": "127.0.0.1",
                            "UserAgent": "curl/8.0",
                        },
                    ]
                },
            }
        )
    return _json_body({"code": 401, "msg": "认证失败，无法访问系统资源"}, status=401)


def _nacos_configs():
    """GET /nacos/v1/cs/configs?dataId=&group=：vuln 配置泄露，safe 403

    真实 Nacos 对该接口返回的是配置**正文**（text/plain），不是 JSON 信封；
    早期靶场用 JSON 包裹 content，会让只认 JSON 的判定看起来「正常」。
    """
    if VULN:
        content = (
            "spring:\n"
            "  datasource:\n"
            "    url: jdbc:mysql://127.0.0.1:3306/ry?useUnicode=true\n"
            "    username: root\n"
            "    password: Ruoyi@2024\n"
        )
        resp = Response(content, status=200, content_type="text/plain;charset=UTF-8")
        return resp
    return _json_body({"code": 403, "msg": "Forbidden"}, status=403)


def _lab_session():
    """测试钩子：返回当前会话的认证状态与验证码（供 selftest 使用）"""
    sid = request.cookies.get("JSESSIONID")
    sess = _get_session(sid)
    if sess is None:
        return _json_body({"ok": False, "error": "no session"}, status=404)
    with _SESSION_LOCK:
        data = {
            "ok": True,
            "profile": PROFILE,
            "session": sid,
            "authenticated": bool(sess.get("authenticated")),
            "captcha": sess.get("captcha"),
        }
    return _json_body(data)


def _lab_executed():
    """测试钩子：返回 vuln 下记录的 invokeTarget「已执行」列表"""
    with _EXEC_LOCK:
        items = list(_EXECUTED)
    return _json_body({"profile": PROFILE, "count": len(items), "executed": items})


# ── 分发与 HTTP 细节 ────────────────────────────────────────────────────────


def dispatch(path, method):
    """统一分发：先处理测试钩子与静态资源，再按若依交互路径分流"""
    if path == "/__lab/health":
        return _json_body({"profile": PROFILE, "ok": True})
    if path == "/__lab/session":
        return _lab_session()
    if path == "/__lab/executed":
        return _lab_executed()

    if path == "/favicon.ico":
        resp = Response(_FAVICON_DATA, status=200, content_type=_FAVICON_MIME)
        resp.headers["Cache-Control"] = "public, max-age=86400"
        return resp

    if path == "/":
        return _nginx_404() if method == "POST" else _login_page()
    if path == "/login":
        return _login_post() if method == "POST" else _login_page()
    if path == "/index":
        return _index_page()
    if path == "/captcha/captchaImage":
        return _captcha_image()

    if path in ("/system/role/list", "/system/dept/list"):
        return _list_endpoint(path)
    if path == "/common/download/resource":
        return _file_download()
    if path == "/common/upload":
        return _file_upload()
    if path == "/monitor/job/list":
        return _job_list()
    if path == "/monitor/job/edit":
        return _job_edit()
    if path == "/monitor/job/run":
        return _job_run()
    if path == "/tool/gen/edit":
        return _gen_edit()

    if path == "/druid/index.html":
        return _druid_index()
    if path == "/druid/websession.json":
        return _druid_websession()
    if path == "/nacos/v1/cs/configs":
        return _nacos_configs()

    return _nginx_404()


@app.before_request
def _before():
    """记录开始时间；非 health 请求加入 20-80ms 随机网络抖动"""
    g.start = time.time()
    if request.path != "/__lab/health":
        time.sleep(random.uniform(0.02, 0.08))


@app.after_request
def _after(resp):
    """移除 X-Powered-By / 对 >1KB HTML 做 gzip / 访问日志（Server 头由 request_handler 覆盖）"""
    resp.headers.pop("X-Powered-By", None)
    try:
        accept_encoding = request.headers.get("Accept-Encoding", "").lower()
        if (
            resp.mimetype == "text/html"
            and resp.status_code == 200
            and "gzip" in accept_encoding
            and not resp.headers.get("Content-Encoding")
        ):
            data = resp.get_data()
            if len(data) > 1024:
                resp.set_data(gzip.compress(data))
                resp.headers["Content-Encoding"] = "gzip"
                resp.headers["Vary"] = "Accept-Encoding"
    except Exception:
        # 压缩失败不影响主流程（例如流式响应不可读取）
        pass
    elapsed = (time.time() - getattr(g, "start", time.time())) * 1000
    print(
        "[lab-%s] %s %s -> %s (%.0fms)" % (PROFILE, request.method, request.path, resp.status_code, elapsed),
        file=sys.stderr,
        flush=True,
    )
    return resp


@app.route("/", defaults={"p": ""}, methods=["GET", "POST"])
@app.route("/<path:p>", methods=["GET", "POST"])
def _route(p):
    """Flask 统一入口"""
    return dispatch(request.path, request.method)


@app.errorhandler(404)
def _handle_404(_e):
    """兜底：特殊字符路径未命中路由时返回 nginx 404"""
    return _nginx_404()


if __name__ == "__main__":
    print("[*] RuoYi 行为级仿真靶场启动：PROFILE=%s PORT=%s HOST=%s" % (PROFILE, PORT, HOST), file=sys.stderr)
    print("[*] vuln=漏洞语义 / safe=已修复语义；所有「执行」仅记录在内存", file=sys.stderr)
    print("[!] 安全提示：请仅绑定本机回环，严禁部署到公网或未授权网络", file=sys.stderr)
    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        threaded=True,
        use_reloader=False,
        request_handler=_LabRequestHandler,
    )
