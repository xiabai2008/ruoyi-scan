# Ruoyi 漏洞扫描器 —— 本地签名靶场（仅用于合法授权测试 / 教学验证）
#
# 设计目标：精确复现 13 个插件命中时的「请求路径 + 响应特征」，
# 使扫描器可在无真实目标的情况下完成判定逻辑对拍（vuln/safe 双模式）。
#
# 本服务不实现任何真实漏洞利用，仅返回与插件判定规则匹配的响应签名，
# 用于验证扫描器「匹配逻辑」是否正确，不属于真实攻击环境。
import json
import os
import time

from flask import Flask, Response, request

# 运行模式：vuln（开启全部漏洞签名）/ safe（全部已修复）
MODE = os.environ.get("LAB_MODE", "vuln")
PORT = int(os.environ.get("LAB_PORT", "8080"))
# 安全收口：默认仅绑定本机回环，避免带洞靶场暴露到局域网；Docker 内通过 LAB_HOST=0.0.0.0 覆盖
HOST = os.environ.get("LAB_HOST", "127.0.0.1")

app = Flask(__name__)

# /etc/passwd 特征内容（file_read / file_read_time 判定要求同时含 'root' 与 ':/'）
PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "bin:x:1:1:bin:/bin:/sbin/nologin\n"
    "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/sbin/nologin\n"
)

# Druid 爆破：与扫描器 settings.DRUID_USERS 对齐的 6 个用户名
DRUID_USERS = {"ruoyi", "druid", "admin", "admin123", "auth", "123456"}
# 命中即返回 success 的弱口令集合（均存在于 password.txt 字典中）
DRUID_OK_PASSWORDS = {"ruoyi", "123456", "admin123", "druid"}

# /monitor/job 的有状态存储：job_invoke_target 插件的判定流程是
# 「读列表 → 写 edit → 回读确认写入生效 → 还原 → 二次确认」，
# 靶场必须跨请求记住 invokeTarget/status，回读才能反映写入结果（模拟服务端持久化）
_JOB_STORE = {"invokeTarget": "ryTask.ryParams('ruoyi')", "status": "0"}

# Step 8 POC 签名 marker 已于 D4 改造（2026-07-18）删除：
# nacos_unauth / file_read_path 改为真实响应特征判定，不再依赖魔法常量

# ── 拟真前端页面（2026-10 新增）────────────────────────────────────────────
# 目标：让靶场在浏览器里呈现真实若依（RuoYi-Vue）观感，便于教学演示与人工访问。
# 约束：以下模板为纯内联 CSS/JS（离线可用），且不得破坏插件判定签名——
#   1. <title>RuoYi管理系统</title> 必须保留（目录扫描标题展示 + 指纹强特征）；
#   2. 页面内保留 "RuoYi" 关键字（login_keywords 强特征命中依据）；
#   3. 登录请求仍走 POST /login JSON 签名（AuthChain 依赖 GET /login 返回 JSON，
#      前端 JS 仅在浏览器侧发起，不影响扫描器观测）；
#   4. 所有漏洞端点（/actuator/env、/druid/index.html 等）的响应体零改动；
#   5. 模板内不落任何凭据字面量：演示提示语由环境变量 LAB_DEMO_CRED 注入，
#      表单字段值统一经 FormData 收集，避免源码出现疑似凭据赋值文本；
#   6. 页面文本不得含 WAF 裸子串关键词——实测教训：CSS 色值 #f59a23 因含 "f5"
#      被判为 F5 BIG-IP ASM，扫描器进入绕过模式导致判定集合漂移（2026-10-01）；
#   7. 版权年份结束年不得落在 core/ruoyi_versions.py 的 COPYRIGHT_YEAR_TO_VERSION
#      收录区间（2021~2026），否则被版权启发式推断为具体若依版本，触发 POC
#      版本过滤、同样改变判定集合（用未收录年份，如 2018-2020）。

_LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
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
  width: 420px; background: #fff; border-radius: 8px;
  box-shadow: 0 14px 44px rgba(0, 21, 41, .35);
  padding: 36px 40px 26px; z-index: 2;
}
.logo-row { text-align: center; }
.logo {
  width: 52px; height: 52px; margin: 0 auto; border-radius: 10px;
  background: linear-gradient(135deg, #e6a23c, #f06431);
  color: #fff; font-size: 30px; font-weight: 700; line-height: 52px; text-align: center;
}
h3.title { text-align: center; color: #707070; font-size: 22px; margin: 14px 0 26px; font-weight: 600; }
.msg {
  display: none; margin-bottom: 14px; padding: 8px 12px;
  background: #fef0f0; color: #eb5757; border: 1px solid #fde2e2;
  border-radius: 4px; font-size: 13px;
}
.form-item { position: relative; margin-bottom: 18px; }
.form-item svg { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); }
.form-item input {
  width: 100%; height: 42px; border: 1px solid #dcdfe6; border-radius: 4px;
  padding: 0 12px 0 34px; font-size: 14px; color: #606266; outline: none; background: #fff;
}
.form-item input:focus { border-color: #409eff; }
.remember { display: flex; align-items: center; font-size: 14px; color: #606266; margin-bottom: 20px; user-select: none; }
.remember input { margin-right: 6px; }
.btn-login {
  width: 100%; height: 42px; border: none; border-radius: 4px; cursor: pointer;
  background: linear-gradient(90deg, #409eff, #2f7ce0); color: #fff;
  font-size: 15px; letter-spacing: 6px; text-indent: 6px;
}
.btn-login:disabled { opacity: .75; cursor: not-allowed; }
.tip { margin-top: 16px; text-align: center; font-size: 13px; color: #889aa4; }
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
    <div class="form-item">
      <svg width="14" height="14" viewBox="0 0 1024 1024" fill="#a8abb2"><path d="M512 512a192 192 0 1 0 0-384 192 192 0 0 0 0 384z m0 64c-176 0-320 96-320 213.3V832h640v-42.7C832 672 688 576 512 576z"/></svg>
      <input name="username" type="text" placeholder="账号">
    </div>
    <div class="form-item">
      <svg width="14" height="14" viewBox="0 0 1024 1024" fill="#a8abb2"><path d="M736 416H704V320a192 192 0 1 0-384 0v96h-32a64 64 0 0 0-64 64v384a64 64 0 0 0 64 64h448a64 64 0 0 0 64-64V480a64 64 0 0 0-64-64z m-352-96a128 128 0 1 1 256 0v96H384V320z"/></svg>
      <input name="password" type="password" placeholder="密码">
    </div>
    <label class="remember"><input type="checkbox" checked>记住密码</label>
    <button class="btn-login" id="btn-login" type="submit">登录</button>
  </form>
  <div class="tip">__DEMO_TIP__</div>
</div>
<div class="copyright">Copyright © 2018-2020 ruoyi.vip All Rights Reserved. | RuoYi 签名靶场</div>
<script>
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
      if (d && d.code === 200 && d.token) {
        try { sessionStorage.setItem('Admin-Token', d.token); } catch (err) {}
        location.href = '/index';
      } else {
        msg.textContent = (d && d.msg) ? d.msg : '登录失败，请重试';
        msg.style.display = 'block';
      }
    })
    .catch(function () { msg.textContent = '网络异常，请稍后重试'; msg.style.display = 'block'; })
    .finally(function () { btn.disabled = false; btn.textContent = '登录'; });
});
</script>
</body>
</html>
"""

_INDEX_PAGE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RuoYi管理系统</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: "Helvetica Neue", Helvetica, "PingFang SC", "Microsoft YaHei", Arial, sans-serif; background: #f0f2f4; }
.sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 200px; background: #304156; overflow: hidden; }
.sidebar .logo { height: 56px; line-height: 56px; text-align: center; color: #fff; font-size: 17px; font-weight: 700; letter-spacing: 3px; background: #2b3a4d; }
.sidebar a { display: block; height: 46px; line-height: 46px; padding: 0 20px; color: #bfcbd9; font-size: 14px; text-decoration: none; cursor: pointer; }
.sidebar a:hover { background: #263445; }
.sidebar a.active { color: #409eff; background: #263445; }
.sidebar a span.ico { display: inline-block; width: 22px; }
.navbar {
  height: 56px; margin-left: 200px; background: #fff;
  box-shadow: 0 1px 4px rgba(0, 21, 41, .08);
  display: flex; align-items: center; justify-content: space-between; padding: 0 20px;
}
.breadcrumb { color: #606266; font-size: 14px; }
.user-box { color: #606266; font-size: 14px; }
.user-box a { color: #409eff; text-decoration: none; margin-left: 10px; }
.main { margin-left: 200px; padding: 22px; }
.cards { display: flex; gap: 16px; margin-bottom: 18px; }
.card {
  flex: 1; background: #fff; border-radius: 6px; padding: 20px;
  box-shadow: 0 1px 4px rgba(0, 21, 41, .06);
}
.card .num { font-size: 26px; font-weight: 700; color: #303133; }
.card .label { font-size: 13px; color: #909399; margin-top: 6px; }
.panel { background: #fff; border-radius: 6px; padding: 22px; box-shadow: 0 1px 4px rgba(0, 21, 41, .06); }
.panel h4 { color: #303133; font-size: 16px; margin-bottom: 12px; }
.panel p { color: #606266; font-size: 14px; line-height: 1.9; }
.mode-badge {
  display: inline-block; padding: 1px 10px; border-radius: 10px; font-size: 12px;
  color: #fff; background: #eb5757; margin: 0 2px; vertical-align: 1px;
}
.mode-badge.safe { background: #67c23a; }
table.info { border-collapse: collapse; margin-top: 14px; width: 100%; }
table.info td { border: 1px solid #ebeef4; padding: 8px 14px; font-size: 13px; color: #606266; }
table.info td:first-child { background: #fafafa; width: 180px; color: #909399; }
</style>
</head>
<body>
<div class="sidebar">
  <div class="logo">RuoYi</div>
  <a class="active"><span class="ico">▤</span>首页</a>
  <a><span class="ico">⚙</span>系统管理</a>
  <a><span class="ico">▦</span>系统监控</a>
  <a><span class="ico">⚒</span>系统工具</a>
  <a><span class="ico">✎</span>表单构建</a>
</div>
<div class="navbar">
  <div class="breadcrumb">☰　首页</div>
  <div class="user-box">admin 超级管理员<a href="/">退出登录</a></div>
</div>
<div class="main">
  <div class="cards">
    <div class="card"><div class="num">2</div><div class="label">用户总数</div></div>
    <div class="card"><div class="num">1</div><div class="label">角色总数</div></div>
    <div class="card"><div class="num">20</div><div class="label">菜单总数</div></div>
    <div class="card"><div class="num">1</div><div class="label">当前在线</div></div>
  </div>
  <div class="panel">
    <h4>欢迎使用 RuoYi 后台管理系统</h4>
    <p>当前站点为 RuoYi 本地签名靶场（<span class="mode-badge__MODE_CLASS__" id="mode-badge">__LAB_MODE__</span> 模式），仅用于漏洞扫描器对拍与教学演示；所有响应均为模拟签名，不含真实漏洞利用代码。</p>
    <table class="info">
      <tr><td>框架版本</td><td>RuoYi 4.8.0（Spring Boot 2.5.15）</td></tr>
      <tr><td>运行环境</td><td>JDK 1.8.0_311 / MySQL 8.0.33 / Redis 6.2.6</td></tr>
      <tr><td>服务地址</td><td>__LAB_ADDR__（仅本机回环，禁止暴露公网）</td></tr>
    </table>
  </div>
</div>
<script>
// 未携带登录 token 时回到登录页（浏览器侧行为，不影响扫描器观测）
try { if (!sessionStorage.getItem('Admin-Token')) { location.replace('/'); } } catch (e) {}
</script>
</body>
</html>
"""


def _render_login_page():
    """渲染登录页：演示提示语由环境变量 LAB_DEMO_CRED 注入，源码不落凭据字面量"""
    demo = os.environ.get("LAB_DEMO_CRED", "").strip()
    tip = ("演示环境账号：" + demo) if demo else "账号密码由部署者在启动环境时指定"
    return _LOGIN_PAGE_HTML.replace("__DEMO_TIP__", tip)


def _render_index_page(vuln):
    """渲染后台首页：展示当前靶场模式（vuln 红 / safe 绿），便于演示时区分"""
    mode_txt = "vuln · 漏洞演示" if vuln else "safe · 已修复"
    mode_cls = "" if vuln else " safe"
    return _INDEX_PAGE_HTML.replace("__LAB_MODE__", mode_txt).replace("__MODE_CLASS__", mode_cls).replace(
        "__LAB_ADDR__", "http://" + request.host
    )


def whitelabel_404():
    """Spring Boot 风格 Whitelabel 错误页（404）：与真实若依（Spring Boot 内嵌容器）一致

    注意保留 "Whitelabel Error Page" 原文——真实站点即返回该文本，
    扫描器组件探测（lib/component_detect.py）据此识别 Spring Boot 属预期行为。
    """
    body = (
        "<html><body><h1>Whitelabel Error Page</h1>"
        "<p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>"
        f"<div id='created'>{time.strftime('%a %b %d %H:%M:%S %Y')}</div>"
        "<div>There was an unexpected error (type=Not Found, status=404).</div></body></html>"
    )
    return html_body(body, 404)


def is_vuln():
    """判断当前运行模式是否为漏洞签名模式

    @return True=vuln（返回带洞签名）/ False=safe（全部已修复）
    """
    return MODE == "vuln"


def json_body(d, code=200):
    """构造 JSON 响应：字典序列化为 UTF-8 JSON（ensure_ascii=False 保留中文）

    @param d: 响应字典
    @param code: HTTP 状态码，默认 200
    @return Flask Response（application/json; charset=utf-8）
    """
    return Response(json.dumps(d, ensure_ascii=False), status=code, mimetype="application/json; charset=utf-8")


def html_body(body, code=200):
    """构造 HTML 文本响应（UTF-8 编码）

    @param body: HTML 字符串
    @param code: HTTP 状态码，默认 200
    @return Flask Response（text/html; charset=utf-8）
    """
    return Response(body, status=code, mimetype="text/html; charset=utf-8")


def dispatch(path, method):
    """统一分发：按 (路径, 方法) 返回与插件判定规则匹配的响应签名"""
    vuln = is_vuln()

    # 根路径 + 登录页：含 RuoYi 标题 → 指纹识别强特征命中
    # （2026-10 拟真化：完整 RuoYi-Vue 风格登录页，标题与关键字签名保持不变）
    if path == "/":
        return html_body(_render_login_page())

    # 任意文件读取（file_read + file_read_time 读取落地文件 2.txt）
    # Step 8 新增 file_read_path：resource 参数以 ../ 开头（相对路径穿越探针）
    #   按 resource 查询参数分流：../ 前缀 → 路径穿越签名；其余 → 原 /etc/passwd 特征
    #   注意：query 参数不影响 request.path 路径匹配，需在端点内读取 request.args 区分
    if path == "/common/download/resource":
        if vuln:
            resource = request.args.get("resource", "")
            if resource.startswith("../"):
                # D4 改造：file_read_path 探针返回真实 /etc/passwd 内容（含 root + 系统账户）
                return Response(PASSWD, mimetype="text/plain; charset=utf-8")
            # file_read / file_read_time 探针：返回含 root 与 :/ 的 /etc/passwd 特征
            return Response(PASSWD, mimetype="text/plain; charset=utf-8")
        return whitelabel_404()

    # 定时任务 list / edit / run（job_rce + file_read_time + job_invoke_target）
    if path == "/monitor/job/list":
        if vuln:
            # job_invoke_target 的判定依赖「写入后回读可见」，故回传有状态存储
            rows = [
                {
                    "jobId": 1,
                    "jobName": "系统默认备份任务",
                    "jobGroup": "DEFAULT",
                    "invokeTarget": _JOB_STORE["invokeTarget"],
                    "cronExpression": "0/10 * * * * ?",
                    "status": _JOB_STORE["status"],
                }
            ]
            return json_body({"code": 200, "rows": rows, "total": len(rows)})
        return json_body({"code": 401, "msg": "请先登录"}, 401)
    if path == "/monitor/job/edit":
        if vuln:
            # 已登录会话（isolated_auth_session 登录后带 Bearer token）：接受写入并记录。
            # job_invoke_target 的判据是「载荷被接受且回读可见」——白名单缺失即漏洞本身。
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer ") and auth[7:]:
                _JOB_STORE["invokeTarget"] = request.form.get("invokeTarget", _JOB_STORE["invokeTarget"])
                _JOB_STORE["status"] = request.form.get("status", _JOB_STORE["status"])
                return json_body({"code": 200, "msg": "操作成功"})
            # 未授权进入业务层：code=500 业务校验失败，证明绕过鉴权（job_rce 判定依据，保持不变）
            return json_body({"code": 500, "msg": "定时任务不存在"})
        return json_body({"code": 401, "msg": "请先登录"}, 401)
    if path == "/monitor/job/run":
        if vuln:
            return json_body({"code": 200, "msg": "操作成功"})
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    # SQL 报错注入（role / dept）
    if path in ("/system/role/list", "/system/dept/list"):
        if vuln:
            # 忠实模拟真实行为（lab/REAL-RUOYI.md 对照组记录）：extractvalue 仅在
            # dataScope 载荷非空时被求值，空载荷返回正常列表。SQLi 插件的差分判定
            # （强特征「注入后出现、基线不出现」）依赖这一区分——旧实现对任意请求都
            # 回错误页，会让正确的反误报逻辑在靶场上恒为 UNKNOWN。
            if (request.form.get("params[dataScope]") or "").strip():
                # 含 '运行时异常' 与 'database()' 双重特征 → 命中
                body = (
                    "<!doctype html><html><body><h1>HTTP Status 500 - "
                    "请求处理失败</h1><pre>java.sql.SQLException: "
                    "XPATH syntax error: '~database()~', 运行时异常</pre>"
                    "</body></html>"
                )
                return html_body(body, 500)
            return json_body({"code": 200, "msg": "操作成功", "rows": [], "total": 0})
        return json_body({"code": 200, "msg": "操作成功", "rows": [], "total": 0})

    # Druid 弱口令爆破
    if path == "/druid/submitLogin":
        user = request.form.get("loginUsername", "")
        pwd = request.form.get("loginPassword", "")
        # 口令必须命中弱口令子集才放行：避免把字典之外的随机口令误判为"登录成功"（safe 模式同理不漏判）
        if vuln and user in DRUID_USERS and pwd in DRUID_OK_PASSWORDS:
            return json_body({"success": True, "message": "登录成功"})
        # safe 模式：失败响应不含 'success' 关键字，避免子串误判
        return json_body({"code": 0, "message": "用户名或密码错误"})

    # 任意文件上传（/common/upload）
    if path == "/common/upload":
        if vuln:
            return json_body(
                {
                    "code": 200,
                    "fileName": "ruoyi_scan_probe.txt",
                    "url": "/profile/upload/2026/07/ruoyi_scan_probe.txt",
                    "newFileName": "ruoyi_scan_probe_20260717.txt",
                }
            )
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    # 后台默认口令（/login）
    # D3 新增：验证码接口（/captcha/captchaImage）
    # vuln 模式返回 captchaEnabled=false（模拟关闭验证码，CI 无 OCR 依赖也能登录）
    # safe 模式返回 404
    if path == "/captcha/captchaImage":
        if vuln:
            return json_body({"code": 200, "captchaEnabled": False, "msg": "操作成功"})
        return whitelabel_404()

    # D3：safe 模式 /login 改为返回密码错误（模拟真实若依验证码校验）
    # vuln 模式 /login 仍返回 code=200（无验证码，供登录链测试）
    if path == "/login":
        if method == "POST":
            if vuln:
                # vuln 模式：检查 validateCode，空则通过（模拟无验证码或验证码正确）
                return json_body({"code": 200, "msg": "操作成功", "token": "eyJhbGciOiJIUzI1NiJ9.ruoyi-lab-signature"})
            # safe 模式：返回密码错误（模拟登录失败，不校验验证码）
            return json_body({"code": 500, "msg": "用户或密码错误"})
        # GET /login 返回 JSON（v5 前后端分离形态）：AuthChain.detect_auth_mode 依此
        # 判定为 v5 JWT，登录后才会以 Authorization: Bearer 携带 token。若返回 HTML
        # 会被判为 v4 Session（依赖 Cookie），而本靶场 /login 从不 Set-Cookie，
        # 隔离会话将永远不带凭证——CVE-2025-46174 / job_invoke_target 的已登录判定
        # 全部退化为未认证请求（实测踩到）。
        return json_body({"code": 401, "msg": "请先登录"})

    # 未授权访问批量端点
    if path == "/actuator/env":
        if vuln:
            return json_body(
                {"propertySources": [{"name": "applicationConfig"}], "activeProfiles": [], "environment": "dev"}
            )
        return json_body({"code": 401, "msg": "请先登录"}, 401)
    if path == "/druid/index.html":
        if vuln:
            return html_body("<html><body><h1>Druid Monitor</h1><p>Druid Stat Index</p></body></html>")
        return json_body({"code": 401, "msg": "请先登录"}, 401)
    if path == "/swagger-ui.html":
        if vuln:
            return html_body("<html><body><h1>swagger 接口文档</h1><p>swagger-ui</p></body></html>")
        return json_body({"code": 401, "msg": "请先登录"}, 401)
    if path == "/system/user/list":
        if vuln:
            # 已登录低权账号：数据范围受限，仅可见自身——CVE-2025-46174 用它建立
            # 「可见用户集合」对照基线（不可见 userId=1 却能渲染其重置密码页 ⇒ 越权）
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer ") and auth[7:]:
                return json_body({"code": 200, "rows": [{"userId": 2, "userName": "scanner_low"}], "total": 1})
            # 未授权可读：用户列表未鉴权（unauth_batch 判定依据，保持不变）
            return json_body({"code": 200, "rows": [{"userId": 1, "userName": "admin"}], "total": 1})
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    # CVE-2025-46174：重置密码页缺数据权限校验（GET /system/user/resetPwd/{userId}）
    if path.startswith("/system/user/resetPwd/"):
        if vuln:
            # 漏洞版（<=4.8.0）：只做 selectUserById，无 checkUserDataScope，
            # 任意 userId 均渲染重置密码页（含目标登录名输入框）
            return html_body(
                '<!doctype html><html><body><form id="form-user-resetPwd">'
                '<input name="userId" value="1"/>'
                '<input name="loginName" value="admin"/>'
                "</form></body></html>"
            )
        # 修复版：checkUserDataScope 抛 ServiceException（文本与插件 PERM_DENIED_MARKER 对齐）
        return html_body("<!doctype html><html><body>没有权限访问用户数据</body></html>", 500)

    # Step 8 新增：Nacos 未授权访问（/nacos/v1/auth/users）
    # query 参数（pageNo/pageSize）不影响 request.path 匹配，无需在端点内读取
    if path == "/nacos/v1/auth/users":
        if vuln:
            # D4 改造：返回真实风格 Nacos 用户列表 JSON（含分页字段 + 多个真实账户）
            # 真实 Nacos 未授权响应结构：totalCount + pageNumber + pageSize + pageItems[]
            # pageItems 每项含 username + password（bcrypt 哈希 $2a$10$...）
            return json_body(
                {
                    "totalCount": 2,
                    "pageNumber": 1,
                    "pageSize": 10,
                    "pageItems": [
                        {
                            "username": "nacos",
                            "password": "$2a$10$EuWPZHzz32dJN7jexM34MOeYirDdFAZm2kuWj7VEOthhhKtQk5zWm",
                        },
                        {
                            "username": "admin",
                            "password": "$2a$10$7Jz9mY8uVQ5t2q3vG1vNkOe8LQf3u8z1Vq8Z3aXb5c9d4e6f7g8h9",
                        },
                    ],
                }
            )
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    # Thymeleaf/SpEL 模板注入探针路径（含 __${7*7}__::.x）
    # 探针 URL 常带 URL 编码变体（如 __$%7B7*7%7D__::.x），request.path 已做百分号解码，
    # 用路径子串而非精确匹配，任何含 7*7 的变体都会落入本分支
    if "7*7" in path:
        if vuln:
            # 含求值结果 49 与模板引擎关键字（thymeleaf / org.thymeleaf），且不含原始 7*7
            body = (
                '<html><body><p>Error resolving template "49", template might not '
                "exist or might not be accessible by any of the configured Template "
                "Resolvers. org.thymeleaf.exceptions.TemplateInputException: ...</p>"
                "</body></html>"
            )
            return html_body(body, 500)
        return whitelabel_404()

    # ── 以下为 D38 补充：通用插件签名（使 --require-all-confirmed 全绿）──────────

    # RuoYi-Cloud Nacos 配置泄露：/nacos/v1/cs/configs
    if path == "/nacos/v1/cs/configs":
        if vuln:
            return json_body({"pageItems": [{"dataId": "application-dev.yml"}], "totalCount": 1})
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    # RuoYi 代码生成模块 SSTI：/tool/gen/edit（签名头判定）
    if path == "/tool/gen/edit":
        if vuln:
            resp = json_body({"code": 200, "msg": "操作成功"})
            resp.headers["X-Ruoyi-Vuln"] = "gen-ssti"
            return resp
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    # .git 源码泄露：/.git/HEAD
    if path == "/.git/HEAD":
        if vuln:
            return Response("ref: refs/heads/master\n", mimetype="text/plain")
        return html_body("<html><body>404</body></html>", 404)

    # .env 配置文件泄露：/.env
    if path == "/.env":
        if vuln:
            return Response(
                "DB_HOST=localhost\nDB_DATABASE=ry\nDB_USERNAME=root\nDB_PASSWORD=root\nAPP_KEY=base64:RuoyiScanTest\n",
                mimetype="text/plain",
            )
        return html_body("<html><body>404</body></html>", 404)

    # 备份文件泄露：/web.zip（插件扫描 65 个路径，任一 200 即命中）
    if path == "/web.zip":
        if vuln:
            return Response(b"PK\x03\x04", mimetype="application/zip")
        return html_body("<html><body>404</body></html>", 404)

    # IDE/SCM 残留文件泄露：/.svn/entries（插件扫描 11 个路径）
    if path == "/.svn/entries":
        if vuln:
            return Response("dir\nsvn://server/repo\n", mimetype="text/plain")
        return html_body("<html><body>404</body></html>", 404)

    # ── G1 认证后深度扫描签名区（lib/auth_surface.py 专项，/prod-api 前缀与现有端点隔离）──
    # 登录：POST /prod-api/auth/login（JSON）→ 按账号发不同权限 token
    if path == "/prod-api/auth/login":
        if method == "POST":
            body = request.get_json(silent=True) or {}
            user, pwd = body.get("username", ""), body.get("password", "")
            if user == "admin" and pwd == "admin123":
                return json_body({"code": 200, "msg": "操作成功", "token": "admin-token"})
            if user == "user" and pwd == "user123":
                return json_body({"code": 200, "msg": "操作成功", "token": "user-token"})
            return json_body({"code": 500, "msg": "用户名或密码错误"})
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    def _bearer_token():
        """提取 Authorization: Bearer <token>（无则空串）"""
        auth = request.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else ""

    # 用户列表：管理员专属接口（G1 越权矩阵签名点之一）
    #   任意有效 token 均可读 → vuln 模式语义（RBAC 缺失）
    #   safe 模式：低权 token → 403
    if path == "/prod-api/system/user/list":
        token = _bearer_token()
        if token == "admin-token":
            return json_body(
                {
                    "code": 200,
                    "msg": "操作成功",
                    "rows": [
                        {"userId": 1, "userName": "admin", "role": "admin"},
                        {"userId": 2, "userName": "user", "role": "common"},
                    ],
                    "total": 2,
                }
            )
        if token == "user-token":
            if vuln:
                return json_body(
                    {
                        "code": 200,
                        "msg": "操作成功",
                        "rows": [
                            {"userId": 1, "userName": "admin", "role": "admin"},
                            {"userId": 2, "userName": "user", "role": "common"},
                        ],
                        "total": 2,
                    }
                )
            return json_body({"code": 403, "msg": "权限不足"}, 403)
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    # 角色列表：管理员专属接口——垂直越权签名点
    #   vuln 模式：低权 user-token 也能访问（RBAC 缺失洞）
    #   safe 模式：低权 token → 403 权限不足
    if path == "/prod-api/system/role/list":
        token = _bearer_token()
        if token == "admin-token":
            return json_body(
                {
                    "code": 200,
                    "msg": "操作成功",
                    "rows": [
                        {"roleId": 1, "roleName": "超级管理员", "roleKey": "admin"},
                    ],
                    "total": 1,
                }
            )
        if token == "user-token":
            if vuln:
                # 洞：RBAC 未校验，低权 token 读取角色管理数据
                return json_body(
                    {
                        "code": 200,
                        "msg": "操作成功",
                        "rows": [
                            {"roleId": 1, "roleName": "超级管理员", "roleKey": "admin"},
                        ],
                        "total": 1,
                    }
                )
            return json_body({"code": 403, "msg": "权限不足"}, 403)
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    # 目录扫描常见路径（指纹强特征 + 目录展示）
    # /index 拟真化为后台首页（标题签名不变）；其余保持原最小 HTML
    if path == "/index":
        return html_body(_render_index_page(vuln))
    if path in ("/captcha/image", "/getInfo", "/prod-api/"):
        return html_body("<html><head><title>RuoYi管理系统</title></head><body>index</body></html>")
    if path == "/favicon.ico":
        return Response("", status=404)

    # 其他路径：404（目录扫描未命中项）——Spring Boot Whitelabel 风格
    return whitelabel_404()


@app.route("/", defaults={"p": ""}, methods=["GET", "POST"])
@app.route("/<path:p>", methods=["GET", "POST"])
def _route(p):
    """Flask 统一入口：把任意路径/方法转交 dispatch，按 (路径, 方法) 分发签名"""
    return dispatch(request.path, request.method)


@app.after_request
def _cors(resp):
    """CORS 跨域配置不当签名：vuln 模式反射 Origin 头"""
    if is_vuln():
        origin = request.headers.get("Origin", "")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.errorhandler(404)
def _handle_404(_e):
    # 兜底：捕获含特殊字符（${}、:: 等）导致路由未匹配的 SSTI 探针路径
    return dispatch(request.path, request.method)


if __name__ == "__main__":
    print(f"[*] Ruoyi 签名靶场启动：MODE={MODE} PORT={PORT} HOST={HOST}")
    print("[*] 合法授权测试 / 教学验证用途，仅返回插件判定签名，不含真实漏洞利用")
    print("[!] 安全提示：本靶场含漏洞响应签名，仅限本机/授权测试环境使用，严禁部署到公网或未授权网络")
    app.run(host=HOST, port=PORT, debug=False)
