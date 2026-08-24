# Ruoyi 漏洞扫描器 —— 本地签名靶场（仅用于合法授权测试 / 教学验证）
#
# 设计目标：精确复现 13 个插件命中时的「请求路径 + 响应特征」，
# 使扫描器可在无真实目标的情况下完成判定逻辑对拍（vuln/safe 双模式）。
#
# 本服务不实现任何真实漏洞利用，仅返回与插件判定规则匹配的响应签名，
# 用于验证扫描器「匹配逻辑」是否正确，不属于真实攻击环境。
import json
import os

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

# Step 8 POC 签名 marker 已于 D4 改造（2026-07-18）删除：
# nacos_unauth / file_read_path 改为真实响应特征判定，不再依赖魔法常量


def is_vuln():
    return MODE == "vuln"


def json_body(d, code=200):
    return Response(json.dumps(d, ensure_ascii=False), status=code, mimetype="application/json; charset=utf-8")


def html_body(body, code=200):
    return Response(body, status=code, mimetype="text/html; charset=utf-8")


def dispatch(path, method):
    """统一分发：按 (路径, 方法) 返回与插件判定规则匹配的响应签名"""
    vuln = is_vuln()

    # 根路径 + 登录页：含 RuoYi 标题 → 指纹识别强特征命中
    if path == "/":
        return html_body("<html><head><title>RuoYi管理系统</title></head><body><h1>RuoYi</h1></body></html>")

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
        return html_body("<html><body>404 资源不存在</body></html>", 404)

    # 定时任务 edit / run（job_rce + file_read_time）
    if path == "/monitor/job/edit":
        if vuln:
            # 未鉴权进入业务层：code=500 业务校验失败，证明绕过鉴权
            return json_body({"code": 500, "msg": "定时任务不存在"})
        return json_body({"code": 401, "msg": "请先登录"}, 401)
    if path == "/monitor/job/run":
        if vuln:
            return json_body({"code": 200, "msg": "操作成功"})
        return json_body({"code": 401, "msg": "请先登录"}, 401)

    # SQL 报错注入（role / dept）
    if path in ("/system/role/list", "/system/dept/list"):
        if vuln:
            # 含 '运行时异常' 与 'database()' 双重特征 → 命中
            body = (
                "<!doctype html><html><body><h1>HTTP Status 500 - "
                "请求处理失败</h1><pre>java.sql.SQLException: "
                "XPATH syntax error: '~database()~', 运行时异常</pre>"
                "</body></html>"
            )
            return html_body(body, 500)
        return json_body({"code": 200, "msg": "操作成功", "rows": [], "total": 0})

    # Druid 弱口令爆破
    if path == "/druid/submitLogin":
        user = request.form.get("loginUsername", "")
        pwd = request.form.get("loginPassword", "")
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
        return html_body("<html>404</html>", 404)

    # D3：safe 模式 /login 改为返回密码错误（模拟真实若依验证码校验）
    # vuln 模式 /login 仍返回 code=200（无验证码，供登录链测试）
    if path == "/login":
        if method == "POST":
            if vuln:
                # vuln 模式：检查 validateCode，空则通过（模拟无验证码或验证码正确）
                return json_body({"code": 200, "msg": "操作成功", "token": "eyJhbGciOiJIUzI1NiJ9.ruoyi-lab-signature"})
            # safe 模式：返回密码错误（模拟登录失败，不校验验证码）
            return json_body({"code": 500, "msg": "用户或密码错误"})
        # GET /login 供目录扫描展示
        return html_body("<html><head><title>RuoYi管理系统</title></head><body>login</body></html>")

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
            return json_body({"code": 200, "rows": [{"userId": 1, "userName": "admin"}], "total": 1})
        return json_body({"code": 401, "msg": "请先登录"}, 401)

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
        return html_body("<html><body>404 Not Found</body></html>", 404)

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

    # 目录扫描常见路径（指纹强特征 + 目录展示）
    if path in ("/index", "/captcha/image", "/getInfo", "/prod-api/"):
        return html_body("<html><head><title>RuoYi管理系统</title></head><body>index</body></html>")
    if path == "/favicon.ico":
        return Response("", status=404)

    # 其他路径：404（目录扫描未命中项）
    return html_body("<html><body>404 Not Found</body></html>", 404)


@app.route("/", defaults={"p": ""}, methods=["GET", "POST"])
@app.route("/<path:p>", methods=["GET", "POST"])
def _route(p):
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
