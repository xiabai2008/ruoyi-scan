# Ruoyi 漏洞扫描器 —— 本地签名靶场（仅用于合法授权测试 / 教学验证）
#
# 设计目标：精确复现 13 个插件命中时的「请求路径 + 响应特征」，
# 使扫描器可在无真实目标的情况下完成判定逻辑对拍（vuln/safe 双模式）。
#
# 本服务不实现任何真实漏洞利用，仅返回与插件判定规则匹配的响应签名，
# 用于验证扫描器「匹配逻辑」是否正确，不属于真实攻击环境。
import json
import os

from flask import Flask, request, Response

# 运行模式：vuln（开启全部漏洞签名）/ safe（全部已修复）
MODE = os.environ.get('LAB_MODE', 'vuln')
PORT = int(os.environ.get('LAB_PORT', '8080'))

app = Flask(__name__)

# /etc/passwd 特征内容（file_read / file_read_time 判定要求同时含 'root' 与 ':/'）
PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "bin:x:1:1:bin:/bin:/sbin/nologin\n"
    "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/sbin/nologin\n"
)

# Druid 爆破：与扫描器 settings.DRUID_USERS 对齐的 6 个用户名
DRUID_USERS = {'ruoyi', 'druid', 'admin', 'admin123', 'auth', '123456'}
# 命中即返回 success 的弱口令集合（均存在于 password.txt 字典中）
DRUID_OK_PASSWORDS = {'ruoyi', '123456', 'admin123', 'druid'}

# Step 8 新增 POC 签名 marker（与 plugins/ruoyi/ 下插件常量一致）
NACOS_UNAUTH_MARKER = 'ruoyi-nacos-unauth-confirmed'
FILE_READ_PATH_MARKER = 'ruoyi-file-read-path-confirmed'


def is_vuln():
    return MODE == 'vuln'


def json_body(d, code=200):
    return Response(json.dumps(d, ensure_ascii=False), status=code,
                    mimetype='application/json; charset=utf-8')


def html_body(body, code=200):
    return Response(body, status=code, mimetype='text/html; charset=utf-8')


def dispatch(path, method):
    """统一分发：按 (路径, 方法) 返回与插件判定规则匹配的响应签名"""
    vuln = is_vuln()

    # 根路径 + 登录页：含 RuoYi 标题 → 指纹识别强特征命中
    if path == '/':
        return html_body(
            '<html><head><title>RuoYi管理系统</title></head>'
            '<body><h1>RuoYi</h1></body></html>')

    # 任意文件读取（file_read + file_read_time 读取落地文件 2.txt）
    # Step 8 新增 file_read_path：resource 参数以 ../ 开头（相对路径穿越探针）
    #   按 resource 查询参数分流：../ 前缀 → 路径穿越签名；其余 → 原 /etc/passwd 特征
    #   注意：query 参数不影响 request.path 路径匹配，需在端点内读取 request.args 区分
    if path == '/common/download/resource':
        if vuln:
            resource = request.args.get('resource', '')
            if resource.startswith('../'):
                # file_read_path 探针：路径穿越读取任意文件
                return Response(FILE_READ_PATH_MARKER, mimetype='text/plain; charset=utf-8')
            # file_read / file_read_time 探针：返回含 root 与 :/ 的 /etc/passwd 特征
            return Response(PASSWD, mimetype='text/plain; charset=utf-8')
        return html_body('<html><body>404 资源不存在</body></html>', 404)

    # 定时任务 edit / run（job_rce + file_read_time）
    if path == '/monitor/job/edit':
        if vuln:
            # 未鉴权进入业务层：code=500 业务校验失败，证明绕过鉴权
            return json_body({'code': 500, 'msg': '定时任务不存在'})
        return json_body({'code': 401, 'msg': '请先登录'}, 401)
    if path == '/monitor/job/run':
        if vuln:
            return json_body({'code': 200, 'msg': '操作成功'})
        return json_body({'code': 401, 'msg': '请先登录'}, 401)

    # SQL 报错注入（role / dept）
    if path in ('/system/role/list', '/system/dept/list'):
        if vuln:
            # 含 '运行时异常' 与 'database()' 双重特征 → 命中
            body = (
                '<!doctype html><html><body><h1>HTTP Status 500 - '
                '请求处理失败</h1><pre>java.sql.SQLException: '
                'XPATH syntax error: \'~database()~\', 运行时异常</pre>'
                '</body></html>'
            )
            return html_body(body, 500)
        return json_body({'code': 200, 'msg': '操作成功', 'rows': [], 'total': 0})

    # Druid 弱口令爆破
    if path == '/druid/submitLogin':
        user = request.form.get('loginUsername', '')
        pwd = request.form.get('loginPassword', '')
        if vuln and user in DRUID_USERS and pwd in DRUID_OK_PASSWORDS:
            return json_body({'success': True, 'message': '登录成功'})
        # safe 模式：失败响应不含 'success' 关键字，避免子串误判
        return json_body({'code': 0, 'message': '用户名或密码错误'})

    # 任意文件上传（/common/upload）
    if path == '/common/upload':
        if vuln:
            return json_body({
                'code': 200,
                'fileName': 'ruoyi_scan_probe.txt',
                'url': '/profile/upload/2026/07/ruoyi_scan_probe.txt',
                'newFileName': 'ruoyi_scan_probe_20260717.txt',
            })
        return json_body({'code': 401, 'msg': '请先登录'}, 401)

    # 后台默认口令（/login）
    if path == '/login':
        if method == 'POST':
            if vuln:
                return json_body({'code': 200, 'msg': '操作成功',
                                  'token': 'eyJhbGciOiJIUzI1NiJ9.ruoyi-lab-signature'})
            return json_body({'code': 500, 'msg': '密码错误'})
        # GET /login 供目录扫描展示
        return html_body(
            '<html><head><title>RuoYi管理系统</title></head><body>login</body></html>')

    # 未授权访问批量端点
    if path == '/actuator/env':
        if vuln:
            return json_body({'propertySources': [{'name': 'applicationConfig'}],
                              'activeProfiles': [], 'environment': 'dev'})
        return json_body({'code': 401, 'msg': '请先登录'}, 401)
    if path == '/druid/index.html':
        if vuln:
            return html_body(
                '<html><body><h1>Druid Monitor</h1><p>Druid Stat Index</p></body></html>')
        return json_body({'code': 401, 'msg': '请先登录'}, 401)
    if path == '/swagger-ui.html':
        if vuln:
            return html_body('<html><body><h1>Swagger UI</h1></body></html>')
        return json_body({'code': 401, 'msg': '请先登录'}, 401)
    if path == '/system/user/list':
        if vuln:
            return json_body({'code': 200, 'rows': [{'userId': 1, 'userName': 'admin'}],
                              'total': 1})
        return json_body({'code': 401, 'msg': '请先登录'}, 401)

    # Step 8 新增：Nacos 未授权访问（/nacos/v1/auth/users）
    # query 参数（pageNo/pageSize）不影响 request.path 匹配，无需在端点内读取
    if path == '/nacos/v1/auth/users':
        if vuln:
            # 未授权可获取用户列表，响应含签名 marker
            return json_body({
                'totalCount': 1, 'pageNumber': 1, 'pageSize': 10,
                'pageItems': [{'username': 'nacos', 'password': '$2a$10$ruoyi-nacos-hash'}],
                'marker': NACOS_UNAUTH_MARKER,
            })
        return json_body({'code': 401, 'msg': '请先登录'}, 401)

    # Thymeleaf/SpEL 模板注入探针路径（含 __${7*7}__::.x）
    if '7*7' in path:
        if vuln:
            # 含求值结果 49 与模板引擎关键字（thymeleaf / org.thymeleaf），且不含原始 7*7
            body = (
                '<html><body><p>Error resolving template "49", template might not '
                'exist or might not be accessible by any of the configured Template '
                'Resolvers. org.thymeleaf.exceptions.TemplateInputException: ...</p>'
                '</body></html>'
            )
            return html_body(body, 500)
        return html_body('<html><body>404 Not Found</body></html>', 404)

    # 目录扫描常见路径（指纹强特征 + 目录展示）
    if path in ('/index', '/captcha/image', '/getInfo', '/prod-api/'):
        return html_body(
            '<html><head><title>RuoYi管理系统</title></head><body>index</body></html>')
    if path == '/favicon.ico':
        return Response('', status=404)

    # 其他路径：404（目录扫描未命中项）
    return html_body('<html><body>404 Not Found</body></html>', 404)


@app.route('/', defaults={'p': ''}, methods=['GET', 'POST'])
@app.route('/<path:p>', methods=['GET', 'POST'])
def _route(p):
    return dispatch(request.path, request.method)


@app.errorhandler(404)
def _handle_404(_e):
    # 兜底：捕获含特殊字符（${}、:: 等）导致路由未匹配的 SSTI 探针路径
    return dispatch(request.path, request.method)


if __name__ == '__main__':
    print(f'[*] Ruoyi 签名靶场启动：MODE={MODE} PORT={PORT}')
    print(f'[*] 合法授权测试 / 教学验证用途，仅返回插件判定签名，不含真实漏洞利用')
    app.run(host='0.0.0.0', port=PORT, debug=False)
