# 泛微 e-cology OA 漏洞扫描器 —— 本地签名靶场（仅用于合法授权测试 / 教学验证）
#
# 设计目标：精确复现 plugins/weaver 八个插件命中时的「请求路径 + 响应特征」，
# 使扫描器可在无真实目标的情况下完成判定逻辑对拍（vuln/safe 双模式）。
#
# 本服务不实现任何真实漏洞利用，仅返回与插件判定规则匹配的响应签名，
# 用于验证扫描器「匹配逻辑」是否正确，不属于真实攻击环境。
import os
import json

from flask import Flask, request, Response

# 运行模式：vuln（开启全部漏洞签名）/ safe（全部已修复）
MODE = os.environ.get('LAB_MODE', 'vuln')
PORT = int(os.environ.get('LAB_PORT', '8090'))

app = Flask(__name__)

# 插件命中签名（必须与 plugins/weaver/*.py 中的 *_MARKER 完全一致）
MARKER_UPLOAD = 'weaver-file-upload-rce-confirmed'
MARKER_FILE_DOWNLOAD = 'weaver-file-download-confirmed'
MARKER_XML = 'weaver-xml-rce-confirmed'
MARKER_BSH = 'weaver-bsh-rce-confirmed'
MARKER_SQLI = 'weaver-sqli-confirmed'
MARKER_LEAK = 'weaver-info-leak-confirmed'
MARKER_XSS = 'weaver-xss-confirmed'


def is_vuln():
    return MODE == 'vuln'


def json_body(d, code=200):
    return Response(json.dumps(d, ensure_ascii=False), status=code,
                    mimetype='application/json; charset=utf-8')


def html_body(body, code=200):
    return Response(body, status=code, mimetype='text/html; charset=utf-8')


def dispatch(path, method):
    vuln = is_vuln()

    # 根路径：泛微 e-cology OA 主页（指纹识别强特征——login_keywords 命中；两模式都返回）
    if path == '/':
        return html_body(
            '<html><head><title>泛微 e-cology OA</title></head>'
            '<body>Weaver e-cology 协同办公系统 <!-- weaver --></body></html>')

    # /login/Login.jsp：OA 登录页（指纹强路径 + weaver 关键字；两模式都返回 200，保证指纹识别）
    if path == '/login/Login.jsp':
        return html_body(
            '<html><head><title>e-cology 登录</title></head>'
            '<body><form action="weaver/" method="post">weaver login</form></body></html>')

    # /weaver/ 内部 OA 路径（unauth 插件探针）
    #   vuln：200 + 含 weaver 关键字（内部内容暴露，未鉴权）
    #   safe：401（已保护，匿名访问被拦截）
    if path in ('/weaver', '/weaver/'):
        if vuln:
            return html_body(
                '<html><head><title>Weaver OA Console</title></head>'
                '<body>泛微 e-cology 内部控制台 weaver admin</body></html>')
        return Response('Unauthorized: authentication required', status=401,
                        mimetype='text/plain; charset=utf-8')

    # /weaver/weaver.file.FileDownloadForOutDoc：
    #   POST → 任意文件上传接口（file_upload 插件探针）
    #   GET  → 任意文件下载接口（file_download 插件探针，file 参数路径穿越）
    # 同一路径按 method 区分两插件，避免互相吞签名
    if path == '/weaver/weaver.file.FileDownloadForOutDoc':
        if vuln:
            if method == 'GET':
                return json_body({'status': 200, '_marker': MARKER_FILE_DOWNLOAD})
            return json_body({'status': 200, '_marker': MARKER_UPLOAD})
        return json_body({'status': 404, 'error': 'Not Found', 'path': path}, 404)

    # /weaver/xml_endpoint：XMLDecoder 反序列化接口（xml_rce 插件探针）
    if path == '/weaver/xml_endpoint':
        if vuln:
            return Response(MARKER_XML, status=200, mimetype='text/xml; charset=utf-8')
        return json_body({'status': 404, 'error': 'Not Found', 'path': path}, 404)

    # /weaver/bsh.servlet.BshServlet：Beanshell 解释器接口（bsh_rce 插件探针）
    if path == '/weaver/bsh.servlet.BshServlet':
        if vuln:
            return Response(MARKER_BSH + ' <!-- bsh script executed -->', status=200,
                            mimetype='text/plain; charset=utf-8')
        return json_body({'status': 404, 'error': 'Not Found', 'path': path}, 404)

    # /weaver/sqlinject：SQL 注入点（sqli 插件探针，忽略 query 参数）
    if path == '/weaver/sqlinject':
        if vuln:
            return json_body({'code': 500, 'msg': MARKER_SQLI,
                              'error': 'XPATH syntax error'})
        return json_body({'status': 404, 'error': 'Not Found', 'path': path}, 404)

    # /weaver/ecology.properties：配置文件泄露（info_leak 插件探针）
    if path == '/weaver/ecology.properties':
        if vuln:
            return Response(
                '# ecology config\n' + MARKER_LEAK + '\n'
                'db.url=jdbc:mysql://localhost:3306/ecology\n'
                'db.username=root\n',
                status=200, mimetype='text/plain; charset=utf-8')
        return Response('Not Found', status=404, mimetype='text/plain; charset=utf-8')

    # /weaver/search.jsp：反射型 XSS（xss 插件探针，keyword 参数未过滤反射）
    if path == '/weaver/search.jsp':
        if vuln:
            return html_body(
                '<html><head><title>搜索结果</title></head>'
                '<body>关键字结果：' + MARKER_XSS + '</body></html>')
        return json_body({'status': 404, 'error': 'Not Found', 'path': path}, 404)

    # 其他路径 → JSON 404（含 favicon.ico，避免污染其他 CMS 指纹）
    return json_body({'status': 404, 'error': 'Not Found', 'path': path}, 404)


@app.route('/', defaults={'p': ''}, methods=['GET', 'POST'])
@app.route('/<path:p>', methods=['GET', 'POST'])
def _route(p):
    return dispatch(request.path, request.method)


if __name__ == '__main__':
    print(f'[*] 泛微 e-cology 签名靶场启动：MODE={MODE} PORT={PORT}')
    print(f'[*] 合法授权测试 / 教学验证用途，仅返回插件判定签名，不含真实漏洞利用')
    app.run(host='0.0.0.0', port=PORT, debug=False)
