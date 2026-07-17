# ThinkPHP 漏洞扫描器 —— 本地签名靶场（仅用于合法授权测试 / 教学验证）
#
# 设计目标：精确复现 plugins/thinkphp 三个插件命中时的「请求路径 + 响应特征」，
# 使扫描器可在无真实目标的情况下完成判定逻辑对拍（vuln/safe 双模式）。
#
# 本服务不实现任何真实漏洞利用，仅返回与插件判定规则匹配的响应签名，
# 用于验证扫描器「匹配逻辑」是否正确，不属于真实攻击环境。
import os

from flask import Flask, request, Response

# 运行模式：vuln（开启全部漏洞签名）/ safe（全部已修复）
MODE = os.environ.get('LAB_MODE', 'vuln')
PORT = int(os.environ.get('LAB_PORT', '8090'))

app = Flask(__name__)

# 插件命中签名（必须与 plugins/thinkphp/*.py 中的 MARKER 完全一致）
MARKER_INVOKE = 'thinkphp-invokefunction-rce-confirmed'
MARKER_CONSTRUCT = 'thinkphp-5023-construct-rce-confirmed'
MARKER_LANG = 'thinkphp-lang-rce-confirmed'
MARKER_51 = 'thinkphp-51-request-rce-confirmed'
MARKER_LOG = 'thinkphp-log-disclosure'
MARKER_CACHE = 'thinkphp-cache-shell-confirmed'
MARKER_DESER = 'thinkphp-deserialize-rce-confirmed'
MARKER_FILE = 'thinkphp-file-read-confirmed'
MARKER_SQLI = 'thinkphp-where-inject-confirmed'
MARKER_REQUEST_V2 = 'thinkphp-request-rce-v2-confirmed'
MARKER_DISPATCH = 'thinkphp-dispatch-rce-confirmed'


def is_vuln():
    return MODE == 'vuln'


def json_body(d, code=200):
    return Response(__import__('json').dumps(d, ensure_ascii=False), status=code,
                    mimetype='application/json; charset=utf-8')


def html_body(body, code=200):
    return Response(body, status=code, mimetype='text/html; charset=utf-8')


def thinkphp_home():
    """ThinkPHP 默认欢迎页（供指纹识别：含 'ThinkPHP Framework' 标题）"""
    return ('<html><head><title>ThinkPHP Framework</title></head>'
            '<body><h1>ThinkPHP</h1><p>V5.0.23</p></body></html>')


def dispatch(path, method):
    vuln = is_vuln()

    # 根路径：含 ThinkPHP Framework 标题 → 指纹识别强特征命中（vuln/safe 一致）
    # 阶段八新增：两个探针都打到根路径 /，但带不同 query 参数，需用 request.args 区分
    if path == '/':
        if method == 'GET':
            s_root = request.args.get('s', '')
            # (10) request_rce_v2：s=captcha + _method=__construct + filter[]=phpinfo
            if 'captcha' in s_root and request.args.get('_method') == '__construct':
                if vuln:
                    return html_body('PHP Version 7.3.2\n' + MARKER_REQUEST_V2)
                return html_body(thinkphp_home())
            # (11) dispatch_rce：s 含 invokefunction + function=call_user_func_array
            if 'invokefunction' in s_root and request.args.get('function') == 'call_user_func_array':
                if vuln:
                    return html_body('PHP Version 7.3.2\n' + MARKER_DISPATCH)
                return html_body('<html><body>404 Not Found</body></html>', 404)
        # 根路径默认：含 ThinkPHP Framework 标题 → 指纹识别强特征命中（vuln/safe 一致）
        return html_body(thinkphp_home())

    if path == '/index.php':
        if method == 'POST':
            form = request.form
            s = form.get('s', '') or request.args.get('s', '')
            fn = form.get('function', '')
            # 1) invokefunction RCE
            if 'invokefunction' in s and fn == 'call_user_func_array':
                if vuln:
                    # 模拟 phpversion() 执行输出 + 命中签名
                    return html_body('PHP Version 7.3.2\n' + MARKER_INVOKE)
                return html_body(thinkphp_home())
            # 2) 5.0.23 method 覆盖 RCE（_method=__construct + filter[]）
            if form.get('_method') == '__construct' and 'filter[]' in form:
                if vuln:
                    return html_body('PHP Version 7.3.2\n' + MARKER_CONSTRUCT)
                return html_body(thinkphp_home())
            # 7) 反序列化 POP 链 RCE
            if 'data' in form and form.get('data', '').startswith('O:'):
                if vuln:
                    return html_body('PHP Version 7.3.2\n' + MARKER_DESER)
                return html_body(thinkphp_home())
            # 其他 POST：正常页面（无签名）
            return html_body(thinkphp_home())
        else:  # GET
            # 3) 5.0.x 多语言 RCE（lang 参数文件包含链）
            lang = request.args.get('lang', '')
            if 'php://' in lang or '..' in lang:
                if vuln:
                    return html_body('PHP Version 7.3.2\n' + MARKER_LANG)
                return html_body(thinkphp_home())
            # 4) 5.1.x 路由 RCE（think\Request/input + filter）
            s51 = request.args.get('s', '')
            if 'think\\Request/input' in s51 and request.args.get('filter', ''):
                if vuln:
                    return html_body('PHP Version 7.3.2\n' + MARKER_51)
                return html_body(thinkphp_home())
            # 8) 模板驱动文件读取
            s_fr = request.args.get('s', '')
            if 'think\\template' in s_fr and request.args.get('file', ''):
                if vuln:
                    return html_body('PHP Version 7.3.2\n' + MARKER_FILE)
                return html_body(thinkphp_home())
            # 9) where 子句 SQL 注入（order 参数含 extractvalue/updatexml 探针）
            qs = request.query_string.decode('utf-8', 'ignore').lower()
            if 'extractvalue' in qs or 'updatexml' in qs:
                if vuln:
                    return html_body('SQL error\n' + MARKER_SQLI)
                return html_body(thinkphp_home())
            if vuln and 'debug_probe' in request.args:
                # APP_DEBUG 开启：错误页暴露异常栈（含 think\exception 特征）
                body = (
                    '<html><body><h1>ThinkPHP Framework</h1><pre>'
                    '[ error ] think\\exception\\ErrorException: Undefined variable: x\n'
                    '#0 /var/www/html/thinkphp/library/think/Exception.php(123): ...\n'
                    'Stack trace:\n'
                    '#1 /var/www/html/application/index/controller/Index.php(45): ...\n'
                    '</pre></body></html>'
                )
                return html_body(body, 500)
            # 正常 GET：欢迎页（不含调试特征）
            return html_body(thinkphp_home())

    # 5) runtime 日志暴露
    if path.startswith('/runtime/log/'):
        if vuln:
            body = ('[ 2024-01-01T00:00:00 ] INFO: [ app ] ' + MARKER_LOG +
                    ' request param: id=1; SQL: SELECT * FROM user WHERE id=1\n')
            return html_body(body)
        return html_body('<html><body>404 Not Found</body></html>', 404)

    # 6) 缓存文件包含 getshell
    if path.startswith('/runtime/cache/'):
        if vuln:
            return html_body('<?php /* cache */ ' + MARKER_CACHE + ' ?>')
        return html_body('<html><body>404 Not Found</body></html>', 404)

    if path == '/favicon.ico':
        return Response('', status=404)

    # 其他路径：404
    return html_body('<html><body>404 Not Found</body></html>', 404)


@app.route('/', defaults={'p': ''}, methods=['GET', 'POST'])
@app.route('/<path:p>', methods=['GET', 'POST'])
def _route(p):
    return dispatch(request.path, request.method)


if __name__ == '__main__':
    print(f'[*] ThinkPHP 签名靶场启动：MODE={MODE} PORT={PORT}')
    print(f'[*] 合法授权测试 / 教学验证用途，仅返回插件判定签名，不含真实漏洞利用')
    app.run(host='0.0.0.0', port=PORT, debug=False)
