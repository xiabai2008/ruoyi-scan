# Spring Boot 漏洞扫描器 —— 本地签名靶场（仅用于合法授权测试 / 教学验证）
#
# 设计目标：精确复现 plugins/spring 五个插件命中时的「请求路径 + 响应特征」，
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

# 插件命中签名（必须与 plugins/spring/*.py 中的 MARKER 完全一致）
MARKER_S4S = 'spring4shell-rce-confirmed'
MARKER_GW = 'spring-gateway-rce-confirmed'
MARKER_ENV = 'spring-actuator-env-rce-confirmed'
MARKER_HEAP = 'spring-heapdump-leak-confirmed'
MARKER_JOLOKIA = 'spring-jolokia-rce-confirmed'
MARKER_SCF = 'spring-cloud-function-rce-confirmed'
MARKER_H2 = 'spring-h2-console-rce-confirmed'


def is_vuln():
    return MODE == 'vuln'


def json_body(d, code=200):
    return Response(json.dumps(d, ensure_ascii=False), status=code,
                    mimetype='application/json; charset=utf-8')


def html_body(body, code=200):
    return Response(body, status=code, mimetype='text/html; charset=utf-8')


def binary_body(data, code=200):
    return Response(data, status=code, mimetype='application/octet-stream')


def actuator_links():
    """标准 Spring Boot Actuator HAL JSON（指纹识别强特征 + actuator_unauth 第一关）"""
    return {
        '_links': {
            'self': {'href': 'http://localhost:PORT/actuator', 'templated': False},
            'health': {'href': 'http://localhost:PORT/actuator/health', 'templated': False},
            'env': {'href': 'http://localhost:PORT/actuator/env', 'templated': False},
            'heapdump': {'href': 'http://localhost:PORT/actuator/heapdump', 'templated': False},
        }
    }


def actuator_env_json():
    """/actuator/env 响应（vuln 嵌入 MARKER 供 actuator_unauth 判定不拦截）"""
    return {
        'activeProfiles': [],
        'propertySources': [
            {
                'name': 'applicationConfig: [classpath:/application.properties]',
                'properties': {
                    'server.port': {'value': '8080', 'origin': 'class path resource [...]'},
                },
            },
        ],
        # 嵌入特征供靶场对拍审计（不影响 actuator_unauth 判定——它只看 200+JSON）
        '_marker': 'actuator-env-accessible',
    }


def dispatch(path, method):
    vuln = is_vuln()

    # 根路径：来自 Spring4Shell 插件 POST + fingerprint 探测（返回简单 JSON 或无特征响应）
    if path == '/':
        if method == 'POST':
            # Spring4Shell 探针：POST 表单含 class.module.classLoader
            if any('class.module.classLoader' in k for k in request.form.keys()):
                if vuln:
                    return json_body({'status': 200, '_marker': MARKER_S4S})
                return json_body({'timestamp': '...', 'status': 400, 'error': 'Bad Request'})
            # 非 Spring4Shell POST → 普通 JSON 响应（无签名）
            return json_body({'status': 200, 'message': 'ok'})
        # GET / → Spring Boot 默认无统一页面，返回 404 JSON（指纹弱特征 WhiteLabel）
        return json_body({'timestamp': '...', 'status': 404,
                          'error': 'Not Found', 'path': '/'}, 404)

    # /actuator 响应（指纹强特征 + actuator_unauth 第一关）
    if path == '/actuator':
        return json_body(actuator_links())

    if path == '/actuator/health':
        return json_body({'status': 'UP'})

    # GET /actuator/env → actuator_unauth 第二关（vuln 返回 JSON / safe 404）
    if path == '/actuator/env':
        if method == 'POST':
            # actuator_env_rce 探针
            if vuln:
                return json_body({'status': 200, '_marker': MARKER_ENV})
            return json_body({'timestamp': '...', 'status': 405,
                              'error': 'Method Not Allowed'}, 405)
        if vuln:
            return json_body(actuator_env_json())
        return json_body({'timestamp': '...', 'status': 404,
                          'error': 'Not Found', 'path': '/actuator/env'}, 404)

    # GET /actuator/heapdump → heapdump_leak 探针
    if path == '/actuator/heapdump':
        if vuln:
            # 小型 heapdump 模拟文件（嵌入 marker 文本供扫描器判定）
            dummy = b'\x01\x0bJAVA PROFILE 1.0.2\n' + MARKER_HEAP.encode() + b'\nHEAPDUMP_END'
            return binary_body(dummy)
        return json_body({'timestamp': '...', 'status': 404,
                          'error': 'Not Found', 'path': '/actuator/heapdump'}, 404)

    # POST /actuator/gateway/routes/<id> → gateway_rce 探针
    if path.startswith('/actuator/gateway/routes/'):
        if vuln:
            return json_body({'status': 201, 'id': path.split('/')[-1],
                              '_marker': MARKER_GW})
        return json_body({'timestamp': '...', 'status': 404,
                          'error': 'Not Found', 'path': path}, 404)

    # GET / POST /actuator/jolokia → jolokia_rce 探针
    if path == '/actuator/jolokia' or path.startswith('/actuator/jolokia/'):
        if vuln:
            if method == 'POST':
                return json_body({'status': 200, 'value': MARKER_JOLOKIA,
                                  'request': {'type': 'EXEC'}})
            return json_body({'request': {}, 'value': {},
                              'timestamp': 0, 'status': 200})
        return json_body({'timestamp': '...', 'status': 404,
                          'error': 'Not Found', 'path': path}, 404)

    # POST /functionRouter → CVE-2022-22963 Cloud Function SpEL RCE 探针
    if path == '/functionRouter':
        if vuln:
            return json_body({'status': 200, '_marker': MARKER_SCF})
        return json_body({'timestamp': '...', 'status': 404,
                          'error': 'Not Found', 'path': path}, 404)

    # POST /h2-console → H2 Console JNDI RCE 探针
    if path == '/h2-console':
        if vuln:
            return html_body('<html><body>H2 Console<!--' + MARKER_H2
                             + '--><form>...</form></body></html>')
        return json_body({'timestamp': '...', 'status': 404,
                          'error': 'Not Found', 'path': path}, 404)

    # GET /actuator/mappings → 路由映射泄露
    if path == '/actuator/mappings':
        if vuln:
            return json_body({
                'contexts': {
                    'application': {
                        'mappings': {
                            'dispatcherServlets': {
                                'dispatcherServlet': [
                                    {'handler': 'com.example.IndexController#index()',
                                     'predicate': '{GET /}'},
                                ],
                            },
                        },
                    },
                },
            })
        return json_body({'timestamp': '...', 'status': 404,
                          'error': 'Not Found', 'path': path}, 404)

    # 其他路径 → Spring Boot 风格 JSON 404
    return json_body({'timestamp': '...', 'status': 404,
                      'error': 'Not Found', 'path': path}, 404)


@app.route('/', defaults={'p': ''}, methods=['GET', 'POST'])
@app.route('/<path:p>', methods=['GET', 'POST'])
def _route(p):
    return dispatch(request.path, request.method)


if __name__ == '__main__':
    print(f'[*] Spring Boot 签名靶场启动：MODE={MODE} PORT={PORT}')
    print(f'[*] 合法授权测试 / 教学验证用途，仅返回插件判定签名，不含真实漏洞利用')
    app.run(host='0.0.0.0', port=PORT, debug=False)
