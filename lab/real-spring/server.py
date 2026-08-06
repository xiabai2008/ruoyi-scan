# Spring Boot 真实漏洞响应复现靶场（阶段九交叉验证用）
#
# 设计目标：精确复现 Spring Boot 真实漏洞环境的「响应特征」（不含扫描器约定的 marker），
# 用于验证 Spring 插件判定逻辑是否能在真实漏洞响应上正确判定 CONFIRMED。
#
# 与 lab/spring_server.py（签名靶场）的区别：
# - 签名靶场返回 marker 字符串（如 'spring-actuator-env-rce-confirmed'）
# - 本靶场返回真实 Spring Boot 漏洞响应（如 propertySources JSON、JAVA PROFILE 二进制等）
#
# 仅用于合法授权测试 / 教学验证，不实现任何真实漏洞利用。
import json
import os

from flask import Flask, Response, request

PORT = int(os.environ.get('LAB_PORT', '8086'))

app = Flask(__name__)


def json_body(d, code=200):
    return Response(json.dumps(d, ensure_ascii=False), status=code,
                    mimetype='application/json; charset=utf-8')


def html_body(body, code=200):
    return Response(body, status=code, mimetype='text/html; charset=utf-8')


def binary_body(data, code=200):
    return Response(data, status=code, mimetype='application/octet-stream')


def actuator_links():
    """标准 Spring Boot Actuator HAL JSON（真实响应：含 _links + 端点列表）"""
    return {
        '_links': {
            'self': {'href': f'http://localhost:{PORT}/actuator', 'templated': False},
            'health': {'href': f'http://localhost:{PORT}/actuator/health', 'templated': False},
            'env': {'href': f'http://localhost:{PORT}/actuator/env', 'templated': False},
            'heapdump': {'href': f'http://localhost:{PORT}/actuator/heapdump', 'templated': False},
            'mappings': {'href': f'http://localhost:{PORT}/actuator/mappings', 'templated': False},
            'trace': {'href': f'http://localhost:{PORT}/actuator/trace', 'templated': False},
            'jolokia': {'href': f'http://localhost:{PORT}/actuator/jolokia', 'templated': False},
            'gatewayroutes': {'href': f'http://localhost:{PORT}/actuator/gateway/routes', 'templated': False},
        }
    }


def actuator_env_json():
    """/actuator/env 真实响应：含 propertySources + 系统属性 + 密码（脱敏）"""
    return {
        'activeProfiles': ['prod'],
        'propertySources': [
            {
                'name': 'systemProperties',
                'properties': {
                    'java.runtime.name': {'value': 'Java(TM) SE Runtime Environment'},
                    'java.vm.version': {'value': '17.0.1+12-39'},
                    'os.name': {'value': 'Linux'},
                },
            },
            {
                'name': 'applicationConfig: [classpath:/application.yml]',
                'properties': {
                    'server.port': {'value': 8080, 'origin': 'class path resource [application.yml]:1:5'},
                    'spring.datasource.password': {'value': '******'},
                    'spring.datasource.url': {
                        'value': 'jdbc:mysql://localhost:3306/prod_db?useSSL=false',
                        'origin': 'class path resource [application.yml]:5:9',
                    },
                },
            },
        ],
    }


def heapdump_binary():
    """真实 heapdump 二进制响应：JAVA PROFILE 头 + 实例数据（含敏感字符串）"""
    # hprof 文件头：JAVA PROFILE 1.0.2 + 时间戳 + 标识符
    header = b'JAVA PROFILE 1.0.2\n'
    # 模拟堆中字符串实例（含敏感信息）
    sensitive_strings = [
        b'jdbc:mysql://localhost:3306/prod_db',
        b'password=Admin@2024',
        b'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        b'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        b'private_key=-----BEGIN RSA PRIVATE KEY-----',
    ]
    body = b'\x00\x01\x02\x03' + b'\n'.join(sensitive_strings) + b'\n\x04\x05\x06'
    return header + body


def h2_console_html():
    """真实 H2 Console HTML 响应（含登录表单）"""
    return '''<!DOCTYPE html>
<html><head><title>H2 Console</title></head>
<body>
<h1>H2 Console</h1>
<form method="post" action="/h2-console">
<input type="hidden" name="language" value="en"/>
<input type="hidden" name="setting" value="Generic H2 (Embedded)"/>
<input type="text" name="driver" value="org.h2.Driver"/>
<input type="text" name="url" value="jdbc:h2:mem:test"/>
<input type="submit" value="Connect"/>
</form>
</body></html>'''


def cloud_function_response():
    """真实 Spring Cloud Function SpEL 求值响应：返回 7*7 的结果 49"""
    # 真实 SpEL T(java.lang.String).valueOf(7*7) 求值返回 "49"
    return '49'


def gateway_route_created():
    """真实 Spring Cloud Gateway 路由创建响应：201 Created + 路由信息"""
    return {
        'id': 'test-route-probe',
        'filters': [{'name': 'AddResponseHeader', 'args': {'name': 'X-Probe', 'value': 'c22947'}}],
        'uri': 'http://localhost:1',
        'order': 0,
    }


def jolokia_list_response():
    """真实 Jolokia /list 响应：含 JMX MBean 域列表"""
    return {
        'timestamp': 1700000000,
        'status': 200,
        'request': {'type': 'LIST'},
        'value': {
            'java.lang': {
                'type=Memory': {'op': {}, 'attr': {'HeapMemoryUsage': {'rw': False, 'type': 'javax.management.openmbean.CompositeData'}}},
            },
            'com.sun.management': {
                'type=DiagnosticCommand': {'op': {'gcInfo': {'args': 0, 'desc': 'gcInfo'}}},
            },
            'ch.qos.logback.classic': {
                'Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator': {
                    'op': {'reloadByURL': {'args': 1, 'desc': 'Reload logback config from URL'}},
                },
            },
        },
    }


def jolokia_exec_response():
    """真实 Jolokia reloadByURL EXEC 响应"""
    return {
        'timestamp': 1700000000,
        'status': 200,
        'request': {
            'type': 'EXEC',
            'mbean': 'ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator',
            'operation': 'reloadByURL',
            'arguments': ['http://jolokia-probe.test/logback.xml'],
        },
        'value': None,
    }


def mappings_response():
    """真实 /actuator/mappings 响应：含 dispatcherServlets 控制器映射"""
    return {
        'contexts': {
            'application': {
                'mappings': {
                    'dispatcherServlets': {
                        'dispatcherServlet': [
                            {
                                'handler': 'com.example.IndexController#index()',
                                'predicate': '{GET /}',
                                'details': {
                                    'handlerMethod': {
                                        'className': 'com.example.IndexController',
                                        'name': 'index',
                                        'descriptor': '()Ljava/lang/String;',
                                    },
                                    'requestMappingConditions': {
                                        'patterns': ['/'], 'methods': ['GET'],
                                    },
                                },
                            },
                            {
                                'handler': 'com.example.UserController#list()',
                                'predicate': '{GET /api/users}',
                            },
                        ],
                    },
                },
            },
        },
    }


def trace_response():
    """真实 /actuator/trace 响应：含 traces 数组（请求历史）"""
    return {
        'traces': [
            {
                'timestamp': '2024-01-01T00:00:00.000Z',
                'request': {
                    'method': 'GET',
                    'uri': 'http://localhost:8080/actuator/env',
                    'headers': {
                        'Cookie': ['SESSION=abc123def456'],
                        'Authorization': ['Bearer eyJhbGciOiJIUzI1NiJ9'],
                    },
                },
                'response': {
                    'status': 200,
                    'headers': {'Content-Type': ['application/json']},
                },
                'timeTaken': 5,
            },
            {
                'timestamp': '2024-01-01T00:00:01.000Z',
                'request': {
                    'method': 'POST',
                    'uri': 'http://localhost:8080/login',
                    'headers': {'Content-Type': ['application/x-www-form-urlencoded']},
                },
                'response': {'status': 200, 'headers': {}},
                'timeTaken': 23,
            },
        ],
    }


@app.route('/', defaults={'p': ''}, methods=['GET', 'POST'])
@app.route('/<path:p>', methods=['GET', 'POST'])
def _route(p):
    path = request.path
    method = request.method

    # 根路径：Spring4Shell 探针（POST class.module.classLoader）
    if path == '/':
        if method == 'POST':
            if any('class.module.classLoader' in k for k in request.form.keys()):
                # 真实 Spring4Shell 利用不直接返回特征，但 Tomcat 会回 200
                # 配合日志写入后续 GET 验证 webshell（这里返回 200 即可触发后续判定逻辑增强）
                return json_body({'timestamp': '2024-01-01T00:00:00.000Z', 'status': 200})
            return json_body({'status': 200, 'message': 'ok'})
        # GET / → Spring Boot WhiteLabel 404
        return json_body({'timestamp': '2024-01-01T00:00:00.000Z', 'status': 404,
                          'error': 'Not Found', 'path': '/'}, 404)

    # /actuator → HAL JSON（真实 Spring Boot Actuator 响应）
    if path == '/actuator':
        return json_body(actuator_links())

    if path == '/actuator/health':
        return json_body({'status': 'UP'})

    # GET /actuator/env → actuator_unauth 第二关（真实响应）
    if path == '/actuator/env':
        if method == 'POST':
            # actuator_env_rce 探针：真实响应是 200 JSON 含 propertySources 或 200 简单 JSON
            return json_body({'timestamp': '2024-01-01T00:00:00.000Z', 'status': 200})
        return json_body(actuator_env_json())

    # GET /actuator/heapdump → 真实 heapdump 二进制
    if path == '/actuator/heapdump':
        return binary_body(heapdump_binary())

    # POST /actuator/gateway/routes/test → 真实 201 Created 响应
    if path.startswith('/actuator/gateway/routes/'):
        return json_body(gateway_route_created(), code=201)

    # GET /actuator/jolokia/list → 真实 Jolokia LIST 响应
    if path == '/actuator/jolokia/list':
        return json_body(jolokia_list_response())

    # GET / POST /actuator/jolokia → 真实 Jolokia EXEC 响应
    if path == '/actuator/jolokia' or path.startswith('/actuator/jolokia/'):
        if method == 'POST':
            return json_body(jolokia_exec_response())
        return json_body(jolokia_list_response())

    # POST /functionRouter → 真实 Cloud Function SpEL 求值响应（49 = 7*7）
    if path == '/functionRouter':
        return Response(cloud_function_response(), status=200, mimetype='text/plain')

    # POST /h2-console → 真实 H2 Console HTML
    if path == '/h2-console':
        return html_body(h2_console_html())

    # GET /actuator/mappings → 真实 mappings 响应
    if path == '/actuator/mappings':
        return json_body(mappings_response())

    # GET /actuator/trace → 真实 trace 响应
    if path == '/actuator/trace':
        return json_body(trace_response())

    # 其他路径 → Spring Boot 风格 JSON 404
    return json_body({'timestamp': '2024-01-01T00:00:00.000Z', 'status': 404,
                      'error': 'Not Found', 'path': path}, 404)


if __name__ == '__main__':
    print(f'[*] Spring Boot 真实漏洞响应复现靶场启动：PORT={PORT}')
    print('[*] 仅用于阶段九交叉验证，返回真实 Spring Boot 漏洞响应特征（不含 marker）')
    app.run(host='0.0.0.0', port=PORT, debug=False)
