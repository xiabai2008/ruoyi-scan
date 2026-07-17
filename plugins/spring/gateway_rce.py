# CVE-2022-22947 Spring Cloud Gateway 远程代码执行
# 漏洞原因：Actuator 暴露 /gateway/routes/ 端点，可 POST 创建含恶意 Filter 的路由触发
#   SPEL 表达式求值执行任意命令（影响 Spring Cloud Gateway 3.1.x）。
# 本插件仅做存在性验证：POST 创建测试路由探针，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
GW_MARKER = 'spring-gateway-rce-confirmed'


class SpringGatewayRcePlugin(PluginBase):
    name = 'CVE-2022-22947 Spring Cloud Gateway 远程代码执行'
    cve = 'CVE-2022-22947'
    severity = 'high'
    category = 'vuln'
    description = 'Actuator /gateway/routes/ 端点可匿名创建路由，SPEL Filter 求值触发 RCE'
    fix = '升级 Spring Cloud Gateway 至 3.1.1+ / 3.0.7+；为 Actuator 端点配置认证'

    def verify(self, target, session):
        url = join_url(target, '/actuator/gateway/routes/test')
        # 路由创建探针（仅触发接口签名，不执行真实 SPEL）
        payload = {
            'id': 'test-route-probe',
            'filters': [{'name': 'AddResponseHeader', 'args': {'name': 'X-Probe', 'value': 'c22947'}}],
            'uri': 'http://localhost:1',
            'order': 0,
        }
        try:
            resp = session.post(url, json=payload)
        except Exception as e:
            print(no('Spring Cloud Gateway RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if GW_MARKER in text:
            print(ok('存在 CVE-2022-22947 Spring Cloud Gateway 远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 Gateway RCE 特征：{GW_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 CVE-2022-22947 Spring Cloud Gateway 远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 Gateway RCE 特征（端点不可达或已修复）')
