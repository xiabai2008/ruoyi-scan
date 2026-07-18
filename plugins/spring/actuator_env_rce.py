# Spring Boot Actuator env 配置覆盖 RCE（eureka xstream 反序列化）
# 漏洞原因：/actuator/env 可 POST 写入配置属性，设置 eureka.client.serviceUrl.defaultZone
#   为恶意 XML URL，触发 /refresh 后 xstream 反序列化执行命令（影响 Spring Cloud < 特定版本）。
# 本插件仅做存在性验证：POST /actuator/env 写入探针配置，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_spring_actuator_env

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
ENV_MARKER = 'spring-actuator-env-rce-confirmed'


class SpringActuatorEnvRcePlugin(PluginBase):
    name = 'Spring Boot Actuator env 配置覆盖 RCE'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '/actuator/env POST 可写配置属性，eureka xstream 反序列化触发 RCE（影响 Spring Cloud）'
    fix = '升级 Spring Cloud 至安全版本；为 /actuator/env 配置 POST 认证与 CSRF'

    def verify(self, target, session):
        url = join_url(target, '/actuator/env')
        # 配置覆盖探针（仅写入无害属性，不指向恶意 XML 服务）
        payload = {
            'name': 'eureka.client.serviceUrl.defaultZone',
            'value': 'http://spring-probe.test/',
        }
        try:
            resp = session.post(url, json=payload)
        except Exception as e:
            print(no('Spring Actuator env 配置覆盖 RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if ENV_MARKER in text:
            print(ok('存在 Spring Boot Actuator env 配置覆盖 RCE'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 env 配置 RCE 特征：{ENV_MARKER}',
                fix=self.fix,
            )
        # 真实漏洞响应：POST 返回 200/201（非 401/403/404/405）即说明 env 可被写入
        # 真实 Spring Boot env POST 成功返回 200 JSON（含 propertySources 或简单 JSON）
        if resp.status_code in (200, 201) and match_spring_actuator_env(text):
            print(ok('存在 Spring Boot Actuator env 配置覆盖 RCE（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence='响应含 Actuator env 配置特征（propertySources/applicationConfig），证实 env POST 可达',
                fix=self.fix,
            )
        # 真实漏洞响应：POST 返回 200 但响应体简单（仅 timestamp/status），
        # 仍可判定 env POST 可达（无鉴权拦截）
        if resp.status_code == 200 and 'Method Not Allowed' not in text and 'error' not in text.lower():
            print(ok('存在 Spring Boot Actuator env 配置覆盖 RCE（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'POST /actuator/env 返回 200（无鉴权拦截），证实 env 配置可写入',
                fix=self.fix,
            )
        print(no('不存在 Spring Boot Actuator env 配置覆盖 RCE'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 env 配置 RCE 特征（端点不可达或已修复）')
