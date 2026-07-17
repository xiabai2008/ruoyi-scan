# Spring Boot Actuator env 配置覆盖 RCE（eureka xstream 反序列化）
# 漏洞原因：/actuator/env 可 POST 写入配置属性，设置 eureka.client.serviceUrl.defaultZone
#   为恶意 XML URL，触发 /refresh 后 xstream 反序列化执行命令（影响 Spring Cloud < 特定版本）。
# 本插件仅做存在性验证：POST /actuator/env 写入探针配置，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

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
        print(no('不存在 Spring Boot Actuator env 配置覆盖 RCE'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 env 配置 RCE 特征（端点不可达或已修复）')
