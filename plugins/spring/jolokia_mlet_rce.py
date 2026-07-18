# Spring Boot Actuator Jolokia MLet 链远程代码执行（远程 MBean 加载 RCE）
# 漏洞原因：Spring Boot Actuator 集成 Jolokia（JMX-HTTP 桥），/actuator/jolokia/list
#   端点可被滥用：攻击者通过 MLet（javax.management.loading.MLet）加载远程恶意 MBean，
#   注册并调用任意代码 MBean（如自定义 MBean），实现远程代码执行。
#   影响 Spring Boot + Jolokia 全版本（Jolokia 端点未授权暴露时）。
# 本插件仅做存在性验证：GET /actuator/jolokia/list 检测响应是否含 MLet 链签名特征。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_jolokia_response

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
JOLOKIA_MLET_MARKER = 'spring-jolokia-mlet-rce-confirmed'


class SpringJolokiaMletRcePlugin(PluginBase):
    name = 'Spring Boot Actuator Jolokia MLet 链远程代码执行'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = 'Jolokia /actuator/jolokia/list 可被滥用通过 MLet 加载远程 MBean 触发 RCE'
    fix = '移除 jolokia 依赖或禁用 Jolokia 端点；为 /actuator/jolokia 配置认证；限制 MBean 加载'

    def verify(self, target, session):
        url = join_url(target, '/actuator/jolokia/list')
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('Spring Jolokia MLet RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if JOLOKIA_MLET_MARKER in text:
            print(ok('存在 Spring Boot Actuator Jolokia MLet 链远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 Jolokia MLet 链特征：{JOLOKIA_MLET_MARKER}',
                fix=self.fix,
            )
        # 真实漏洞响应：Jolokia LIST 响应含 JMX MBean 域列表（reloadByURL / JMXConfigurator 等）
        if resp.status_code == 200 and match_jolokia_response(text):
            print(ok('存在 Spring Boot Actuator Jolokia MLet 链远程代码执行漏洞（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence='响应含 Jolokia JMX MBean 响应特征（reloadByURL/JMXConfigurator），证实 Jolokia 端点可达',
                fix=self.fix,
            )
        print(no('不存在 Spring Boot Actuator Jolokia MLet 链远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 Jolokia MLet 链特征（端点不可达或已修复）')
