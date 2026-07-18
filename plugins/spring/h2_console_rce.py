# Spring Boot Actuator H2 Database Console 未授权访问 + JNDI RCE
# 漏洞原因：spring-boot-starter-actuator 搭配 H2 数据库时，/h2-console 端点可匿名访问，
#   攻击者可通过 JNDI 连接字符串登录 H2 控制台执行任意 SQL / 代码（high）。
# 本插件仅做存在性验证：POST /h2-console 带 JNDI 连接探针，检测响应特征判定接口可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_h2_console

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
H2_MARKER = 'spring-h2-console-rce-confirmed'


class SpringH2ConsoleRcePlugin(PluginBase):
    name = 'Spring Boot Actuator H2 Console 未授权 JNDI RCE'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = 'H2 Console 可匿名访问，通过 JNDI 连接字符串执行任意代码（影响 H2 + Actuator）'
    fix = '为 /h2-console 配置认证；禁用 H2 Console 生产环境；移除 H2 依赖改用生产级数据库'

    def verify(self, target, session):
        url = join_url(target, '/h2-console')
        # JNDI 连接探针（仅触发签名，不执行真实 JNDI 查找）
        data = {
            'language': 'en',
            'setting': 'Generic+H2+(Embedded)',
            'name': 'Generic+H2+(Embedded)',
            'driver': 'javax.naming.InitialContext',
            'url': 'jdbc:h2:mem:probe',
        }
        try:
            resp = session.post(url, data=data)
        except Exception as e:
            print(no('Spring H2 Console RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if H2_MARKER in text:
            print(ok('存在 Spring Boot Actuator H2 Console 未授权 JNDI RCE'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 H2 Console RCE 特征：{H2_MARKER}',
                fix=self.fix,
            )
        # 真实漏洞响应：响应含 H2 Console HTML 特征（<title>H2 Console</title> 等）
        if resp.status_code == 200 and match_h2_console(text):
            print(ok('存在 Spring Boot Actuator H2 Console 未授权 JNDI RCE（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence='响应含 H2 Console 页面特征（H2 Console 标题 / 表单），证实 H2 Console 可达',
                fix=self.fix,
            )
        print(no('不存在 Spring Boot Actuator H2 Console 未授权 JNDI RCE'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='H2 Console 不可达或已修复（404/401）')
