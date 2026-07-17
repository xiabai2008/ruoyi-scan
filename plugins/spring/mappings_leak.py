# Spring Boot Actuator /mappings 路由映射泄露（信息泄露）
# 漏洞原因：/actuator/mappings 端点可匿名访问，暴露应用全部 URL 映射、控制器类名、
#   请求方法等内部细节，便于攻击者绘制攻击面（影响 Spring Boot 1.x ~ 2.x 默认暴露）。
# 本插件仅做存在性验证：GET /actuator/mappings 200+JSON 且含 handler/dispatcher 特征。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url


class SpringMappingsLeakPlugin(PluginBase):
    name = 'Spring Boot Actuator /mappings 路由映射泄露'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = '/actuator/mappings 暴露全部控制器映射与请求方法，泄露内部 API 结构'
    fix = '为 /actuator/mappings 端点配置认证；或设置 management.endpoints.web.exposure.exclude=mappings'

    def verify(self, target, session):
        url = join_url(target, '/actuator/mappings')
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('Spring Actuator /mappings 泄露（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        ct = (resp.headers.get('Content-Type') or '').lower()
        text = resp.text or ''

        # 判别：200 + JSON + 含 mappings/dispatcherServlets 特征
        if resp.status_code == 200 and 'json' in ct and 'dispatcherServlets' in text:
            print(ok('存在 Spring Boot Actuator /mappings 路由映射泄露'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence='响应含 dispatcherServlets 映射（泄露控制器与请求方法）',
                fix=self.fix,
            )
        print(no('不存在 Spring Boot Actuator /mappings 路由映射泄露'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='/actuator/mappings 不可达或需认证（404/401）')
