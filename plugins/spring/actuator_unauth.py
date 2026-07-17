# Spring Boot Actuator 未授权访问（信息泄露 / 配置暴露）
# 漏洞原因：Actuator 端点未配置认证，/actuator/env 等暴露配置、环境变量、密码与密钥。
# 本插件仅做存在性验证：探测 /actuator 与 /actuator/env 是否均可匿名访问。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url


class SpringActuatorUnauthPlugin(PluginBase):
    name = 'Spring Boot Actuator 未授权访问'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = 'Actuator 端点 /actuator/env 可匿名访问，泄露环境变量、配置属性与密钥'
    fix = '引入 spring-boot-starter-security 为 Actuator 端点配置认证；或设置 management.endpoints.web.exposure.include 白名单'

    def verify(self, target, session):
        # 第一关：/actuator 是否可访问（返回 HAL JSON）
        url_root = join_url(target, '/actuator')
        try:
            r1 = session.get(url_root)
        except Exception as e:
            print(no('Spring Boot Actuator 未授权（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url_root, evidence=str(e))

        if r1.status_code != 200 or 'application/json' not in (r1.headers.get('Content-Type', '') or ''):
            print(no('不存在 Spring Boot Actuator 未授权（/actuator 不可达）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url_root,
                              evidence='/actuator 不可达（404 或非 JSON 响应）')

        # 第二关：/actuator/env 是否可访问（含配置属性）
        url_env = join_url(target, '/actuator/env')
        try:
            r2 = session.get(url_env)
        except Exception as e:
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url_env, evidence=str(e))

        if r2.status_code == 200 and 'application/json' in (r2.headers.get('Content-Type', '') or ''):
            print(ok('存在 Spring Boot Actuator 未授权访问'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url_env,
                evidence='/actuator/env 可匿名访问，泄露环境变量与配置属性',
                fix=self.fix,
            )
        print(no('不存在 Spring Boot Actuator 未授权（/actuator/env 需认证）'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url_env,
                          evidence='/actuator 可达但 /actuator/env 需认证（端点已保护）')
