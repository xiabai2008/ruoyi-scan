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
    cve = 'N/A'
    severity = 'medium'
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
    compliance = '等保2.0:8.1.4;OWASP:A01:2021'
    category = 'vuln'
    description = '/actuator/mappings 暴露全部控制器映射与请求方法，泄露内部 API 结构'
    fix = '为 /actuator/mappings 端点配置认证；或设置 management.endpoints.web.exposure.exclude=mappings'
    fix_detail = (
        '【引入依赖】pom.xml 添加 Spring Security：\n'
        '  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>\n'
        '【配置加固】application.yml 收敛 Actuator 端点暴露：\n'
        '  management.endpoints.web.exposure.include: health,info  # 仅暴露必要端点\n'
        '  management.endpoints.web.exposure.exclude: mappings  # 显式排除 mappings\n'
        '【SecurityConfig】为 mappings 端点配置角色：\n'
        '  .antMatchers("/actuator/mappings").hasRole("ADMIN")\n'
        '【端口隔离】management.server.port: 9090  # 管理端口与业务端口分离，仅内网访问\n'
        '【WAF 规则】拦截外网对 /actuator/mappings 的访问\n'
        '【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制'
    )
    reproduce = (
        '# 1. 探测 mappings 端点可达性：\n'
        'curl -i "http://target/actuator/mappings"\n'
        '\n'
        '# 2. 读取全部控制器路由映射：\n'
        'curl "http://target/actuator/mappings" | python -m json.tool\n'
        '  # 返回 JSON 含 dispatcherServlets / handlerMappings 字段即泄露\n'
        '\n'
        '# 3. 提取所有 API 路径与方法（绘制攻击面）：\n'
        'curl -s "http://target/actuator/mappings" | jq ".. | .details?.requestMappingConditions?.patterns?"\n'
        '\n'
        '# 预期响应：200 + JSON 含 dispatcherServlets 字段即漏洞存在'
    )

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
