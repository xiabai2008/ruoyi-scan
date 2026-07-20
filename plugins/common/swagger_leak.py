# Swagger/OpenAPI 文档泄露 — 常见 API 文档路径探测
from common.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, ScanResult
from core.http import join_url
from plugins.base import PluginBase


class SwaggerLeakPlugin(PluginBase):
    """检测目标是否存在 Swagger/OpenAPI/Knife4j 等 API 文档未授权访问"""

    name = "Swagger API 文档泄露"
    cve = "N/A"
    severity = SEVERITY_MEDIUM
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    description = "目标存在未授权的 API 文档界面，攻击者可了解全部 API 接口、参数及数据结构，辅助进一步攻击"
    fix = "为 Swagger/API 文档添加访问认证，或在生产环境中禁用 Swagger 端点"
    fix_detail = (
        "【配置加固·Spring Boot】application.yml 生产环境禁用文档端点：\n"
        "  springdoc.api-docs.enabled: false\n"
        "  springdoc.swagger-ui.enabled: false\n"
        "  springfox.documentation.enabled: false          # springfox 旧版\n"
        "  knife4j.production: true                        # Knife4j 生产环境屏蔽\n"
        "【代码修复·Spring Security】SecurityConfig.configure() 强制鉴权：\n"
        '  http.antMatchers("/swagger-ui/**", "/swagger-ui.html",\n'
        '                   "/swagger-resources/**", "/v2/api-docs", "/v3/api-docs/**",\n'
        '                   "/doc.html", "/druid/**").authenticated()\n'
        "【配置加固·nginx】为文档端点加 Basic Auth 或限制内网访问：\n"
        '  location /swagger-ui/ { auth_basic "Restricted"; auth_basic_user_file /etc/nginx/.htpasswd; }\n'
        "  location /v3/api-docs { allow 10.0.0.0/8; deny all; }\n"
        "【配置加固·Druid】StatViewServlet 配置 loginUsername / loginPassword，并设置 allow IP 白名单\n"
        "【WAF 规则】拦截 /swagger-ui.html、/swagger-resources、/v2/api-docs、/v3/api-docs、/doc.html、/druid/index.html 外网访问\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测 Swagger UI 主界面：\n"
        'curl -i "http://target/swagger-ui.html"\n'
        'curl -i "http://target/swagger-ui/index.html"\n'
        'curl -i "http://target/doc.html"   # Knife4j\n'
        "\n"
        '# 预期响应（漏洞存在）：HTTP/1.1 200，HTML 含 "Swagger UI" / "knife4j" / "OpenAPI"\n'
        "\n"
        "# 2. 直接读取 API 定义 JSON（含全部接口、参数、模型）：\n"
        'curl "http://target/v2/api-docs" | python -m json.tool | head -100\n'
        'curl "http://target/v3/api-docs" | python -m json.tool\n'
        'curl "http://target/swagger-resources" | python -m json.tool\n'
        "\n"
        '# 预期响应：JSON 含 "swagger":"2.0" 或 "openapi":"3.0.x"，paths 列出全部接口\n'
        "\n"
        "# 3. Druid 监控台未授权（同属信息泄露）：\n"
        'curl -i "http://target/druid/index.html"\n'
        'curl -i "http://target/druid/sql.html"   # 可查看慢 SQL、执行过的语句\n'
        "\n"
        "# 4. 基于泄露的 API 文档批量调用敏感接口：\n"
        'curl "http://target/api/admin/users"     # 利用文档发现的越权接口\n'
        'curl -X POST "http://target/api/admin/user" -H "Content-Type: application/json" -d \'{"name":"test"}\''
    )

    # 常见 API 文档路径
    _SWAGGER_PATHS = [
        "/swagger-ui.html",
        "/swagger-ui/",
        "/swagger-ui/index.html",
        "/swagger-resources",
        "/swagger-resources/configuration/ui",
        "/v2/api-docs",
        "/v3/api-docs",
        "/v3/api-docs/swagger-config",
        "/doc.html",
        "/api-docs",
        "/api.html",
        "/druid/index.html",  # Druid 监控（也属于信息泄露类）
    ]

    _POSITIVE = ["swagger", "Swagger", "openapi", "OpenAPI", "api-docs", "Knife4j", "swagger-ui", '"swagger"']

    def verify(self, target, session) -> ScanResult:
        found = []
        for path in self._SWAGGER_PATHS:
            url = join_url(target, path)
            try:
                resp = session.get(url)
                if resp.status_code != 200:
                    continue
                text = (resp.text or "")[:500]
                ct = (resp.headers.get("Content-Type") or "").lower()
                # JSON API 文档 或 HTML Swagger 界面
                if ("json" in ct and ('"swagger"' in text or '"openapi"' in text or '"paths"' in text)) or any(
                    kw in text for kw in self._POSITIVE
                ):
                    found.append(path)
            except Exception:
                continue
        if found:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=target,
                evidence=f"发现 {len(found)} 个 API 文档端点: {', '.join(found)}",
                extra={"paths": found},
                fix=self.fix,
            )
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=target,
            evidence="未发现公开的 Swagger/Druid API 文档",
        )
