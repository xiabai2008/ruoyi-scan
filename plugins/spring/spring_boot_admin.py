# Spring Boot Admin 未授权访问
from common.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, ScanResult
from core.http import join_url
from plugins.base import PluginBase


class SpringBootAdminPlugin(PluginBase):
    name = "Spring Boot Admin 未授权访问"
    cve = "N/A"
    severity = SEVERITY_MEDIUM
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    description = "Spring Boot Admin 监控界面未设置认证，可查看所有注册服务的状态、配置、日志等敏感信息"
    fix = "为 Spring Boot Admin Server 添加 spring-boot-admin-server-ui 的登录认证"
    fix_detail = (
        "【引入依赖】pom.xml 添加 Spring Security 与 SBA 安全集成：\n"
        "  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>\n"
        "  <dependency><groupId>de.codecentric</groupId><artifactId>spring-boot-admin-server-ui-login</artifactId></dependency>\n"
        "【配置加固】application.yml 配置 SBA 登录账号：\n"
        "  spring.security.user.name: admin\n"
        "  spring.security.user.password: <strong-password>\n"
        "  spring.security.user.roles: ADMIN\n"
        "【SecurityConfig】为 SBA 路径配置认证：\n"
        "  http.authorizeRequests()\n"
        '      .antMatchers("/assets/**", "/login").permitAll()\n'
        '      .antMatchers("/**").hasRole("ADMIN")\n'
        "      .and().formLogin()\n"
        "【端口隔离】SBA Server 独立部署于内网，仅通过 VPN 访问\n"
        "【WAF 规则】拦截外网对 /applications /wallboard /instances 的访问\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测 Spring Boot Admin 主页：\n"
        'curl -i "http://target/"\n'
        "  # 返回 200 + HTML 含 spring-boot-admin 即 SBA 暴露\n"
        "\n"
        "# 2. 访问注册服务列表（无认证）：\n"
        'curl "http://target/applications" | head -200\n'
        "\n"
        "# 3. 访问实例详情与日志：\n"
        'curl "http://target/instances" | head -200\n'
        'curl "http://target/wallboard" | head -200\n'
        "\n"
        "# 预期响应：200 + HTML 含 applications / spring-boot-admin 关键字即漏洞存在"
    )

    def verify(self, target, session) -> ScanResult:
        """验证 SBA 未授权访问：依次探测 3 个管理端点，任一端点命中关键字即确认。
        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话
        @return: ScanResult——命中任一端点返回 CONFIRMED，全部未命中返回 SAFE
        """
        for path in ["/applications", "/wallboard", "/instances"]:
            url = join_url(target, path)
            try:
                resp = session.get(url)
                # 只匹配响应前 500 字符：SBA 页面体积大，关键字头部即可命中，避免全量匹配开销
                if resp.status_code == 200 and any(
                    kw in (resp.text or "")[:500] for kw in ["spring-boot-admin", "applications"]
                ):
                    return ScanResult(
                        kind=self.category,
                        name=self.name,
                        severity=self.severity,
                        status=STATUS_CONFIRMED,
                        url=url,
                        evidence=f"{path} 可未授权访问",
                        fix=self.fix,
                    )
            # 单一路径异常视为不可达，继续探测其余路径（容错而非整体失败）
            except Exception:
                continue
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=target,
            evidence="未发现 SBA 未授权端点",
        )
