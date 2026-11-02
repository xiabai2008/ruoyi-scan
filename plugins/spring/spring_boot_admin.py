# Spring Boot Admin 未授权访问
import json

from common.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase

# SBA 的 JSON API 返回实例/应用列表；SPA 壳页不含该标识。
_SBA_HTML_MARKER = "spring-boot-admin"


class SpringBootAdminPlugin(PluginBase):
    name = "Spring Boot Admin 未授权访问"
    cve = "N/A"
    severity = SEVERITY_MEDIUM
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    # v1.6：判定的是「**未登录**能否访问」，必须用匿名会话探测
    # （实际隔离动作在 verify() 里，见 core/session.py::SessionManager.anonymous）。
    anonymous_probe = True
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

    @staticmethod
    def _json_item_count(body: str) -> int:
        """解析 SBA JSON 响应，返回实例/应用数量；不是有效列表时返回 0。

        SBA 的 /applications、/instances、/wallboard 在 `Accept: application/json`
        下返回 JSON 数组；部分版本包一层 {"applications": [...]} / {"instances": [...]}。
        空数组、SPA 壳页、错误 JSON 一律不算命中。
        """
        try:
            payload = json.loads(body or "")
        except (TypeError, ValueError):
            return 0
        if isinstance(payload, list):
            return len(payload)
        if isinstance(payload, dict):
            for key in ("instances", "applications"):
                value = payload.get(key)
                if isinstance(value, list):
                    return len(value)
        return 0

    def verify(self, target, session):
        """未授权判定必须用**匿名会话**：高权会话下的 200 是「登录后可读」，不是未授权。

        与 ruoyi 侧的 nacos/minio/unauth_batch 同一口径（core.session.SessionManager.anonymous）。
        复用共享会话时，若调用方注入了 cookie/token（--auth / --auth-login），
        本插件会把「已鉴权的正常响应」误读成「未授权暴露」——
        客户现场最常见的形态是「Actuator 开了但配了认证」，此时报告会写
        「可匿名访问」，复核时被当场打回（2026-11-02 能力缺口调研 P1-13）。
        """
        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        try:
            return self._verify_anonymous(target, probe)
        finally:
            if probe is not session:
                probe.close()

    def _verify_anonymous(self, target, session) -> ScanResult:
        """验证 SBA 未授权访问：带 Accept: application/json 探测 3 个管理端点。

        判定顺序：
        1. JSON 可解析且列表非空（或 dict 中的 instances/applications 非空）→ CONFIRMED
        2. JSON 不成立时回退 HTML 关键字（仅 spring-boot-admin 专有标识）→ CONFIRMED
        3. 至少拿到一个响应（含 404/403）且均未命中 → SAFE
        4. 三个端点全部请求异常（不可达 / 超时 / WAF 断连）→ UNKNOWN

        实测 2026-10-31 C2-1a：默认 Accept 返回 1279 字节 SPA 壳（判 SAFE），
        带 `Accept: application/json` 才返回 1876 字节实例列表——只请求 HTML 会漏报。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话
        @return: ScanResult
        """
        errors = []
        responded = 0
        for path in ["/applications", "/instances", "/wallboard"]:
            url = join_url(target, path)
            try:
                resp = session.get(url, headers={"Accept": "application/json"})
            # 单一路径异常视为不可达，继续探测其余路径（容错而非整体失败）
            except Exception as e:
                errors.append(f"{path}: {e}")
                continue
            responded += 1
            if resp.status_code != 200:
                continue
            body = resp.text or ""
            count = self._json_item_count(body)
            if count > 0:
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=f"{path} JSON 接口可未授权访问（{count} 个实例/应用）",
                    fix=self.fix,
                )
            # JSON 不成立才回退 HTML 判定：只认 SBA 专有标识，避免裸词 applications 误报。
            if _SBA_HTML_MARKER in body.lower():
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=f"{path} 页面含 SBA 专有标识，可未授权访问",
                    fix=self.fix,
                )
        if responded == 0:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=target,
                evidence="三个 SBA 端点均请求失败，无法判定（测不到 ≠ 安全）：" + "；".join(errors),
            )
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=target,
            evidence="未发现 SBA 未授权端点",
        )
