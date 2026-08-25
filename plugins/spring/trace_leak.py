# Spring Boot Actuator /trace 请求历史泄露（信息泄露）
# 漏洞原因：/actuator/trace（Spring Boot 1.x）或 /actuator/httptrace（2.x）端点
#   可匿名访问，暴露最近请求历史（含 headers/cookies/sessions 等敏感信息），
#   便于攻击者窃取会话凭证、复现请求链、绘制攻击面（影响 Spring Boot 默认暴露配置）。
# 本插件仅做存在性验证：GET /actuator/trace 检测响应是否含 trace 泄露签名特征。
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_trace_leak
from plugins.base import PluginBase

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
TRACE_LEAK_MARKER = "spring-trace-leak-confirmed"


class SpringTraceLeakPlugin(PluginBase):
    name = "Spring Boot Actuator /trace 请求历史泄露"
    cve = "N/A"
    severity = "medium"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    description = "/actuator/trace 暴露最近请求历史，含 headers/cookies/sessions 等敏感信息"
    fix = "为 /actuator/trace 端点配置认证；或设置 management.endpoints.web.exposure.exclude=trace,httptrace"
    fix_detail = (
        "【引入依赖】pom.xml 添加 Spring Security：\n"
        "  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>\n"
        "【配置加固】application.yml 收敛 trace/httptrace 端点：\n"
        "  management.endpoints.web.exposure.include: health,info\n"
        "  management.endpoints.web.exposure.exclude: trace,httptrace\n"
        "  # Spring Boot 1.x: endpoints.trace.enabled: false\n"
        "【SecurityConfig】为 trace 端点配置角色：\n"
        '  .antMatchers("/actuator/trace", "/actuator/httptrace").hasRole("ADMIN")\n'
        "【端口隔离】management.server.port: 9090  # 管理端口与业务端口分离，仅内网访问\n"
        "【WAF 规则】拦截外网对 /actuator/trace 与 /actuator/httptrace 的访问\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测 Spring Boot 1.x 的 trace 端点：\n"
        'curl -i "http://target/actuator/trace"\n'
        "\n"
        "# 2. 探测 Spring Boot 2.x 的 httptrace 端点：\n"
        'curl -i "http://target/actuator/httptrace"\n'
        "\n"
        "# 3. 读取最近请求历史（含 headers/cookies/sessions）：\n"
        'curl "http://target/actuator/httptrace" | python -m json.tool\n'
        "  # 返回 JSON 含 traces 数组与 timeTaken 字段即泄露\n"
        "\n"
        "# 预期响应：200 + JSON 含 traces 数组（含 Cookie/Authorization 头）即漏洞存在"
    )

    def verify(self, target, session):
        """验证 /trace 请求历史泄露：GET /actuator/trace 并判定 traces 数组特征。
        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话
        @return: ScanResult——命中 trace 特征返回 CONFIRMED，否则 SAFE，网络异常 UNKNOWN
        """
        url = join_url(target, "/actuator/trace")
        try:
            resp = session.get(url)
        except Exception as e:
            print(no("Spring Actuator /trace 泄露（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        if TRACE_LEAK_MARKER in text:
            print(ok("存在 Spring Boot Actuator /trace 请求历史泄露漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"响应含 /trace 泄露特征：{TRACE_LEAK_MARKER}",
                fix=self.fix,
            )
        # 探测 Boot 1.x 的 /actuator/trace（2.x 为 /actuator/httptrace），matcher 对两种端点响应形态均兼容
        # 真实漏洞响应：/actuator/trace 返回 200 + traces 数组 / timeTaken 等特征
        if resp.status_code == 200 and match_trace_leak(text):
            print(ok("存在 Spring Boot Actuator /trace 请求历史泄露漏洞（真实漏洞响应）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 /trace 请求历史特征（traces 数组 / timeTaken），证实 trace 端点暴露",
                fix=self.fix,
            )
        print(no("不存在 Spring Boot Actuator /trace 请求历史泄露漏洞"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=url,
            evidence="响应未含 /trace 泄露特征（端点不可达或已修复）",
        )
