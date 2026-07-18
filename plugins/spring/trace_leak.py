# Spring Boot Actuator /trace 请求历史泄露（信息泄露）
# 漏洞原因：/actuator/trace（Spring Boot 1.x）或 /actuator/httptrace（2.x）端点
#   可匿名访问，暴露最近请求历史（含 headers/cookies/sessions 等敏感信息），
#   便于攻击者窃取会话凭证、复现请求链、绘制攻击面（影响 Spring Boot 默认暴露配置）。
# 本插件仅做存在性验证：GET /actuator/trace 检测响应是否含 trace 泄露签名特征。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_trace_leak

# 漏洞命中签名（与 lab/spring_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
TRACE_LEAK_MARKER = 'spring-trace-leak-confirmed'


class SpringTraceLeakPlugin(PluginBase):
    name = 'Spring Boot Actuator /trace 请求历史泄露'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = '/actuator/trace 暴露最近请求历史，含 headers/cookies/sessions 等敏感信息'
    fix = '为 /actuator/trace 端点配置认证；或设置 management.endpoints.web.exposure.exclude=trace,httptrace'

    def verify(self, target, session):
        url = join_url(target, '/actuator/trace')
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('Spring Actuator /trace 泄露（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if TRACE_LEAK_MARKER in text:
            print(ok('存在 Spring Boot Actuator /trace 请求历史泄露漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 /trace 泄露特征：{TRACE_LEAK_MARKER}',
                fix=self.fix,
            )
        # 真实漏洞响应：/actuator/trace 返回 200 + traces 数组 / timeTaken 等特征
        if resp.status_code == 200 and match_trace_leak(text):
            print(ok('存在 Spring Boot Actuator /trace 请求历史泄露漏洞（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence='响应含 /trace 请求历史特征（traces 数组 / timeTaken），证实 trace 端点暴露',
                fix=self.fix,
            )
        print(no('不存在 Spring Boot Actuator /trace 请求历史泄露漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 /trace 泄露特征（端点不可达或已修复）')
