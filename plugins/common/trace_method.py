# HTTP 方法探测 — OPTIONS 请求 + TRACE 探测
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, SEVERITY_LOW
from lib.http import join_url


class TraceMethodPlugin(PluginBase):
    """探测目标 Web 服务器支持的 HTTP 方法，检测是否开启危险的 TRACE 方法"""
    name = 'HTTP 方法探测'
    cve = 'N/A'
    severity = SEVERITY_LOW
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'
    compliance = '等保2.0:8.1.4;OWASP:A05:2021'
    category = 'recon'
    description = '通过 OPTIONS 请求探测目标支持的 HTTP 方法，检测 TRACE 方法是否开启（可被利用于跨站追踪攻击）'
    fix = '在 Web 服务器中禁用 TRACE/TRACK 方法；限制 Allow 头中仅暴露必要方法'
    fix_detail = (
        '【配置加固·nginx】nginx 默认不处理 TRACE，确保未通过第三方模块启用；限制仅允许必要方法：\n'
        '  limit_except GET POST { deny all; }\n'
        '  # 显式拒绝 TRACE/TRACK：\n'
        '  if ($request_method = TRACE) { return 405; }\n'
        '  if ($request_method = TRACK) { return 405; }\n'
        '【配置加固·Apache】httpd.conf 全局关闭 TRACE：\n'
        '  TraceEnable off\n'
        '【配置加固·Tomcat】conf/server.xml 的 Connector 添加 allowTrace="false"：\n'
        '  <Connector port="8080" protocol="HTTP/1.1" allowTrace="false" />\n'
        '【配置加固·IIS】Request Filtering → HTTP Verbs → Deny Verb：TRACE、TRACK\n'
        '  或 web.config：<security><requestFiltering><verbs><add verb="TRACE" allowed="false"/></verbs></requestFiltering></security>\n'
        '【WAF 规则】拒绝 TRACE/TRACK 方法请求，返回 405 Method Not Allowed；监测 Allow 头中是否暴露危险方法\n'
        '【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制'
    )
    reproduce = (
        '# 1. OPTIONS 探测目标支持的 HTTP 方法：\n'
        'curl -i -X OPTIONS "http://target/"\n'
        '\n'
        '# 预期响应：\n'
        '#   HTTP/1.1 200\n'
        '#   Allow: GET,HEAD,POST,OPTIONS,TRACE     # 含 TRACE 即存在风险\n'
        '\n'
        '# 2. TRACE 方法探测（XST 跨站追踪，可绕过 HttpOnly 读取 Cookie）：\n'
        'curl -i -X TRACE "http://target/"\n'
        'curl -i -H "Cookie: session=secret" -X TRACE "http://target/"\n'
        '\n'
        '# 预期响应（漏洞存在）：HTTP/1.1 200，响应体原样回显请求头：\n'
        '#   TRACE / HTTP/1.1\n'
        '#   Host: target\n'
        '#   Cookie: session=secret\n'
        '\n'
        '# 3. TRACK 方法探测（部分服务器作为 TRACE 别名，规避代理过滤）：\n'
        'curl -i -X TRACK "http://target/"\n'
        '\n'
        '# 4. 批量方法探测（结合 fuzzer）：\n'
        'for m in GET POST PUT DELETE TRACE TRACK OPTIONS CONNECT PATCH; do\n'
        '  code=$(curl -s -o /dev/null -w "%{http_code}" -X $m "http://target/")\n'
        '  echo "[$m] $code"\n'
        'done'
    )

    def verify(self, target, session) -> ScanResult:
        try:
            # OPTIONS 请求：获取支持的 HTTP 方法
            resp = session.request('OPTIONS', target)
            allow = resp.headers.get('Allow', '')
            methods = [m.strip() for m in allow.split(',') if m.strip()] if allow else []

            # TRACE 探测：发送 TRACE 请求
            try:
                trace_resp = session.request('TRACE', target)
                trace_enabled = trace_resp.status_code < 400
            except Exception:
                trace_enabled = False

            if methods or trace_enabled:
                evidence_parts = []
                if methods:
                    evidence_parts.append(f'Allow={", ".join(methods)}')
                if trace_enabled:
                    evidence_parts.append('TRACE 已启用（存在 XST 攻击风险）')

                # TRACE 开启视为确认漏洞（低危）
                if trace_enabled:
                    return ScanResult(
                        kind=self.category, name=self.name, severity=self.severity,
                        status=STATUS_CONFIRMED, url=target,
                        evidence='; '.join(evidence_parts),
                        fix=self.fix
                    )
                # 仅 OPTIONS 有返回，信息级
                return ScanResult(
                    kind=self.category, name=self.name, severity=self.severity,
                    status=STATUS_CONFIRMED, url=target,
                    evidence='; '.join(evidence_parts)
                )
            return ScanResult(
                kind=self.category, name=self.name, severity=self.severity,
                status=STATUS_SAFE, url=target,
                evidence='OPTIONS 无 Allow 头，TRACE 未开启'
            )
        except Exception as e:
            return ScanResult(kind='error', name=self.name, status=STATUS_UNKNOWN,
                              evidence=f'请求异常: {e}')
