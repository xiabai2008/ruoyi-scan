# HTTP 方法探测 — OPTIONS 请求 + TRACE 探测
import uuid

from common.models import SEVERITY_LOW, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from plugins.base import PluginBase


class TraceMethodPlugin(PluginBase):
    """探测目标 Web 服务器支持的 HTTP 方法，检测是否开启危险的 TRACE 方法"""

    name = "HTTP 方法探测"
    cve = "N/A"
    severity = SEVERITY_LOW
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
    compliance = "等保2.0:8.1.4;OWASP:A05:2021"
    category = "recon"
    description = "通过 OPTIONS 请求探测目标支持的 HTTP 方法，检测 TRACE 方法是否开启（可被利用于跨站追踪攻击）"
    fix = "在 Web 服务器中禁用 TRACE/TRACK 方法；限制 Allow 头中仅暴露必要方法"
    fix_detail = (
        "【配置加固·nginx】nginx 默认不处理 TRACE，确保未通过第三方模块启用；限制仅允许必要方法：\n"
        "  limit_except GET POST { deny all; }\n"
        "  # 显式拒绝 TRACE/TRACK：\n"
        "  if ($request_method = TRACE) { return 405; }\n"
        "  if ($request_method = TRACK) { return 405; }\n"
        "【配置加固·Apache】httpd.conf 全局关闭 TRACE：\n"
        "  TraceEnable off\n"
        '【配置加固·Tomcat】conf/server.xml 的 Connector 添加 allowTrace="false"：\n'
        '  <Connector port="8080" protocol="HTTP/1.1" allowTrace="false" />\n'
        "【配置加固·IIS】Request Filtering → HTTP Verbs → Deny Verb：TRACE、TRACK\n"
        '  或 web.config：<security><requestFiltering><verbs><add verb="TRACE" allowed="false"/></verbs></requestFiltering></security>\n'
        "【WAF 规则】拒绝 TRACE/TRACK 方法请求，返回 405 Method Not Allowed；监测 Allow 头中是否暴露危险方法\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. OPTIONS 探测目标支持的 HTTP 方法：\n"
        'curl -i -X OPTIONS "http://target/"\n'
        "\n"
        "# 预期响应：\n"
        "#   HTTP/1.1 200\n"
        "#   Allow: GET,HEAD,POST,OPTIONS,TRACE     # 含 TRACE 即存在风险\n"
        "\n"
        "# 2. TRACE 方法探测（XST 跨站追踪，可绕过 HttpOnly 读取 Cookie）：\n"
        'curl -i -X TRACE "http://target/"\n'
        'curl -i -H "Cookie: session=secret" -X TRACE "http://target/"\n'
        "\n"
        "# 预期响应（漏洞存在）：HTTP/1.1 200，响应体原样回显请求头：\n"
        "#   TRACE / HTTP/1.1\n"
        "#   Host: target\n"
        "#   Cookie: session=secret\n"
        "\n"
        "# 3. TRACK 方法探测（部分服务器作为 TRACE 别名，规避代理过滤）：\n"
        'curl -i -X TRACK "http://target/"\n'
        "\n"
        "# 4. 批量方法探测（结合 fuzzer）：\n"
        "for m in GET POST PUT DELETE TRACE TRACK OPTIONS CONNECT PATCH; do\n"
        '  code=$(curl -s -o /dev/null -w "%{http_code}" -X $m "http://target/")\n'
        '  echo "[$m] $code"\n'
        "done"
    )

    # TRACE 回显探针头名。RFC 9110 规定 TRACE 必须把收到的请求报文原样回显，
    # 因此只有响应体中出现本次发送的自定义头值，才能证明 TRACE 真实启用。
    # 仅凭状态码 <400 判定不可靠：SPA 路由 / nginx 兜底 location 对任意方法都返回 200。
    TRACE_PROBE_HEADER = "X-Ruoyi-Scan-Probe"

    def verify(self, target, session) -> ScanResult:
        """探测服务器支持的 HTTP 方法，并按回显证据判定 TRACE 是否真实启用

        判定规则：
          - CONFIRMED：状态码 <400 **且**响应体回显了探针头值（TRACE 真实启用，存在 XST 风险）
          - SAFE：仅 OPTIONS 返回 Allow（信息级发现，不构成漏洞），或 TRACE 未回显报文
          - UNKNOWN：请求异常，绝不判 SAFE

        @param target: 目标站点 URL
        @param session: 已配置的 HTTP 会话
        @return: STATUS_CONFIRMED / STATUS_SAFE / STATUS_UNKNOWN
        """
        try:
            # OPTIONS 请求：获取支持的 HTTP 方法
            resp = session.request("OPTIONS", target)
            allow = resp.headers.get("Allow", "")
            # Allow 头逗号分隔且可能含空格/空段，逐项 strip 并过滤空串
            methods = [m.strip() for m in allow.split(",") if m.strip()] if allow else []

            # TRACE 探测：带唯一探针头发送，要求响应体回显该值才算真实启用
            trace_echoed = False
            probe_value = uuid.uuid4().hex
            try:
                trace_resp = session.request("TRACE", target, headers={self.TRACE_PROBE_HEADER: probe_value})
                trace_body = trace_resp.text or ""
                trace_echoed = trace_resp.status_code < 400 and probe_value in trace_body
            except Exception:
                trace_echoed = False

            evidence_parts = []
            if methods:
                evidence_parts.append(f"Allow={', '.join(methods)}")
            if trace_echoed:
                evidence_parts.append("TRACE 已启用且回显请求报文（存在 XST 攻击风险）")

            # TRACE 真实启用 → CONFIRMED
            if trace_echoed:
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=target,
                    evidence="; ".join(evidence_parts),
                    fix=self.fix,
                )
            # 仅 OPTIONS 返回 Allow：信息级发现，不构成漏洞 → SAFE
            # 历史缺陷：原实现把「仅 OPTIONS 有返回」也判 CONFIRMED，与代码注释「信息级」
            # 自相矛盾；且 TRACE 判定只看 status_code < 400，导致兜底路由一类的服务器被误报。
            if methods:
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_SAFE,
                    url=target,
                    evidence="; ".join(evidence_parts) + "（信息级发现，TRACE 未回显请求报文）",
                )
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=target,
                evidence="OPTIONS 无 Allow 头，TRACE 未回显请求报文",
            )
        except Exception as e:
            return ScanResult(kind="error", name=self.name, status=STATUS_UNKNOWN, evidence=f"请求异常: {e}")
