# shiro_rememberme - Shiro rememberMe 反序列化 RCE 检测插件
from common.models import STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase


class ShiroRemembermePlugin(PluginBase):
    name = "shiro_rememberme"
    cve = "CVE-2016-4437"
    severity = "high"
    category = "vuln"
    description = (
        "Apache Shiro rememberMe 反序列化远程代码执行漏洞。"
        "Shiro 默认使用 AES-128-CBC 加密 rememberMe Cookie，密钥硬编码为 kPH+bIxk5D2deZiIxcaaaA==。"
        "攻击者可利用已知密钥构造恶意序列化对象，实现 RCE。"
    )
    fix = "更换 Shiro rememberMe 加密密钥，升级 Shiro 至 1.2.5+，并配置反序列化过滤器"
    fix_detail = (
        "【升级方案】升级 Shiro 至 1.2.5 及以上版本，1.4.2+ 默认使用 AES-256-GCM\n"
        "【配置加固】修改 shiro.ini 或 application.yml 中的 securityManager.rememberMe.cipherKey，"
        "生成随机 128/256 位密钥替换默认密钥\n"
        "【代码修复】自定义 RememberMeManager，禁止使用硬编码密钥；"
        "添加反序列化白名单 ClassResolvingObjectInputStream\n"
        "【WAF 规则】拦截 rememberMe Cookie 超长请求（>1024 bytes），检测序列化特征 Base64 头 rO0AB\n"
        "【合规映射】OWASP A03:2021 注入 / OWASP A08:2021 软件和数据完整性故障 / 等保2.0 8.1.3"
    )
    reproduce = (
        "# 1. 检测是否存在 Shiro rememberMe 特征（Set-Cookie 含 rememberMe=deleteMe）\n"
        'curl -i -b "rememberMe=1" "http://target/login"\n'
        "# 预期响应：HTTP 200，Set-Cookie 头包含 rememberMe=deleteMe 表示存在 Shiro 框架\n"
        "\n"
        "# 2. 使用 ysoserial 生成 payload 并用默认密钥加密\n"
        "# python shiro_exploit.py -t http://target/login -k kPH+bIxk5D2deZiIxcaaaA== \\\n"
        "#   -g CommonsBeanutils1 -c 'whoami'\n"
        "# 预期响应：服务端执行命令，DNSLog/OAST 收到回连确认 RCE"
    )
    affected_versions = "Shiro < 1.2.5（默认密钥）；Shiro < 1.4.2（CBC 模式 Padding Oracle）"
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "Dengbao2.0:8.1.3;OWASP:A03:2021"
    vuln_type = "rce"
    supports_waf_bypass = False

    # Shiro 默认 AES 密钥（Base64 编码）
    DEFAULT_KEYS = [
        "kPH+bIxk5D2deZiIxcaaaA==",
        "2AvVhdsgUs0FSA3SDFAdag==",
        "3AvVhmFLUs0KTA3Kprsdag==",
        "4AvVhmFLUs0KTA3Kprsdag==",
        "Z3Vybg==",
        "wGiHplamyXlVB11UXWol8g==",
        "fCq+/x448o9wCM4BqR5bJw==",
    ]

    # rememberMe Cookie 检测特征
    SHIRO_COOKIE = "rememberMe"
    DELETE_ME = "rememberMe=deleteMe"

    def verify(self, target, session) -> ScanResult:
        """检测 Shiro rememberMe 反序列化漏洞

        检测逻辑：
        1. 发送带有 rememberMe Cookie 的请求
        2. 检查响应 Set-Cookie 是否含 rememberMe=deleteMe（Shiro 特征）
        3. 若存在 Shiro 特征，判定为 UNKNOWN（需进一步验证密钥）
        """
        url = join_url(target, "/login")
        try:
            # 发送带有 rememberMe Cookie 的请求触发 Shiro 处理
            resp = session.get(url, headers={"Cookie": f"{self.SHIRO_COOKIE}=test"})

            # 检查响应头是否包含 Shiro rememberMe 特征
            set_cookie = resp.headers.get("Set-Cookie", "")
            resp_headers = str(resp.headers)

            if self.DELETE_ME in set_cookie or self.DELETE_ME in resp_headers:
                # 存在 Shiro 框架，但未确认密钥是否可利用
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_UNKNOWN,
                    url=url,
                    evidence=(
                        f"检测到 Shiro rememberMe 特征（{self.DELETE_ME}），存在反序列化风险，需进一步验证密钥可利用性"
                    ),
                    fix=self.fix,
                    fix_detail=self.fix_detail,
                    reproduce=self.reproduce,
                )

            # 未检测到 Shiro 特征
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=url,
                evidence="未检测到 Shiro rememberMe 特征",
            )
        except Exception as e:
            return ScanResult(
                kind="error",
                name=self.name,
                status=STATUS_UNKNOWN,
                evidence=f"exception: {e}",
            )
