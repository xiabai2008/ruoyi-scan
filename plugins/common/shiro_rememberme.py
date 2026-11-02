# shiro_rememberme - Shiro 框架指纹识别（rememberMe Cookie 特征）
#
# ⚠ 能力边界（2026-11-02 方案 A 收口，务必先读）
# ============================================
# 本插件**只做框架指纹识别**，不做反序列化利用验证：读到 `rememberMe=deleteMe` 说明
# 站点用的是 Shiro，仅此而已。**它永远不会 CONFIRMED**——判定结果只有两种：
#   SAFE（无 rememberMe 特征） / UNKNOWN（有特征，但密钥可利用性未验证）
#
# 历史问题：本插件曾挂 `cve="CVE-2016-4437"` + `severity=high`、名称带「反序列化」，
# 报告读者看到「high 级 Shiro 反序列化 RCE」会以为扫描器确认了可利用性；而
# `docs/verification-matrix.md` 还把它标成 L1「已验证」——两处叠加等于能力虚报。
# 一个永远无法 CONFIRMED 的 high 级 RCE 条目，比不报更糟：它消耗读者对报告的信任。
#
# 收口方式（方案 A）：去掉 CVE 归属、降为 low、名称去掉「反序列化」、类别改为 recon，
# 并在 description 里写清「需人工验证密钥」。真正的密钥爆破 + 回显验证留给 v1.6
# （需要可控回显靶场与速率控制设计，不该挤在收尾版）。
#
# 需要的用户仍能从 reproduce 里拿到 ysoserial 手工验证步骤，只是扫描器不再替它下结论。
from common.models import SEVERITY_LOW, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase


class ShiroRemembermePlugin(PluginBase):
    """识别 Shiro 框架（rememberMe Cookie 特征）；反序列化可利用性需人工验证"""

    # 名称去掉「反序列化」：本插件验证不了反序列化，只认框架指纹
    name = "Shiro 框架指纹（rememberMe）"
    # 去掉 CVE 归属：CVE-2016-4437 是「反序列化 RCE」的编号，本插件并不验证该漏洞。
    # 挂编号会让报告的 CVE 统计把它算作一个已发现的 CVE 漏洞（能力虚报）。
    cve = "N/A"
    # high → low：指纹本身不构成高风险，风险取决于密钥是否可被利用（未验证）
    severity = SEVERITY_LOW
    # vuln → recon：与 dir_listing / trace_method 同类，属侦察信息而非漏洞判定
    category = "recon"
    description = (
        "站点使用 Apache Shiro 框架（响应含 rememberMe=deleteMe 特征）。"
        "Shiro 的 rememberMe Cookie 在默认配置下使用硬编码 AES 密钥，存在反序列化 RCE 风险"
        "（CVE-2016-4437），但**是否可利用需人工验证密钥**——本插件只确认框架存在。"
    )
    fix = "确认 Shiro 版本 ≥1.2.5 且 rememberMe 密钥已更换（默认密钥 kPH+bIxk5D2deZiIxcaaaA== 必须替换）"
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
        "# 1. 确认 Shiro 框架特征（Set-Cookie 含 rememberMe=deleteMe）\n"
        'curl -i -b "rememberMe=1" "http://target/login"\n'
        "# 预期响应：HTTP 200，Set-Cookie 头包含 rememberMe=deleteMe 表示存在 Shiro 框架\n"
        "\n"
        "# 2. 手工验证密钥可利用性（扫描器不做这一步，需独立进行）\n"
        "#    仅对已授权目标执行；用 ysoserial 生成 payload 并以默认密钥加密：\n"
        "# python shiro_exploit.py -t http://target/login -k kPH+bIxk5D2deZiIxcaaaA== \\\n"
        "#   -g CommonsBeanutils1 -c 'whoami'\n"
        "# 预期响应：DNSLog/OAST 收到回连 → 确认 RCE 可利用；无回连 → 密钥已更换，风险解除"
    )
    # 版本范围由 Shiro 自身版本决定，与若依版本无关；留空表示不参与若依版本过滤
    affected_versions = ""
    # CVSS 保留「潜在影响」而非「已确认影响」：这是指纹命中的最坏情况评分，
    # 与 severity=low 不矛盾——severity 表达「本次扫描能确认的风险等级」，
    # CVSS 表达「若不处理可能的上限」。报告里两者并列展示，读者能看出差别。
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "Dengbao2.0:8.1.3;OWASP:A03:2021"
    # 指纹类不再是漏洞类型：置空后 dedup 回退到「kind:name」作为指纹键，
    # 避免和真正的 rce 类结果被聚合到一起
    vuln_type = ""
    supports_waf_bypass = False

    # rememberMe Cookie 检测特征
    SHIRO_COOKIE = "rememberMe"
    DELETE_ME = "rememberMe=deleteMe"
    # 候选探测路径：Shiro rememberMe 只处理 filter chain 覆盖的 URL，
    # 不同部署受保护端点不同（仅探 /login 会在保护其他端点的部署上漏报），
    # 故逐个探测，任一返回 deleteMe 即判框架特征
    PROBE_PATHS = ["/", "/login"]

    def verify(self, target, session) -> ScanResult:
        """识别 Shiro 框架（rememberMe Cookie 特征）

        检测逻辑：
        1. 依次对候选路径发送带 rememberMe Cookie 的请求
        2. 检查响应 Set-Cookie 是否含 rememberMe=deleteMe（Shiro 特征）
        3. 若存在 Shiro 特征，判定为 UNKNOWN——**指纹不等于可利用**，
           密钥是否可被利用需人工按 reproduce 步骤验证（本插件不做这一步）
        """
        got_response = False
        last_url = join_url(target, self.PROBE_PATHS[0])
        last_error = None
        for path in self.PROBE_PATHS:
            url = join_url(target, path)
            last_url = url
            try:
                # 用 cookies= 传值而非手写 Cookie 头：requests 会把它与 session 的
                # cookie jar 合并；手写 Cookie 头会在 jar 已持有该 host cookie 时
                # 被 prepare_cookies 重建覆盖，探针可能实际未发出（假 SAFE）
                resp = session.get(url, cookies={self.SHIRO_COOKIE: "test"})
            except Exception as e:
                last_error = e
                continue
            got_response = True

            # 检查响应头是否包含 Shiro rememberMe 特征
            # 双重检查：Set-Cookie 可能出现在多值响应头中，get() 只取首值，故再对完整头字符串匹配
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
                        f"检测到 Shiro 框架特征（{self.DELETE_ME}）。这是指纹而非漏洞判定："
                        "rememberMe 反序列化是否可利用取决于密钥，需按复现步骤人工验证"
                    ),
                    fix=self.fix,
                    fix_detail=self.fix_detail,
                    reproduce=self.reproduce,
                )

        # 所有候选路径均请求失败：无法判定，不得当作「无 Shiro 特征」判 SAFE
        if not got_response:
            return ScanResult(
                kind="error",
                name=self.name,
                status=STATUS_UNKNOWN,
                evidence=f"exception: {last_error}",
            )

        # 未检测到 Shiro 特征
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=last_url,
            evidence="未检测到 Shiro rememberMe 特征",
        )
