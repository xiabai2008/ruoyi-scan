# RuoYi-Plus 登录接口未授权探测（variant='ruoyi-plus' 专项）
# Plus 版使用 Sa-Token 认证，登录接口为 /auth/login（独立认证服务）
# 存在性验证：POST 空凭据探测接口存在性 + 是否返回业务 JSON（未配置登录限制时）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_positive
from plugins.base import PluginBase


class PlusAuthLoginProbePlugin(PluginBase):
    name = "RuoYi-Plus 认证接口探测"
    cve = "N/A"
    severity = "low"
    category = "vuln"
    description = "RuoYi-Vue-Plus 认证服务 /auth/login 接口探测（Sa-Token 架构确认 + 登录风控检查）"
    fix = "确认 /auth/login 启用验证码与登录限流（Plus 需配置 captchaEnabled 与登录失败锁定）"
    fix_detail = (
        "【配置加固】application.yml 确认 captchaEnabled: true 且启用登录失败次数限制\n"
        "【代码修复】登录接口加 RateLimit 注解（Sa-Token 内置限流）\n"
        "【合规】OWASP A07:2021 身份认证失败；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl -X POST "http://target/auth/login" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"username":"admin","password":"x"}\'\n'
        "# 预期响应：JSON 含 code/msg 字段（认证服务存在且可探测）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A07:2021"
    vuln_type = "auth"
    supports_waf_bypass = False
    # F6：仅 ruoyi-plus 变体执行
    variant = "ruoyi-plus"

    def verify(self, target, session):
        url = join_url(target, "/auth/login")
        try:
            resp = session.post(
                url,
                data='{"username":"admin","password":"x"}',
                headers={"Content-Type": "application/json"},
            )
            text = resp.text or ""
        except Exception as e:
            print(no("RuoYi-Plus 认证接口探测（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 认证服务存在：返回业务 JSON（code/msg）而非 404/405
        if resp.status_code in (200, 400, 401, 500) and match_positive(text, ["code", "msg"]):
            print(ok("确认 RuoYi-Plus 认证服务（建议人工验证登录风控）"))
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity, status=STATUS_CONFIRMED,
                url=url, evidence="认证接口返回业务 JSON（Sa-Token 架构确认）",
                fix=self.fix, extra={"vuln_type": "auth", "plugin_name": "plus_auth_probe"},
            )
        print(no("未探测到 RuoYi-Plus 认证服务"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
