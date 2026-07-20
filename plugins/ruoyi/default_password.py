# 后台默认口令：POST /login 尝试 admin/admin123，按 token/code:200/Set-Cookie 判定
from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_positive
from plugins.base import PluginBase

logger = get_logger(__name__)


class DefaultPasswordPlugin(PluginBase):
    name = "后台默认口令（admin/admin123）"
    cve = "N/A"
    severity = "high"
    category = "brute"
    description = (
        "若依后台默认口令 admin/admin123：POST /login 不带验证码尝试登录，"
        "响应含 token 或 code:200 即默认口令未修改。验证码场景会显式标记 UNKNOWN"
    )
    fix = (
        "强制修改 admin 默认口令为高强度密码；启用登录验证码；"
        "限制 admin 仅内网访问；登录失败次数阈值锁定；定期审计用户列表"
    )
    fix_detail = (
        "【口令修改】首次部署后立即执行：登录后台 → 个人中心 → 修改密码（≥12 位，含大小写+数字+符号）\n"
        "【SQL 修改】update sys_user set password = '$2a$10$7JB720yubVSZvUI0rEqK/.VqGOZTH.ulu33dHOiBE8ByOhJIrdAu2' where user_name = 'admin';\n"
        "  （示例为 admin123 的 BCrypt 哈希，替换为目标强口令的哈希）\n"
        "【启用验证码】application.yml: shiro.captchaEnabled: true\n"
        '【失败锁定】SysLoginController.login() 添加：if (loginRecordService.isLocked(username)) throw new ServiceException("账号已锁定")\n'
        "【WAF 规则】拦截 username=admin 且 password=admin123 的 /login 请求\n"
        "【合规】等保 2.0 8.1.4 要求：身份鉴别信息复杂度并定期更换"
    )
    reproduce = (
        "# 尝试默认口令登录（admin/admin123）：\n"
        'curl -X POST "http://target/login" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"username":"admin","password":"admin123"}\'\n'
        "\n"
        '# 预期响应：HTTP 200 + JSON 含 {"code":200,"msg":"操作成功","token":"..."} 字段\n'
        "\n"
        "# 验证登录成功后访问后台接口：\n"
        'curl "http://target/getInfo" -H "Authorization: Bearer <token>"\n'
        "  # 返回用户信息即确认默认口令有效"
    )
    # D2：默认口令全版本存在（取决于是否修改默认 admin/admin123）
    affected_versions = ""
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.4;OWASP:A07:2021"
    # D7: WAF 绕过支持
    vuln_type = "auth"
    supports_waf_bypass = True

    # 默认凭据（仅这一组，符合 agents.md §6「不得新增炫技功能」原则，聚焦若依官方默认口令）
    USERNAME = "admin"
    PASSWORD = "admin123"

    # 验证码相关关键字（命中即视为需要验证码，无法判定，标 UNKNOWN）
    CAPTCHA_KEYWORDS = ["验证码", "captcha", "code expired", "验证码已失效", "code is null"]

    def verify(self, target, session):
        url = join_url(target, "login")
        # RuoYi /login 接收 JSON body（Content-Type: application/json）
        # 部分版本也接受 form 表单，这里用 JSON 兼容主流前后端分离版本
        data = {
            "username": self.USERNAME,
            "password": self.PASSWORD,
            # 不传 code/uuid：若服务端启用验证码，会返回验证码错误（标记 UNKNOWN）
        }
        headers = {"Content-Type": "application/json"}
        try:
            resp = session.post(url, json=data, headers=headers)
        except Exception as e:
            print(no("后台默认口令（网络异常）"))
            return ScanResult(kind="brute", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        text = resp.text or ""
        code = getattr(resp, "status_code", 0)
        set_cookie = ""
        if hasattr(resp, "headers") and resp.headers.get("Set-Cookie"):
            set_cookie = resp.headers.get("Set-Cookie", "")

        # 解析 JSON 响应
        body = {}
        try:
            body = resp.json()
        except Exception:
            logger.debug("登录响应 JSON 解析失败", exc_info=True)

        # 1) 验证码拦截：服务端要求验证码 → 无法判定（非 SAFE，避免漏报）
        if match_positive(text, self.CAPTCHA_KEYWORDS):
            print(no("后台默认口令：服务端要求验证码，无法判定"))
            return ScanResult(
                kind="brute",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                evidence=f"响应含验证码关键字，无法在无验证码场景判定。前 200 字节：{text[:200]}",
                extra={"captcha_required": True},
            )

        # 2) 命中判定：JSON 含 token / code == 200 / Set-Cookie 含 session/Admin-Token
        token = body.get("token") if isinstance(body, dict) else ""
        r_code = body.get("code") if isinstance(body, dict) else None
        msg = str(body.get("msg", "")) if isinstance(body, dict) else ""

        # 排除「code:200 但 msg 含错误」的误报（部分版本错误也返 200）
        has_login_failure_kw = any(
            kw in msg for kw in ["密码错误", "用户不存在", "登录失败", "password", "incorrect", "invalid"]
        )

        if token:
            # 含 token → 强命中
            print(ok("存在后台默认口令漏洞（admin/admin123，返回 token）"))
            return ScanResult(
                kind="brute",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"登录返回 token={str(token)[:30]}...",
                extra={"username": self.USERNAME, "password": self.PASSWORD, "token": str(token)[:50], "code": r_code},
                fix=self.fix,
            )

        if r_code == 200 and not has_login_failure_kw:
            # code == 200 且 msg 不含错误关键字
            print(ok("存在后台默认口令漏洞（admin/admin123，code=200）"))
            return ScanResult(
                kind="brute",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"登录返回 code=200 msg={msg}",
                extra={"username": self.USERNAME, "password": self.PASSWORD, "code": r_code, "msg": msg},
                fix=self.fix,
            )

        if "Admin-Token" in set_cookie:
            # Admin-Token 是 RuoYi 前后端分离版登录成功下发的专属 token Cookie
            # 注意：JSESSIONID 不在此判定中——Java 应用登录失败时通常也会下发 JSESSIONID，
            # 仅凭 JSESSIONID 会产生大量误报（P0 修复）
            print(ok("存在后台默认口令漏洞（admin/admin123，Set-Cookie 含会话）"))
            return ScanResult(
                kind="brute",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"登录返回 Set-Cookie={set_cookie[:100]}",
                extra={"username": self.USERNAME, "password": self.PASSWORD, "set_cookie": set_cookie[:200]},
                fix=self.fix,
            )

        # 3) 明确的失败信号：code == 500 / msg 含「密码错误」等
        if r_code == 500 or has_login_failure_kw:
            print(no("不存在后台默认口令漏洞（口令已修改）"))
            return ScanResult(
                kind="brute",
                name=self.name,
                status=STATUS_SAFE,
                url=url,
                evidence=f"登录失败：code={r_code} msg={msg}",
                extra={"username": self.USERNAME, "code": r_code, "msg": msg},
            )

        # 4) 响应特征不明确（非 JSON、无 token/code/cookie 关键字）→ UNKNOWN
        print(no("后台默认口令：响应特征不明确，判 UNKNOWN"))
        return ScanResult(
            kind="brute",
            name=self.name,
            status=STATUS_UNKNOWN,
            url=url,
            evidence=f"HTTP {code} 响应前 200 字节：{text[:200]}",
            extra={"username": self.USERNAME},
        )
