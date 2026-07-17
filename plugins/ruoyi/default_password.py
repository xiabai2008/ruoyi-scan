# 后台默认口令：POST /login 尝试 admin/admin123，按 token/code:200/Set-Cookie 判定
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no


class DefaultPasswordPlugin(PluginBase):
    name = '后台默认口令（admin/admin123）'
    cve = ''
    severity = 'high'
    category = 'brute'
    description = (
        '若依后台默认口令 admin/admin123：POST /login 不带验证码尝试登录，'
        '响应含 token 或 code:200 即默认口令未修改。验证码场景会显式标记 UNKNOWN'
    )
    fix = (
        '强制修改 admin 默认口令为高强度密码；启用登录验证码；'
        '限制 admin 仅内网访问；登录失败次数阈值锁定；定期审计用户列表'
    )

    # 默认凭据（仅这一组，符合 agents.md §6「不得新增炫技功能」原则，聚焦若依官方默认口令）
    USERNAME = 'admin'
    PASSWORD = 'admin123'

    # 验证码相关关键字（命中即视为需要验证码，无法判定，标 UNKNOWN）
    CAPTCHA_KEYWORDS = ['验证码', 'captcha', 'code expired', '验证码已失效', 'code is null']

    def verify(self, target, session):
        url = target + 'login'
        # RuoYi /login 接收 JSON body（Content-Type: application/json）
        # 部分版本也接受 form 表单，这里用 JSON 兼容主流前后端分离版本
        data = {
            'username': self.USERNAME,
            'password': self.PASSWORD,
            # 不传 code/uuid：若服务端启用验证码，会返回验证码错误（标记 UNKNOWN）
        }
        headers = {'Content-Type': 'application/json'}
        try:
            resp = session.post(url, json=data, headers=headers)
        except Exception as e:
            print(no('后台默认口令（网络异常）'))
            return ScanResult(kind='brute', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        code = getattr(resp, 'status_code', 0)
        set_cookie = ''
        if hasattr(resp, 'headers') and resp.headers.get('Set-Cookie'):
            set_cookie = resp.headers.get('Set-Cookie', '')

        # 解析 JSON 响应
        body = {}
        try:
            body = resp.json()
        except Exception:
            pass

        # 1) 验证码拦截：服务端要求验证码 → 无法判定（非 SAFE，避免漏报）
        lower_text = text.lower()
        if any(kw.lower() in lower_text for kw in self.CAPTCHA_KEYWORDS):
            print(no('后台默认口令：服务端要求验证码，无法判定'))
            return ScanResult(
                kind='brute', name=self.name, status=STATUS_UNKNOWN, url=url,
                evidence=f'响应含验证码关键字，无法在无验证码场景判定。前 200 字节：{text[:200]}',
                extra={'captcha_required': True},
            )

        # 2) 命中判定：JSON 含 token / code == 200 / Set-Cookie 含 session/Admin-Token
        token = body.get('token') if isinstance(body, dict) else ''
        r_code = body.get('code') if isinstance(body, dict) else None
        msg = str(body.get('msg', '')) if isinstance(body, dict) else ''

        # 排除「code:200 但 msg 含错误」的误报（部分版本错误也返 200）
        has_login_failure_kw = any(kw in msg for kw in ['密码错误', '用户不存在', '登录失败',
                                                        'password', 'incorrect', 'invalid'])

        if token:
            # 含 token → 强命中
            print(ok('存在后台默认口令漏洞（admin/admin123，返回 token）'))
            return ScanResult(
                kind='brute', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'登录返回 token={str(token)[:30]}...',
                extra={'username': self.USERNAME, 'password': self.PASSWORD,
                       'token': str(token)[:50], 'code': r_code},
                fix=self.fix,
            )

        if r_code == 200 and not has_login_failure_kw:
            # code == 200 且 msg 不含错误关键字
            print(ok('存在后台默认口令漏洞（admin/admin123，code=200）'))
            return ScanResult(
                kind='brute', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'登录返回 code=200 msg={msg}',
                extra={'username': self.USERNAME, 'password': self.PASSWORD,
                       'code': r_code, 'msg': msg},
                fix=self.fix,
            )

        if 'Admin-Token' in set_cookie or 'JSESSIONID' in set_cookie:
            # 任意会话 Cookie 出现可能是登录成功（保守起见标 CONFIRMED 但提示需复核）
            print(ok('存在后台默认口令漏洞（admin/admin123，Set-Cookie 含会话）'))
            return ScanResult(
                kind='brute', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'登录返回 Set-Cookie={set_cookie[:100]}',
                extra={'username': self.USERNAME, 'password': self.PASSWORD,
                       'set_cookie': set_cookie[:200]},
                fix=self.fix,
            )

        # 3) 明确的失败信号：code == 500 / msg 含「密码错误」等
        if r_code == 500 or has_login_failure_kw:
            print(no('不存在后台默认口令漏洞（口令已修改）'))
            return ScanResult(
                kind='brute', name=self.name, status=STATUS_SAFE, url=url,
                evidence=f'登录失败：code={r_code} msg={msg}',
                extra={'username': self.USERNAME, 'code': r_code, 'msg': msg},
            )

        # 4) 响应特征不明确（非 JSON、无 token/code/cookie 关键字）→ UNKNOWN
        print(no('后台默认口令：响应特征不明确，判 UNKNOWN'))
        return ScanResult(
            kind='brute', name=self.name, status=STATUS_UNKNOWN, url=url,
            evidence=f'HTTP {code} 响应前 200 字节：{text[:200]}',
            extra={'username': self.USERNAME},
        )
