# 若依登录链编排器（D1 阶段）
#
# 功能：实现 RuoYi v4(Session) / v5(JWT) 双链路登录，为需鉴权 POC 提供会话。
#
# 核心逻辑：
#   1. detect_auth_mode()  探测鉴权模式（v4 Session / v5 JWT / 无鉴权）
#   2. login()             按探测到的模式登录，成功后会话自动带凭证
#       - v4 Session：POST /login 表单 → Cookie 自动复用（session.cookies 持久化）
#       - v5 JWT：POST /login JSON → 提取 token → session.headers['Authorization']
#   3. 验证码处理：先尝试无验证码登录，失败则探测验证码类型
#       - 无验证码：直接登录
#       - 验证码可绕过（旧版 4.2-）：空 code 绕过（D1 暂不支持，留 D3）
#       - 验证码必校验：返回 captcha_required=True，调用方判 UNKNOWN（D3 接 OCR）
#
# 设计原则：
#   - 不修改 SessionManager 的接口，登录成功后 session 自带凭证
#   - 登录失败不抛异常，返回 (ok, reason)，调用方决定是否继续
#   - 兼容签名靶场（无验证码）与真实若依（有验证码，D1 阶段判 UNKNOWN）
import json as _json

from lib.http import join_url

# 鉴权模式
AUTH_NONE = "none"  # 无鉴权（如 VulnPreviewController 直接暴露）
AUTH_V4_SESSION = "v4"  # RuoYi v4 Session（Cookie）
AUTH_V5_JWT = "v5"  # RuoYi v5 JWT（Authorization 头）

# 登录结果
LOGIN_OK = "ok"  # 登录成功
LOGIN_FAIL = "fail"  # 登录失败（用户名/密码错误）
LOGIN_CAPTCHA = "captcha"  # 需要验证码（D1 不处理，留 D3）
LOGIN_ERROR = "error"  # 网络异常或响应异常


class RuoYiAuthChain:
    """若依登录链编排器

    用法：
        chain = RuoYiAuthChain(target, session, username='admin', password='admin123')
        ok, reason = chain.login()
        if ok:
            # session 已带凭证，后续请求自动鉴权
            resp = session.get(join_url(target, '/monitor/job/edit'))
    """

    def __init__(self, target, session, username="admin", password="admin123", remember_me=False, timeout=None):
        self.target = target
        self.session = session
        self.username = username
        self.password = password
        self.remember_me = remember_me
        self.timeout = timeout
        self.auth_mode = None

    def detect_auth_mode(self):
        """探测鉴权模式：v4 Session / v5 JWT / 无鉴权

        判定依据：
        - GET /login 返回 HTML 登录页 → v4 Session（Shiro 表单登录）
        - GET /login 返回 JSON（{code:401} 或重定向）→ v5 JWT（前后端分离）
        - GET /login 404 或无响应 → 无鉴权
        """
        try:
            resp = self.session.get(join_url(self.target, "/login"))
        except Exception:
            self.auth_mode = AUTH_NONE
            return AUTH_NONE

        code = getattr(resp, "status_code", 0)
        text = resp.text or ""
        ct = (resp.headers.get("Content-Type", "") or "").lower()
        text_lower = text.lower()

        # 404 / 无响应 → 无鉴权
        if code == 404:
            self.auth_mode = AUTH_NONE
            return AUTH_NONE

        # JSON 响应优先判定（v5 JWT，前后端分离）
        # 注意：必须先于 HTML 关键字判定，避免 JSON msg 含"登录"二字被误判
        if "json" in ct:
            self.auth_mode = AUTH_V5_JWT
            return AUTH_V5_JWT
        try:
            _json.loads(text)
            self.auth_mode = AUTH_V5_JWT
            return AUTH_V5_JWT
        except (ValueError, TypeError):
            pass

        # HTML 响应（含登录表单/html 标签）→ v4 Session
        # 严格判定：<html> 或 <form> 标签，避免 JSON msg 含"登录"误判
        if "html" in ct or "<html" in text_lower or "<form" in text_lower:
            self.auth_mode = AUTH_V4_SESSION
            return AUTH_V4_SESSION

        # 默认按 v4 Session 处理（最常见）
        self.auth_mode = AUTH_V4_SESSION
        return AUTH_V4_SESSION

    def login(self, captcha_code=None):
        """按探测到的鉴权模式登录

        Args:
            captcha_code: 验证码（D3）。None=自动探测+OCR；''=跳过验证码；非空=手动提供

        Returns:
            (ok: bool, reason: str)
            ok=True, reason=LOGIN_OK：登录成功，session 已带凭证
            ok=False, reason=LOGIN_CAPTCHA：需要验证码且 OCR 失败
            ok=False, reason=LOGIN_FAIL：用户名/密码错误
            ok=False, reason=LOGIN_ERROR：网络异常
        """
        if self.auth_mode is None:
            self.detect_auth_mode()

        if self.auth_mode == AUTH_NONE:
            # 无鉴权，直接返回成功
            return True, LOGIN_OK

        if self.auth_mode == AUTH_V4_SESSION:
            return self._login_v4_session(captcha_code)

        if self.auth_mode == AUTH_V5_JWT:
            return self._login_v5_jwt(captcha_code)

        return False, LOGIN_ERROR

    def _login_v4_session(self, captcha_code=None):
        """RuoYi v4 Session 登录：POST /login 表单 → Cookie 自动复用

        表单字段：username / password / rememberMe / validateCode
        验证码处理（D3）：
        - captcha_code=None：自动探测验证码接口，有则 OCR 识别
        - captcha_code=''：跳过验证码（用于无验证码环境）
        - captcha_code='8'：直接用提供的验证码
        """
        # D3：验证码处理
        validate_code = ""
        if captcha_code is None:
            try:
                from core.captcha_solver import CaptchaSolver

                solver = CaptchaSolver(self.target, self.session)
                has_captcha, code = solver.solve()
                if has_captcha:
                    if code:
                        validate_code = code
                    else:
                        # 有接口但 OCR 失败（图片为空或后端不可用）
                        return False, f"{LOGIN_CAPTCHA}: 接口存在但识别失败(后端={solver.backend_name})"
            except Exception as e:
                return False, f"{LOGIN_CAPTCHA}: 探测异常 {e}"
        elif captcha_code:
            validate_code = captcha_code

        url = join_url(self.target, "/login")
        data = {
            "username": self.username,
            "password": self.password,
            "rememberMe": "true" if self.remember_me else "false",
            "validateCode": validate_code,
        }
        try:
            resp = self.session.post(url, data=data)
        except Exception as e:
            return False, f"{LOGIN_ERROR}: {e}"

        code = getattr(resp, "status_code", 0)

        # 解析 JSON 响应（RuoYi AjaxResult）
        body = {}
        try:
            body = resp.json()
        except (ValueError, TypeError):
            pass

        # code=0 或 code=200 → 登录成功（若依 success() 返回 code=0，部分版本 200）
        r_code = body.get("code")
        if r_code in (0, 200):
            return True, LOGIN_OK

        # 验证码错误 → 需要验证码（D1 不处理，留 D3 OCR）
        msg = str(body.get("msg", ""))
        if "验证码" in msg or "captcha" in msg.lower():
            return False, LOGIN_CAPTCHA

        # 用户名/密码错误
        if "用户" in msg or "密码" in msg or "password" in msg.lower() or "user" in msg.lower():
            return False, f"{LOGIN_FAIL}: {msg}"

        # 其他失败（code=500 等）
        if r_code is not None and r_code != 0 and r_code != 200:
            return False, f"{LOGIN_FAIL}: code={r_code} msg={msg}"

        # 非 JSON 响应但 HTTP 200（可能是重定向到首页，登录成功）
        if code == 200 and not body:
            # 检查是否有 Set-Cookie（登录成功会下发新 JSESSIONID）
            set_cookie = resp.headers.get("Set-Cookie", "") or ""
            if "JSESSIONID" in set_cookie and "deleteMe" not in set_cookie:
                return True, LOGIN_OK

        return False, f"{LOGIN_FAIL}: 未知响应 code={r_code} msg={msg}"

    def _login_v5_jwt(self, captcha_code=None):
        """RuoYi v5 JWT 登录：POST /login JSON → 提取 token → 加 Authorization 头

        请求体：{"username":"admin","password":"admin123","code":"验证码","uuid":"uuid"}
        响应体：{"code":200,"token":"eyJhbGciOi..."}
        验证码处理（D3）：同 v4，captcha_code=None 自动探测+OCR
        """
        # D3：验证码处理（v5 用 code 字段，uuid 关联验证码 session）
        validate_code = ""
        captcha_uuid = ""
        if captcha_code is None:
            try:
                from core.captcha_solver import CaptchaSolver

                solver = CaptchaSolver(self.target, self.session)
                has_captcha, code = solver.solve()
                if has_captcha:
                    if code:
                        validate_code = code
                    else:
                        return False, f"{LOGIN_CAPTCHA}: 接口存在但识别失败(后端={solver.backend_name})"
            except Exception as e:
                return False, f"{LOGIN_CAPTCHA}: 探测异常 {e}"
        elif captcha_code:
            validate_code = captcha_code

        url = join_url(self.target, "/login")
        json_data = {
            "username": self.username,
            "password": self.password,
            "code": validate_code,
            "uuid": captcha_uuid,
        }
        try:
            resp = self.session.post(url, json=json_data)
        except Exception as e:
            return False, f"{LOGIN_ERROR}: {e}"

        body = {}
        try:
            body = resp.json()
        except (ValueError, TypeError):
            return False, f"{LOGIN_ERROR}: 响应非 JSON"

        r_code = body.get("code")
        if r_code == 200:
            token = body.get("token") or ""
            if token:
                # 设置 Authorization 头，后续请求自动带
                self.session.session.headers["Authorization"] = f"Bearer {token}"
                return True, LOGIN_OK
            return False, f"{LOGIN_FAIL}: 响应无 token 字段"

        msg = str(body.get("msg", ""))
        if "验证码" in msg or "captcha" in msg.lower():
            return False, LOGIN_CAPTCHA

        return False, f"{LOGIN_FAIL}: code={r_code} msg={msg}"
