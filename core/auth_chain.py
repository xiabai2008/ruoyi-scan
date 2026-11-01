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
import re
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional, Tuple
from urllib.parse import urljoin, urlparse

from common.logger import get_logger
from core.http import join_url

logger = get_logger(__name__)

# 鉴权模式
AUTH_NONE = "none"  # 无鉴权（受保护接口直接返回业务数据）
AUTH_V4_SESSION = "v4"  # RuoYi v4 Session（Cookie）
AUTH_V5_JWT = "v5"  # RuoYi v5 JWT（Authorization 头）
AUTH_UNKNOWN = "unknown"  # 有鉴权迹象但没找到登录入口（/login 404 且受保护接口非 200）
AUTH_ERROR = "error"  # 探测失败（网络异常），区别于「确认无鉴权」

# 登录结果
LOGIN_OK = "ok"  # 登录成功
LOGIN_FAIL = "fail"  # 登录失败（用户名/密码错误）
LOGIN_CAPTCHA = "captcha"  # 验证码错误（换图重试有意义）
LOGIN_CAPTCHA_INFRA = "captcha_infra"  # 验证码接口/OCR 后端故障（换图重试无意义，不重试）
LOGIN_ERROR = "error"  # 网络异常或响应异常
LOGIN_MFA = "mfa_required"  # 目标启用了二次验证（动态口令/OTP/MFA），无法自动登录

# 二次验证（MFA）特征：登录响应出现这些词说明账号/站点要求第二因素，
# 不能笼统记为 failed——安全团队需要据此改走人工登录或排除该目标。
MFA_KEYWORDS = ("动态口令", "otp", "mfa", "二次验证", "验证码已发送")

# 验证码挡住登录时的下一步动作：只报「识别失败」用户无从下手，
# 实测（行为级靶场）没有 OCR 后端时注入/上传类全部只能停在 UNKNOWN。
CAPTCHA_HINT = (
    "；可执行 pip install ddddocr 启用识别（本项目未提供 [ocr] extra），"
    '或用 --auth "cookie=JSESSIONID=..." 复用浏览器已登录会话'
)


@contextmanager
def isolated_auth_session(
    target: str,
    username: str,
    password: str,
    timeout: Optional[float] = None,
) -> Iterator[Tuple[Any, bool, str]]:
    """在**独立会话**中登录，yield (session, ok, reason)；退出时关闭该会话。

    为什么需要独立会话（2026-09-17 多版本矩阵实测后确立）
    ----------------------------------------------------
    扫描器让所有插件复用同一个 `SessionManager`。若插件直接在共享会话上登录，
    认证状态会**一直保留给后续插件**，而其余插件的判定普遍以「未认证基线」为前提：
      - 未认证时未知路径 → 302 → 登录页（200，约 4KB）；
      - 已认证时未知路径 → v4.7.8 返回 404，但 v4.8.3（Spring Boot 4.0.3）返回 200。
    于是 v4.8.3 上一次性多出 6 个误报（备份文件 65 个 / MinIO / RocketMQ /
    Swagger / IDE 残留 / Plus 认证），属**跨插件状态污染**。

    ⚠ 不能用「cookie 快照 + 还原」做隔离——已实测无效：Shiro 把认证状态存在
    服务端 session（按 JSESSIONID 索引），把 cookie 还原成同一个 JSESSIONID 后，
    服务端仍视其为已认证。唯一的正确做法是让需鉴权的插件自建会话。

    用法：
        with isolated_auth_session(target, user, pwd) as (sess, ok, reason):
            if not ok:
                return ScanResult(... STATUS_UNKNOWN ...)
            resp = sess.get(join_url(target, "/monitor/job"))

    Args:
        target: 目标站点根 URL
        username / password: 登录凭据
        timeout: 请求超时（None 用 SessionManager 默认）
    """
    from core.session import SessionManager

    own = SessionManager(timeout=int(timeout) if timeout is not None else None)
    try:
        chain = RuoYiAuthChain(target, own, username=username, password=password, timeout=timeout)
        ok, reason = chain.login(max_attempts=8)
        # 登录入口可能不在根路径（如 D1 的 /portal 上下文），后续受保护接口取证
        # 需要同一前缀。挂在会话上而不是增加返回元组字段，保持既有调用方不变。
        setattr(own, "auth_base", chain.base_path)
        setattr(own, "auth_login_url", chain.login_url)
        yield own, ok, reason
    finally:
        try:
            own.close()
        except Exception:  # pragma: no cover - 关闭失败不应影响扫描结论
            logger.debug("关闭隔离会话失败", exc_info=True)


def login_with_password(
    target: str,
    username: str,
    password: str,
    timeout: Optional[float] = None,
    attempts: int = 8,
) -> Tuple[bool, str, Dict[str, Any]]:
    """公共登录器：显式凭据 + 验证码求解（含算术验证码运算符轮换）。

    这是 `lib.auth_scan.auto_login` 与 `--auth-surface` 共用的登录能力，抽出来的
    目的不是「合并认证链」，而是让高权登录也能用上验证码 OCR：
    - 不内置任何默认账号，username/password 必须由调用方显式传入；
    - v4 表单 / v5 JWT 由 RuoYiAuthChain 自动探测；
    - 验证码错误时由 CaptchaSolver 换图重试，OCR 丢掉运算符时在 +、-、*、/
      四个候选答案间轮换（Phase 2 盲测验证过的策略）。

    Args:
        target: 目标站点根 URL
        username / password: 显式凭据
        timeout: 请求超时（None 用 SessionManager 默认）
        attempts: 验证码错误时的最大尝试次数

    Returns:
        (ok, reason, config)
        config = {"cookies": {...}, "headers": {...}, "type": "cookie"|"bearer"|None}
        失败时 config 为空字典；不会抛异常。
    """
    from core.session import SessionManager

    own = SessionManager(timeout=int(timeout) if timeout is not None else None)
    try:
        chain = RuoYiAuthChain(target, own, username=username, password=password, timeout=timeout)
        ok, reason = chain.login(max_attempts=attempts)
        if not ok:
            return False, reason, {}

        headers: Dict[str, str] = {}
        auth_header = own.session.headers.get("Authorization")
        if auth_header:
            headers["Authorization"] = auth_header
        cookies = dict(own.session.cookies)
        if not cookies and not headers:
            # 目标无鉴权：login() 会返回成功，但没有任何凭据可注入
            return False, "no_credentials", {}
        return (
            True,
            reason,
            {
                "cookies": cookies,
                "headers": headers,
                "type": "bearer" if headers else "cookie",
            },
        )
    except Exception as exc:  # noqa: BLE001 - 登录失败不应中断扫描
        logger.debug("公共登录器异常", exc_info=True)
        return False, f"{LOGIN_ERROR}: {exc}", {}
    finally:
        try:
            own.close()
        except Exception:  # pragma: no cover - 关闭失败不影响登录结论
            logger.debug("关闭公共登录器会话失败", exc_info=True)


class RuoYiAuthChain:
    """若依登录链编排器

    用法：
        chain = RuoYiAuthChain(target, session, username='admin', password='admin123')
        ok, reason = chain.login()
        if ok:
            # session 已带凭证，后续请求自动鉴权
            resp = session.get(join_url(target, '/monitor/job/edit'))
    """

    def __init__(
        self,
        target: str,
        session: Any,
        username: str = "admin",
        password: str = "admin123",
        remember_me: bool = False,
        timeout: Optional[float] = None,
    ) -> None:
        """初始化登录链（默认尝试 admin/admin123 弱口令）

        Args:
            target: 目标站点根 URL
            session: SessionManager 实例，登录成功后自动携带凭证
            remember_me: 是否勾选"记住我"（v4 表单 rememberMe 字段）
            timeout: 请求超时秒数（None 使用 session 默认）
        """
        self.target = target
        self.session = session
        self.username = username
        self.password = password
        self.remember_me = remember_me
        self.timeout = timeout
        self.auth_mode: Optional[str] = None
        # 登录入口：默认按 RuoYi 约定 /login；探测到 302 Location 后改为实际地址
        # （例如 /portal/auth/signin）。后续 _login_once 必须使用它，不能硬编码。
        self.login_url: str = join_url(target, "/login")
        # 应用上下文前缀（例如 D1 部署在 /portal）：根路径下探测不到受保护接口时，
        # 从站点根的同源目录重定向通用推导，供受保护接口探测与登录后取证复用。
        self.base_path: str = ""

    # 受保护接口：仅用于判断「目标到底有没有鉴权」，不依赖任何具体登录页路径。
    # 这些是若依各形态共有的业务列表接口；返回业务 JSON 即证明无需登录即可取数。
    PROTECTED_ENDPOINTS = ("/system/user/list", "/monitor/job/list", "/system/dept/list")

    # Location 中含这些片段即视为「指向登录页」（大小写不敏感）。
    # 不写死 /portal/auth/signin——D1 这类自定义入口靠 302 通用发现。
    LOGIN_LOCATION_HINTS = ("login", "logon", "signin", "sign-in", "sign_in", "auth", "sso")

    @staticmethod
    def _mentions_mfa(text: str) -> bool:
        """响应是否提到二次验证（动态口令/OTP/MFA/短信验证码已发送）。"""
        low = (text or "").lower()
        if any(k in low for k in ("动态口令", "二次验证", "验证码已发送")):
            return True
        # otp/mfa 用词边界匹配，避免 prototype 之类的普通英文单词误触发
        return bool(re.search(r"\b(otp|mfa)\b", low))

    @staticmethod
    def _is_login_location(location: str) -> bool:
        low = (location or "").lower()
        return any(hint in low for hint in RuoYiAuthChain.LOGIN_LOCATION_HINTS)

    @staticmethod
    def _classify_login_response(resp: Any) -> str:
        """按登录页内容判定 v5（JSON）或 v4（HTML/表单）。

        与旧 detect_auth_mode 的后半段判定保持一致：先 JSON 再 HTML，
        避免 JSON 的 msg 含「登录」二字被 HTML 规则抢判。
        """
        text = resp.text or ""
        ct = (resp.headers.get("Content-Type", "") or "").lower()
        if "json" in ct:
            return AUTH_V5_JWT
        try:
            _json.loads(text)
            return AUTH_V5_JWT
        except (ValueError, TypeError):
            logger.debug("鉴权模式 JSON 响应解析失败", exc_info=True)

        text_lower = text.lower()
        if "html" in ct or "<html" in text_lower or "<form" in text_lower:
            return AUTH_V4_SESSION
        return AUTH_V4_SESSION

    def _follow_login_location(self, location: str, base_url: str) -> Optional[str]:
        """跟随 Location 到登录页，更新 self.login_url 并返回鉴权模式。"""
        abs_url = urljoin(base_url, location)
        try:
            resp = self.session.get(abs_url, allow_redirects=True)
        except Exception:
            logger.debug("跟随登录页 Location 失败: %s", abs_url, exc_info=True)
            return None
        code = int(resp.status_code) if hasattr(resp, "status_code") else 0
        if code >= 400:
            return None
        self.login_url = abs_url
        return self._classify_login_response(resp)

    @staticmethod
    def _protected_body_has_data(body: Any) -> bool:
        """受保护接口响应是否含业务数据（rows 非空 / total>0 / data 非空）。"""
        if not isinstance(body, dict):
            return False
        rows = body.get("rows")
        if isinstance(rows, list) and rows:
            return True
        total = body.get("total")
        if isinstance(total, int) and not isinstance(total, bool) and total > 0:
            return True
        data = body.get("data")
        if isinstance(data, list) and data:
            return True
        return bool(isinstance(data, dict) and data)

    def _discover_context_base(self) -> str:
        """从站点根的同源目录重定向推导应用上下文前缀。

        背景（D1 实测）：应用部署在 `/portal`，根路径 `/login`、`/system/user/list`
        都只命中 Nginx 的 404；受保护接口的真实地址是 `/portal/system/user/list`。
        直接猜 `/portal` 属于对单座靶场特判，这里改为通用能力：
            GET / -> 302 Location: /portal/
        只接受同源、以 `/` 结尾、且不像登录页的目录重定向；其余一律返回空串，
        行为与改动前一致（按根路径探测）。
        """
        root = join_url(self.target, "/")
        try:
            resp = self.session.get(root, allow_redirects=False)
        except Exception:
            logger.debug("根路径上下文探测失败", exc_info=True)
            return ""
        code = int(resp.status_code) if hasattr(resp, "status_code") else 0
        if code not in (301, 302, 303, 307, 308):
            return ""
        location = (getattr(resp, "headers", {}) or {}).get("Location", "") or ""
        if not location:
            return ""
        abs_url = urljoin(root, location)
        if urlparse(abs_url).netloc != urlparse(self.target).netloc:
            return ""
        path: str = str(urlparse(abs_url).path)
        if not path.endswith("/") or path == "/":
            return ""
        if self._is_login_location(path):
            return ""
        return path.rstrip("/")

    def _detect_by_protected_endpoints(self) -> str:
        """用受保护接口判断「到底有没有鉴权」并顺便发现登录页。

        - 200 + 业务 JSON（rows/data/total）→ AUTH_NONE
        - 302/401/403 → 有鉴权；若 302 Location 指向登录页则跟随并判定 v4/v5，
          否则 AUTH_UNKNOWN
        - 全部 404/异常 → AUTH_UNKNOWN（绝不当作「无鉴权」）

        先按根路径探测；全部落空时再尝试从站点根重定向推导出的上下文前缀
        （例如 /portal），避免把「部署在子路径」误判成「没有登录入口」。
        """
        bases = [""]
        context_base = self._discover_context_base()
        if context_base:
            bases.append(context_base)
        for base in bases:
            for path in self.PROTECTED_ENDPOINTS:
                url = join_url(self.target, base + path)
                for method in ("get", "post"):
                    try:
                        resp = getattr(self.session, method)(url, allow_redirects=False)
                    except Exception:
                        logger.debug("受保护接口探测失败: %s %s", method.upper(), url, exc_info=True)
                        continue

                    code = int(resp.status_code) if hasattr(resp, "status_code") else 0
                    if code == 200:
                        try:
                            body = resp.json()
                        except (ValueError, TypeError):
                            body = None
                        if self._protected_body_has_data(body):
                            self.base_path = base
                            self.auth_mode = AUTH_NONE
                            return AUTH_NONE
                        # 200 + JSON code=401/403 是前后端分离版未登录的常见形态
                        if isinstance(body, dict) and body.get("code") in (401, 403):
                            continue

                    if code in (301, 302, 303, 307, 308):
                        location = (getattr(resp, "headers", {}) or {}).get("Location", "") or ""
                        if location and self._is_login_location(location):
                            mode = self._follow_login_location(location, url)
                            if mode:
                                self.base_path = base
                                self.auth_mode = mode
                                return mode
                        continue

                    if code in (401, 403):
                        # 有鉴权，但响应里没有可用的登录页地址 → UNKNOWN
                        continue

        self.auth_mode = AUTH_UNKNOWN
        return AUTH_UNKNOWN

    def detect_auth_mode(self) -> str:
        """探测鉴权模式：v4 Session / v5 JWT / 无鉴权 / 未知 / 探测失败

        判定顺序（F6-1）：
        1. GET /login：
           - 200 + HTML/表单/JSON → v4/v5（保持原判定）
           - 301/302 且 Location 指向登录页 → 跟随，用实际地址作为 login_url
           - 404 → 进入第 2 步
        2. 用受保护接口判断「到底有没有鉴权」：
           - 200 + 业务 JSON（rows/data/total）→ AUTH_NONE
           - 302/401/403 → 有鉴权；能发现登录页则按内容判 v4/v5，否则 AUTH_UNKNOWN
           - 全部 404/异常 → AUTH_UNKNOWN
        3. 传输失败 → AUTH_ERROR（不等于无鉴权）

        关键：404 只说明「没有这个登录入口」，不能说明「没有鉴权」。
        """
        self.login_url = join_url(self.target, "/login")
        try:
            # 必须自己看 3xx：requests 默认自动跟随会让 /login -> 登录页 的站点
            # 丢掉 Location，login_url 仍停在 /login，后续 POST 自然打不中。
            resp = self.session.get(self.login_url, allow_redirects=False)
        except Exception:
            # 传输失败绝不能当作「无鉴权」：那会让 login() 直接返回成功，
            # 调用方在「已认证」的错误前提下继续扫描。记 AUTH_ERROR，
            # 由 login() 映射为 LOGIN_ERROR（网络异常）。
            logger.debug("探测鉴权模式失败（网络异常）", exc_info=True)
            self.auth_mode = AUTH_ERROR
            return AUTH_ERROR

        http_code = int(resp.status_code) if hasattr(resp, "status_code") else 0

        if http_code in (301, 302, 303, 307, 308):
            location = (getattr(resp, "headers", {}) or {}).get("Location", "") or ""
            if location and self._is_login_location(location):
                mode = self._follow_login_location(location, self.login_url)
                if mode:
                    self.auth_mode = mode
                    return mode
            # 重定向目标不像登录页：交给受保护接口判断是否存在鉴权
            return self._detect_by_protected_endpoints()

        if http_code == 404:
            # 没有 /login 不代表没有鉴权（C2-2 的 Tomcat 应用 /login 就是 404）
            return self._detect_by_protected_endpoints()

        mode = self._classify_login_response(resp)
        self.auth_mode = mode
        return mode

    def login(self, captcha_code: Optional[str] = None, max_attempts: int = 8) -> Tuple[bool, str]:
        """按探测到的鉴权模式登录（验证码错误时自动重试）

        为什么需要重试：RuoYi 4.x 登录必带验证码，而 OCR 不可能 100% 准确。
        2026-09-17 在真实 4.7.8 实例上实测：ddddocr 单次识别并登录成功约 67%。
        验证码错误时重新取一张新图再识别即可，因此重试是**有效**的；
        加上重试后整体成功率约为 1-(1-p)^n——3 次约 96%（矩阵实测仍会偶发失败），
        5 次约 99.6%。

        只对「验证码错误」重试——账号密码错误、网络异常重试没有意义。

        Args:
            captcha_code: 验证码（D3）。None=自动探测+OCR；''=跳过验证码；非空=手动提供
            max_attempts: 含首次在内的最大尝试次数（显式传入 captcha_code 时不重试）

        Returns:
            (ok: bool, reason: str)
            ok=True, reason=LOGIN_OK：登录成功，session 已带凭证
            ok=False, reason=LOGIN_CAPTCHA：验证码错误且多次 OCR 均失败
            ok=False, reason=LOGIN_CAPTCHA_INFRA：验证码接口/OCR 后端故障（不重试）
            ok=False, reason=LOGIN_FAIL：用户名/密码错误
            ok=False, reason=LOGIN_ERROR：网络异常
        """
        if self.auth_mode is None:
            self.detect_auth_mode()

        if self.auth_mode == AUTH_NONE:
            # 受保护接口已返回业务数据：确实无鉴权，direct 成功
            return True, LOGIN_OK

        if self.auth_mode == AUTH_UNKNOWN:
            # /login 不存在且受保护接口没有给出「无鉴权」证据：
            # 绝不能返回 True——那会把「没发生登录」写成「登录成功」。
            return False, "login_endpoint_not_found"

        if self.auth_mode == AUTH_ERROR:
            return False, f"{LOGIN_ERROR}: 鉴权模式探测失败"

        # 只有 None（自动探测）才需要重试 OCR 识别错误；''（跳过）与手动验证码都不重试
        attempts = 1 if captcha_code is not None else max(1, max_attempts)
        last_reason = LOGIN_ERROR
        for i in range(attempts):
            ok, reason = self._login_once(captcha_code, attempt_index=i)
            if ok:
                return True, LOGIN_OK
            last_reason = reason
            # 仅「验证码错误」值得换图重试；探测异常/OCR 后端故障换图也不会好，
            # 重试只会浪费 5 倍请求
            if reason != LOGIN_CAPTCHA:
                break
            logger.debug("第 %d/%d 次登录因验证码失败，换图重试", i + 1, attempts)
        return False, last_reason

    def _login_once(self, captcha_code: Optional[str] = None, attempt_index: int = 0) -> Tuple[bool, str]:
        """执行一次登录尝试（按 auth_mode 分发，不含重试）"""
        if self.auth_mode == AUTH_V4_SESSION:
            return self._login_v4_session(captcha_code, attempt_index=attempt_index)

        if self.auth_mode == AUTH_V5_JWT:
            return self._login_v5_jwt(captcha_code, attempt_index=attempt_index)

        return False, LOGIN_ERROR

    def _login_v4_session(self, captcha_code: Optional[str] = None, attempt_index: int = 0) -> Tuple[bool, str]:
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
                has_captcha, code = solver.solve(math_op_index=attempt_index)
                if has_captcha:
                    if code:
                        validate_code = code
                    else:
                        # 接口在但拿不到可识别图片（后端不可用/空图）：基础设施故障，
                        # 换图重试无意义，用独立原因避免 login() 5 次空转
                        return (
                            False,
                            f"{LOGIN_CAPTCHA_INFRA}: 接口存在但识别失败(后端={solver.backend_name}){CAPTCHA_HINT}",
                        )
            except Exception as e:
                return False, f"{LOGIN_CAPTCHA_INFRA}: 探测异常 {e}"
        elif captcha_code:
            validate_code = captcha_code

        url = self.login_url
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

        http_code = int(resp.status_code) if hasattr(resp, "status_code") else 0

        # 解析 JSON 响应（RuoYi AjaxResult）；body 显式声明 Any：resp.json() 形状不可预知
        body: Any = {}
        try:
            body = resp.json()
        except (ValueError, TypeError):
            logger.debug("登录响应 JSON 解析失败", exc_info=True)
        if not isinstance(body, dict):
            # 非字典 JSON（列表/标量）按无 JSON body 处理，避免 .get() 抛 AttributeError
            body = {}

        # code=0 或 code=200 → 登录成功（若依 success() 返回 code=0，部分版本 200）
        # 显式排除 JSON 布尔：False == 0，`False in (0, 200)` 会误判登录成功
        r_code = body.get("code")
        success_code = isinstance(r_code, int) and not isinstance(r_code, bool) and r_code in (0, 200)
        if success_code:
            return True, LOGIN_OK
        # 定制登录端点可能不用若依 AjaxResult：D1 的 /portal/auth/signin 返回
        # {"success":true,"message":"登录成功"}。只认严格的 JSON true，
        # 不能把字符串 "true"/1 当成功（服务端/代理可能回显任意值）。
        if body.get("success") is True:
            return True, LOGIN_OK

        # 二次验证必须先于「验证码」判断：「验证码已发送」也含"验证码"，
        # 但它指 MFA 短信/邮件，不是图形验证码，重试换图没有意义。
        if self._mentions_mfa(str(body.get("msg", ""))) or self._mentions_mfa(resp.text or ""):
            return False, LOGIN_MFA

        # 验证码错误 → 需要验证码（D1 不处理，留 D3 OCR）
        msg = str(body.get("msg", ""))
        if "验证码" in msg or "captcha" in msg.lower():
            return False, LOGIN_CAPTCHA

        # 用户名/密码错误
        if "用户" in msg or "密码" in msg or "password" in msg.lower() or "user" in msg.lower():
            return False, f"{LOGIN_FAIL}: {msg}"

        # 其他失败（code=500 等）
        if r_code is not None and not success_code:
            return False, f"{LOGIN_FAIL}: code={r_code} msg={msg}"

        # 非 JSON 响应但 HTTP 200：可能是登录成功后重定向到首页。
        # 不能只看「响应带新 JSESSIONID」——登录失败重定向回 /login 也会（重）下发
        # 会话 cookie，仅凭 cookie 会误报成功；要求确实发生了重定向且落点不是登录页，
        # 另外 Shiro 认证失败会下发 deleteMe 销毁会话，出现它即未成功。
        if http_code == 200:
            history = getattr(resp, "history", None) or []
            final_url = str(getattr(resp, "url", "") or "").lower()
            # Set-Cookie 可能出现在重定向链的任一响应上（登录成功通常在 302 响应上下发
            # 新会话 cookie，跟随重定向后的最终响应头里看不到它）
            set_cookie_parts = []
            for r in [resp] + list(history):
                sc = (getattr(r, "headers", {}) or {}).get("Set-Cookie", "") or ""
                if sc:
                    set_cookie_parts.append(sc)
            set_cookie = "; ".join(set_cookie_parts)
            if history and "/login" not in final_url and "JSESSIONID" in set_cookie and "deleteMe" not in set_cookie:
                return True, LOGIN_OK
            return False, f"{LOGIN_FAIL}: 非 JSON 响应且无成功信号 http={http_code} msg={msg}"

        return False, f"{LOGIN_FAIL}: 未知响应 code={r_code} msg={msg}"

    def _login_v5_jwt(self, captcha_code: Optional[str] = None, attempt_index: int = 0) -> Tuple[bool, str]:
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
                has_captcha, code = solver.solve(math_op_index=attempt_index)
                if has_captcha:
                    # uuid 必须与本次识别的图片同批下发，否则服务端校验必然失败
                    captcha_uuid = solver.captcha_uuid
                    if code:
                        validate_code = code
                    else:
                        return (
                            False,
                            f"{LOGIN_CAPTCHA_INFRA}: 接口存在但识别失败(后端={solver.backend_name}){CAPTCHA_HINT}",
                        )
            except Exception as e:
                return False, f"{LOGIN_CAPTCHA_INFRA}: 探测异常 {e}"
        elif captcha_code:
            # 手动提供验证码：无对应 uuid 可用（调用方无法得知），如实提交
            validate_code = captcha_code

        url = self.login_url
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

        body: Any = {}
        try:
            body = resp.json()
        except (ValueError, TypeError):
            return False, f"{LOGIN_ERROR}: 响应非 JSON"
        if not isinstance(body, dict):
            # 非字典 JSON（列表/标量）按异常响应处理，避免 .get() 抛 AttributeError
            return False, f"{LOGIN_ERROR}: 响应 JSON 非对象"

        r_code = body.get("code")
        if r_code == 200:
            token = body.get("token") or ""
            if token:
                # 设置 Authorization 头，后续请求自动带
                self.session.session.headers["Authorization"] = f"Bearer {token}"
                return True, LOGIN_OK
            return False, f"{LOGIN_FAIL}: 响应无 token 字段"

        msg = str(body.get("msg", ""))
        if self._mentions_mfa(msg) or self._mentions_mfa(resp.text or ""):
            return False, LOGIN_MFA
        if "验证码" in msg or "captcha" in msg.lower():
            return False, LOGIN_CAPTCHA

        return False, f"{LOGIN_FAIL}: code={r_code} msg={msg}"
