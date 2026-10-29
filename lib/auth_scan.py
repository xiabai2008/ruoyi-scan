# D26：认证扫描增强（Cookie / Token / Bearer 注入）
#
# 支持登录后扫描，覆盖需认证才能访问的漏洞端点
#
# 使用方式：
#   # Cookie 注入（从浏览器复制）
#   python main.py -u http://target/ --auth cookie="JSESSIONID=abc123; token=xyz"
#
#   # Bearer Token 注入
#   python main.py -u http://target/ --auth bearer="eyJhbGciOiJIUzI1NiJ9..."
#
#   # Authorization Header 注入
#   python main.py -u http://target/ --auth header="Authorization: Basic dXNlcjpwYXNz"
#
#   # 从文件加载认证信息
#   python main.py -u http://target/ --auth-file cookies.txt
#
#   # 自动登录（用户名+密码）
#   python main.py -u http://target/ --auth-login admin:password123
#
# 支持的认证类型：
#   1. cookie  - Cookie 头注入（最常用）
#   2. bearer  - Authorization: Bearer <token>
#   3. header  - 自定义头（格式：Header-Name: value）
#   4. login   - 自动登录（用户名:密码，支持表单/JSON 登录）
import os
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin, urlparse

from common.logger import get_logger
from lib.reporter import emit

logger = get_logger(__name__)


def parse_auth_arg(auth_args: List[str]) -> Dict[str, Any]:
    """解析 --auth 参数列表

    Args:
        auth_args: --auth 参数值列表，如 ['cookie=JSESSIONID=abc', 'bearer=xyz']
    Returns:
        认证配置字典
        {
            'cookies': {'JSESSIONID': 'abc'},
            'headers': {'Authorization': 'Bearer xyz'},
            'type': 'cookie' / 'bearer' / 'header',
        }
    """
    config = {
        "cookies": {},
        "headers": {},
        "type": None,
    }
    types_seen = set()

    for arg in auth_args:
        # 跳过不含 "=" 的无效项（空值/描述文本），避免误解析
        if "=" not in arg:
            continue
        auth_type, _, value = arg.partition("=")
        auth_type = auth_type.strip().lower()
        value = value.strip()
        if not value:
            continue

        if auth_type == "cookie":
            # Cookie 格式：name1=value1; name2=value2
            types_seen.add("cookie")
            for pair in value.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    config["cookies"][k.strip()] = v.strip()
        elif auth_type == "bearer":
            types_seen.add("bearer")
            config["headers"]["Authorization"] = f"Bearer {value}"
        elif auth_type == "header":
            # 自定义头格式：Header-Name: value
            if ":" in value:
                hname, _, hval = value.partition(":")
                types_seen.add("header")
                config["headers"][hname.strip()] = hval.strip()
            else:
                # 无冒号的值会被静默丢弃，用户却以为已配置 → 明确告警
                logger.warning("--auth header 格式错误（应为 'Header-Name: value'）: %s", value)
                emit(f"  [!]--auth header 格式错误（应为 'Header-Name: value'）: {value}")
        elif auth_type == "basic":
            # Basic 认证：username:password
            types_seen.add("basic")
            import base64

            encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
            config["headers"]["Authorization"] = f"Basic {encoded}"

    # 多类型混用时 type 取最后一次赋值会与已注入的凭据不符：显式标记 mixed 并告警
    if len(types_seen) > 1:
        logger.warning("--auth 同时指定了多种认证类型 %s，凭据将全部注入，type 标记为 mixed", sorted(types_seen))
        config["type"] = "mixed"
    elif types_seen:
        config["type"] = next(iter(types_seen))

    return config


def load_auth_file(filepath: str) -> Dict[str, Any]:
    """从文件加载认证信息

    文件格式：
        # 注释
        type: cookie
        JSESSIONID: abc123
        token: xyz

    或纯 Cookie 字符串：
        JSESSIONID=abc123; token=xyz

    Args:
        filepath: 认证文件路径
    Returns:
        认证配置字典
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"认证文件不存在: {filepath}")

    with open(filepath, encoding="utf-8") as f:
        content = f.read().strip()

    config = {
        "cookies": {},
        "headers": {},
        "type": None,
    }

    # 检查是否有 type: 行
    lines = content.splitlines()
    has_type = any(line.strip().lower().startswith("type:") for line in lines)

    if has_type:
        # 结构化格式
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key.lower() == "type":
                config["type"] = val.lower()
            elif key.lower() == "authorization":
                config["headers"]["Authorization"] = val
            else:
                config["cookies"][key] = val
        if config["type"] == "bearer" and "Authorization" not in config["headers"]:
            # bearer 类型但无 Authorization 头，从 cookies 中取 token
            # pop：取出后即从 cookies 移除，避免 token 又当作 Cookie 重复发送
            token = config["cookies"].pop("token", "")
            if token:
                config["headers"]["Authorization"] = f"Bearer {token}"
    else:
        # 纯 Cookie 字符串
        config["type"] = "cookie"
        for pair in content.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, _, v = pair.partition("=")
                config["cookies"][k.strip()] = v.strip()

    return config


def auto_login(
    target: str,
    username: str,
    password: str,
    login_url: str = "",
    login_type: str = "form",
    username_field: str = "username",
    password_field: str = "password",
    verbose: bool = True,
) -> Dict[str, Any]:
    """自动登录获取认证信息

    Args:
        target: 目标 URL
        username: 用户名
        password: 密码
        login_url: 登录接口 URL（为空时按 RuoYi 约定推断 /login）
        login_type: 登录类型 form/json
        username_field: 用户名字段名（非 RuoYi 应用可自行指定）
        password_field: 密码字段名（非 RuoYi 应用可自行指定）
        verbose: 是否打印日志
    Returns:
        认证配置字典（含 cookies 和 headers）
    """
    try:
        import requests
    except ImportError:
        if verbose:
            emit("  [!]requests 未安装，无法自动登录")
        return {"cookies": {}, "headers": {}, "type": None}

    # 推断登录 URL
    if not login_url:
        # RuoYi 默认登录接口（其他应用请通过 login_url 参数显式指定）
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        login_url = urljoin(base, "/login")

    if verbose:
        emit(f"  [*]自动登录: {login_url}（用户: {username}）")

    try:
        session = requests.Session()
        # 先访问首页获取 cookie（如 JSESSIONID）
        session.get(target, timeout=10)
        # 记录预登录 Cookie：GET 首页下发的会话 Cookie 不能作为登录成功依据
        pre_login_cookies = dict(session.cookies)

        if login_type == "json":
            # JSON 登录
            payload = {username_field: username, password_field: password}
            resp = session.post(login_url, json=payload, timeout=10)
        else:
            # 表单登录
            payload = {username_field: username, password_field: password}
            resp = session.post(login_url, data=payload, timeout=10)

        def _extract_token(r: Any) -> str:
            """从登录响应里取 token（顶层或 data 子对象）"""
            try:
                d = r.json()
            except Exception:
                return ""
            if not isinstance(d, dict):
                return ""
            tok = d.get("token") or (d.get("data") or {}).get("token", "")
            return str(tok or "")

        token = _extract_token(resp)
        # 表单提交拿不到 token 时，用 JSON 再试一次。
        # RuoYi-Vue 前后端分离版（3.x / 5.x）的 /login 是 @RequestBody，**只认 JSON**；
        # 用表单提交会得到「用户不存在/密码错误」，token 永远拿不到，
        # 结果是分离版站点一律登录失败（实测 2026-10-29：若依 v3.9.2 靶场）。
        if not token and login_type != "json":
            resp = session.post(login_url, json=payload, timeout=10)
            token = _extract_token(resp)

        # 登录成功判据：POST 后新增/变更的 Cookie（排除预登录 GET 已下发的会话 Cookie）
        post_login_cookies = dict(session.cookies)
        new_cookies = {k: v for k, v in post_login_cookies.items() if pre_login_cookies.get(k) != v}

        # 检查登录是否成功
        config = {
            "cookies": post_login_cookies,
            "headers": {},
            "type": "cookie",
        }

        # 使用从响应中提取到的 token
        if token:
            config["headers"]["Authorization"] = f"Bearer {token}"
            config["type"] = "bearer"
            if verbose:
                emit("  [+]登录成功，获取到 Bearer Token")

        if not config["headers"].get("Authorization"):
            # 无 token 时以「HTTP 非错误 + 出现新 Cookie」作为登录成功信号，
            # 预登录 GET 已下发的 Cookie 不再被误当作认证成功凭据
            if resp.status_code < 400 and new_cookies:
                if verbose:
                    emit(f"  [+]登录成功，获取到 {len(new_cookies)} 个新 Cookie")
            else:
                if verbose:
                    emit(f"  [!]登录可能失败（HTTP {resp.status_code}），未获取到新认证信息")
                return {"cookies": {}, "headers": {}, "type": None}

        return config
    except requests.RequestException as e:
        # 仅兜底网络/HTTP 层异常并记录堆栈；其余异常向上抛出，避免真实配置错误被静默吞掉
        logger.exception("自动登录请求异常: %s", e)
        if verbose:
            emit(f"  [!]自动登录异常: {e}")
        return {"cookies": {}, "headers": {}, "type": None}


def apply_auth_to_session(session, auth_config: Dict[str, Any]):
    """将认证配置应用到 SessionManager

    Args:
        session: SessionManager 实例
        auth_config: 认证配置字典
    """
    if not auth_config:
        return

    # 注入 Cookie
    cookies = auth_config.get("cookies", {})
    if cookies:
        # 仅写 cookie jar：requests 发请求时会由 jar 重建 Cookie 头；
        # 再手工设置 Cookie 头会造成重复注入并可能覆盖 jar 的真实匹配结果
        for name, value in cookies.items():
            session.session.cookies.set(name, value)

    # 注入自定义头
    headers = auth_config.get("headers", {})
    if headers:
        session.session.headers.update(headers)


def parse_login_arg(login_arg: str) -> Tuple[str, str]:
    """解析 --auth-login 参数

    格式：username:password

    Args:
        login_arg: --auth-login 参数值
    Returns:
        (username, password)
    """
    if ":" not in login_arg:
        raise ValueError(f"--auth-login 格式应为 username:password，实际: {login_arg}")
    # partition 按首个冒号切分：密码本身含冒号时也能正确解析
    username, _, password = login_arg.partition(":")
    return username.strip(), password.strip()
