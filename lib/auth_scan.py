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

    for arg in auth_args:
        if "=" not in arg:
            continue
        auth_type, _, value = arg.partition("=")
        auth_type = auth_type.strip().lower()
        value = value.strip()
        if not value:
            continue

        if auth_type == "cookie":
            # Cookie 格式：name1=value1; name2=value2
            config["type"] = "cookie"
            for pair in value.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    config["cookies"][k.strip()] = v.strip()
        elif auth_type == "bearer":
            config["type"] = "bearer"
            config["headers"]["Authorization"] = f"Bearer {value}"
        elif auth_type == "header":
            # 自定义头格式：Header-Name: value
            if ":" in value:
                hname, _, hval = value.partition(":")
                config["type"] = "header"
                config["headers"][hname.strip()] = hval.strip()
        elif auth_type == "basic":
            # Basic 认证：username:password
            config["type"] = "basic"
            import base64

            encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
            config["headers"]["Authorization"] = f"Basic {encoded}"

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
    target: str, username: str, password: str, login_url: str = "", login_type: str = "form", verbose: bool = True
) -> Dict[str, Any]:
    """自动登录获取认证信息

    Args:
        target: 目标 URL
        username: 用户名
        password: 密码
        login_url: 登录接口 URL（为空时自动推断）
        login_type: 登录类型 form/json
        verbose: 是否打印日志
    Returns:
        认证配置字典（含 cookies 和 headers）
    """
    try:
        import requests
    except ImportError:
        if verbose:
            print("  [!]requests 未安装，无法自动登录")
        return {"cookies": {}, "headers": {}, "type": None}

    # 推断登录 URL
    if not login_url:
        # RuoYi 默认登录接口
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        login_url = urljoin(base, "/login")

    if verbose:
        print(f"  [*]自动登录: {login_url}（用户: {username}）")

    try:
        session = requests.Session()
        # 先访问首页获取 cookie（如 JSESSIONID）
        session.get(target, timeout=10)

        if login_type == "json":
            # JSON 登录
            payload = {"username": username, "password": password}
            resp = session.post(login_url, json=payload, timeout=10)
        else:
            # 表单登录
            payload = {"username": username, "password": password}
            resp = session.post(login_url, data=payload, timeout=10)

        # 检查登录是否成功
        config = {
            "cookies": dict(session.cookies),
            "headers": {},
            "type": "cookie",
        }

        # 尝试从响应中提取 token
        try:
            data = resp.json()
            token = data.get("token") or data.get("data", {}).get("token", "")
            if token:
                config["headers"]["Authorization"] = f"Bearer {token}"
                config["type"] = "bearer"
                if verbose:
                    print("  [+]登录成功，获取到 Bearer Token")
        except Exception:
            logger.debug("从登录响应中提取 Token 失败", exc_info=True)

        if config["cookies"] and not config["headers"].get("Authorization"):
            if verbose:
                print(f"  [+]登录成功，获取到 {len(config['cookies'])} 个 Cookie")
        elif not config["cookies"] and not config["headers"].get("Authorization"):
            if verbose:
                print("  [!]登录可能失败，未获取到认证信息")
            return {"cookies": {}, "headers": {}, "type": None}

        return config
    except Exception as e:
        if verbose:
            print(f"  [!]自动登录异常: {e}")
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
        for name, value in cookies.items():
            session.session.cookies.set(name, value)
        # 同时设置 Cookie 头（部分场景需要）
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            session.session.headers["Cookie"] = cookie_str

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
    username, _, password = login_arg.partition(":")
    return username.strip(), password.strip()
