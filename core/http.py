# HTTP 工具：URL 归一化、目标可达性预检

import socket
from typing import Tuple
from urllib.parse import urlsplit


def normalize_target(url: str) -> str:
    """目标归一化：确保以 / 结尾（对齐原 self.url += '/' 逻辑）"""
    if not url:
        return url
    if not url.endswith("/"):
        url = url + "/"
    return url


def join_url(base: str, path: str) -> str:
    """拼接 URL，处理双斜杠（对齐原 path_scan 归一化逻辑）

    原逻辑：if self.url[-1] == '/' and path[0] == '/': path = path[1:]
    """
    if base.endswith("/") and path.startswith("/"):
        return base + path[1:]
    return base + path


def host_of(url: str) -> str:
    """提取 host:port（去掉协议与路径），用于原脚本 headers 的 Host 字段

    注意：必须只返回 netloc，不能带路径（如尾斜杠），否则 Host/Origin/Referer
    头会变成 '127.0.0.1:8080/' 这类非法值，Tomcat 直接返回 400 Bad Request，
    导致依赖这些头的 POST 型插件（如 SQL 报错注入）误判 SAFE。
    """
    if "://" in url:
        rest = url.split("://", 1)[1]
    else:
        rest = url
    # 去掉路径部分，只保留 host[:port]
    return rest.split("/", 1)[0]


def split_target(url: str) -> Tuple[str, int]:
    """解析目标 URL 的 (host, port)，用于可达性预检。

    协议可省略（如 '192.168.1.1:8080' 按 http 处理）；端口缺省时按协议补
    80/443。路径与查询串一律忽略——预检只关心能否建立 TCP 连接。

    Args:
        url: 目标 URL 或 host[:port]

    Returns:
        (host, port)；无法解析主机名时 host 为空串
    """
    raw = url if "://" in url else "http://" + url
    parts = urlsplit(raw)
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.hostname or "", port


def probe_reachable(url: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """TCP 可达性预检：扫描前确认目标端口可连接。

    存在意义：目标不可达时，每个插件都会各自发起请求并触发 urllib3 重试，
    控制台被重试日志刷屏（实测单个插件产 2 行警告 × 数十插件），扫描要数分钟
    才有结论，且工具自身的进度输出被完全淹没。一次 TCP 连接即可替代。

    Args:
        url: 目标 URL（协议可省略）
        timeout: 连接超时秒数（TCP 握手受 RTT 限制，5 秒足够）

    Returns:
        (True, "") 端口可连接；(False, 失败原因)
    """
    host, port = split_target(url)
    if not host:
        return False, "无法从目标 URL 解析出主机名"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except OSError as exc:
        return False, f"连接 {host}:{port} 失败（{exc}）"


# 目标协议白名单：本工具只会说 HTTP(S)。拒绝 file:// gopher:// dict:// 等协议，
# 避免畸形目标串进入请求层（注意：目标 URL 由操作者通过 -u 显式提供，扫描内网地址
# 正是本工具的用途，因此不做私网/回环地址拦截——边界是操作者的授权范围）。
_ALLOWED_SCHEMES = ("http", "https")


def probe_http_responsive(url: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """HTTP 层响应性探测：确认目标能在超时内返回响应（任意状态码均视为通过）。

    与 probe_reachable 的分工：TCP 握手成功不代表目标可用。防火墙「接受 SYN 后丢包」、
    服务假死、连接池耗尽等情况下 TCP 探测会放行，但每个插件都要等满超时——实测黑洞
    目标 120 秒仅完成数个插件。本函数用一次带超时的真实请求提前识别这类目标。

    任意状态码（含 4xx/5xx）都算通过：能返回错误页说明服务是活的，扫描有意义。
    TLS 策略复用 settings.VERIFY_TLS（与会话层同一事实来源），证书错误单独给出可操作提示。

    Args:
        url: 目标 URL
        timeout: 响应超时秒数

    Returns:
        (True, "") 目标有响应；(False, 失败原因)
    """
    import requests
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning

    from config import settings

    if "://" in url and url.split("://", 1)[0].lower() not in _ALLOWED_SCHEMES:
        return False, f"不支持的协议（仅支持 http/https）：{url.split('://', 1)[0]}://"

    # 预检发生在 SessionManager 创建之前，需在此独立抑制证书警告，
    # 否则不校验证书时首个 HTTPS 请求会把 urllib3 的 InsecureRequestWarning 打到控制台
    if not settings.VERIFY_TLS:
        urllib3.disable_warnings(InsecureRequestWarning)

    # allow_redirects=False：只探测目标本身，不跟随跳转（避免被引向第三方地址）
    # stream=True：只取响应头即关闭，不为目标的大响应体付出下载代价
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=settings.VERIFY_TLS,
            allow_redirects=False,
            stream=True,
        )
        resp.close()
        return True, ""
    except requests.exceptions.SSLError as exc:
        return False, f"TLS 证书校验失败（当前 --verify-tls 已开启，目标可能使用自签名证书）：{exc}"
    except requests.exceptions.Timeout:
        return False, f"{timeout:.0f} 秒内无任何响应（端口可连接，但 HTTP 层无响应）"
    except Exception as exc:
        return False, f"HTTP 请求失败（{exc}）"
