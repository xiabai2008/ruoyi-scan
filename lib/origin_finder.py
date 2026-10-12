# 源站真实 IP 探测（D7 阶段，标准库 + 免费 API，零依赖）
#
# 探测顺序（与 find_origin_ip 实现一致，结果为按优先级去重排序）：
#   1. 响应头泄漏（X-Originating-IP / X-Forwarded-For / X-Cache / Via / CF-RAY）
#   2. 子域名直连（www/mail/dev 等常未挂 CDN，DNS 解析）
#   3. SSL 证书 SAN（crt.sh 免费查询，无 API key）
#   4. DNS 直接解析（兜底，排除 CDN IP 段）
#
# 注意：本模块仅用于授权安全测试，源站 IP 信息敏感，结果不写入报告。
import json
import re
import socket
import urllib.parse
import urllib.request
from typing import Any, List

from common.logger import get_logger

logger = get_logger(__name__)


class OriginIPFinder:
    """源站真实 IP 探测器（4 路探测，标准库 + crt.sh 免费 API）

    用法：
        finder = OriginIPFinder()
        ips = finder.find_origin_ip('example.com', session)
        if ips:
            print(f'源站 IP: {ips[0]}')
    """

    # 常见子域名（常未挂 CDN）
    _SUBDOMAINS = [
        "www",
        "mail",
        "dev",
        "test",
        "staging",
        "api",
        "admin",
        "portal",
        "direct",
        "origin",
        "backend",
        "webmail",
        "cpanel",
        "ftp",
        "ssh",
        "vpn",
    ]

    def __init__(self, timeout: float = 5) -> None:
        """初始化源站 IP 探测器

        Args:
            timeout: 单次网络操作超时秒数（默认 5）
        """
        self.timeout = timeout

    def find_origin_ip(self, domain: str, session: Any = None) -> List[str]:
        """主入口：综合 4 路探测源站 IP

        Args:
            domain: 目标域名（如 example.com）
            session: SessionManager 实例（用于 HTTP 探测，None 则仅用 DNS）

        Returns:
            源站 IP 列表（按探测优先级去重排序：响应头 > 子域名 > SSL SAN > DNS）
        """
        # 列表 + seen 集合：保留探测优先级顺序（文档约定 ips[0] 为最高置信度候选），
        # 同时完成去重
        ips: List[str] = []
        seen = set()

        def _add(candidates: List[str]) -> None:
            for ip in candidates:
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)

        # 1. 响应头泄漏（最可靠且无副作用）
        if session:
            _add(self._check_response_headers(domain, session))

        # 2. 子域名直连（DNS 解析，无 HTTP 请求）
        _add(self._check_subdomains(domain))

        # 3. SSL 证书 SAN（crt.sh 免费 API）
        if session:
            _add(self._check_ssl_san(domain, session))

        # 4. DNS 直接解析（兜底）
        try:
            direct_ip = socket.gethostbyname(domain)
            # 排除常见 CDN IP 段（粗略过滤）
            if not self._is_cdn_ip(direct_ip):
                _add([direct_ip])
        except Exception:
            logger.debug("DNS 直接解析域名失败", exc_info=True)

        return ips

    def _check_response_headers(self, domain: str, session) -> List[str]:
        """检查响应头中的源站 IP 泄漏

        常见泄漏头：X-Originating-IP / X-Cache / Via / X-Forwarded-For
        """
        ips = []
        headers_to_check = [
            "X-Originating-IP",
            "X-Forwarded-For",
            "X-Real-IP",
            "Via",
            "X-Cache",
            "X-Served-By",
            "CF-RAY",
        ]
        try:
            url = f"http://{domain}/"
            if hasattr(session, "get"):
                resp = session.get(url)
            else:
                resp = None
            if resp is None:
                return ips
            for header in headers_to_check:
                value = resp.headers.get(header, "")
                if value:
                    # 提取 IP 地址（校验每段 0-255，避免 999.999.999.999 这类伪 IP）
                    for ip in self._extract_ips(value):
                        if not self._is_cdn_ip(ip):
                            ips.append(ip)
        except Exception:
            logger.debug("检查响应头源站 IP 泄漏失败", exc_info=True)
        return ips

    def _check_subdomains(self, domain: str) -> List[str]:
        """检查常见子域名是否直连源站（未挂 CDN）

        通过 DNS 解析子域名，若 IP 与主域名不同且非 CDN，可能是源站。
        """
        ips = []
        for sub in self._SUBDOMAINS:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                if not self._is_cdn_ip(ip):
                    ips.append(ip)
            except Exception:
                continue
        return list(set(ips))

    def _check_ssl_san(self, domain: str, session) -> List[str]:
        """查询 crt.sh 获取 SSL 证书 SAN 中的 IP

        crt.sh 是免费服务，无需 API key。
        API: https://crt.sh/?q=<domain>&output=json
        """
        ips = []
        try:
            url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
            if hasattr(session, "get"):
                resp = session.get(url)
                text = resp.text
            else:
                # 用 urllib 兜底
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    text = r.read().decode("utf-8")

            # 解析 JSON
            data = json.loads(text)
            for entry in data:
                # SAN 字段可能含多个名称（逗号分隔），统一用正则提取其中出现的 IP
                name_value = entry.get("name_value", "")
                # 从 SAN 中提取 IP（校验每段 0-255，避免版本号/构建号被当作 IP）
                for ip in self._extract_ips(name_value):
                    if not self._is_cdn_ip(ip):
                        ips.append(ip)
        except Exception:
            logger.debug("查询 crt.sh 获取 SSL 证书 SAN 失败", exc_info=True)
        return list(set(ips))

    @staticmethod
    def _extract_ips(text: str) -> List[str]:
        """从文本中提取合法 IPv4 地址（每段 0-255；正则本身允许 1-3 位数字，需二次校验）"""
        ips = []
        for ip in re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text or ""):
            if all(0 <= int(part) <= 255 for part in ip.split(".")):
                ips.append(ip)
        return ips

    def _is_cdn_ip(self, ip: str) -> bool:
        """粗略判断是否为 CDN IP 段（基于常见 CDN IP 前缀）

        注意：这是粗略过滤，生产环境应使用专业 IP 库。
        """
        # Cloudflare 常见段
        cdn_prefixes = [
            "104.16.",
            "104.17.",
            "104.18.",
            "104.19.",
            "104.20.",
            "172.64.",
            "172.67.",
            "162.159.",
            # 阿里云 CDN
            "47.246.",
            "120.241.",
            # 腾讯云 CDN
            "119.91.",
            "129.226.",
            # 百度云加速
            "182.61.",
        ]
        for prefix in cdn_prefixes:
            if ip.startswith(prefix):
                return True
        return False

    def build_origin_url(self, original_url: str, origin_ip: str) -> str:
        """构建直连源站的 URL（替换域名，保留路径和参数）

        Args:
            original_url: 原始 URL（如 http://example.com/path?query=1）
            origin_ip: 源站 IP

        Returns:
            直连 URL（如 http://1.2.3.4/path?query=1）
        """
        parsed = urllib.parse.urlparse(original_url)
        # 保留端口；非法端口（如 http://host:abc/）解析为 None 而非抛 ValueError
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = origin_ip
        if port:
            netloc = f"{origin_ip}:{port}"
        elif parsed.scheme == "https":
            netloc = f"{origin_ip}:443"
        elif parsed.scheme == "http":
            netloc = f"{origin_ip}:80"
        return urllib.parse.urlunparse(
            (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
        )
