# 源站真实 IP 探测（D7 阶段，标准库 + 免费 API，零依赖）
#
# 探测顺序：
#   1. SSL 证书 SAN（crt.sh 免费查询，无 API key）
#   2. DNS 历史记录（本地缓存/常见记录，不依赖第三方 API）
#   3. 响应头泄漏（X-Originating-IP / X-Cache / Via / CF-RAY）
#   4. 子域名直连（www/mail/dev 等常未挂 CDN）
#
# 注意：本模块仅用于授权安全测试，源站 IP 信息敏感，结果不写入报告。
import json
import re
import socket
import urllib.parse
import urllib.request
from typing import List


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

    def __init__(self, timeout=5):
        self.timeout = timeout

    def find_origin_ip(self, domain: str, session=None) -> List[str]:
        """主入口：综合 4 路探测源站 IP

        Args:
            domain: 目标域名（如 example.com）
            session: SessionManager 实例（用于 HTTP 探测，None 则仅用 DNS）

        Returns:
            去重后的源站 IP 列表（可能为空）
        """
        ips = set()

        # 1. 响应头泄漏（最可靠且无副作用）
        if session:
            header_ips = self._check_response_headers(domain, session)
            ips.update(header_ips)

        # 2. 子域名直连（DNS 解析，无 HTTP 请求）
        subdomain_ips = self._check_subdomains(domain)
        ips.update(subdomain_ips)

        # 3. SSL 证书 SAN（crt.sh 免费 API）
        if session:
            san_ips = self._check_ssl_san(domain, session)
            ips.update(san_ips)

        # 4. DNS 直接解析（兜底）
        try:
            direct_ip = socket.gethostbyname(domain)
            # 排除常见 CDN IP 段（粗略过滤）
            if not self._is_cdn_ip(direct_ip):
                ips.add(direct_ip)
        except Exception:
            pass

        return list(ips)

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
                    # 提取 IP 地址
                    found = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", value)
                    for ip in found:
                        if not self._is_cdn_ip(ip):
                            ips.append(ip)
        except Exception:
            pass
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
                name_value = entry.get("name_value", "")
                # 从 SAN 中提取 IP
                found = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", name_value)
                for ip in found:
                    if not self._is_cdn_ip(ip):
                        ips.append(ip)
        except Exception:
            pass
        return list(set(ips))

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
        # 保留端口
        netloc = origin_ip
        if parsed.port:
            netloc = f"{origin_ip}:{parsed.port}"
        elif parsed.scheme == "https":
            netloc = f"{origin_ip}:443"
        elif parsed.scheme == "http":
            netloc = f"{origin_ip}:80"
        return urllib.parse.urlunparse(
            (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
        )
