# D14 子域名收集：被动枚举（不进行爆破，避免对目标造成压力）
#
# 设计目标：
#   1. 纯被动信息收集：证书透明日志 + 内置字典 + DNS 解析
#   2. 不引入外部依赖（不用 subfinder/api-hunter）
#   3. 多源聚合： crt.sh + 内置 top 子域字典 + 可选 DNS 验证
#   4. 支持自定义字典扩展
#   5. 与 SessionManager 集成（crt.sh 通过 HTTPS 查询）
#
# 数据源：
#   1. crt.sh 证书透明日志（HTTPS API，免费无 key）
#   2. 内置 top 50 子域名字典（dev/www/test/api/admin 等）
#   3. 可选：DNS 解析验证（过滤不存在子域）
#
# 用法：
#   from lib.subdomain import SubdomainEnumerator
#   enum = SubdomainEnumerator(verify_dns=False)
#   subs = enum.enumerate('example.com', session)
import socket
import threading
from typing import Callable, List, Optional, Set
from urllib.parse import urlparse

from common.logger import get_logger

logger = get_logger(__name__)

# 内置 top 50 常见子域名字典（按出现频率排序）
DEFAULT_SUBDOMAIN_WORDS = [
    "www",
    "mail",
    "remote",
    "blog",
    "web",
    "dev",
    "test",
    "stage",
    "staging",
    "api",
    "admin",
    "portal",
    "app",
    "m",
    "shop",
    "store",
    "forum",
    "wiki",
    "docs",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "video",
    "download",
    "ftp",
    "sftp",
    "ns1",
    "ns2",
    "dns",
    "mx",
    "smtp",
    "pop",
    "imap",
    "vpn",
    "gateway",
    "proxy",
    "auth",
    "sso",
    "oauth",
    "cloud",
    "aws",
    "azure",
    "git",
    "gitlab",
    "jenkins",
    "jira",
    "confluence",
    "crm",
    "erp",
    "oa",
]


class SubdomainEnumerator:
    """被动子域名枚举器

    用法：
        enum = SubdomainEnumerator(verify_dns=False)
        subs = enum.enumerate('example.com', session)
    """

    CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

    def __init__(
        self,
        word_list: Optional[List[str]] = None,
        verify_dns: bool = False,
        use_crtsh: bool = True,
        use_dictionary: bool = True,
        timeout: int = 10,
        on_found: Optional[Callable[[str], None]] = None,
    ):
        """初始化枚举器

        Args:
            word_list: 自定义子域字典（None=用默认 top 50）
            verify_dns: 是否对发现的子域做 DNS 解析验证（默认 False，避免阻塞）
            use_crtsh: 是否查询 crt.sh 证书透明日志
            use_dictionary: 是否使用字典枚举
            timeout: HTTP 请求超时秒数
            on_found: 每发现一个子域的回调
        """
        # 用 is not None 而非 or：空列表 [] 也视为自定义字典（可借此禁用内置字典）
        self.word_list = word_list if word_list is not None else DEFAULT_SUBDOMAIN_WORDS
        self.verify_dns = verify_dns
        self.use_crtsh = use_crtsh
        self.use_dictionary = use_dictionary
        self.timeout = timeout
        self.on_found = on_found
        # 统计
        self.found: Set[str] = set()
        self.sources: dict = {}  # subdomain -> [source1, source2]
        self.errors: List[str] = []
        self._lock = threading.Lock()

    def enumerate(self, domain: str, session=None) -> List[str]:
        """枚举子域名

        Args:
            domain: 主域名（如 example.com，不含协议）
            session: SessionManager 实例（用于 crt.sh 查询）

        Returns:
            发现的子域名列表（含主域名本身，按字母序）
        """
        # 清理输入：去除协议和路径
        domain = self._clean_domain(domain)
        if not domain:
            return []

        # 加入主域名本身
        self._add(domain, "root")

        # 1. crt.sh 证书透明日志
        if self.use_crtsh:
            self._enumerate_crtsh(domain, session)

        # 2. 字典枚举
        if self.use_dictionary:
            self._enumerate_dictionary(domain, session)

        return sorted(self.found)

    def _clean_domain(self, domain: str) -> str:
        """清理域名：去除协议、路径、端口"""
        if not domain:
            return ""
        # 去除协议
        if "://" in domain:
            domain = urlparse(domain).hostname or ""
        # 去除路径
        domain = domain.split("/")[0]
        # 去除端口
        domain = domain.split(":")[0]
        # 小写化
        return domain.lower().strip(".")

    def _add(self, subdomain: str, source: str):
        """添加发现的子域名"""
        subdomain = subdomain.lower().strip(".")
        if not subdomain:
            return
        with self._lock:
            if subdomain not in self.found:
                self.found.add(subdomain)
                self.sources[subdomain] = [source]
                if self.on_found:
                    try:
                        self.on_found(subdomain)
                    except Exception:
                        logger.debug("执行子域名发现回调失败", exc_info=True)
            else:
                if source not in self.sources.get(subdomain, []):
                    self.sources[subdomain].append(source)

    def _enumerate_crtsh(self, domain: str, session=None):
        """从 crt.sh 查询证书透明日志"""
        url = self.CRT_SH_URL.format(domain=domain)
        try:
            if session is not None:
                resp = session.get(url)
            else:
                import requests as _requests

                resp = _requests.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                self.errors.append(f"crt.sh -> HTTP {resp.status_code}")
                return
            # crt.sh 返回 JSON 数组，每项含 name_value 字段（可能含多行）
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "") if isinstance(entry, dict) else ""
                if not name_value:
                    continue
                # name_value 可能是多行（一个证书可包含多个域名）
                for line in name_value.split("\n"):
                    line = line.strip().lower()
                    # 跳过空行与通配符条目（*.domain 无法确认具体子域，且会污染结果）
                    if not line or "*" in line:
                        continue
                    # 仅保留属于该主域的子域
                    # 只保留主域本身或按 .主域 后缀归属的条目，杜绝收集到无关域名
                    if line == self._clean_domain(domain) or line.endswith("." + self._clean_domain(domain)):
                        self._add(line, "crt.sh")
        except Exception as e:
            self.errors.append(f"crt.sh -> {type(e).__name__}: {e}")

    def _enumerate_dictionary(self, domain: str, session=None):
        """字典枚举：尝试常见子域前缀"""
        for word in self.word_list:
            subdomain = f"{word}.{domain}"
            # 验证 DNS（可选）
            if self.verify_dns:
                if self._dns_resolve(subdomain):
                    self._add(subdomain, "dict+dns")
            else:
                # 不验证 DNS，直接加入候选（让后续扫描器验证）
                self._add(subdomain, "dict")

    def _dns_resolve(self, hostname: str) -> bool:
        """DNS 解析验证"""
        try:
            socket.gethostbyname(hostname)
            return True
        except Exception:
            return False


# === 便捷函数 ===


def enumerate_subdomains(domain: str, session=None, verify_dns: bool = False, use_crtsh: bool = True) -> List[str]:
    """便捷子域名枚举函数

    Args:
        domain: 主域名
        session: SessionManager 实例（用于 crt.sh 查询）
        verify_dns: 是否 DNS 验证
        use_crtsh: 是否查询 crt.sh（测试环境可设 False 避免真实网络请求）
    """
    enum = SubdomainEnumerator(verify_dns=verify_dns, use_crtsh=use_crtsh)
    return enum.enumerate(domain, session)


def get_default_word_list() -> List[str]:
    """返回默认子域字典"""
    return list(DEFAULT_SUBDOMAIN_WORDS)
