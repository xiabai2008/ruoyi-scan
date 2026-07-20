# 端口扫描 + 服务 Banner 识别（纯 socket 实现，不依赖 nmap）
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PortResult:
    """单端口扫描结果"""

    port: int
    protocol: str = "tcp"
    state: str = "closed"  # open / closed / filtered
    service: str = ""  # 识别到的服务名（http/ssh/mysql 等）
    banner: str = ""  # Banner 原始文本
    version: str = ""  # 版本号


# 默认扫描端口（常见 Web / 数据库 / 中间件 / 远程管理）
DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    81,
    88,
    110,
    111,
    135,
    139,
    143,
    161,
    389,
    443,
    445,
    465,
    514,
    587,
    636,
    873,
    993,
    995,
    1080,
    1433,
    1521,
    1723,
    2049,
    2181,
    2375,
    2376,
    3128,
    3306,
    3389,
    4440,
    4848,
    5000,
    5432,
    5632,
    5900,
    5984,
    6379,
    7001,
    7002,
    8000,
    8009,
    8080,
    8081,
    8088,
    8089,
    8443,
    8448,
    8888,
    8983,
    9000,
    9042,
    9090,
    9200,
    9300,
    9999,
    10000,
    11211,
    27017,
    50000,
    50030,
    50070,
    61616,
    61613,
]

# 常见端口 → 服务名映射（IANA + 实践）
PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    81: "http-alt",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "smtp-submission",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-tls",
    3128: "squid",
    3306: "mysql",
    3389: "rdp",
    4440: "rundeck",
    4848: "glassfish",
    5000: "flask-dev",
    5432: "postgresql",
    5632: "pcanywhere",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    7001: "weblogic",
    7002: "weblogic-ssl",
    8000: "http-alt",
    8009: "ajp",
    8080: "http-proxy",
    8088: "hadoop-yarn",
    8089: "splunk",
    8443: "https-alt",
    8888: "http-alt",
    8983: "solr",
    9000: "php-fpm",
    9042: "cassandra",
    9090: "prometheus",
    9200: "elasticsearch",
    9300: "elasticsearch-node",
    9999: "java-rmi",
    10000: "webmin",
    11211: "memcached",
    27017: "mongodb",
    50000: "sap",
    50030: "hadoop",
    50070: "hadoop-namenode",
    61616: "activemq",
    61613: "activemq-stomp",
}

# 服务 Banner 探测 payload（发完立即 recv）
BANNER_PROBES = {
    "ssh": b"",
    "ftp": b"",
    "smtp": b"",
    "mysql": b"",
    "redis": b"*1\r\n$4\r\nPING\r\n",
    "memcached": b"stats\r\n",
    "mongodb": b"",
    "http": b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "https": b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
}


class PortScanner:
    """TCP 端口扫描器 + Banner 识别（纯标准库 socket）

    用法:
        scanner = PortScanner(timeout=3, threads=20)
        results = scanner.scan('192.168.1.1')
        for r in results:
            print(f'{r.port}/tcp {r.service} {r.banner[:50]}')
    """

    def __init__(self, timeout=3, threads=20):
        self.timeout = timeout
        self.threads = threads

    def scan(self, host: str, ports: Optional[List[int]] = None) -> List[PortResult]:
        """扫描指定主机的端口列表

        Args:
            host: 目标 IP 或主机名
            ports: 端口列表（默认 DEFAULT_PORTS）
        Returns:
            PortResult 列表（仅 open 的端口）
        """
        if ports is None:
            ports = DEFAULT_PORTS
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan_port, host, p): p for p in ports}
            for fut in as_completed(futures):
                res = fut.result()
                if res.state == "open":
                    results.append(res)
        return sorted(results, key=lambda r: r.port)

    def _scan_port(self, host: str, port: int) -> PortResult:
        """扫描单个端口：TCP connect → 成功则抓 Banner"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            if sock.connect_ex((host, port)) != 0:
                return PortResult(port=port, state="closed")
            # 端口开放，识别服务名
            service = PORT_SERVICE_MAP.get(port, "unknown")
            banner = self._grab_banner(sock, service)
            return PortResult(port=port, state="open", service=service, banner=banner)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return PortResult(port=port, state="filtered")
        finally:
            sock.close()

    def _grab_banner(self, sock: socket.socket, service: str) -> str:
        """尝试抓取 Banner（发探测包 → 接收响应）"""
        probe = BANNER_PROBES.get(service)
        if probe:
            try:
                sock.send(probe)
                data = sock.recv(1024)
                return self._clean_banner(data)
            except Exception:
                pass
        # 无特定探测包，尝试直接 recv
        try:
            sock.settimeout(1)
            data = sock.recv(1024)
            return self._clean_banner(data)
        except Exception:
            return ""

    @staticmethod
    def _clean_banner(data: bytes) -> str:
        """清洗 Banner：去掉控制字符，取第一行"""
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")
        # 取第一行，移除 \r\n
        line = text.split("\n")[0].replace("\r", "").strip()
        return line[:200] if len(line) > 200 else line
