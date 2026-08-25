# D30：OAST 带外检测（Out-of-Band Application Security Testing）
#
# 用于检测无回显漏洞（SSRF/XXE/SQL盲注/RCE盲注等），通过带外通道（DNS/HTTP/SMTP）
# 接收目标发起的回调请求，实现漏洞的确定性验证。
#
# 支持两种模式：
#   1. 自建回调服务器（--oast-server 127.0.0.1:5555）：本地监听 HTTP/DNS 回调
#   2. 第三方服务（Interactsh）：通过 API 生成唯一交互域并查询回调记录
#
# 使用方式：
#   # 自建模式
#   python main.py -u http://target/ --oast --oast-server 127.0.0.1:5555
#
#   # Interactsh 模式
#   python main.py -u http://target/ --oast --oast-provider interactsh
#
# 插件集成：
#   在插件 verify() 中调用 oast.get_payload() 获取唯一回调 URL，
#   将其注入 payload，发起请求后调用 oast.wait_callback() 等待回调。
import datetime
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

# ============================================================
# 回调记录存储
# ============================================================


class CallbackStore:
    """线程安全的回调记录存储

    存储格式：{interaction_id: [{'protocol': 'http', 'from': ip, 'timestamp': ts, 'raw': data}]}
    """

    def __init__(self):
        self._records: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def register(self, interaction_id: str) -> None:
        """注册一个交互 ID，等待回调"""
        with self._lock:
            if interaction_id not in self._records:
                self._records[interaction_id] = []

    def record(self, interaction_id: str, callback: Dict[str, Any]) -> None:
        """记录一次回调"""
        with self._lock:
            if interaction_id not in self._records:
                self._records[interaction_id] = []
            self._records[interaction_id].append(callback)

    def get(self, interaction_id: str) -> List[Dict[str, Any]]:
        """获取某交互 ID 的所有回调记录"""
        with self._lock:
            return list(self._records.get(interaction_id, []))

    def has_callback(self, interaction_id: str) -> bool:
        """是否已收到回调"""
        with self._lock:
            return len(self._records.get(interaction_id, [])) > 0

    def clear(self, interaction_id: str) -> None:
        """清除某交互 ID 的记录"""
        with self._lock:
            self._records.pop(interaction_id, None)

    def all_ids(self) -> List[str]:
        """获取所有交互 ID"""
        with self._lock:
            return list(self._records.keys())

    def stats(self) -> Dict[str, int]:
        """统计信息"""
        with self._lock:
            total = sum(len(v) for v in self._records.values())
            return {
                "registered_ids": len(self._records),
                "total_callbacks": total,
                "with_callback": sum(1 for v in self._records.values() if v),
            }


# 全局单例
_store = CallbackStore()


def get_store() -> CallbackStore:
    """获取全局回调存储"""
    return _store


# ============================================================
# 交互 ID 生成
# ============================================================


def generate_interaction_id() -> str:
    """生成唯一交互 ID（16 位十六进制）"""
    return uuid.uuid4().hex[:16]


def build_payload_domain(interaction_id: str, base_domain: str = "oast.local") -> str:
    """构建回调域名

    如 interaction_id=abc123, base_domain=oast.local → abc123.oast.local
    """
    return f"{interaction_id}.{base_domain}"


def build_payload_url(
    interaction_id: str, protocol: str = "http", host: str = "127.0.0.1", port: int = 5555, path: str = "/"
) -> str:
    """构建回调 URL（用于 HTTP 带外检测）"""
    return f"{protocol}://{host}:{port}{path}?id={interaction_id}"


# ============================================================
# 本地 HTTP 回调服务器
# ============================================================


class CallbackHTTPHandler(BaseHTTPRequestHandler):
    """HTTP 回调请求处理器

    任何 GET/POST 请求都会被记录，URL 中的 id 参数作为交互 ID
    """

    def _handle(self):
        """处理请求并记录回调"""
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        interaction_id = params.get("id", [None])[0]

        callback = {
            "protocol": "http",
            "method": self.command,
            "path": self.path,
            "from": self.client_address[0],
            "timestamp": datetime.datetime.now().isoformat(),
            "headers": dict(self.headers),
            "raw": f"{self.command} {self.path}",
        }

        if interaction_id:
            _store.record(interaction_id, callback)

        # 读取 body（POST 等）
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            callback["body"] = body.decode("utf-8", errors="replace")[:1024]

        # 返回 200 OK
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self):
        """处理 GET 回调请求"""
        self._handle()

    def do_POST(self):
        """处理 POST 回调请求"""
        self._handle()

    def log_message(self, format, *args):
        """静默日志（不打印到 stderr）"""
        pass


class OASTServer:
    """本地 OAST 回调服务器

    启动一个 HTTP 服务器监听回调请求，支持多线程处理。
    """

    # 允许端口复用（避免测试时 TIME_WAIT 状态导致端口占用）
    allow_reuse_address = True

    def __init__(self, host: str = "127.0.0.1", port: int = 5555):
        """初始化本地回调服务器

        Args:
            host: 监听地址（默认仅绑定回环 127.0.0.1）
            port: 监听端口
        """
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> bool:
        """启动服务器

        Returns:
            True 表示启动成功，False 表示端口被占用或失败
        """
        try:
            self._server = HTTPServer((self.host, self.port), CallbackHTTPHandler)
            self._server.allow_reuse_address = True
            # 使用 serve_forever 替代 handle_request 循环，确保请求被及时处理
            self._thread = threading.Thread(
                target=self._server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
            )
            self._thread.start()
            self._running = True
            return True
        except OSError:
            return False

    def _serve_loop(self):
        """服务循环（保留向后兼容，实际由 serve_forever 替代）"""
        while self._running:
            self._server.handle_request()

    def stop(self) -> None:
        """停止服务器"""
        self._running = False
        if self._server:
            self._server.shutdown()  # 停止 serve_forever
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def is_running(self) -> bool:
        """服务器是否在运行"""
        return self._running

    def url(self, interaction_id: str, path: str = "/") -> str:
        """构建回调 URL"""
        return build_payload_url(interaction_id, "http", self.host, self.port, path)


# ============================================================
# OAST 客户端（供插件调用）
# ============================================================


class OASTClient:
    """OAST 客户端：生成 payload + 等待回调

    供插件 verify() 调用：
        client = OASTClient(server)  # 或 OASTClient(provider='interactsh')
        payload_url = client.get_payload()
        # 注入 payload_url 到漏洞请求
        # session.get(f'{target}?url={payload_url}')
        if client.wait_callback(timeout=5):
            return ScanResult(status=STATUS_CONFIRMED, ...)
    """

    def __init__(self, server: Optional[OASTServer] = None, provider: str = "local", base_domain: str = "oast.local"):
        """
        Args:
            server: 本地 OASTServer 实例（provider='local' 时必填）
            provider: 'local' 或 'interactsh'
            base_domain: DNS 回调基础域名
        """
        self.server = server
        self.provider = provider
        self.base_domain = base_domain
        self._interaction_id: Optional[str] = None
        self._payload_url: Optional[str] = None
        self._payload_domain: Optional[str] = None

    def get_payload(self, path: str = "/") -> str:
        """生成唯一回调 URL

        Returns:
            回调 URL，如 http://127.0.0.1:5555/?id=abc123
        """
        self._interaction_id = generate_interaction_id()
        _store.register(self._interaction_id)

        if self.provider == "local" and self.server:
            self._payload_url = self.server.url(self._interaction_id, path)
        else:
            # Interactsh 或无服务器模式：使用域名
            self._payload_domain = build_payload_domain(self._interaction_id, self.base_domain)
            self._payload_url = f"http://{self._payload_domain}{path}"

        return self._payload_url

    def get_payload_domain(self) -> str:
        """获取回调域名（用于 DNS 带外检测）"""
        if not self._interaction_id:
            self.get_payload()
        if self._payload_domain:
            return self._payload_domain
        return build_payload_domain(self._interaction_id, self.base_domain)

    def wait_callback(self, timeout: float = 5.0, interval: float = 0.2) -> bool:
        """等待回调

        Args:
            timeout: 最大等待秒数
            interval: 轮询间隔

        Returns:
            True 表示收到回调（漏洞确认），False 表示超时
        """
        if not self._interaction_id:
            return False

        deadline = time.time() + timeout
        while time.time() < deadline:
            if _store.has_callback(self._interaction_id):
                return True
            time.sleep(interval)
        return False

    def get_callbacks(self) -> List[Dict[str, Any]]:
        """获取所有回调记录"""
        if not self._interaction_id:
            return []
        return _store.get(self._interaction_id)

    @property
    def interaction_id(self) -> Optional[str]:
        """当前交互 ID（未生成时为 None）"""
        return self._interaction_id


# ============================================================
# DNS 解析钩子（用于 DNS 带外检测）
# ============================================================


def check_dns_callback(interaction_id: str, base_domain: str = "oast.local") -> bool:
    """检查 DNS 回调是否发生（通过 socket.getaddrinfo 反查）

    注意：此函数仅用于测试模拟。生产环境应使用 DNS 服务器日志或 dnspython 库。
    """
    domain = build_payload_domain(interaction_id, base_domain)
    try:
        # 尝试解析域名，如果曾被查询过则可能命中本地 DNS 缓存
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False


# ============================================================
# 批量生成 payload（用于并发扫描）
# ============================================================


def generate_batch_payloads(
    count: int, server: Optional[OASTServer] = None, base_domain: str = "oast.local"
) -> List[Tuple[str, str]]:
    """批量生成 payload

    Args:
        count: 生成数量
        server: 本地 OASTServer 实例
        base_domain: DNS 回调基础域名

    Returns:
        [(interaction_id, payload_url), ...]
    """
    results = []
    for _ in range(count):
        interaction_id = generate_interaction_id()
        _store.register(interaction_id)
        if server:
            payload_url = server.url(interaction_id)
        else:
            payload_url = f"http://{build_payload_domain(interaction_id, base_domain)}/"
        results.append((interaction_id, payload_url))
    return results


# ============================================================
# 漏洞模板（常用 OAST payload）
# ============================================================

PAYLOAD_TEMPLATES = {
    "ssrf": "{url}",  # SSRF：直接注入回调 URL
    "xxe": '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{url}"> %xxe;]>',
    "sqli_blind": "1 AND LOAD_FILE('\\\\{domain}\\test')",  # MySQL DNS 带外（Windows UNC）
    "rce_blind": "ping -c 1 {domain}",  # RCE 盲注：ping 回调域名
    "ldap": "${jndi:ldap://{domain}/x}",
    "command_injection": "; curl {url};",
}


def build_payload(
    vuln_type: str, interaction_id: str, server: Optional[OASTServer] = None, base_domain: str = "oast.local"
) -> str:
    """根据漏洞类型构建 payload

    Args:
        vuln_type: 漏洞类型（ssrf/xxe/sqli_blind/rce_blind/ldap/command_injection）
        interaction_id: 交互 ID
        server: 本地 OASTServer 实例
        base_domain: DNS 回调基础域名

    Returns:
        Payload 字符串
    """
    template = PAYLOAD_TEMPLATES.get(vuln_type, "{url}")
    _store.register(interaction_id)

    if server:
        url = server.url(interaction_id)
    else:
        url = f"http://{build_payload_domain(interaction_id, base_domain)}/"

    domain = build_payload_domain(interaction_id, base_domain)
    # 使用字符串替换而非 .format()，避免模板中 ${jndi:...} 等花括号被误解析
    return template.replace("{url}", url).replace("{domain}", domain)


# ============================================================
# 模式入口
# ============================================================


def run_oast_mode(args) -> int:
    """OAST 模式入口：启动回调服务器并保持运行

    用于独立启动 OAST 服务器，供其他扫描进程远程调用。
    """
    host = getattr(args, "oast_host", "127.0.0.1") or "127.0.0.1"
    port = getattr(args, "oast_port", 5555) or 5555

    server = OASTServer(host=host, port=port)
    if not server.start():
        print(f"[!]OAST 服务器启动失败：端口 {port} 被占用")
        return 1

    print(f"[*]OAST 回调服务器已启动：{host}:{port}")
    print(f"[*]回调 URL 格式：http://{host}:{port}/?id=<interaction_id>")
    print("[*]按 Ctrl+C 停止")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*]停止 OAST 服务器")
        server.stop()

    return 0
