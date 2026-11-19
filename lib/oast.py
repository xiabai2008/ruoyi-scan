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
#   1. 扫描侧（--oast）：编排器自动启动回调服务器，插件通过 session.oast_client 取值；
#   2. 独立服务器（--oast-server）：供外部工具/多进程扫描复用。
#
# 扫描侧支持两类回调通道：
#   HTTP（SSRF / XXE）：http://<host>:<port>/?id=<interaction>
#   TCP （Log4j JNDI）：ldap://<host>:<port>/<interaction>（只记录 TCP 连接与原始字节，
#                       不返回 LDAP 响应；JNDI lookup 的连接本身即可证明表达式被求值）
#
# 插件集成：
#   client = session.oast_client
#   interaction = client.new_http_interaction()
#   # 把 interaction.url 注入 payload，发请求，然后 interaction.wait(timeout)
import datetime
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

from lib.output import emit

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

        # 先读完 body 再登记，避免 poller 看到 has_callback()==True 时记录仍缺 body 字段
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            callback["body"] = body.decode("utf-8", errors="replace")[:1024]

        if interaction_id:
            _store.record(interaction_id, callback)

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

    启动一个 HTTP 服务器监听回调请求，使用 ThreadingHTTPServer 支持多线程处理。
    """

    # 注：http.server.HTTPServer 已默认 allow_reuse_address=1（避免 TIME_WAIT 占用端口），
    # 无需再声明类属性或在 bind 之后赋值（后者对已创建的 socket 无效）。

    def __init__(self, host: str = "127.0.0.1", port: int = 5555):
        """初始化本地回调服务器

        Args:
            host: 监听地址（默认仅绑定回环 127.0.0.1）
            port: 监听端口
        """
        self.host = host
        self.port = port
        self.bound_port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> bool:
        """启动服务器

        Returns:
            True 表示启动成功，False 表示端口被占用或失败
        """
        try:
            # ThreadingHTTPServer：每个回调请求独立线程处理，避免并发回调被串行阻塞
            self._server = ThreadingHTTPServer((self.host, self.port), CallbackHTTPHandler)
            # port=0 时由系统分配，必须把实际端口记下来供 payload 构造
            self.bound_port = int(self._server.server_address[1])
            # 使用 serve_forever 替代 handle_request 循环，确保请求被及时处理
            self._thread = threading.Thread(
                target=self._server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
            )
            self._thread.start()
            self._running = True
            return True
        except OSError:
            return False

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
        """构建回调 URL（使用实际绑定端口，支持 port=0 自动分配）。"""
        return build_payload_url(interaction_id, "http", self.host, self.bound_port, path)


# ============================================================
# OAST 客户端（供插件调用）
# ============================================================


class TCPCallbackServer:
    """单次交互的 TCP 回调监听器（Log4j JNDI 用）。

    为什么不用共享端口：
      JNDI LDAP/RMI 客户端在 bind 阶段不会携带 URL 里的 interaction id，无法像
      HTTP 的 ?id= 一样在共享监听器上归因。每次探测绑定一个临时端口，端口本身
      就是 correlation id——命中即证明该 probe 的 JNDI 表达式被求值。

    只接受连接、读取首包、记录来源与原始字节后关闭；不实现完整 LDAP 协议。
    对"确认 lookup 发生"这个目的足够，也不做任何反序列化/加载远程类。
    """

    def __init__(self, host: str, interaction_id: str, port: int = 0):
        self.host = host
        self.interaction_id = interaction_id
        self.bound_port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.bound_port))
            sock.listen(16)
            sock.settimeout(0.2)
            self.bound_port = int(sock.getsockname()[1])
            self._sock = sock
            self._running = True
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            return True
        except OSError:
            self._running = False
            return False

    def _serve(self) -> None:
        while self._running and self._sock is not None:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn: socket.socket, addr: Any) -> None:
        raw = b""
        try:
            conn.settimeout(0.5)
            try:
                raw = conn.recv(4096)
            except (socket.timeout, OSError):
                raw = b""
        finally:
            try:
                conn.close()
            except OSError:
                pass
        _store.record(
            self.interaction_id,
            {
                "protocol": "tcp",
                "from": addr[0],
                "port": addr[1],
                "timestamp": datetime.datetime.now().isoformat(),
                "bytes": len(raw),
                "raw_hex": raw[:512].hex(),
            },
        )

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=1)
            self._thread = None


class OASTInteraction:
    """一次带外交互：唯一 id + 回调 URL/端口 + 等待与取证。"""

    def __init__(
        self,
        interaction_id: str,
        client: "OASTClient",
        url: str = "",
        host: str = "",
        port: int = 0,
        protocol: str = "http",
    ):
        self.interaction_id = interaction_id
        self.client = client
        self.url = url
        self.host = host
        self.port = port
        self.protocol = protocol

    def jndi_url(self, protocol: str = "ldap") -> str:
        """构造 JNDI URL（host/port 来自 TCP 监听器，path 带 interaction id）。"""
        return f"{protocol}://{self.host}:{self.port}/{self.interaction_id}"

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self.client.wait_for(self.interaction_id, timeout=timeout)

    def callbacks(self) -> List[Dict[str, Any]]:
        return _store.get(self.interaction_id)

    def close(self) -> None:
        self.client.close_interaction(self.interaction_id)


class OASTClient:
    """OAST 客户端：生成交互、等待回调、交给插件取证。

    兼容旧接口（get_payload/wait_callback/get_callbacks），同时提供并发安全的
    new_http_interaction()/new_tcp_interaction()；一个扫描的多个插件/多个 payload
    不应共享一个 _interaction_id（旧实现会互相覆盖，导致回调归因错误）。
    """

    def __init__(
        self,
        server: Optional[OASTServer] = None,
        provider: str = "local",
        base_domain: str = "oast.local",
        host: Optional[str] = None,
        bind_host: Optional[str] = None,
        timeout: float = 8.0,
        tcp_port: int = 0,
    ):
        self.server = server
        self.provider = provider
        self.base_domain = base_domain
        # host 是写进 payload、目标实际访问的地址；bind_host 是本机监听地址。
        # 远程目标场景：host=公网 IP，bind_host=0.0.0.0。
        self.host = host or (server.host if server else "127.0.0.1")
        self.bind_host = bind_host or (server.host if server else "127.0.0.1")
        # Log4j JNDI 的 TCP 监听端口：0=每次探测临时端口（本地默认）；
        # 远程目标被防火墙限制时指定固定端口并放行（同一时刻只跑一个 JNDI 探测）。
        self.tcp_port = int(tcp_port or 0)
        self.timeout = float(timeout)
        self._interaction_id: Optional[str] = None
        self._payload_url: Optional[str] = None
        self._payload_domain: Optional[str] = None
        self._tcp_servers: Dict[str, TCPCallbackServer] = {}

    # ── 新接口：每个 payload 一个 interaction ──
    def new_http_interaction(self, path: str = "/") -> OASTInteraction:
        """创建 HTTP 回调交互（SSRF/XXE/任意可发起 HTTP 请求的漏洞）。"""
        interaction_id = generate_interaction_id()
        _store.register(interaction_id)
        if self.provider == "local" and self.server:
            # 用客户端 host（目标可达地址）而非 server.host（可能只是 0.0.0.0）
            url = build_payload_url(interaction_id, "http", self.host, self.server.bound_port, path)
        else:
            domain = build_payload_domain(interaction_id, self.base_domain)
            url = f"http://{domain}{path}"
            self._payload_domain = domain
        return OASTInteraction(interaction_id, self, url=url, protocol="http")

    def new_tcp_interaction(self, protocol: str = "ldap") -> OASTInteraction:
        """创建 TCP 回调交互（Log4j JNDI：ldap/rmi 均可；只确认 lookup 发生）。"""
        interaction_id = generate_interaction_id()
        _store.register(interaction_id)
        tcp_server = TCPCallbackServer(self.bind_host, interaction_id, port=self.tcp_port)
        if not tcp_server.start():
            raise OSError("OAST TCP 回调端口绑定失败（bind=%s）" % self.bind_host)
        self._tcp_servers[interaction_id] = tcp_server
        return OASTInteraction(
            interaction_id,
            self,
            host=self.host,
            port=tcp_server.bound_port,
            protocol=protocol,
        )

    # ── 兼容旧接口 ──
    def get_payload(self, path: str = "/") -> str:
        """生成当前交互的回调 URL（旧 API；并发场景请用 new_http_interaction）。"""
        interaction = self.new_http_interaction(path)
        self._interaction_id = interaction.interaction_id
        self._payload_url = interaction.url
        return interaction.url

    def get_payload_domain(self) -> str:
        """获取回调域名（用于 DNS 带外检测）。"""
        if not self._interaction_id:
            self.get_payload()
        if self._payload_domain:
            return self._payload_domain
        return build_payload_domain(self._interaction_id or "", self.base_domain)

    def wait_for(self, interaction_id: str, timeout: Optional[float] = None) -> bool:
        """等待指定 interaction 的回调；timeout=None 用客户端默认值。"""
        deadline = time.time() + (self.timeout if timeout is None else float(timeout))
        while time.time() < deadline:
            if _store.has_callback(interaction_id):
                return True
            time.sleep(0.2)
        return _store.has_callback(interaction_id)

    def wait_callback(self, timeout: float = 5.0, interval: float = 0.2, interaction_id: Optional[str] = None) -> bool:
        """兼容旧接口：等待当前/指定 interaction 的回调。"""
        target_id = interaction_id or self._interaction_id
        if not target_id:
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            if _store.has_callback(target_id):
                return True
            time.sleep(interval)
        return _store.has_callback(target_id)

    def wait_any(
        self, interactions: List[OASTInteraction], timeout: Optional[float] = None
    ) -> Optional[OASTInteraction]:
        """并发发出多个 payload 后统一等待，返回第一个命中的 interaction。"""
        deadline = time.time() + (self.timeout if timeout is None else float(timeout))
        while time.time() < deadline:
            for interaction in interactions:
                if _store.has_callback(interaction.interaction_id):
                    return interaction
            time.sleep(0.2)
        for interaction in interactions:
            if _store.has_callback(interaction.interaction_id):
                return interaction
        return None

    def get_callbacks(self, interaction_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取回调记录（默认当前交互）。"""
        target_id = interaction_id or self._interaction_id
        if not target_id:
            return []
        return _store.get(target_id)

    def close_interaction(self, interaction_id: str) -> None:
        server = self._tcp_servers.pop(interaction_id, None)
        if server is not None:
            server.stop()
        _store.clear(interaction_id)

    def close(self) -> None:
        """关闭本客户端创建的所有 TCP 监听（HTTP server 由调用方关闭）。"""
        for interaction_id in list(self._tcp_servers):
            self.close_interaction(interaction_id)

    @property
    def interaction_id(self) -> Optional[str]:
        """当前交互 ID（未生成时为 None；新接口请直接用 OASTInteraction）。"""
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
    bind = getattr(args, "oast_bind", None) or host
    port = getattr(args, "oast_port", 5555) or 5555

    server = OASTServer(host=bind, port=port)
    if not server.start():
        emit(f"[!]OAST 服务器启动失败：端口 {port} 被占用")
        return 1

    emit(f"[*]OAST 回调服务器已启动：{host}:{port}")
    emit(f"[*]回调 URL 格式：http://{host}:{port}/?id=<interaction_id>")
    emit("[*]按 Ctrl+C 停止")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        emit("\n[*]停止 OAST 服务器")
    finally:
        # 无论正常退出、Ctrl+C 还是其他异常，都必须释放监听 socket 与守护线程
        server.stop()

    return 0
