# HTTP/HTTPS 代理服务器（被动扫描模式）
# 纯标准库实现，作为中间人代理捕获流量 URL 加入主动扫描队列
import socket
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, List, Optional, Set

from common.logger import get_logger

logger = get_logger(__name__)


class ScanQueue:
    """线程安全的 URL 去重队列（生产者：代理捕获 → 消费者：扫描引擎）"""

    def __init__(self) -> None:
        self._urls: List[str] = []
        self._seen: Set[str] = set()
        self._lock = threading.Lock()

    def add(self, url: str) -> bool:
        """添加 URL 到队列（自动去重）"""
        # 去掉末尾斜杠再判重：同一 URL 带/不带尾部斜杠视为一条，避免重复扫描
        normalized = url.rstrip("/") if url.endswith("/") else url
        with self._lock:
            if normalized not in self._seen:
                self._seen.add(normalized)
                self._urls.append(normalized)
                return True
        return False

    def drain(self) -> List[str]:
        """取出所有待扫描 URL 并清空队列"""
        with self._lock:
            urls = list(self._urls)
            self._urls.clear()
            # 同步清空去重集合：否则长会话中 _seen 无限增长（内存泄漏），
            # 且已 drain 的 URL 再被访问时会被 add() 静默丢弃，永远无法重新捕获
            self._seen.clear()
        return urls

    def size(self) -> int:
        """返回队列中待扫描 URL 数量"""
        with self._lock:
            return len(self._urls)


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP 代理请求处理器：转发请求并记录 URL 到收集队列"""

    # 类变量：由 ProxyServer 在启动时注入
    queue: Optional["ScanQueue"] = None
    target_hosts: Set[str] = set()
    # 保护 target_hosts：_record_url 在工作线程写入，captured_hosts() 在调用方线程读取，
    # 无锁并发 add/迭代会抛 RuntimeError: Set changed size during iteration
    _hosts_lock = threading.Lock()

    def do_GET(self) -> None:
        """GET 代理请求入口（委托通用处理逻辑）"""
        self._handle_request("GET")

    def do_POST(self) -> None:
        """POST 代理请求入口（委托通用处理逻辑）"""
        self._handle_request("POST")

    def do_CONNECT(self) -> None:
        """HTTPS CONNECT 隧道：建立隧道，记录域名"""
        host, port = self.path.split(":") if ":" in self.path else (self.path, "443")
        self._record_url(f"https://{host}:{port}/")
        try:
            self._tunnel(host, int(port))
        except Exception:
            self.send_error(502)

    def _handle_request(self, method: str) -> None:
        """处理 HTTP 代理请求（如 GET http://example.com/page HTTP/1.1）"""
        parsed = urllib.parse.urlparse(self.path)
        if parsed.scheme and parsed.netloc:
            # 绝对 URL（代理模式）：必须保留 query（扫描输入常位于 ?id=1 这类参数中），
            # 与下方 _forward 的转发路径保持同一形态
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                url = f"{url}?{parsed.query}"
            self._record_url(url)
            self._forward(method, parsed)
        else:
            self.send_error(400, "Bad proxy request")

    def _record_url(self, url: str) -> None:
        """记录 URL 到扫描队列"""
        if self.queue is not None:
            # 同步登记域名：URL 即使已被去重丢弃，该主机仍纳入后续扫描范围
            host = urllib.parse.urlparse(url).netloc.split(":")[0]
            with self._hosts_lock:
                self.target_hosts.add(host)
            if self.queue.add(url):
                # log_message 已被重写为空实现（抑制 BaseHTTPRequestHandler 默认输出），
                # 捕获明细必须走 logger 才可见
                logger.debug("Captured: %s", url)

    def _tunnel(self, host: str, port: int) -> None:
        """建立 CONNECT 隧道"""
        try:
            remote = socket.create_connection((host, port), timeout=10)
        except Exception:
            self.send_error(502, "Cannot connect to remote")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        # 双向转发
        self._relay(self.connection, remote)
        remote.close()

    def _relay(self, client: socket.socket, remote: socket.socket) -> None:
        """双向数据转发"""
        import select

        sockets = [client, remote]
        try:
            while True:
                rlist, _, _ = select.select(sockets, [], [], 30)
                if not rlist:
                    break
                for s in rlist:
                    data = s.recv(8192)
                    if not data:
                        return
                    if s is client:
                        remote.sendall(data)
                    else:
                        client.sendall(data)
        except Exception:
            logger.debug("代理双向数据转发失败", exc_info=True)

    def _forward(self, method: str, parsed: Any) -> None:
        """转发 HTTP 请求并返回响应"""
        try:
            import http.client

            netloc = parsed.netloc
            host = netloc
            port = 80
            if ":" in netloc:
                host, port = netloc.split(":", 1)
                port = int(port)
            conn = http.client.HTTPConnection(host, port, timeout=10)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            # 剥离 Proxy-Connection 代理专用头，避免把客户端代理语义转发给源站
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("proxy-connection",)}
            conn.request(method, path, body=self._read_body(), headers=headers)
            resp = conn.getresponse()
            # 先整体读回响应体再发送响应头：chunked 响应由 http.client 在此解码，
            # Content-Length 需由实际字节数推导（见下）
            body = resp.read()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                # 剥离 Transfer-Encoding（已整体读回）与 hop-by-hop 头（Connection/Keep-Alive），
                # 并丢弃源站 Content-Length，改为下方按实际读回字节数显式定长返回
                if k.lower() not in ("transfer-encoding", "content-length", "connection", "keep-alive"):
                    self.send_header(k, v)
            # 无实体状态码（1xx/204/304）不补 Content-Length
            if resp.status >= 200 and resp.status not in (204, 304):
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            conn.close()
        except Exception:
            self.send_error(502)

    def _read_body(self) -> Optional[bytes]:
        """读取请求体"""
        length = int(self.headers.get("Content-Length", 0))
        # 无请求体（length=0）时返回 None，避免对空体做无谓读取
        return self.rfile.read(length) if length > 0 else None

    def log_message(self, fmt: str, *args: Any) -> None:
        """抑制默认日志输出（用 stderr）"""
        pass


class ProxyServer:
    """被动扫描代理服务器

    用法:
        queue = ScanQueue()
        proxy = ProxyServer(host='127.0.0.1', port=8080, queue=queue)
        proxy.start()
        # ... 浏览器设置代理后，定期 drain 队列 ...
        urls = queue.drain()
        proxy.stop()
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080, queue: Optional[ScanQueue] = None) -> None:
        """初始化被动扫描代理

        Args:
            host: 代理监听地址
            port: 代理监听端口
            queue: ScanQueue 实例（缺省自建，需经 start() 注入给处理器）
        """
        self.host = host
        self.port = port
        self.queue = queue or ScanQueue()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.running = False

    def start(self) -> "ProxyServer":
        """启动代理服务器（后台线程）"""
        # 通过类变量注入队列：所有处理器实例共享同一队列与主机集合
        ProxyHandler.queue = self.queue
        with ProxyHandler._hosts_lock:
            ProxyHandler.target_hosts = set()
        # ThreadingHTTPServer：CONNECT 隧道会在处理线程内阻塞到关闭；单线程 HTTPServer
        # 会让一条 HTTPS 隧道独占服务循环，期间其余 HTTP 请求/CONNECT 全部无法捕获
        self._server = ThreadingHTTPServer((self.host, self.port), ProxyHandler)
        self._server.timeout = 1
        self.running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        """服务主循环：单请求轮询（timeout=1 使 stop() 能及时打断阻塞）"""
        while self.running:
            if self._server is not None:
                self._server.handle_request()

    def stop(self) -> None:
        """停止代理服务器"""
        self.running = False
        if self._thread:
            # _serve 由 handle_request + timeout=1 轮询驱动，置 running=False 后
            # 最多 1 秒即退出循环，join 可及时返回
            self._thread.join(timeout=2)
        if self._server:
            try:
                # 注意：不能调用 BaseServer.shutdown()——该实现只在 serve_forever()
                # 结束时设置 __is_shut_down 事件，而本类的 _serve 从未调用 serve_forever，
                # shutdown() 会永久阻塞（stop() 卡死）。改为直接关闭监听套接字。
                self._server.server_close()
            except Exception:
                logger.debug("代理服务器关闭失败", exc_info=True)

    def captured_hosts(self) -> List[str]:
        """返回代理会话中捕获到的主机列表（供后续定向扫描使用）"""
        with ProxyHandler._hosts_lock:
            return list(ProxyHandler.target_hosts)
