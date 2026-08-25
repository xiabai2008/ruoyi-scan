# 会话封装：Cookie / 代理 / 重试 / keep-alive / 连接池
from __future__ import annotations

import sys
import threading
from typing import TYPE_CHECKING, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import settings

if TYPE_CHECKING:
    from lib.proxy_pool import ProxyPool


class SessionManager:
    """requests.Session 封装，统一 UA / 代理 / 超时 / keep-alive / 连接池 / 重试

    性能优化（P0）：
    - HTTPAdapter 连接池：pool_connections/pool_maxsize 随线程数动态调整
    - urllib3 Retry：网络抖动自动重试（total=2, backoff_factor=0.3），5xx 和连接错误触发
    - 线程安全请求计数：threading.Lock 保护 request_count

    D13：支持代理池轮换。传入 proxy_pool 时，每次请求自动从池中获取代理。
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: Optional[int] = None,
        ua: Optional[str] = None,
        debug: bool = False,
        proxy_pool: Optional[ProxyPool] = None,
        pool_size: Optional[int] = None,
        max_retries: int = 2,
    ) -> None:
        """初始化统一的 requests 会话

        Args:
            proxy: 固定代理地址（配置了 proxy_pool 时被忽略）
            timeout: 单请求超时秒数（缺省用 settings.TIMEOUT）
            ua: User-Agent（缺省用 settings.DEFAULT_UA）
            debug: True 时逐请求打印方法/URL/状态/字节数到 stderr
            proxy_pool: 代理池（存在时优先于固定代理，每请求轮换取代理）
            pool_size: 连接池容量（下限 10，随线程数自动放大）
            max_retries: 网络抖动重试次数（仅 502/503/504 与连接错误触发）
        """
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": ua or settings.DEFAULT_UA})
        self.proxy = proxy if proxy is not None else settings.PROXY
        self.timeout = timeout or settings.TIMEOUT
        self.proxy_pool = proxy_pool  # D13: 代理池
        # 代理池优先：存在代理池时固定代理不生效，改为每请求从池中轮换
        if self.proxy and not self.proxy_pool:
            self.session.proxies.update({"http": self.proxy, "https": self.proxy})
        # keep-alive 复用连接
        self.session.keep_alive = True

        # P0: HTTPAdapter 连接池配置（随线程数动态调整，默认 pool_size=10）
        # 连接池容量下限 10：线程数较小时也保留余量，缓冲瞬时并发避免频繁建连
        _pool = max(pool_size or settings.THREADS or 10, 10)
        _retry = Retry(
            total=max_retries,
            backoff_factor=0.3,
            # 仅重试网关/服务不可用错误（502/503/504），
            # 不重试 500（应用错误可能包含漏洞证据，如 SQL 报错注入）
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"]),
        )
        _adapter = HTTPAdapter(
            pool_connections=_pool,
            pool_maxsize=_pool * 2,
            max_retries=_retry,
            pool_block=False,
        )
        self.session.mount("http://", _adapter)
        self.session.mount("https://", _adapter)

        # 请求计数（报告摘要用，线程安全）
        self._count_lock = threading.Lock()
        self.request_count = 0
        # 调试模式：打印每个请求的方法/URL/状态/响应大小到 stderr（不影响正常输出）
        self.debug = bool(debug)

    def _get_proxy_for_request(self):
        """D13: 从代理池获取当前请求的代理"""
        if not self.proxy_pool:
            return self.proxy
        proxy = self.proxy_pool.get()
        return proxy

    def _record_proxy_result(self, proxy_url, success):
        """D13: 记录代理使用结果"""
        if self.proxy_pool and proxy_url:
            self.proxy_pool.record_result(proxy_url, success)

    def _log_debug(self, method, url, resp):
        """调试日志：方法 URL 状态码 响应字节，输出到 stderr"""
        if not self.debug:
            return
        try:
            code = resp.status_code
            size = len(resp.content or b"")
        except Exception:
            code = "?"
            size = "?"
        print(f"[debug] {method} {url} -> {code} ({size} bytes)", file=sys.stderr)

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> requests.Response:
        """发送 GET 请求（自动附加超时，计数并入报告统计）

        Args:
            url: 目标 URL
            headers: 附加请求头
        Returns:
            requests.Response
        """
        kwargs.setdefault("timeout", self.timeout)
        with self._count_lock:
            self.request_count += 1
        resp = self.session.get(url, headers=headers, **kwargs)
        self._log_debug("GET", url, resp)
        return resp

    def post(
        self, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, str]] = None, **kwargs
    ) -> requests.Response:
        """发送 POST 请求（自动附加超时，计数并入报告统计）

        Args:
            url: 目标 URL
            headers: 附加请求头
            data: 表单数据
        Returns:
            requests.Response
        """
        kwargs.setdefault("timeout", self.timeout)
        with self._count_lock:
            self.request_count += 1
        resp = self.session.post(url, headers=headers, data=data, **kwargs)
        self._log_debug("POST", url, resp)
        return resp

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> requests.Response:
        """通用 HTTP 请求（支持 OPTIONS/TRACE 等非标准方法）"""
        kwargs.setdefault("timeout", self.timeout)
        with self._count_lock:
            self.request_count += 1
        resp = self.session.request(method, url, headers=headers, **kwargs)
        self._log_debug(method.upper(), url, resp)
        return resp

    def close(self) -> None:
        """关闭底层 session（释放 keep-alive 连接与连接池）"""
        self.session.close()
