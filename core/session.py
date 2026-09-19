# 会话封装：Cookie / 代理 / 重试 / keep-alive / 连接池 / TLS 策略 / 超时熔断
from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, Dict, Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

from common.logger import get_logger
from config import settings
from core.http import host_of

logger = get_logger(__name__)

if TYPE_CHECKING:
    from lib.proxy_pool import ProxyPool


# 行尾定向 ignore 的原因：CI 环境未安装 requests 类型桩，--ignore-missing-imports 使
# 基类退化为 Any，strict 模式禁止继承 Any；本地装有类型桩时该 ignore 属于未使用，
# 由 --no-warn-unused-ignores 压制，两种环境下均可通过。
class TargetUnresponsiveError(requests.exceptions.ConnectionError):  # type: ignore[misc]
    """连续超时熔断触发：目标接受 TCP 连接但不返回响应。

    继承 ConnectionError，使插件既有的 `except Exception` 语义完全不变——结果仍按三态
    纪律降级为 UNKNOWN，绝不会因为熔断而被误判为 SAFE。
    """


def is_timeout_error(exc: BaseException) -> bool:
    """判断异常是否为「超时」，含被 urllib3 重试包装后的形态。

    必要性：启用 Retry 的 HTTPAdapter 在重试耗尽后抛 MaxRetryError，requests 将其映射为
    ConnectionError——此时 `isinstance(exc, requests.exceptions.Timeout)` 为 False，超时
    语义已在包装中丢失。实测黑洞目标经 SessionManager 抛出的是 ConnectionError，只按最外层
    类型判断会导致熔断永不触发。故沿原因链（__cause__/__context__/urllib3 的 reason）判定。
    """
    seen: set[int] = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, requests.exceptions.Timeout):
            return True
        if "timeout" in type(cur).__name__.lower() or "timed out" in str(cur).lower():
            return True
        nxt = getattr(cur, "reason", None) or cur.__cause__ or cur.__context__
        cur = nxt if isinstance(nxt, BaseException) else None
    return False


class _HostBreaker:
    """按主机共享的超时熔断状态（见 SessionManager 中的使用说明）"""

    __slots__ = ("lock", "consecutive_timeouts", "tripped", "threshold")

    def __init__(self, threshold: int) -> None:
        self.lock = threading.Lock()
        self.consecutive_timeouts = 0
        self.tripped = False
        self.threshold = threshold


_HOST_BREAKERS: Dict[str, _HostBreaker] = {}
_HOST_BREAKERS_LOCK = threading.Lock()


def _host_breaker(host: str, threshold: int) -> _HostBreaker:
    """取（或惰性创建）指定主机的熔断状态

    按 host 分键而非全局单例：批量扫描多个目标时，某个死目标不应让其余目标被短路。
    """
    with _HOST_BREAKERS_LOCK:
        breaker = _HOST_BREAKERS.get(host)
        if breaker is None:
            breaker = _HostBreaker(threshold)
            _HOST_BREAKERS[host] = breaker
        return breaker


def reset_host_breakers() -> None:
    """清空熔断状态（供测试隔离使用）"""
    with _HOST_BREAKERS_LOCK:
        _HOST_BREAKERS.clear()


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
        verify: Optional[bool] = None,
        breaker_threshold: Optional[int] = None,
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
            verify: 是否校验 TLS 证书（缺省用 settings.VERIFY_TLS）
            breaker_threshold: 连续超时熔断阈值（缺省用 settings.TIMEOUT_BREAKER_THRESHOLD）
        """
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": ua or settings.DEFAULT_UA})
        self.proxy = proxy if proxy is not None else settings.PROXY
        self.timeout = timeout or settings.TIMEOUT
        self.proxy_pool = proxy_pool  # D13: 代理池
        # TLS 策略：默认不校验（内网自签名证书是若依部署常态，校验会让全部请求降级为
        # UNKNOWN 且无提示）；关闭校验时抑制 urllib3 的逐请求警告，否则会重现刷屏
        self.verify = settings.VERIFY_TLS if verify is None else verify
        self.session.verify = self.verify
        if not self.verify:
            urllib3.disable_warnings(InsecureRequestWarning)
        # 代理池优先：存在代理池时固定代理不生效，改为每请求从池中轮换
        if self.proxy and not self.proxy_pool:
            self.session.proxies.update({"http": self.proxy, "https": self.proxy})
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

        # 超时熔断：目标「接受连接但永不响应」时，逐请求等满超时会把扫描拖成数分钟
        # 无效重试。状态按 host 存放在模块级（见 _HostBreaker 说明），因为一次扫描会
        # 创建多个 SessionManager（侦察/漏洞/爆破/认证链各自一个），实例级计数会让每个
        # 新实例重新积累阈值——实测 -p 模式因此仍有 120 秒无效等待。
        self._breaker_threshold = (
            breaker_threshold if breaker_threshold is not None else settings.TIMEOUT_BREAKER_THRESHOLD
        )
        self._last_host = ""
        self.short_circuited = 0  # 因熔断被立即失败的请求数（本实例计数，报告可用）

    @property
    def breaker_tripped(self) -> bool:
        """最近请求过的主机是否已熔断（目标无响应）"""
        if not self._last_host:
            return False
        return _host_breaker(self._last_host, self._breaker_threshold).tripped

    def _check_breaker(self, url: str) -> None:
        """熔断已触发时立即失败，不再发起真实请求"""
        host = host_of(url)
        self._last_host = host
        if not _host_breaker(host, self._breaker_threshold).tripped:
            return
        with self._count_lock:
            self.short_circuited += 1
        # 消息刻意不含本次请求 URL：熔断时失败原因对所有路径都相同，带上 URL 会让
        # 每条路径的异常文本互不相同，下游按原因去重/聚合失效（实测目录扫描 696 条
        # 路径刷出 541 行、报告 evidence 被 696 个唯一原因撑爆）。引发熔断的目标主机
        # 已在 host 变量中，调用方的 ScanResult.url 也自带本次路径。
        raise TargetUnresponsiveError(
            f"连续 {self._breaker_threshold} 个请求超时，已判定目标无响应（{host}），短路后续请求"
        )

    def _note_outcome(self, url: str, timed_out: bool) -> None:
        """记录请求结果：超时累加并在达阈值时熔断，成功则复位计数"""
        self._last_host = host_of(url)
        breaker = _host_breaker(self._last_host, self._breaker_threshold)
        with breaker.lock:
            if not timed_out:
                breaker.consecutive_timeouts = 0
                return
            breaker.consecutive_timeouts += 1
            if breaker.consecutive_timeouts >= breaker.threshold and not breaker.tripped:
                breaker.tripped = True
                # 走 WARNING：默认日志级别下用户可见，说明「为什么后面全是 UNKNOWN」
                logger.warning(
                    "连续 %d 个请求超时，判定目标无响应：后续请求立即失败以避免无效重试（%s）",
                    breaker.consecutive_timeouts,
                    self._last_host,
                )

    def _send(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """统一请求出口：熔断检查 → 发起请求 → 记录结果"""
        self._check_breaker(url)
        kwargs.setdefault("timeout", self.timeout)
        with self._count_lock:
            self.request_count += 1
        try:
            resp = self.session.request(method, url, **kwargs)
        except Exception as exc:
            # 仅「超时」计入熔断序列。其他异常（连接被拒/SSL 失败/协议错误）既不计入
            # 也不复位——复位只应发生在确实收到响应时，否则「超时与其他错误交替」的
            # 目标会让计数反复归零，熔断永不触发。
            if is_timeout_error(exc):
                self._note_outcome(url, timed_out=True)
            raise
        self._note_outcome(url, timed_out=False)
        self._log_debug(method.upper(), url, resp)
        return resp

    def _get_proxy_for_request(self) -> Optional[str]:
        """D13: 从代理池获取当前请求的代理"""
        if not self.proxy_pool:
            return self.proxy
        proxy = self.proxy_pool.get()
        return proxy

    def _record_proxy_result(self, proxy_url: Optional[str], success: bool) -> None:
        """D13: 记录代理使用结果"""
        if self.proxy_pool and proxy_url:
            self.proxy_pool.record_result(proxy_url, success)

    def _log_debug(self, method: str, url: str, resp: Any) -> None:
        """调试日志：方法 URL 状态码 响应字节，输出到 stderr"""
        if not self.debug:
            return
        try:
            code: Any = resp.status_code
            size: Any = len(resp.content or b"")
        except Exception:
            code = "?"
            size = "?"
        # 请求明细走 DEBUG 日志：默认 WARNING 级别下静默，
        # 排查时用 --debug 或 RUOYI_SCAN_DEBUG=1 打开
        logger.debug("%s %s -> %s (%s bytes)", method, url, code, size)

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> requests.Response:
        """发送 GET 请求（自动附加超时，计数并入报告统计）

        Args:
            url: 目标 URL
            headers: 附加请求头
        Returns:
            requests.Response
        """
        return self._send("GET", url, headers=headers, **kwargs)

    def post(
        self, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, str]] = None, **kwargs: Any
    ) -> requests.Response:
        """发送 POST 请求（自动附加超时，计数并入报告统计）

        Args:
            url: 目标 URL
            headers: 附加请求头
            data: 表单数据
        Returns:
            requests.Response
        """
        return self._send("POST", url, headers=headers, data=data, **kwargs)

    def request(
        self, method: str, url: str, headers: Optional[Dict[str, str]] = None, **kwargs: Any
    ) -> requests.Response:
        """通用 HTTP 请求（支持 OPTIONS/TRACE 等非标准方法）"""
        return self._send(method, url, headers=headers, **kwargs)

    def close(self) -> None:
        """关闭底层 session（释放 keep-alive 连接与连接池）"""
        self.session.close()
