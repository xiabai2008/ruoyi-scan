# D34：异步扫描引擎
#
# 在不破坏现有同步插件（38 个 POC）的前提下，通过 asyncio + ThreadPoolExecutor
# 实现并发扫描，提升大规模扫描场景的吞吐量。
#
# 设计原则：
#   1. 现有 SessionManager 和插件零改动（同步代码）
#   2. 异步引擎通过 ThreadPoolExecutor 调度同步插件
#   3. 提供原生 asyncio HTTP 客户端（aiohttp）供新插件使用（可选）
#   4. 向后兼容：--async 关闭时走原同步路径
#
# 使用方式：
#   python main.py -u http://target/ --async --async-workers 20
#   python main.py -f targets.txt --async --async-workers 50
import asyncio
import concurrent.futures
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from common.logger import get_logger

logger = get_logger(__name__)

# ============================================================
# 异步扫描引擎
# ============================================================


class AsyncScanEngine:
    """异步扫描引擎

    使用 ThreadPoolExecutor 并发执行同步插件，避免阻塞主线程。
    适用于：
    - 批量扫描多个目标
    - 单目标多插件并发
    - 大规模资产盘点
    """

    def __init__(self, max_workers: int = 10):
        """
        Args:
            max_workers: 最大并发工作线程数
        """
        self.max_workers = max_workers
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._lock = threading.Lock()
        self._stats = {
            "submitted": 0,
            "completed": 0,
            "failed": 0,
            "total_duration": 0.0,
        }

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self) -> None:
        """启动线程池"""
        with self._lock:
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.max_workers,
                    thread_name_prefix="async-scan",
                )

    def stop(self) -> None:
        """停止线程池并等待所有任务完成"""
        with self._lock:
            if self._executor:
                self._executor.shutdown(wait=True)
                self._executor = None

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return dict(self._stats)

    def reset_stats(self) -> None:
        """重置统计"""
        with self._lock:
            self._stats = {
                "submitted": 0,
                "completed": 0,
                "failed": 0,
                "total_duration": 0.0,
            }

    def submit(self, fn: Callable, *args, **kwargs) -> concurrent.futures.Future:
        """提交同步任务到线程池

        Args:
            fn: 同步函数（如 Plugin.verify）
            *args, **kwargs: 函数参数

        Returns:
            Future 对象
        """
        if not self._executor:
            self.start()

        # _stats 在多 worker 线程中累加，用 self._lock 保护，避免丢更新
        with self._lock:
            self._stats["submitted"] += 1
        # 统一经 _wrap_task 包装，自动累计成功/失败/耗时统计
        future = self._executor.submit(self._wrap_task, fn, *args, **kwargs)
        return future

    def _wrap_task(self, fn: Callable, *args, **kwargs):
        """包装任务，记录统计"""
        start = time.time()
        try:
            result = fn(*args, **kwargs)
            # 旧实现缺陷：本节在 worker 线程执行，_stats["completed"] += 1 等非原子操作
            # 无锁保护（self._lock 只用于 executor 生命周期），并发下会丢统计。现加锁。
            with self._lock:
                self._stats["completed"] += 1
            return result
        except Exception:
            with self._lock:
                self._stats["failed"] += 1
            raise
        finally:
            with self._lock:
                self._stats["total_duration"] += time.time() - start

    def map(self, fn: Callable, iterable: List[Any]) -> List[Any]:
        """批量提交任务并等待全部完成

        Args:
            fn: 同步函数
            iterable: 参数列表（每个元素作为 fn 的单个参数）

        Returns:
            结果列表（顺序与输入一致）
        """
        if not self._executor:
            self.start()

        futures = []
        for item in iterable:
            with self._lock:
                self._stats["submitted"] += 1
            future = self._executor.submit(self._wrap_task, fn, item)
            futures.append(future)

        results = []
        for f in concurrent.futures.as_completed(futures):
            try:
                results.append(f.result())
            except Exception:
                results.append(None)

        return results

    async def submit_async(self, fn: Callable, *args, **kwargs) -> Any:
        """异步提交任务（在 asyncio 事件循环中调用）

        将同步函数提交到线程池，返回 awaitable
        """
        if not self._executor:
            self.start()

        loop = asyncio.get_event_loop()
        with self._lock:
            self._stats["submitted"] += 1
        # lambda 闭包携带参数：run_in_executor 只调无参 callable，参数须经闭包传入
        return await loop.run_in_executor(self._executor, lambda: self._wrap_task(fn, *args, **kwargs))

    async def map_async(self, fn: Callable, iterable: List[Any]) -> List[Any]:
        """异步批量执行

        Args:
            fn: 同步函数
            iterable: 参数列表

        Returns:
            结果列表
        """
        if not self._executor:
            self.start()

        tasks = []
        for item in iterable:
            with self._lock:
                self._stats["submitted"] += 1
            task = self.submit_async(fn, item)
            tasks.append(task)

        # return_exceptions=True：单个任务异常不中断整体，失败在下方循环统一计数
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # 统计（加锁保护，与其他累加路径一致）
        for r in results:
            with self._lock:
                if isinstance(r, Exception):
                    self._stats["failed"] += 1
                else:
                    self._stats["completed"] += 1

        return results


# ============================================================
# 批量目标扫描器
# ============================================================


def flatten(results_by_target: Dict[str, List[Any]]) -> List[Any]:
    """把 {target: results} 按 target 顺序扁平化为单个列表。

    供 scan_batch_targets 的返回值消费方使用：旧调用点直接 `flatten(scan_batch_targets(...))`
    即可拿到与旧扁平静态一致的结果，无需改动业务逻辑。
    """
    flat: List[Any] = []
    for lst in results_by_target.values():
        if lst:
            flat.extend(lst)
    return flat


def group_by_target(targets: List[str], flat_results: List[Any]) -> Dict[str, List[Any]]:
    """把旧式扁平结果按 target 顺序切分回 {target: results}。

    仅对“每个 target 恰好返回 List”的调用方有效（如 --async 批量：_scan_single 必返回 list）。
    现实中扁平列表本身不携带归属信息，故切分长度不足以覆盖全部 target 时，剩余 target
    保持为空列表（宁可标 0 也不猜归属）。新调用点应直接用 scan_batch_targets 的 dict 返回值。
    """
    grouped: Dict[str, List[Any]] = {t: [] for t in targets}
    pos = 0
    for t in targets:
        seg = flat_results[pos : pos + 1]
        if seg and isinstance(seg[0], list):
            grouped[t] = seg[0]
        pos += 1
    return grouped


def scan_batch_targets(
    scan_fn: Callable[[str], List[Any]],
    targets: List[str],
    max_workers: int = 10,
    progress_callback: Optional[Callable] = None,
) -> Dict[str, List[Any]]:
    """批量扫描多个目标

    Args:
        scan_fn: 单目标扫描函数（输入 target URL，返回结果列表）
        targets: 目标 URL 列表
        max_workers: 最大并发数
        progress_callback: 进度回调 fn(completed, total, current_target)

    Returns:
        {target: 该目标的扫描结果列表}

    旧实现缺陷：返回扁平的 all_results，丢失了每个结果的 target 归属，导致调用方
    （cli/runner.py `_run_batch_async`）无法按目标重建报告，只能把全部结果硬塞给第一个
    目标，其余目标报告显示 0 漏洞（高危数据丢失）。改为按 target 归位的字典后根除该问题。
    需要旧扁平行为的调用方用模块级 `flatten()` 转换即可，无需逐个改签名。
    """
    results_by_target: Dict[str, List[Any]] = {t: [] for t in targets}
    total = len(targets)

    with AsyncScanEngine(max_workers=max_workers) as engine:
        futures = {}
        for i, target in enumerate(targets):
            future = engine.submit(scan_fn, target)
            futures[future] = (i, target)

        completed = 0
        for future in concurrent.futures.as_completed(futures):
            idx, target = futures[future]
            try:
                results = future.result()
                # 显式写回对应 target，避免归属丢失；扫描函数抛异常时该 target 保持空列表
                if results:
                    results_by_target[target] = list(results)
            except Exception:
                logger.warning("批量扫描目标 %s 失败，该目标无结果", target, exc_info=True)
            completed += 1
            if progress_callback:
                progress_callback(completed, total, target)

    return results_by_target


# ============================================================
# 单目标多插件并发扫描
# ============================================================


def scan_plugins_concurrent(
    plugin_verify_fn: Callable, plugins: List[Any], target: str, session, max_workers: int = 10
) -> List[Any]:
    """并发执行多个插件的 verify 方法

    Args:
        plugin_verify_fn: 插件执行函数 fn(plugin, target, session) → ScanResult
        plugins: 插件列表
        target: 目标 URL
        session: SessionManager 实例
        max_workers: 最大并发数

    Returns:
        ScanResult 列表
    """
    with AsyncScanEngine(max_workers=max_workers) as engine:
        futures = []
        for plugin in plugins:
            future = engine.submit(plugin_verify_fn, plugin, target, session)
            futures.append(future)

        results = []
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception:
                logger.debug("单目标多插件扫描获取结果失败", exc_info=True)

        return results


# ============================================================
# 异步 HTTP 客户端（可选，供新插件使用）
# ============================================================


async def async_http_get(
    url: str, headers: Dict = None, timeout: float = 10.0, verify_ssl: bool = False
) -> Dict[str, Any]:
    """异步 HTTP GET 请求（使用 aiohttp）

    注意：需要安装 aiohttp（pip install aiohttp）。未安装时抛出 ImportError。

    Args:
        url: 请求 URL
        headers: 请求头
        timeout: 超时秒数
        verify_ssl: 是否验证 SSL 证书

    Returns:
        {'status_code': int, 'text': str, 'headers': dict, 'url': str}
    """
    try:
        import aiohttp
    except ImportError:
        raise ImportError("异步 HTTP 需要安装 aiohttp：pip install aiohttp")

    import ssl

    ssl_ctx = ssl.create_default_context()
    # 默认不校验 SSL 证书：靶场/自签名证书场景可正常抓取
    if not verify_ssl:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_ctx)
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout_cfg) as http_session:
        async with http_session.get(url, headers=headers or {}) as resp:
            text = await resp.text()
            return {
                "status_code": resp.status,
                "text": text,
                "headers": dict(resp.headers),
                "url": str(resp.url),
            }


async def async_http_post(
    url: str, data: Dict = None, json_data: Dict = None, headers: Dict = None, timeout: float = 10.0
) -> Dict[str, Any]:
    """异步 HTTP POST 请求"""
    try:
        import aiohttp
    except ImportError:
        raise ImportError("异步 HTTP 需要安装 aiohttp：pip install aiohttp")

    timeout_cfg = aiohttp.ClientTimeout(total=timeout)

    async with aiohttp.ClientSession(timeout=timeout_cfg) as http_session:
        kwargs = {}
        if data:
            kwargs["data"] = data
        if json_data:
            kwargs["json"] = json_data
        if headers:
            kwargs["headers"] = headers

        async with http_session.post(url, **kwargs) as resp:
            text = await resp.text()
            return {
                "status_code": resp.status,
                "text": text,
                "headers": dict(resp.headers),
                "url": str(resp.url),
            }


# ============================================================
# 性能基准测试
# ============================================================


def benchmark_sync_vs_async(sync_fn: Callable, targets: List[str], max_workers: int = 10) -> Dict[str, Any]:
    """对比同步 vs 异步扫描性能

    Args:
        sync_fn: 同步扫描函数
        targets: 目标列表
        max_workers: 异步并发数

    Returns:
        {'sync_duration': float, 'async_duration': float, 'speedup': float}
    """
    # 同步执行
    start = time.time()
    sync_results = []
    for target in targets:
        try:
            result = sync_fn(target)
            if result:
                sync_results.extend(result if isinstance(result, list) else [result])
        except Exception:
            logger.debug("基准测试同步执行失败", exc_info=True)
    sync_duration = time.time() - start

    # 异步执行（scan_batch_targets 现返回 {target: results}，用 flatten 还原为扁平计数）
    start = time.time()
    async_results = flatten(scan_batch_targets(sync_fn, targets, max_workers=max_workers))
    async_duration = time.time() - start

    # 防御 async_duration 为 0（空目标列表）导致的除零
    speedup = sync_duration / async_duration if async_duration > 0 else 0

    return {
        "sync_duration": round(sync_duration, 3),
        "async_duration": round(async_duration, 3),
        "speedup": round(speedup, 2),
        "sync_results": len(sync_results),
        "async_results": len(async_results),
        "targets": len(targets),
        "max_workers": max_workers,
    }


# ============================================================
# 模式入口
# ============================================================


def run_async_scan_mode(
    scan_fn: Callable[[str], List[Any]],
    targets: List[str],
    max_workers: int = 10,
    progress_callback: Optional[Callable] = None,
) -> List[Any]:
    """异步扫描模式入口

    Args:
        scan_fn: 单目标扫描函数
        targets: 目标列表
        max_workers: 最大并发数
        progress_callback: 进度回调

    Returns:
        扫描结果列表（保持扁平，向后兼容旧调用方）
    """
    # scan_batch_targets 现返回 {target: results}，此处 flatten 维持本函数原有的扁平返回契约
    return flatten(scan_batch_targets(scan_fn, targets, max_workers, progress_callback))
