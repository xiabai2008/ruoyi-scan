# 扫描引擎：并发编排 + 令牌桶限速
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Callable, List, Optional, cast

from common.models import STATUS_UNKNOWN, ScanResult

if TYPE_CHECKING:
    from core.session import SessionManager


class ScanEngine:
    """插件执行引擎：同步或并发运行插件，可选限速"""

    def __init__(self, threads: int = 1, rate: int = 0) -> None:
        """初始化扫描引擎

        Args:
            threads: 并发执行插件的线程数（<=1 退化为串行）
            rate: 每秒请求数上限（0=不限速，令牌桶实现见 _rate_limit）
        """
        self.threads = max(1, threads)
        self.rate = rate  # 每秒请求数，0 表示不限速
        self._timestamps: List[float] = []  # 令牌桶：最近 1 秒内的请求时间戳
        self._rate_lock = threading.Lock()  # 保护 _rate_limit 的互斥锁（多线程安全）

    def run(
        self,
        plugin_classes: List[type],
        target: str,
        session: SessionManager,
        on_result: Optional[Callable[[ScanResult], None]] = None,
        waf_bypass_coordinator: Optional[Any] = None,
    ) -> List[ScanResult]:
        """运行插件集合

        Args:
            plugin_classes: 插件类列表
            target: 目标 URL（已归一化）
            session: SessionManager 实例
            on_result: 每个结果回调 on_result(ScanResult)
            waf_bypass_coordinator: WAF 绕过协调器（D7，None 则不绕过）
        Returns:
            结果列表
        """
        results = []

        def _exec(cls: type) -> ScanResult:
            # 执行前限速（单线程和多线程统一走此路径，线程安全）
            self._rate_limit()
            try:
                inst = cls()
                # ⚠ 共享会话存在「认证状态泄漏」风险：各插件复用同一个 SessionManager，
                # 而 file_read_time、cve_2025_46174_resetpwd_scope 等插件会在其上**登录**。
                # 登录状态会一直保留给后续插件，而其余插件普遍以「未认证基线」为前提判定，
                # 于是把「已认证下返回的 200」误读为「文件/接口存在」。
                # 注意：**不能用 cookie 快照/还原来做隔离**——已实测无效：
                # Shiro 把认证状态存在服务端 session（按 JSESSIONID 索引），
                # 把 cookie 还原成同一个 JSESSIONID，服务端仍视其为已认证。
                # 需鉴权的插件必须自建独立会话（见 plugins/ruoyi/file_read_time.py 的写法）。
                original = cast(ScanResult, inst.verify(target, session))
                # D7: WAF 绕过（仅当协调器存在且插件支持绕过且原结果非 CONFIRMED）
                if (
                    waf_bypass_coordinator is not None
                    and getattr(inst, "supports_waf_bypass", False)
                    and original.status != "CONFIRMED"
                ):
                    try:
                        original = cast(
                            ScanResult, waf_bypass_coordinator.maybe_bypass(inst, target, session, original)
                        )
                    except Exception as e:
                        # 绕过异常不降级为 SAFE，保持原状态
                        if not original.extra:
                            original.extra = {}
                        original.extra["waf_bypass_error"] = str(e)
                # 元信息回填：统一在此补齐 cve/cvss_vector/compliance/fix_detail/reproduce，
                # 只填空值不覆盖插件已写入的值。放在 WAF 绕过之后，保证绕过路径同样生效。
                enrich = getattr(inst, "enrich", None)
                if callable(enrich):
                    original = cast(ScanResult, enrich(original))
                return original
            except Exception as e:
                # 网络异常等不阻断整体流程，判为 UNKNOWN（绝不判 SAFE）
                return ScanResult(
                    kind="error",
                    name=getattr(cls, "name", cls.__name__),
                    status=STATUS_UNKNOWN,
                    evidence=f"执行异常: {e}",
                )

        # 单线程模式：按插件定义顺序串行执行，结果顺序稳定（多线程用 as_completed 无序）
        if self.threads <= 1:
            for cls in plugin_classes:
                res = _exec(cls)
                results.append(res)
                if on_result:
                    on_result(res)
        else:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(_exec, cls): cls for cls in plugin_classes}
                for fut in as_completed(futures):
                    res = fut.result()
                    results.append(res)
                    if on_result:
                        on_result(res)
        return results

    def _rate_limit(self) -> None:
        """令牌桶限速：保证每秒请求数不超过 self.rate（线程安全）

        多线程环境下通过 _rate_lock 保护竞态条件。令牌桶算法：
        维护最近 1 秒内的请求时间戳列表，若已达上限则 sleep 等待。

        修复：sleep 必须在锁外执行，否则任一线程睡眠时其余线程全在锁上排队，
        多线程退化为串行。锁只保护时间戳列表的读写临界区。
        """
        if self.rate <= 0:
            return
        sleep = 0.0
        with self._rate_lock:
            now = time.time()
            self._timestamps = [t for t in self._timestamps if now - t < 1.0]
            if len(self._timestamps) >= self.rate:
                sleep = 1.0 - (now - self._timestamps[0])
            self._timestamps.append(time.time())
        # 锁外睡眠：不阻塞其他线程获取令牌（它们会各自判定并睡眠）
        if sleep > 0:
            time.sleep(sleep)
