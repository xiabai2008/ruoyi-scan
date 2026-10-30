# 扫描引擎：并发编排 + 令牌桶限速
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Callable, List, Optional, cast

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_UNKNOWN, ScanResult

if TYPE_CHECKING:
    from core.session import SessionManager

logger = get_logger(__name__)


class ScanEngine:
    """插件执行引擎：同步或并发运行插件，可选限速"""

    def __init__(self, threads: int = 1, rate: int = 0, deadline: Optional[float] = None) -> None:
        """初始化扫描引擎

        Args:
            threads: 并发执行插件的线程数（<=1 退化为串行）
            rate: 每秒插件启动数上限（0=不限速，令牌桶实现见 _rate_limit）。
                注意：这是插件级限速，不是逐 HTTP 请求限速——单个插件内部发出
                的多个请求不受此约束
            deadline: time.monotonic() 口径的截止时间；超过后不再启动新插件，
                直接给 UNKNOWN。用于慢站/被限速目标（chaos slow 实测：2–5s/请求的
                站点会让一次 -p 跑过 5 分钟，操作者以为卡死）。None = 不限制
        """
        self.threads = max(1, threads)
        self.rate = rate  # 每秒插件启动数上限，0 表示不限速
        self.deadline = deadline  # 单目标时间预算截止点（monotonic）
        self._timestamps: List[float] = []  # 令牌桶：最近 1 秒内的插件启动时间戳
        self._rate_lock = threading.Lock()  # 保护 _rate_limit 的互斥锁（多线程安全）

    def run(
        self,
        plugin_classes: List[type],
        target: str,
        session: SessionManager,
        on_result: Optional[Callable[[ScanResult], None]] = None,
        waf_bypass_coordinator: Optional[Any] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> List[ScanResult]:
        """运行插件集合

        Args:
            plugin_classes: 插件类列表
            target: 目标 URL（已归一化）
            session: SessionManager 实例
            on_result: 每个结果回调 on_result(ScanResult)
            waf_bypass_coordinator: WAF 绕过协调器（D7，None 则不绕过）
            should_stop: 协作式取消检查（每插件入口调用；True 则不再启动新插件）
        Returns:
            结果列表
        """
        results = []

        def _exec(cls: type) -> Optional[ScanResult]:
            # 协作式取消：立即停止启动新插件。已启动的插件无法强杀（requests
            # 不支持中断），但会在自身 HTTP 超时内结束，不会无限占住线程。
            if should_stop is not None and should_stop():
                return None
            # 时间预算：慢站/被限速时宁可留 UNKNOWN，也不要让整次扫描无限拖长
            if self.deadline is not None and time.monotonic() > self.deadline:
                return ScanResult(
                    kind="info",
                    name=getattr(cls, "name", cls.__name__),
                    status=STATUS_UNKNOWN,
                    evidence="超出扫描时间预算（--time-budget），本项未执行",
                )
            # 执行前限速（单线程和多线程统一走此路径，线程安全）
            self._rate_limit()
            try:
                inst = cls()
                # ⚠ 共享会话存在「认证状态泄漏」风险：各插件复用同一个 SessionManager，
                # 而 job_invoke_target、cve_2025_46174_resetpwd_scope 等插件会在其上**登录**。
                # 登录状态会一直保留给后续插件，而其余插件普遍以「未认证基线」为前提判定，
                # 于是把「已认证下返回的 200」误读为「文件/接口存在」。
                # 注意：**不能用 cookie 快照/还原来做隔离**——已实测无效：
                # Shiro 把认证状态存在服务端 session（按 JSESSIONID 索引），
                # 把 cookie 还原成同一个 JSESSIONID，服务端仍视其为已认证。
                # 需鉴权的插件必须自建独立会话（见 plugins/ruoyi/job_invoke_target.py 的写法）。
                original = cast(ScanResult, inst.verify(target, session))
                # D7: WAF 绕过（仅当协调器存在且插件支持绕过且原结果非 CONFIRMED）
                if (
                    waf_bypass_coordinator is not None
                    and getattr(inst, "supports_waf_bypass", False)
                    and original.status != STATUS_CONFIRMED
                ):
                    try:
                        original = cast(
                            ScanResult, waf_bypass_coordinator.maybe_bypass(inst, target, session, original)
                        )
                    except Exception as e:
                        # 绕过异常不降级为 SAFE，保持原状态；同时记录日志：
                        # 否则绕过失败（及其部分执行的副作用）只留在 extra 里，对操作者不可见
                        logger.exception("WAF 绕过执行失败，保持原判定: %s", e)
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
                if res is None:  # 已取消：停止启动后续插件
                    break
                results.append(res)
                if on_result:
                    on_result(res)
        else:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(_exec, cls): cls for cls in plugin_classes}
                for fut in as_completed(futures):
                    res = fut.result()
                    if res is None:  # 已取消：跳过未执行项
                        continue
                    results.append(res)
                    if on_result:
                        on_result(res)
        return results

    def _rate_limit(self) -> None:
        """令牌桶限速：保证每秒启动的插件数不超过 self.rate（线程安全）

        注意：限的是一个插件「开始执行」的速率（_exec 入口调用），不是插件内部
        逐 HTTP 请求的 QPS；单插件多请求的场景不受此约束。CLI --rate 的宣传语
        「每秒请求数」在语义上以此为实际行为。

        多线程环境下通过 _rate_lock 保护竞态条件。令牌桶算法：
        维护最近 1 秒内的插件启动时间戳列表，若已达上限则等待令牌释放后重新竞争。

        修复（2026 评审）：原实现「先在锁内预约时间戳、再到锁外睡眠」，多个线程
        会同时预约（列表被撑过 rate）并算出几乎相同的睡眠时间，醒来后一起发起
        请求，形成超过配置速率的突发。现改为：锁内判定无令牌则释放锁睡眠，
        醒来后回到锁内重新竞争，只有真正拿到令牌（写入时间戳）的线程才继续请求。
        """
        if self.rate <= 0:
            return
        while True:
            with self._rate_lock:
                now = time.time()
                self._timestamps = [t for t in self._timestamps if now - t < 1.0]
                if len(self._timestamps) < self.rate:
                    # 拿到令牌：此刻才记录时间戳（即请求即将发出的时刻）
                    self._timestamps.append(now)
                    return
                sleep = 1.0 - (now - self._timestamps[0])
            # 锁外睡眠：不阻塞其他线程；醒来后重新竞争令牌，避免同时醒来的突发
            if sleep > 0:
                time.sleep(sleep)
