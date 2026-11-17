# 进程内令牌桶限速（引擎插件级与会话请求级共用）
#
# 为什么抽到 lib：
#   限速算法原先只存在于 core/engine.py::_rate_limit（按插件启动限速）。v1.7.2 起
#   --rate 默认改为「每秒 HTTP 请求数」，需要在 core/session.py 的请求出口复用同一
#   算法。同一份滑动窗口逻辑维护两份必然漂移，故收敛为唯一实现。
#
# 算法要点（评审修复版）：
#   锁内只做判定与记账，睡眠一律放到锁外，醒来后回到锁内重新竞争令牌。旧实现
#   「锁内预约时间戳 + 锁外睡眠」会让多个线程同时预约、同时醒来形成超过配置速率
#   的突发。
"""进程内令牌桶限速（引擎插件级与会话请求级共用）。"""

from __future__ import annotations

import threading
import time
from typing import Callable, List, Optional


class TokenBucket:
    """滑动窗口令牌桶：任意 1 秒窗口内最多放行 rate 次。

    进程内对象，不做全局单例、不做进程间共享（分布式限速见 lib/distributed.py，
    那是另一套基于 Redis 的协调逻辑）。
    """

    def __init__(
        self,
        rate: int,
        clock: Optional[Callable[[], float]] = None,
        sleeper: Optional[Callable[[float], None]] = None,
    ) -> None:
        """rate<=0 表示不限速（acquire 立即返回）。

        clock / sleeper 可注入，供单测用假时钟，避免真实 sleep。
        """
        self.rate = max(0, int(rate))
        self._clock: Callable[[], float] = clock or time.monotonic
        self._sleeper: Callable[[float], None] = sleeper or time.sleep
        self._lock = threading.Lock()
        # 最近 1 秒内放行的时间戳（monotonic 口径）
        self._timestamps: List[float] = []

    def acquire(self) -> None:
        """取得一个令牌；无令牌则睡眠到有令牌为止（线程安全）。"""
        # 不限速：不加锁、不取时，保证 --rate 0 零额外开销
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                now = self._clock()
                self._timestamps = [t for t in self._timestamps if now - t < 1.0]
                if len(self._timestamps) < self.rate:
                    # 拿到令牌：此刻才记录时间戳（即请求即将发出的时刻）
                    self._timestamps.append(now)
                    return
                wait = 1.0 - (now - self._timestamps[0])
            # 锁外睡眠：不阻塞其他线程；醒来后重新竞争令牌，避免同时醒来的突发
            if wait > 0:
                self._sleeper(wait)
