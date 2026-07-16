# 扫描引擎：并发编排 + 令牌桶限速
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.models import ScanResult, STATUS_UNKNOWN


class ScanEngine:
    """插件执行引擎：同步或并发运行插件，可选限速"""

    def __init__(self, threads=1, rate=0):
        self.threads = max(1, threads)
        self.rate = rate  # 每秒请求数，0 表示不限速
        self._timestamps = []  # 令牌桶：最近 1 秒内的请求时间戳

    def run(self, plugin_classes, target, session, on_result=None):
        """运行插件集合

        Args:
            plugin_classes: 插件类列表
            target: 目标 URL（已归一化）
            session: SessionManager 实例
            on_result: 每个结果回调 on_result(ScanResult)
        Returns:
            结果列表
        """
        results = []

        def _exec(cls):
            try:
                inst = cls()
                return inst.verify(target, session)
            except Exception as e:
                # 网络异常等不阻断整体流程，判为 UNKNOWN（绝不判 SAFE）
                return ScanResult(
                    kind='error',
                    name=getattr(cls, 'name', cls.__name__),
                    status=STATUS_UNKNOWN,
                    evidence=f'执行异常: {e}'
                )

        if self.threads <= 1:
            for cls in plugin_classes:
                res = _exec(cls)
                results.append(res)
                if on_result:
                    on_result(res)
                self._rate_limit()
        else:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(_exec, cls): cls for cls in plugin_classes}
                for fut in as_completed(futures):
                    res = fut.result()
                    results.append(res)
                    if on_result:
                        on_result(res)
        return results

    def _rate_limit(self):
        """令牌桶限速：保证每秒请求数不超过 self.rate"""
        if self.rate <= 0:
            return
        now = time.time()
        self._timestamps = [t for t in self._timestamps if now - t < 1.0]
        if len(self._timestamps) >= self.rate:
            sleep = 1.0 - (now - self._timestamps[0])
            if sleep > 0:
                time.sleep(sleep)
        self._timestamps.append(time.time())
