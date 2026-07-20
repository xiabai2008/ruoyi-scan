# D13 代理池：多代理轮换 + 健康检查 + 自动剔除
#
# 设计目标：
#   1. 从文件加载代理列表（每行一个 URL，如 http://user:pass@host:port）
#   2. 轮换策略：round-robin / random / least-fail
#   3. 健康检查：连续 3 次失败自动剔除，每 5 分钟重试一次
#   4. 与 SessionManager 集成：每请求轮换代理
#   5. 向后兼容：单 --proxy 仍可用
#
# 用法：
#   pool = ProxyPool(['http://1.1.1.1:8080', 'http://2.2.2.2:8080'])
#   proxy = pool.get()  # 获取下一个可用代理
#   pool.record_result(proxy, success=True)  # 记录结果
import random
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ProxyStats:
    """代理统计数据"""

    url: str
    success_count: int = 0
    fail_count: int = 0
    consecutive_fails: int = 0
    last_used: float = 0.0
    last_check: float = 0.0
    disabled: bool = False

    @property
    def total(self) -> int:
        return self.success_count + self.fail_count

    @property
    def fail_rate(self) -> float:
        return self.fail_count / self.total if self.total > 0 else 0.0


class ProxyPool:
    """代理池管理器（线程安全）

    用法：
        pool = ProxyPool(['http://1.1.1.1:8080', 'http://2.2.2.2:8080'],
                         strategy='round-robin')
        proxy = pool.get()
        try:
            resp = requests.get(url, proxies={'http': proxy, 'https': proxy})
            pool.record_result(proxy, success=True)
        except Exception:
            pool.record_result(proxy, success=False)
    """

    # 剔除阈值：连续失败次数
    DISABLE_THRESHOLD = 3
    # 重试间隔：被剔除的代理多久后重试（秒）
    RECHECK_INTERVAL = 300  # 5 分钟

    def __init__(self, proxies: List[str] = None, strategy: str = "round-robin"):
        """初始化代理池

        Args:
            proxies: 代理 URL 列表
            strategy: 轮换策略 round-robin / random / least-fail
        """
        self._lock = threading.Lock()
        self._strategy = strategy
        self._round_robin_idx = 0
        self._stats: Dict[str, ProxyStats] = {}
        if proxies:
            for url in proxies:
                self._stats[url] = ProxyStats(url=url)

    @classmethod
    def from_file(cls, file_path: str, strategy: str = "round-robin") -> "ProxyPool":
        """从文件加载代理列表

        文件格式：每行一个代理 URL，# 开头为注释

        Args:
            file_path: 文件路径
            strategy: 轮换策略

        Returns:
            ProxyPool 实例
        """
        proxies = []
        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        proxies.append(line)
        except FileNotFoundError:
            logger.debug("代理文件未找到，使用空代理列表", exc_info=True)
        return cls(proxies, strategy)

    def add(self, proxy_url: str):
        """添加代理"""
        with self._lock:
            if proxy_url not in self._stats:
                self._stats[proxy_url] = ProxyStats(url=proxy_url)

    def get(self) -> Optional[str]:
        """获取下一个可用代理

        Returns:
            代理 URL，无可用代理返回 None
        """
        with self._lock:
            # 自动重试被剔除的代理（超过 RECHECK_INTERVAL）
            now = time.time()
            for stats in self._stats.values():
                if stats.disabled and (now - stats.last_check) > self.RECHECK_INTERVAL:
                    stats.disabled = False
                    stats.consecutive_fails = 0

            # 筛选可用代理
            available = [s for s in self._stats.values() if not s.disabled]
            if not available:
                return None

            if self._strategy == "random":
                return random.choice(available).url
            elif self._strategy == "least-fail":
                # 优先用失败率最低的
                return min(available, key=lambda s: s.fail_rate).url
            else:  # round-robin（默认）
                idx = self._round_robin_idx % len(available)
                self._round_robin_idx += 1
                proxy = available[idx]
                proxy.last_used = now
                return proxy.url

    def record_result(self, proxy_url: str, success: bool):
        """记录代理使用结果

        Args:
            proxy_url: 代理 URL
            success: 是否成功
        """
        with self._lock:
            if proxy_url not in self._stats:
                self._stats[proxy_url] = ProxyStats(url=proxy_url)

            stats = self._stats[proxy_url]
            stats.last_check = time.time()
            if success:
                stats.success_count += 1
                stats.consecutive_fails = 0
            else:
                stats.fail_count += 1
                stats.consecutive_fails += 1
                # 连续失败超过阈值，自动剔除
                if stats.consecutive_fails >= self.DISABLE_THRESHOLD:
                    stats.disabled = True

    def get_stats(self) -> List[dict]:
        """获取所有代理统计"""
        with self._lock:
            return [
                {
                    "url": s.url,
                    "success": s.success_count,
                    "fail": s.fail_count,
                    "fail_rate": round(s.fail_rate, 2),
                    "disabled": s.disabled,
                    "consecutive_fails": s.consecutive_fails,
                }
                for s in self._stats.values()
            ]

    def healthy_count(self) -> int:
        """可用代理数"""
        with self._lock:
            return sum(1 for s in self._stats.values() if not s.disabled)

    def total_count(self) -> int:
        """总代理数"""
        with self._lock:
            return len(self._stats)

    def remove_disabled(self):
        """清除所有被剔除的代理"""
        with self._lock:
            disabled = [url for url, s in self._stats.items() if s.disabled]
            for url in disabled:
                del self._stats[url]
