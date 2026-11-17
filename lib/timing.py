"""时序差分判定公共层（无回显漏洞的时间维度证据）。

为什么单独成层：SQL 盲注、模板注入、命令注入等「能执行但看不到回显」的漏洞，
唯一可用的证据就是服务端被要求延迟后的响应耗时。判定规则一旦散落在各插件里，
「慢站被判成漏洞」这类误报就会各写一遍、各漂一次（与 lib/matcher 的抽取动机相同）。

本模块只做两件事：
  1. measure() —— 一次请求的耗时采样（异常/超时返回 None，调用方必须按 UNKNOWN 处理）；
  2. classify() —— 基线 vs 探测采样 → 'confirmed' / 'safe' / 'unknown' 三态。

设计要点：
- 用 time.monotonic：time.time 会被系统时钟调整（NTP 校正、夏令时）污染，
  一次回拨就能把 3 秒延迟算成负数。
- 「慢站不得 CONFIRMED」靠**差分**而非绝对阈值：目标本来就慢（基线 4s）时，
  探测 4.1s 与基线的差只有 0.1s，不管绝对值多大都判 safe。
- 超时 ≠ 没延迟：任一采样为 None 直接 unknown，绝不把 None 当 0 秒参与平均。
"""

import time
from typing import List, Optional

# 探测延迟：够压过网络抖动，又让一轮 6-8 次请求控制在 25s 内
DELAY_SECONDS = 3.0


def measure(session, method: str, url: str, **kwargs) -> Optional[float]:
    """返回本次请求耗时（秒）；异常/超时返回 None（调用方必须按 UNKNOWN 处理）。

    用 time.monotonic，不用 time.time（后者会被系统时钟调整污染）。

    Args:
        session: 共享 HTTP 会话（SessionManager，或测试用的鸭子类型对象）
        method: HTTP 方法（'POST' / 'GET'）
        url: 请求 URL
        **kwargs: 透传给 session 的 post/get（headers/data 等）

    Returns:
        耗时秒数；请求抛异常（含超时、熔断）时返回 None
    """
    # 按方法名取会话上的同名方法：SessionManager 有 post/get/request，
    # 但测试与部分包装会话只实现 post/get。退化路径用 request(method, url)。
    sender = getattr(session, method.lower(), None)
    if callable(sender):
        args = (url,)
    else:
        sender = getattr(session, "request", None)
        if not callable(sender):
            return None
        args = (method, url)
    start = time.monotonic()
    try:
        sender(*args, **kwargs)
    except Exception:
        return None
    return time.monotonic() - start


def median(values: List[float]) -> float:
    """中位数；空列表返回 0.0（statistics.median([]) 会抛异常，这里自己兜底）。

    用中位数而不是平均值：单次抖动尖峰（GC、TCP 重传）会把均值拉过阈值，
    中位数要求「多数采样都成立」，与 classify 的「至少 2 次」规则同向。
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (float(ordered[mid - 1]) + float(ordered[mid])) / 2.0


def classify(baseline_s: float, probe_s: List[Optional[float]], delay: float = DELAY_SECONDS) -> str:
    """返回 'confirmed' / 'safe' / 'unknown'。

    规则顺序不可调换（先排除不可判定，再确认，再排除「没延迟」，最后中间地带一律 unknown）：
      1. 任一采样为 None → unknown（超时不等于「没延迟」）；
      2. confirmed 需同时满足：中位数 >= delay*0.8（延迟确实发生）、
         中位数 - 基线 >= delay*0.7（差分，排除本来就慢的站点）、
         至少 2 个采样相对基线 >= delay*0.5（排除单次抖动尖峰）；
      3. 中位数 - 基线 < delay*0.3 → safe（没延迟，两组一致）；
      4. 其余 → unknown（中间地带不判：既不敢确认，也不敢说「不存在」）。

    Args:
        baseline_s: 对照组（条件为假）耗时中位数/单次耗时（秒）
        probe_s: 探测组（条件为真）采样列表（秒，可含 None）
        delay: 本次探测期望注入的延迟秒数
    """
    if not probe_s:
        return "unknown"
    if any(x is None for x in probe_s):
        return "unknown"
    base = float(baseline_s or 0.0)
    probes = [float(x) for x in probe_s]
    probe_median = median(probes)
    # 「成立」与 confirmed 第三条用同一差分门槛，避免两处阈值漂移
    hits = sum(1 for x in probes if x - base >= delay * 0.5)
    if probe_median >= delay * 0.8 and probe_median - base >= delay * 0.7 and hits >= 2:
        return "confirmed"
    if probe_median - base < delay * 0.3:
        return "safe"
    return "unknown"
