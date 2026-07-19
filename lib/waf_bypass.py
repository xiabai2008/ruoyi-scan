# WAF 绕过策略库与编排器（D7 阶段）
#
# 架构：
#   - WafBypassStrategy: 策略抽象基类（apply_transport + tamper_payload）
#   - 8+ 策略类: 每种 WAF 的专项绕过策略 + 通用兜底策略
#   - StrategyRegistry: 策略注册表（按 WAF 类型索引）
#   - BypassContext: 绕过上下文（waf_type/vuln_type/payload/origin_ip）
#   - BypassSession: SessionManager 的轻量包装（应用传输层变换）
#   - WafBypassCoordinator: 编排器（由 ScanEngine 调用）
#
# 三态判定保护矩阵：
#   - CONFIRMED 不绕过（已确认不绕过）
#   - 真 SAFE 不绕过（不误绕）
#   - 假 SAFE（被拦）尝试绕过，成功→CONFIRMED，失败→原状态+标记
#   - UNKNOWN 尝试绕过，成功→CONFIRMED，失败→UNKNOWN+标记（不降级）
#   - 绕过异常→原状态+UNKNOWN 兜底（绝不判 SAFE）
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.tamper import (space2comment, mysql_version_comment, randomcase,
                        between_replace, url_encode, double_urlencode,
                        split_for_chunked, hpp_duplicate, append_nullbyte)


# === 上下文 ===

@dataclass
class BypassContext:
    """绕过上下文（传递给策略类和插件 verify_with_bypass）

    Attributes:
        waf_type: WAF 标识（如 'cloudflare'）
        vuln_type: 漏洞类型（如 'sqli'）
        original_payload: 原始 payload 字符串（插件可设置）
        original_url: 原始请求 URL
        origin_ip: 源站 IP（L4 策略使用，可能为空）
        attempt: 当前尝试次数（第几次绕过）
        max_attempts: 最大尝试次数
        strategy: 当前策略实例（插件可调用 strategy.tamper_payload() 变形 payload）
    """
    waf_type: str = ''
    vuln_type: str = ''
    original_payload: str = ''
    original_url: str = ''
    origin_ip: str = ''
    attempt: int = 0
    max_attempts: int = 3
    strategy: Any = None  # WafBypassStrategy 实例（供插件调用 tamper_payload）


# === 策略基类 ===

class WafBypassStrategy(ABC):
    """WAF 绕过策略抽象基类

    子类需实现：
        - apply_transport: 返回传输层变换
        - tamper_payload: 变形 payload
    """
    name = ''                  # 策略中文名
    strategy_id = ''           # BP-XX-N
    layer = ''                 # L1/L2/L3/L4
    waf_types = []             # 适用的 WAF 标识列表（['cloudflare'] 或 ['*']）
    vuln_types = []            # 适用的漏洞类型（['sqli','xss','rce','file_read','auth','*']）
    priority = 50              # 优先级（小先执行，0-100）

    @abstractmethod
    def apply_transport(self, ctx: BypassContext) -> dict:
        """返回传输层变换

        Returns:
            {'headers': {...}, 'chunked': bool, 'origin_ip': '', 'http_version': '1.0'}
        """
        return {}

    @abstractmethod
    def tamper_payload(self, payload: str, ctx: BypassContext) -> str:
        """变形 payload（纯函数语义）"""
        return payload

    def is_applicable(self, waf_type: str, vuln_type: str) -> bool:
        """判断策略是否适用于当前 WAF 和漏洞类型"""
        waf_ok = '*' in self.waf_types or waf_type in self.waf_types
        vuln_ok = '*' in self.vuln_types or vuln_type in self.vuln_types
        return waf_ok and vuln_ok


# === L1: payload 变形策略 ===

class InlineCommentStrategy(WafBypassStrategy):
    """内联注释变形（空格→/**/）"""
    name = '内联注释变形'
    strategy_id = 'BP-SD-1'
    layer = 'L1'
    waf_types = ['safedog', 'aliyun_waf', 'modsecurity']
    vuln_types = ['sqli']
    priority = 20

    def apply_transport(self, ctx):
        return {'headers': {}, 'chunked': False}

    def tamper_payload(self, payload, ctx):
        return space2comment(payload)


class MysqlVersionCommentStrategy(WafBypassStrategy):
    """MySQL 版本注释变形"""
    name = 'MySQL 版本注释'
    strategy_id = 'BP-SD-1b'
    layer = 'L1'
    waf_types = ['safedog', 'aliyun_waf']
    vuln_types = ['sqli']
    priority = 25

    def apply_transport(self, ctx):
        return {'headers': {}, 'chunked': False}

    def tamper_payload(self, payload, ctx):
        return mysql_version_comment(payload)


class RandomCaseStrategy(WafBypassStrategy):
    """大小写混淆（通用兜底，最轻量）"""
    name = '大小写混淆'
    strategy_id = 'BP-GEN-1'
    layer = 'L1'
    waf_types = ['*']
    vuln_types = ['sqli', 'xss', 'rce']
    priority = 10  # 通用策略，优先执行

    def apply_transport(self, ctx):
        return {'headers': {}, 'chunked': False}

    def tamper_payload(self, payload, ctx):
        return randomcase(payload)


class BetweenReplaceStrategy(WafBypassStrategy):
    """between 替换（=→BETWEEN x AND x）"""
    name = 'BETWEEN 替换'
    strategy_id = 'BP-SD-3'
    layer = 'L1'
    waf_types = ['safedog', 'modsecurity']
    vuln_types = ['sqli']
    priority = 30

    def apply_transport(self, ctx):
        return {'headers': {}, 'chunked': False}

    def tamper_payload(self, payload, ctx):
        return between_replace(payload)


# === L2: 编码绕过策略 ===

class UrlEncodeStrategy(WafBypassStrategy):
    """URL 编码（通用）"""
    name = 'URL 编码'
    strategy_id = 'BP-GEN-2'
    layer = 'L2'
    waf_types = ['*']
    vuln_types = ['sqli', 'xss', 'rce', 'file_read']
    priority = 15

    def apply_transport(self, ctx):
        return {'headers': {}, 'chunked': False}

    def tamper_payload(self, payload, ctx):
        return url_encode(payload)


class DoubleUrlEncodeStrategy(WafBypassStrategy):
    """双重 URL 编码"""
    name = '双重 URL 编码'
    strategy_id = 'BP-CP-1'
    layer = 'L2'
    waf_types = ['chaitin', 'modsecurity']
    vuln_types = ['sqli', 'rce']
    priority = 35

    def apply_transport(self, ctx):
        return {'headers': {}, 'chunked': False}

    def tamper_payload(self, payload, ctx):
        return double_urlencode(payload)


# === L3: 协议层策略 ===

class ChunkedTransferStrategy(WafBypassStrategy):
    """分块传输（通用，L3 最常用）"""
    name = '分块传输'
    strategy_id = 'BP-GEN-3'
    layer = 'L3'
    waf_types = ['*']
    vuln_types = ['sqli', 'rce', 'file_read']
    priority = 40

    def apply_transport(self, ctx):
        return {
            'headers': {'Transfer-Encoding': 'chunked'},
            'chunked': True,
            'http_version': '1.1',
        }

    def tamper_payload(self, payload, ctx):
        return split_for_chunked(payload)


class HppStrategy(WafBypassStrategy):
    """HPP 参数污染"""
    name = 'HPP 参数污染'
    strategy_id = 'BP-ALI-3'
    layer = 'L3'
    waf_types = ['aliyun_waf', 'tencent_waf']
    vuln_types = ['sqli']
    priority = 45

    def apply_transport(self, ctx):
        return {'headers': {}, 'chunked': False}

    def tamper_payload(self, payload, ctx):
        return hpp_duplicate(payload)


class Http10DowngradeStrategy(WafBypassStrategy):
    """HTTP/1.0 降级（部分 WAF 对 1.0 协议解析不同）"""
    name = 'HTTP/1.0 降级'
    strategy_id = 'BP-CP-2b'
    layer = 'L3'
    waf_types = ['chaitin', 'knownsec']
    vuln_types = ['*']
    priority = 50

    def apply_transport(self, ctx):
        return {
            'headers': {'Connection': 'close'},
            'chunked': False,
            'http_version': '1.0',
        }

    def tamper_payload(self, payload, ctx):
        return payload  # 仅传输层变换，payload 不变


class GooglebotStrategy(WafBypassStrategy):
    """Googlebot 伪装（Cloudflare 对 Googlebot 放行）"""
    name = 'Googlebot 伪装'
    strategy_id = 'BP-CF-2'
    layer = 'L3'
    waf_types = ['cloudflare']
    vuln_types = ['*']
    priority = 15

    GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

    def apply_transport(self, ctx):
        return {
            'headers': {'User-Agent': self.GOOGLEBOT_UA},
            'chunked': False,
        }

    def tamper_payload(self, payload, ctx):
        return payload


# === L4: 源站直连策略 ===

class OriginDirectStrategy(WafBypassStrategy):
    """源站 IP 直连（绕过 CDN 边缘）"""
    name = '源站 IP 直连'
    strategy_id = 'BP-CF-1'
    layer = 'L4'
    waf_types = ['cloudflare', 'baidu_waf', 'chaitin']
    vuln_types = ['*']
    priority = 60  # L4 策略优先级较低（需先探测源站 IP）

    def apply_transport(self, ctx):
        return {
            'headers': {},
            'chunked': False,
            'origin_ip': ctx.origin_ip,
        }

    def tamper_payload(self, payload, ctx):
        return payload


# === 策略注册表 ===

class StrategyRegistry:
    """策略注册表（按 WAF 类型索引）"""

    def __init__(self):
        self._strategies: List[WafBypassStrategy] = []
        self._register_defaults()

    def _register_defaults(self):
        """注册默认策略集（11 个）"""
        strategies = [
            # 通用兜底策略（priority 低，优先执行）
            RandomCaseStrategy(),
            UrlEncodeStrategy(),
            ChunkedTransferStrategy(),
            # L1 变形策略
            InlineCommentStrategy(),
            MysqlVersionCommentStrategy(),
            BetweenReplaceStrategy(),
            # L2 编码策略
            DoubleUrlEncodeStrategy(),
            # L3 协议层策略
            HppStrategy(),
            Http10DowngradeStrategy(),
            GooglebotStrategy(),
            # L4 源站直连
            OriginDirectStrategy(),
        ]
        for s in strategies:
            self.register(s)

    def register(self, strategy: WafBypassStrategy):
        """注册策略"""
        self._strategies.append(strategy)

    def get_strategies(self, waf_type: str, vuln_type: str) -> List[WafBypassStrategy]:
        """获取适用于指定 WAF 和漏洞类型的策略（按 priority 排序）

        Args:
            waf_type: WAF 标识（如 'cloudflare'）
            vuln_type: 漏洞类型（如 'sqli'）

        Returns:
            排序后的策略列表（priority 小的在前）
        """
        applicable = [s for s in self._strategies
                      if s.is_applicable(waf_type, vuln_type)]
        return sorted(applicable, key=lambda s: s.priority)

    def all_strategies(self) -> List[WafBypassStrategy]:
        """返回所有已注册策略"""
        return list(self._strategies)


# === D7.4: 策略成功率追踪器 ===

class BypassStatsTracker:
    """策略成功率追踪器（D7.4 性能优化）

    记录每种策略的历史成功率，动态调整优先级：
        - 成功率高的策略 priority 降低（更早尝试）
        - 成功率低的策略 priority 升高（更晚尝试）
        - 新策略无记录时保持原始 priority

    调整公式：
        adjusted_priority = base_priority + (1 - success_rate) * penalty_factor
        其中 penalty_factor=20，success_rate=success/(success+failure)

    线程安全：内部用 dict 统计，单线程引擎下无需加锁；
    多线程引擎下统计为近似值（允许少量竞态，不影响正确性）。
    """

    def __init__(self, penalty_factor: int = 20):
        """初始化追踪器

        Args:
            penalty_factor: 失败惩罚因子（越大则低成功率策略 priority 惩罚越重）
        """
        self._stats: Dict[str, Dict[str, int]] = {}  # {strategy_id: {'success': N, 'failure': N}}
        self.penalty_factor = penalty_factor

    def record_result(self, strategy_id: str, success: bool):
        """记录策略执行结果

        Args:
            strategy_id: 策略 ID（如 'BP-CF-2'）
            success: True=成功，False=失败
        """
        if strategy_id not in self._stats:
            self._stats[strategy_id] = {'success': 0, 'failure': 0}
        key = 'success' if success else 'failure'
        self._stats[strategy_id][key] += 1

    def get_success_rate(self, strategy_id: str) -> float:
        """获取策略成功率（0.0-1.0，无记录返回 -1.0）"""
        s = self._stats.get(strategy_id)
        if not s:
            return -1.0
        total = s['success'] + s['failure']
        if total == 0:
            return -1.0
        return s['success'] / total

    def get_adjusted_priority(self, strategy_id: str, base_priority: int) -> int:
        """获取调整后的优先级

        成功率高 → priority 降低（更早尝试）
        成功率低 → priority 升高（更晚尝试）
        无记录 → 保持 base_priority

        Returns:
            调整后的 priority（int）
        """
        rate = self.get_success_rate(strategy_id)
        if rate < 0:
            return base_priority
        # 成功率 1.0 → penalty=0；成功率 0.0 → penalty=penalty_factor
        penalty = int((1 - rate) * self.penalty_factor)
        return base_priority + penalty

    def get_sorted_strategies(self, strategies: List[WafBypassStrategy]) -> List[WafBypassStrategy]:
        """按调整后 priority 排序策略列表"""
        return sorted(strategies, key=lambda s: self.get_adjusted_priority(s.strategy_id, s.priority))

    def get_stats(self) -> Dict[str, Dict[str, int]]:
        """返回所有策略统计（副本）"""
        return {k: dict(v) for k, v in self._stats.items()}

    def summary(self) -> str:
        """返回可读的统计摘要"""
        if not self._stats:
            return '无绕过统计'
        lines = []
        for sid, s in sorted(self._stats.items()):
            total = s['success'] + s['failure']
            rate = (s['success'] / total * 100) if total > 0 else 0
            lines.append(f'  {sid}: {s["success"]}/{total} ({rate:.0f}%)')
        return '\n'.join(lines)


# === BypassSession: SessionManager 的轻量包装 ===

class BypassSession:
    """绕过会话：包装 SessionManager，透明应用传输层变换

    组合模式（不继承、不改 SessionManager 源码）：
        - 透传 get/post/request
        - 在出站前注入 chunked/origin IP/自定义 headers
    """

    def __init__(self, session, transport_config: dict = None,
                 origin_url: str = None):
        """初始化绕过会话

        Args:
            session: 原始 SessionManager 实例
            transport_config: 传输层变换配置
                {'headers': {...}, 'chunked': bool, 'origin_ip': '', 'http_version': '1.0'}
            origin_url: 源站直连 URL（L4 策略使用，替换原始 URL）
        """
        self._session = session
        self._transport = transport_config or {}
        self._origin_url = origin_url
        self._extra_headers = self._transport.get('headers', {})

    def _apply_transform(self, url, kwargs):
        """应用传输层变换"""
        # L4: 源站 IP 直连（替换 URL 中的域名）
        if self._origin_url:
            url = self._replace_host(url, self._origin_url)
        # 合并自定义 headers
        headers = kwargs.get('headers') or {}
        headers = {**headers, **self._extra_headers}
        if headers:
            kwargs['headers'] = headers
        return url, kwargs

    def _replace_host(self, url, origin_url):
        """替换 URL 中的 host 部分为源站 IP"""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        origin_parsed = urlparse(origin_url)
        return urlunparse((
            parsed.scheme,
            origin_parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        ))

    def get(self, url, **kwargs):
        url, kwargs = self._apply_transform(url, kwargs)
        return self._session.get(url, **kwargs)

    def post(self, url, **kwargs):
        url, kwargs = self._apply_transform(url, kwargs)
        return self._session.post(url, **kwargs)

    def request(self, method, url, **kwargs):
        url, kwargs = self._apply_transform(url, kwargs)
        return self._session.request(method, url, **kwargs)

    @property
    def request_count(self):
        return self._session.request_count

    def close(self):
        self._session.close()


# === WafBypassCoordinator: 编排器 ===

class WafBypassCoordinator:
    """WAF 绕过编排器（由 ScanEngine 在 WAF 命中后调用）

    生命周期：
        1. main.py 在 detect_waf 命中后构建 coordinator（预探测源站 IP）
        2. ScanEngine._exec 中，原 verify 返回非 CONFIRMED 且响应被拦 → 调 maybe_bypass
        3. coordinator 按策略矩阵尝试，首个成功即返回
        4. 结果 extra 标记 waf_bypass 元信息

    不变量（三态判定保护矩阵）：
        - original_result.status == CONFIRMED → 直接返回原结果（不绕过）
        - 原响应未被 WAF 拦截（真 SAFE）→ 返回原结果（不绕过）
        - 绕过失败 → 返回原结果，extra 标记 bypass_attempted
        - 绕过成功 → 返回新 CONFIRMED，extra 标记 strategy_used
        - 绕过异常 → 原状态 + UNKNOWN 兜底（绝不判 SAFE）
    """

    def __init__(self, waf_type: str = '', origin_ip: str = '',
                 registry: StrategyRegistry = None,
                 stats_tracker: 'BypassStatsTracker' = None):
        """初始化编排器

        Args:
            waf_type: 检测到的 WAF 标识（如 'cloudflare'）
            origin_ip: 预探测的源站 IP（L4 策略使用，可为空）
            registry: 策略注册表（None 则使用默认）
            stats_tracker: 策略成功率追踪器（D7.4，None 则不追踪）
        """
        self.waf_type = waf_type
        self.origin_ip = origin_ip
        self.registry = registry or StrategyRegistry()
        self.stats_tracker = stats_tracker  # D7.4: 策略成功率追踪

    def maybe_bypass(self, plugin, target, session, original_result) -> ScanResult:
        """主入口：原 verify 结果非 CONFIRMED 时尝试绕过

        Args:
            plugin: PluginBase 实例（需 supports_waf_bypass=True）
            target: 扫描目标 URL
            session: SessionManager 实例
            original_result: 原 verify 的 ScanResult

        Returns:
            绕过后的 ScanResult（成功则 CONFIRMED，失败则原状态+标记）
        """
        # 铁律 1：CONFIRMED 不绕过
        if original_result.status == STATUS_CONFIRMED:
            return original_result

        # 获取漏洞类型
        vuln_type = getattr(plugin, 'vuln_type', '')
        if not vuln_type:
            return original_result  # 无漏洞类型，无法选择策略

        # 获取可用策略
        strategies = self.registry.get_strategies(self.waf_type, vuln_type)
        if not strategies:
            return original_result  # 无可用策略

        # D7.4: 使用成功率追踪器动态调整策略排序（成功率高的优先尝试）
        if self.stats_tracker:
            strategies = self.stats_tracker.get_sorted_strategies(strategies)

        # 最大尝试次数
        max_attempts = getattr(plugin, 'bypass_max_attempts', 3)
        attempts = min(max_attempts, len(strategies))

        # 尝试每个策略
        for i in range(attempts):
            strategy = strategies[i]
            ctx = BypassContext(
                waf_type=self.waf_type,
                vuln_type=vuln_type,
                original_payload='',  # 由插件 get_payloads 提供
                original_url=target,
                origin_ip=self.origin_ip,
                attempt=i + 1,
                max_attempts=attempts,
                strategy=strategy,  # 供插件调用 strategy.tamper_payload()
            )

            try:
                # 构建绕过会话
                transport = strategy.apply_transport(ctx)
                origin_url = None
                if transport.get('origin_ip') and transport['origin_ip']:
                    from lib.origin_finder import OriginIPFinder
                    finder = OriginIPFinder()
                    origin_url = finder.build_origin_url(target, transport['origin_ip'])
                bypass_session = BypassSession(session, transport, origin_url)

                # 调用插件的绕过验证
                result = plugin.verify_with_bypass(target, bypass_session, ctx)
                if result is None:
                    # D7.4: 记录失败
                    if self.stats_tracker:
                        self.stats_tracker.record_result(strategy.strategy_id, False)
                    continue

                # 绕过成功
                if result.status == STATUS_CONFIRMED:
                    # 标记绕过信息
                    if not result.extra:
                        result.extra = {}
                    result.extra['waf_bypass'] = {
                        'strategy_used': strategy.strategy_id,
                        'strategy_name': strategy.name,
                        'layer': strategy.layer,
                        'attempt': i + 1,
                        'waf_type': self.waf_type,
                    }
                    # D7.4: 记录成功
                    if self.stats_tracker:
                        self.stats_tracker.record_result(strategy.strategy_id, True)
                    return result

                # 绕过后仍非 CONFIRMED，尝试下一策略
                # D7.4: 记录失败
                if self.stats_tracker:
                    self.stats_tracker.record_result(strategy.strategy_id, False)
                continue

            except Exception:
                # 绕过异常，尝试下一策略（绝不降级为 SAFE）
                # D7.4: 记录失败
                if self.stats_tracker:
                    self.stats_tracker.record_result(strategy.strategy_id, False)
                continue

        # 所有策略均失败，返回原结果 + 标记
        if not original_result.extra:
            original_result.extra = {}
        original_result.extra['waf_bypass'] = {
            'bypass_attempted': True,
            'strategies_tried': attempts,
            'waf_type': self.waf_type,
            'bypass_success': False,
        }
        return original_result
