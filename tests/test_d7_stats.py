# D7.4 策略成功率追踪 + 性能优化测试
#
# 验收目标：
#   1. BypassStatsTracker 记录策略成功/失败
#   2. 动态调整策略优先级（成功率高的更早尝试）
#   3. Coordinator 集成追踪器，统计可审计
#   4. 报告徽标渲染 WAF 绕过信息
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from plugins.base import PluginBase
from lib.waf_bypass import (BypassStatsTracker, WafBypassCoordinator,
                            StrategyRegistry, BypassContext)


# === BypassStatsTracker 单元测试 ===

def test_stats_tracker_initial_empty():
    """初始化时无统计"""
    tracker = BypassStatsTracker()
    assert tracker.get_stats() == {}
    assert tracker.get_success_rate('BP-TEST') == -1.0


def test_stats_tracker_record_success():
    """记录成功"""
    tracker = BypassStatsTracker()
    tracker.record_result('BP-CF-2', True)
    assert tracker.get_success_rate('BP-CF-2') == 1.0
    stats = tracker.get_stats()
    assert stats['BP-CF-2']['success'] == 1
    assert stats['BP-CF-2']['failure'] == 0


def test_stats_tracker_record_failure():
    """记录失败"""
    tracker = BypassStatsTracker()
    tracker.record_result('BP-GEN-1', False)
    assert tracker.get_success_rate('BP-GEN-1') == 0.0
    stats = tracker.get_stats()
    assert stats['BP-GEN-1']['success'] == 0
    assert stats['BP-GEN-1']['failure'] == 1


def test_stats_tracker_mixed_results():
    """混合结果：3 成功 1 失败 → 75% 成功率"""
    tracker = BypassStatsTracker()
    tracker.record_result('BP-SD-1', True)
    tracker.record_result('BP-SD-1', True)
    tracker.record_result('BP-SD-1', True)
    tracker.record_result('BP-SD-1', False)
    assert tracker.get_success_rate('BP-SD-1') == 0.75


def test_stats_tracker_adjusted_priority_no_record():
    """无记录时保持原始 priority"""
    tracker = BypassStatsTracker()
    assert tracker.get_adjusted_priority('BP-NEW', 30) == 30


def test_stats_tracker_adjusted_priority_high_success():
    """高成功率 → priority 不变（penalty=0）"""
    tracker = BypassStatsTracker()
    tracker.record_result('BP-GOOD', True)
    tracker.record_result('BP-GOOD', True)
    # 成功率 1.0 → penalty=0 → priority 不变
    assert tracker.get_adjusted_priority('BP-GOOD', 20) == 20


def test_stats_tracker_adjusted_priority_low_success():
    """低成功率 → priority 升高（penalty 大）"""
    tracker = BypassStatsTracker()
    tracker.record_result('BP-BAD', False)
    tracker.record_result('BP-BAD', False)
    tracker.record_result('BP-BAD', False)
    tracker.record_result('BP-BAD', False)
    # 成功率 0.0 → penalty=20 → priority=30+20=50
    assert tracker.get_adjusted_priority('BP-BAD', 30) == 50


def test_stats_tracker_adjusted_priority_half_success():
    """50% 成功率 → penalty=10"""
    tracker = BypassStatsTracker(penalty_factor=20)
    tracker.record_result('BP-MID', True)
    tracker.record_result('BP-MID', False)
    # 成功率 0.5 → penalty=10 → priority=25+10=35
    assert tracker.get_adjusted_priority('BP-MID', 25) == 35


def test_stats_tracker_sorted_strategies():
    """按调整后 priority 排序策略"""
    tracker = BypassStatsTracker(penalty_factor=50)

    # 模拟策略列表
    class MockStrategy:
        def __init__(self, sid, priority):
            self.strategy_id = sid
            self.priority = priority

    strategies = [
        MockStrategy('BP-A', 20),  # 原始 priority 20
        MockStrategy('BP-B', 10),  # 原始 priority 10
        MockStrategy('BP-C', 30),  # 原始 priority 30
    ]

    # BP-A 全失败 → priority 升高
    tracker.record_result('BP-A', False)
    tracker.record_result('BP-A', False)
    # BP-B 全成功 → priority 不变
    tracker.record_result('BP-B', True)

    sorted_list = tracker.get_sorted_strategies(strategies)
    ids = [s.strategy_id for s in sorted_list]
    # BP-B (10) < BP-C (30) < BP-A (20+50=70)
    assert ids == ['BP-B', 'BP-C', 'BP-A']


def test_stats_tracker_summary():
    """统计摘要可读"""
    tracker = BypassStatsTracker()
    tracker.record_result('BP-1', True)
    tracker.record_result('BP-1', False)
    tracker.record_result('BP-2', True)
    tracker.record_result('BP-2', True)

    summary = tracker.summary()
    assert 'BP-1' in summary
    assert 'BP-2' in summary
    assert '50%' in summary  # BP-1: 1/2 = 50%
    assert '100%' in summary  # BP-2: 2/2 = 100%


def test_stats_tracker_get_stats_returns_copy():
    """get_stats 返回副本（修改不影响内部状态）"""
    tracker = BypassStatsTracker()
    tracker.record_result('BP-1', True)
    stats = tracker.get_stats()
    stats['BP-1']['success'] = 999  # 修改副本
    # 内部状态不受影响
    assert tracker.get_stats()['BP-1']['success'] == 1


# === Coordinator + StatsTracker 集成测试 ===

class MockBypassSession:
    """Mock BypassSession"""
    def __init__(self):
        self.request_count = 0
    def get(self, url, **kwargs):
        self.request_count += 1
        return MagicMock(text='', status_code=200, headers={})
    def post(self, url, **kwargs):
        self.request_count += 1
        return MagicMock(text='', status_code=200, headers={})
    def request(self, method, url, **kwargs):
        self.request_count += 1
        return MagicMock(text='', status_code=200, headers={})
    def close(self):
        pass


class SuccessOnSecondStrategyPlugin(PluginBase):
    """第二次策略绕过成功的插件"""
    name = '策略成功率测试'
    vuln_type = 'sqli'
    supports_waf_bypass = True
    bypass_max_attempts = 3
    _call_count = 0

    def verify(self, target, session):
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                          url=target, evidence='safe')

    def verify_with_bypass(self, target, bypass_session, bypass_ctx):
        self._call_count += 1
        if self._call_count >= 2:
            return ScanResult(kind='vuln', name=self.name, severity='high',
                              status=STATUS_CONFIRMED, url=target,
                              evidence='第二次成功')
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                          url=target, evidence='失败')


def test_coordinator_with_stats_tracker_records_success():
    """Coordinator + StatsTracker 记录成功"""
    tracker = BypassStatsTracker()
    coord = WafBypassCoordinator(waf_type='cloudflare', stats_tracker=tracker)
    session = MockBypassSession()
    plugin = SuccessOnSecondStrategyPlugin()

    original = plugin.verify('http://x.com/', session)
    result = coord.maybe_bypass(plugin, 'http://x.com/', session, original)

    assert result.status == STATUS_CONFIRMED
    stats = tracker.get_stats()
    # 至少有 1 个成功记录和 1 个失败记录
    total_success = sum(s['success'] for s in stats.values())
    total_failure = sum(s['failure'] for s in stats.values())
    assert total_success >= 1, '应有至少 1 个成功记录'
    assert total_failure >= 1, '应有至少 1 个失败记录（第一次尝试）'


def test_coordinator_without_stats_tracker_works():
    """无 StatsTracker 时 Coordinator 正常工作（向后兼容）"""
    coord = WafBypassCoordinator(waf_type='cloudflare')  # stats_tracker=None
    session = MockBypassSession()

    class SimplePlugin(PluginBase):
        name = '简单测试'
        vuln_type = 'sqli'
        supports_waf_bypass = True
        def verify(self, target, session):
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=target, evidence='safe')
        def verify_with_bypass(self, target, bypass_session, bypass_ctx):
            return ScanResult(kind='vuln', name=self.name, severity='high',
                              status=STATUS_CONFIRMED, url=target, evidence='成功')

    plugin = SimplePlugin()
    original = plugin.verify('http://x.com/', session)
    result = coord.maybe_bypass(plugin, 'http://x.com/', session, original)
    assert result.status == STATUS_CONFIRMED


def test_stats_tracker_dynamic_priority_adjustment():
    """动态优先级调整：低成功率策略被排到后面"""
    tracker = BypassStatsTracker(penalty_factor=50)

    # 模拟 BP-GEN-1 全失败，BP-CF-2 全成功
    for _ in range(5):
        tracker.record_result('BP-GEN-1', False)
        tracker.record_result('BP-CF-2', True)

    # 获取 cloudflare sqli 策略列表
    reg = StrategyRegistry()
    strategies = reg.get_strategies('cloudflare', 'sqli')

    # 原始排序
    original_order = [s.strategy_id for s in strategies]

    # 调整后排序
    adjusted = tracker.get_sorted_strategies(strategies)
    adjusted_order = [s.strategy_id for s in adjusted]

    # BP-CF-2 在调整后应更靠前（成功率高）
    cf2_orig_idx = original_order.index('BP-CF-2') if 'BP-CF-2' in original_order else -1
    cf2_adj_idx = adjusted_order.index('BP-CF-2') if 'BP-CF-2' in adjusted_order else -1
    if cf2_orig_idx >= 0 and cf2_adj_idx >= 0:
        assert cf2_adj_idx <= cf2_orig_idx, '高成功率策略应更靠前'

    # BP-GEN-1 在调整后应更靠后（成功率低）
    gen1_orig_idx = original_order.index('BP-GEN-1') if 'BP-GEN-1' in original_order else -1
    gen1_adj_idx = adjusted_order.index('BP-GEN-1') if 'BP-GEN-1' in adjusted_order else -1
    if gen1_orig_idx >= 0 and gen1_adj_idx >= 0:
        assert gen1_adj_idx >= gen1_orig_idx, '低成功率策略应更靠后'


def test_stats_tracker_multiple_waf_types():
    """多 WAF 类型统计独立"""
    tracker = BypassStatsTracker()

    # 模拟 cloudflare 场景下 BP-CF-2 成功
    tracker.record_result('BP-CF-2', True)
    # 模拟 safedog 场景下 BP-SD-1 失败
    tracker.record_result('BP-SD-1', False)

    stats = tracker.get_stats()
    assert 'BP-CF-2' in stats
    assert 'BP-SD-1' in stats
    assert stats['BP-CF-2']['success'] == 1
    assert stats['BP-SD-1']['failure'] == 1


# === 报告徽标渲染测试 ===

def test_report_renders_bypass_success_badge():
    """HTML 报告渲染绕过成功徽标"""
    from core.report import ReportBuilder

    result = ScanResult(
        kind='vuln', name='SQL注入', severity='high',
        status=STATUS_CONFIRMED, url='http://x.com/vuln',
        evidence='报错注入命中',
        extra={'waf_bypass': {
            'strategy_used': 'BP-CF-2',
            'strategy_name': 'Googlebot 伪装',
            'layer': 'L3',
            'attempt': 1,
            'waf_type': 'cloudflare',
        }},
        fix='参数化查询',
    )

    builder = ReportBuilder(results=[result], target='http://x.com/', dedup=False)
    html = builder.to_html()

    assert 'WAF绕过:BP-CF-2' in html, '应含绕过成功徽标'
    assert 'Googlebot' in html or 'Googlebot' in html, '应含策略名称（title 属性）'


def test_report_renders_bypass_failed_badge():
    """HTML 报告渲染绕过失败徽标"""
    from core.report import ReportBuilder

    result = ScanResult(
        kind='vuln', name='SQL注入', severity='high',
        status=STATUS_SAFE, url='http://x.com/vuln',
        evidence='未命中',
        extra={'waf_bypass': {
            'bypass_attempted': True,
            'strategies_tried': 3,
            'waf_type': 'cloudflare',
            'bypass_success': False,
        }},
        fix='参数化查询',
    )

    builder = ReportBuilder(results=[result], target='http://x.com/', dedup=False)
    html = builder.to_html()

    assert 'WAF绕过失败' in html, '应含绕过失败徽标'


def test_report_no_badge_without_bypass_info():
    """无绕过信息时不渲染徽标"""
    from core.report import ReportBuilder

    result = ScanResult(
        kind='vuln', name='SQL注入', severity='high',
        status=STATUS_CONFIRMED, url='http://x.com/vuln',
        evidence='直接命中',
        extra={},
        fix='参数化查询',
    )

    builder = ReportBuilder(results=[result], target='http://x.com/', dedup=False)
    html = builder.to_html()

    assert 'WAF绕过' not in html, '无绕过信息时不应有徽标'


if __name__ == '__main__':
    test_stats_tracker_initial_empty()
    test_stats_tracker_record_success()
    test_stats_tracker_record_failure()
    test_stats_tracker_mixed_results()
    test_stats_tracker_adjusted_priority_no_record()
    test_stats_tracker_adjusted_priority_high_success()
    test_stats_tracker_adjusted_priority_low_success()
    test_stats_tracker_adjusted_priority_half_success()
    test_stats_tracker_sorted_strategies()
    test_stats_tracker_summary()
    test_stats_tracker_get_stats_returns_copy()
    test_coordinator_with_stats_tracker_records_success()
    test_coordinator_without_stats_tracker_works()
    test_stats_tracker_dynamic_priority_adjustment()
    test_stats_tracker_multiple_waf_types()
    test_report_renders_bypass_success_badge()
    test_report_renders_bypass_failed_badge()
    test_report_no_badge_without_bypass_info()
    print('All D7.4 stats tracker and optimization tests passed!')
