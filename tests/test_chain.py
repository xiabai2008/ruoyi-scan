# D6.1 漏洞利用链编排器单元测试
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from common.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, FingerprintResult, ScanResult
from core.chain import (
    CHAIN_BLOCKED,
    CHAIN_CONFIRMED,
    CHAIN_PARTIAL,
    NODE_AMBIGUOUS,
    NODE_ERROR,
    NODE_FAILED,
    NODE_SKIPPED,
    NODE_SUCCESS,
    ON_FAIL_ABORT,
    ON_FAIL_CONTINUE,
    ON_FAIL_FALLBACK,
    ChainContext,
    ChainDef,
    ChainEdge,
    ChainEngine,
    ChainStep,
)
from plugins.base import PluginBase

# === 测试用 Mock 插件 ===

class MockConfirmedPlugin(PluginBase):
    """总是返回 CONFIRMED 的 mock 插件"""
    name = 'Mock CONFIRMED'
    severity = 'high'
    category = 'vuln'
    description = '测试用'
    fix = '测试修复'

    def verify(self, target, session):
        return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                          status=STATUS_CONFIRMED, url=target,
                          evidence='mock confirmed', fix=self.fix)


class MockSafePlugin(PluginBase):
    """总是返回 SAFE 的 mock 插件"""
    name = 'Mock SAFE'
    severity = 'medium'
    category = 'vuln'

    def verify(self, target, session):
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE,
                          url=target, evidence='mock safe')


class MockUnknownPlugin(PluginBase):
    """总是返回 UNKNOWN 的 mock 插件"""
    name = 'Mock UNKNOWN'
    severity = 'low'
    category = 'vuln'

    def verify(self, target, session):
        return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                          url=target, evidence='mock unknown')


class MockErrorPlugin(PluginBase):
    """verify 抛异常的 mock 插件"""
    name = 'Mock ERROR'
    severity = 'high'
    category = 'vuln'

    def verify(self, target, session):
        raise RuntimeError('mock error')


class MockExtractPlugin(PluginBase):
    """从 extra 中提取数据的 mock 插件"""
    name = 'Mock Extract'
    severity = 'high'
    category = 'vuln'

    def verify(self, target, session):
        return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                          status=STATUS_CONFIRMED, url=target,
                          evidence='db_name=ry',
                          extra={'db_name': 'ry', 'db_password': 'root123'})


# === 辅助函数 ===

def _make_chain(steps, edges=None):
    """构造测试用链定义"""
    return ChainDef(
        name='test_chain',
        display_name='测试链',
        description='测试用链',
        severity=SEVERITY_HIGH,
        steps=steps,
        edges=edges or [],
    )


def _run_chain(chain_def, on_unknown='fail'):
    """执行测试链"""
    engine = ChainEngine(on_unknown=on_unknown)
    fp = FingerprintResult(cms='ruoyi', confidence=0.9)
    return engine.run(chain_def, 'http://target/', session=None, fp_result=fp)


# === 链定义校验测试 ===

def test_chain_def_validate_no_cycle():
    """无环链定义校验通过"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin, depends_on=[]),
        ChainStep(id='b', plugin_cls=MockConfirmedPlugin, depends_on=['a']),
        ChainStep(id='c', plugin_cls=MockConfirmedPlugin, depends_on=['b']),
    ])
    errors = chain.validate()
    assert errors == [], f'无环链应校验通过，错误: {errors}'


def test_chain_def_validate_cycle_detected():
    """有环链定义校验失败"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin, depends_on=['c']),
        ChainStep(id='b', plugin_cls=MockConfirmedPlugin, depends_on=['a']),
        ChainStep(id='c', plugin_cls=MockConfirmedPlugin, depends_on=['b']),
    ])
    errors = chain.validate()
    assert len(errors) > 0, '有环链应检测到循环依赖'
    assert '循环依赖' in errors[0] or '重复' in errors[0]


def test_chain_def_validate_unique_ids():
    """节点 id 重复校验失败"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin),
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin),
    ])
    errors = chain.validate()
    assert any('重复' in e for e in errors), '应检测到 id 重复'


def test_chain_def_validate_missing_dependency():
    """依赖不存在的节点校验失败"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin, depends_on=['nonexistent']),
    ])
    errors = chain.validate()
    assert any('不存在' in e for e in errors), '应检测到依赖不存在'


# === 拓扑排序测试 ===

def test_topological_sort_linear():
    """线性链拓扑排序正确"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin, depends_on=[]),
        ChainStep(id='b', plugin_cls=MockConfirmedPlugin, depends_on=['a']),
        ChainStep(id='c', plugin_cls=MockConfirmedPlugin, depends_on=['b']),
    ])
    engine = ChainEngine()
    order = engine._topological_sort(chain)
    assert order == ['a', 'b', 'c'], f'线性链顺序应为 a→b→c，实际 {order}'


def test_topological_sort_parallel():
    """并行分支拓扑排序正确"""
    chain = _make_chain([
        ChainStep(id='root', plugin_cls=MockConfirmedPlugin, depends_on=[]),
        ChainStep(id='branch_a', plugin_cls=MockConfirmedPlugin, depends_on=['root']),
        ChainStep(id='branch_b', plugin_cls=MockConfirmedPlugin, depends_on=['root']),
        ChainStep(id='merge', plugin_cls=MockConfirmedPlugin,
                  depends_on=['branch_a', 'branch_b']),
    ])
    engine = ChainEngine()
    order = engine._topological_sort(chain)
    assert order[0] == 'root', 'root 应在最前'
    assert order[-1] == 'merge', 'merge 应在最后'
    assert set(order[1:3]) == {'branch_a', 'branch_b'}, '分支节点应在中间'


# === 条件分支测试 ===

def test_condition_skipped():
    """condition 不满足时节点被跳过"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin),
        ChainStep(id='b', plugin_cls=MockConfirmedPlugin,
                  condition=lambda ctx: False),  # 永远 False
    ])
    result = _run_chain(chain)
    assert result.node_status['b'] == NODE_SKIPPED, 'b 应被跳过'


def test_condition_eval_exception():
    """condition 异常默认返回 False（跳过）"""
    def bad_condition(ctx):
        return ctx.nonexistent.key  # AttributeError

    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin,
                  condition=bad_condition),
    ])
    result = _run_chain(chain)
    assert result.node_status['a'] == NODE_SKIPPED, 'condition 异常应跳过'


# === 失败策略测试 ===

def test_failure_abort_propagation():
    """abort 策略：节点失败则下游全跳过"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockSafePlugin, on_fail=ON_FAIL_ABORT),
        ChainStep(id='b', plugin_cls=MockConfirmedPlugin, depends_on=['a']),
        ChainStep(id='c', plugin_cls=MockConfirmedPlugin, depends_on=['b']),
    ])
    result = _run_chain(chain)
    assert result.node_status['a'] == NODE_FAILED
    assert result.node_status['b'] == NODE_SKIPPED, 'b 应被 abort 跳过'
    assert result.node_status['c'] == NODE_SKIPPED, 'c 应被 abort 跳过'


def test_failure_continue_propagation():
    """continue 策略：节点失败但下游继续执行"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockSafePlugin, on_fail=ON_FAIL_CONTINUE),
        ChainStep(id='b', plugin_cls=MockConfirmedPlugin, depends_on=['a']),
    ])
    result = _run_chain(chain)
    assert result.node_status['a'] == NODE_FAILED
    assert result.node_status['b'] == NODE_SUCCESS, 'b 应继续执行'


def test_failure_fallback():
    """fallback 策略：节点失败时执行 fallback 节点"""
    chain = _make_chain([
        ChainStep(id='main', plugin_cls=MockSafePlugin,
                  on_fail=ON_FAIL_FALLBACK, fallback_steps=['backup']),
        ChainStep(id='backup', plugin_cls=MockConfirmedPlugin),
    ])
    result = _run_chain(chain)
    assert result.node_status['main'] == NODE_FAILED
    assert result.node_status['backup'] == NODE_SUCCESS, 'backup 应执行'


# === 上下文与输出提取测试 ===

def test_context_fact_extraction():
    """outputs 映射正确提取到 facts"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockExtractPlugin,
                  outputs={'db_name': 'extra:db_name',
                           'db_url': 'field:url'}),
    ])
    result = _run_chain(chain)
    assert result.facts.get('db_name') == 'ry', '应提取 db_name=ry'
    assert result.facts.get('db_url') == 'http://target/', '应提取 url'


def test_context_secret_masking():
    """secrets 在 snapshot 中脱敏"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockExtractPlugin,
                  outputs={'db_password': 'secret:db_password'}),
    ])
    engine = ChainEngine()
    fp = FingerprintResult()
    ctx = ChainContext('http://target/', None, fp)
    step = chain.steps[0]
    scan_result = MockExtractPlugin().verify('http://target/', None)
    ctx.set_result('a', scan_result, NODE_SUCCESS)
    ctx.extract_outputs('a', step, scan_result)
    snap = ctx.snapshot()
    assert snap['secrets']['db_password'] == '******', 'secrets 应脱敏'


# === 链整体状态测试 ===

def test_chain_status_confirmed():
    """所有节点成功 → CONFIRMED"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin),
        ChainStep(id='b', plugin_cls=MockConfirmedPlugin, depends_on=['a']),
    ])
    result = _run_chain(chain)
    assert result.status == CHAIN_CONFIRMED, f'全成功应为 CONFIRMED，实际 {result.status}'


def test_chain_status_partial():
    """部分成功部分失败 → PARTIAL"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin, on_fail=ON_FAIL_CONTINUE),
        ChainStep(id='b', plugin_cls=MockSafePlugin, on_fail=ON_FAIL_CONTINUE),
    ])
    result = _run_chain(chain)
    assert result.status == CHAIN_PARTIAL, f'部分成功应为 PARTIAL，实际 {result.status}'


def test_chain_status_blocked():
    """关键节点 abort 失败 → BLOCKED"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockSafePlugin, on_fail=ON_FAIL_ABORT),
        ChainStep(id='b', plugin_cls=MockConfirmedPlugin, depends_on=['a']),
    ])
    result = _run_chain(chain)
    assert result.status == CHAIN_BLOCKED, f'abort 失败应为 BLOCKED，实际 {result.status}'


def test_unknown_status_default_fail():
    """UNKNOWN 默认按 fail 处理"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockUnknownPlugin, on_fail=ON_FAIL_ABORT),
        ChainStep(id='b', plugin_cls=MockConfirmedPlugin, depends_on=['a']),
    ])
    result = _run_chain(chain)
    # on_unknown='fail'（默认），a 的 ambiguous 按 failed 处理 → abort 传播
    assert result.node_status['a'] == NODE_AMBIGUOUS
    assert result.node_status['b'] == NODE_SKIPPED, 'b 应被跳过（UNKNOWN 按 fail 处理）'
    assert result.status == CHAIN_BLOCKED


def test_to_scan_result_kind_chain():
    """链结果转换为 ScanResult（kind='chain'）"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockConfirmedPlugin),
    ])
    result = _run_chain(chain)
    scan_result = result.to_scan_result(chain)
    assert scan_result.kind == 'chain', 'kind 应为 chain'
    assert scan_result.status == STATUS_CONFIRMED, '链 CONFIRMED → ScanResult CONFIRMED'
    assert 'chain_name' in scan_result.extra
    assert scan_result.extra['success_count'] == 1


def test_chain_error_plugin():
    """插件异常处理为 NODE_ERROR"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockErrorPlugin, on_fail=ON_FAIL_ABORT),
    ])
    result = _run_chain(chain)
    assert result.node_status['a'] == NODE_ERROR, '异常插件应为 NODE_ERROR'
    assert result.status == CHAIN_BLOCKED


def test_chain_edges_explicit():
    """显式 edges 声明依赖"""
    chain = _make_chain(
        steps=[
            ChainStep(id='a', plugin_cls=MockConfirmedPlugin),
            ChainStep(id='b', plugin_cls=MockConfirmedPlugin),
        ],
        edges=[ChainEdge(from_id='a', to_id='b')],
    )
    engine = ChainEngine()
    order = engine._topological_sort(chain)
    assert order == ['a', 'b'], f'显式边应影响排序，实际 {order}'


def test_chain_result_to_scan_result_blocked():
    """BLOCKED 链 → ScanResult SAFE"""
    chain = _make_chain([
        ChainStep(id='a', plugin_cls=MockSafePlugin, on_fail=ON_FAIL_ABORT),
    ])
    result = _run_chain(chain)
    scan_result = result.to_scan_result(chain)
    assert scan_result.status == STATUS_SAFE, 'BLOCKED → SAFE'


# === P2 新增：拓扑排序正确性 + 超时控制 + 真实链定义验证 ===

def test_topological_sort_real_chain_sql_to_rce():
    from chains.ruoyi_sql_to_rce import CHAIN
    engine = ChainEngine()
    order = engine._topological_sort(CHAIN)
    sql_step = next((s.id for s in CHAIN.steps if 'sql' in s.id.lower()), None)
    if sql_step:
        assert order.index(sql_step) < len(order) - 1, f'{sql_step} 不应排最后'
    assert CHAIN.validate() == [], f'链定义校验失败: {CHAIN.validate()}'
    assert len(order) == len(CHAIN.steps), f'排序后节点数={len(order)} != 定义节点数={len(CHAIN.steps)}'


def test_topological_sort_real_chain_defaultpw():
    from chains.ruoyi_defaultpw_to_webshell import CHAIN
    engine = ChainEngine()
    order = engine._topological_sort(CHAIN)
    login_steps = [s.id for s in CHAIN.steps if 'login' in s.id.lower() or 'password' in s.id.lower()]
    upload_steps = [s.id for s in CHAIN.steps if 'upload' in s.id.lower()]
    if login_steps and upload_steps:
        max_login_idx = max(order.index(s) for s in login_steps if s in order)
        min_upload_idx = min(order.index(s) for s in upload_steps if s in order)
        assert max_login_idx < min_upload_idx, '登录节点必须在上传节点之前执行'
    assert CHAIN.validate() == [], f'链定义校验失败: {CHAIN.validate()}'


def test_topological_sort_real_chain_nacos():
    from chains.ruoyi_nacos_to_dbcreds import CHAIN
    engine = ChainEngine()
    order = engine._topological_sort(CHAIN)
    assert CHAIN.validate() == [], f'链定义校验失败: {CHAIN.validate()}'
    assert len(order) == len(CHAIN.steps)


def test_all_chains_no_cycles():
    from chains.registry import get_chain, list_chains
    for c in list_chains():
        chain_def = get_chain(c['name'])
        assert chain_def is not None, f'链 {c["name"]} 获取失败'
        errors = chain_def.validate()
        assert errors == [], f'链 {c["name"]} 校验失败: {errors}'


def test_chain_step_timeout_configurable():
    engine_default = ChainEngine()
    assert engine_default.step_timeout == 30.0, f'默认超时应为 30s, 实际 {engine_default.step_timeout}'
    engine_custom = ChainEngine(step_timeout=5.0)
    assert engine_custom.step_timeout == 5.0
    engine_unlimited = ChainEngine(step_timeout=0)
    assert engine_unlimited.step_timeout == 0


def test_chain_node_timeout_constant():
    from core.chain import NODE_TIMEOUT
    assert NODE_TIMEOUT == 'timeout'


class MockSlowPlugin(PluginBase):
    name = 'Mock Slow'
    severity = 'medium'
    category = 'vuln'
    def verify(self, target, session):
        import time
        time.sleep(2.0)
        return ScanResult(kind='vuln', name=self.name, status=STATUS_CONFIRMED, url=target, evidence='should not reach')


def test_chain_step_timeout_triggers():
    chain = _make_chain([
        ChainStep(id='slow', plugin_cls=MockSlowPlugin, on_fail=ON_FAIL_CONTINUE),
    ])
    engine = ChainEngine(step_timeout=1.0)
    session = {}
    result = engine.run(chain, 'http://test/', session)
    assert result.node_status['slow'] == 'timeout', f'应返回 timeout, 实际 {result.node_status["slow"]}'


if __name__ == '__main__':
    test_chain_def_validate_no_cycle()
    test_chain_def_validate_cycle_detected()
    test_chain_def_validate_unique_ids()
    test_chain_def_validate_missing_dependency()
    test_topological_sort_linear()
    test_topological_sort_parallel()
    test_condition_skipped()
    test_condition_eval_exception()
    test_failure_abort_propagation()
    test_failure_continue_propagation()
    test_failure_fallback()
    test_context_fact_extraction()
    test_context_secret_masking()
    test_chain_status_confirmed()
    test_chain_status_partial()
    test_chain_status_blocked()
    test_unknown_status_default_fail()
    test_to_scan_result_kind_chain()
    test_chain_error_plugin()
    test_chain_edges_explicit()
    test_chain_result_to_scan_result_blocked()
    print('All D6.1 chain orchestrator tests passed!')
