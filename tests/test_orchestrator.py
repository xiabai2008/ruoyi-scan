# D9.1 ScanOrchestrator 单元测试
#
# 验收目标：
#   1. ScanRequest/ScanTask 数据模型正确
#   2. run_sync 同步执行返回结果
#   3. submit 异步提交返回 task_id
#   4. 事件回调机制正确触发
#   5. CLI 行为兼容（通过 on_event 回调）
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, ScanResult
from core.orchestrator import ScanOrchestrator, ScanRequest, ScanTask
from tests.helpers import wait_for


@pytest.fixture(autouse=True)
def _mock_router():
    """自动 mock Router，避免真实插件加载与网络请求（所有测试共享）

    未 mock Router 时 router.resolve() 会返回 16 个真实 RuoYi 插件，
    对 http://example.com/ 发起真实 HTTP 请求，导致 CI D9 任务超时。
    """
    with patch('core.orchestrator.Router') as mock_router:
        mock_router.return_value.resolve.return_value = []
        mock_router.return_value.resolve_by_name.return_value = []
        yield mock_router


# === 数据模型测试 ===

def test_scan_request_defaults():
    """ScanRequest 默认值"""
    req = ScanRequest(target='http://example.com/')
    assert req.target == 'http://example.com/'
    assert req.mode == 'u'
    assert req.threads == 1
    assert req.rate == 0
    assert req.cms == ''
    assert req.bypass_waf == 'auto'
    assert req.plugins is None


def test_scan_request_full():
    """ScanRequest 完整参数"""
    req = ScanRequest(
        target='http://target:8080/',
        mode='p',
        cms='ruoyi',
        threads=5,
        rate=10,
        proxy='http://127.0.0.1:8080',
        timeout=15,
        debug=True,
        report_dir='reports',
        report_format='html,json',
        no_dedup=True,
        pass_level='top100',
        portscan=True,
        ports='80,443,8080',
        bypass_waf='on',
        plugins=['SQL注入-角色列表'],
        auth={'username': 'admin'},
    )
    assert req.mode == 'p'
    assert req.cms == 'ruoyi'
    assert req.threads == 5
    assert req.bypass_waf == 'on'
    assert req.plugins == ['SQL注入-角色列表']


def test_scan_task_to_dict():
    """ScanTask.to_dict 序列化"""
    req = ScanRequest(target='http://x.com/', mode='p')
    task = ScanTask(task_id='abc123', request=req, status='done')
    task.results = [
        ScanResult(kind='vuln', name='SQL注入', severity='high',
                   status=STATUS_CONFIRMED, url='http://x.com/', evidence='命中'),
    ]
    task.duration = 12.5
    task.request_count = 30

    d = task.to_dict()
    assert d['task_id'] == 'abc123'
    assert d['status'] == 'done'
    assert d['target'] == 'http://x.com/'
    assert d['mode'] == 'p'
    assert d['result_count'] == 1
    assert d['confirmed_count'] == 1
    assert d['duration'] == 12.5
    assert d['request_count'] == 30


def test_scan_task_to_dict_empty_results():
    """ScanTask.to_dict 空结果"""
    req = ScanRequest(target='http://x.com/')
    task = ScanTask(task_id='empty', request=req)
    d = task.to_dict()
    assert d['result_count'] == 0
    assert d['confirmed_count'] == 0
    assert d['fingerprint'] is None
    assert d['waf'] is None


# === Orchestrator 同步执行测试 ===

def test_run_sync_returns_results():
    """run_sync 同步执行返回结果列表"""
    orch = ScanOrchestrator()
    req = ScanRequest(target='http://example.com/', mode='p')

    # Mock detect_cms/detect_waf 避免真实网络请求
    with patch('core.orchestrator.detect_cms') as mock_cms, \
         patch('core.orchestrator.detect_waf') as mock_waf, \
         patch('core.orchestrator.load_plugins') as mock_load:
        mock_cms.return_value = MagicMock(cms='ruoyi', version='', confidence=0.9, matched=['test'])
        mock_waf.return_value = {'waf': '', 'display': '无', 'bypass_hint': ''}
        mock_load.return_value = []

        results = orch.run_sync(req)

    assert isinstance(results, list)


def test_run_sync_with_event_callback():
    """run_sync 事件回调正确触发"""
    orch = ScanOrchestrator()
    req = ScanRequest(target='http://example.com/', mode='p')
    events = []

    def on_event(event_type, payload):
        events.append((event_type, payload))

    with patch('core.orchestrator.detect_cms') as mock_cms, \
         patch('core.orchestrator.detect_waf') as mock_waf, \
         patch('core.orchestrator.load_plugins') as mock_load:
        mock_cms.return_value = MagicMock(cms='ruoyi', version='', confidence=0.9, matched=['test'])
        mock_waf.return_value = {'waf': '', 'display': '无', 'bypass_hint': ''}
        mock_load.return_value = []

        orch.run_sync(req, on_event=on_event)

    # 应至少触发 status(running)、fingerprint、waf、status(done)、complete 事件
    event_types = [e[0] for e in events]
    assert 'status' in event_types, '应触发 status 事件'
    assert 'fingerprint' in event_types, '应触发 fingerprint 事件'
    assert 'waf' in event_types, '应触发 waf 事件'
    assert 'complete' in event_types, '应触发 complete 事件'


def test_run_sync_status_running_first():
    """run_sync 首个事件为 status=running"""
    orch = ScanOrchestrator()
    req = ScanRequest(target='http://example.com/', mode='p')
    events = []

    def on_event(event_type, payload):
        events.append((event_type, payload))

    with patch('core.orchestrator.detect_cms') as mock_cms, \
         patch('core.orchestrator.detect_waf') as mock_waf, \
         patch('core.orchestrator.load_plugins') as mock_load:
        mock_cms.return_value = MagicMock(cms='', version='', confidence=0, matched=[])
        mock_waf.return_value = {'waf': '', 'display': '', 'bypass_hint': ''}
        mock_load.return_value = []

        orch.run_sync(req, on_event=on_event)

    # 第一个事件应是 status=running
    assert events[0][0] == 'status'
    assert events[0][1]['status'] == 'running'


def test_run_sync_complete_event_has_duration():
    """complete 事件含 duration 和结果计数"""
    orch = ScanOrchestrator()
    req = ScanRequest(target='http://example.com/', mode='p')
    complete_payload = None

    def on_event(event_type, payload):
        nonlocal complete_payload
        if event_type == 'complete':
            complete_payload = payload

    with patch('core.orchestrator.detect_cms') as mock_cms, \
         patch('core.orchestrator.detect_waf') as mock_waf, \
         patch('core.orchestrator.load_plugins') as mock_load:
        mock_cms.return_value = MagicMock(cms='', version='', confidence=0, matched=[])
        mock_waf.return_value = {'waf': '', 'display': '', 'bypass_hint': ''}
        mock_load.return_value = []

        orch.run_sync(req, on_event=on_event)

    assert complete_payload is not None
    assert 'duration' in complete_payload
    assert 'result_count' in complete_payload
    assert 'confirmed_count' in complete_payload
    assert complete_payload['duration'] >= 0


def test_run_sync_error_handling():
    """run_sync 异常时标记 failed 并推送 error 事件"""
    orch = ScanOrchestrator()
    req = ScanRequest(target='http://example.com/', mode='p')
    error_event = None
    status_events = []

    def on_event(event_type, payload):
        nonlocal error_event
        if event_type == 'error':
            error_event = payload
        if event_type == 'status':
            status_events.append(payload)

    with patch('core.orchestrator.detect_cms', side_effect=RuntimeError('模拟异常')):
        orch.run_sync(req, on_event=on_event)

    assert error_event is not None, '应触发 error 事件'
    assert '模拟异常' in error_event['error']
    # 最后一个 status 应为 failed
    assert status_events[-1]['status'] == 'failed'


# === Orchestrator 异步提交测试 ===

def test_submit_returns_task_id():
    """submit 返回 task_id"""
    registry = MagicMock()
    orch = ScanOrchestrator(registry=registry)
    try:
        req = ScanRequest(target='http://example.com/', mode='p')

        with patch('core.orchestrator.detect_cms') as mock_cms, \
             patch('core.orchestrator.detect_waf') as mock_waf, \
             patch('core.orchestrator.load_plugins') as mock_load:
            mock_cms.return_value = MagicMock(cms='', version='', confidence=0, matched=[])
            mock_waf.return_value = {'waf': '', 'display': '', 'bypass_hint': ''}
            mock_load.return_value = []

            task_id = orch.submit(req)

        assert isinstance(task_id, str)
        assert len(task_id) == 12
    finally:
        orch.shutdown()


def test_submit_registers_with_registry():
    """submit 向 registry 注册任务"""
    registry = MagicMock()
    orch = ScanOrchestrator(registry=registry)
    try:
        req = ScanRequest(target='http://example.com/', mode='p')

        with patch('core.orchestrator.detect_cms') as mock_cms, \
             patch('core.orchestrator.detect_waf') as mock_waf, \
             patch('core.orchestrator.load_plugins') as mock_load:
            mock_cms.return_value = MagicMock(cms='', version='', confidence=0, matched=[])
            mock_waf.return_value = {'waf': '', 'display': '', 'bypass_hint': ''}
            mock_load.return_value = []

            orch.submit(req)
            wait_for(lambda: registry.register.called, timeout=3)

        # 应调用 registry.register（task_id, task_dict）
        assert registry.register.called, '应调用 registry.register'
        call_args = registry.register.call_args
        # 第一个参数是 task_id（字符串）
        assert isinstance(call_args[0][0], str)
    finally:
        orch.shutdown()


def test_submit_notifies_pending_status():
    """submit 后立即推送 pending 状态"""
    registry = MagicMock()
    orch = ScanOrchestrator(registry=registry)
    try:
        req = ScanRequest(target='http://example.com/', mode='p')

        with patch('core.orchestrator.detect_cms') as mock_cms, \
             patch('core.orchestrator.detect_waf') as mock_waf, \
             patch('core.orchestrator.load_plugins') as mock_load:
            mock_cms.return_value = MagicMock(cms='', version='', confidence=0, matched=[])
            mock_waf.return_value = {'waf': '', 'display': '', 'bypass_hint': ''}
            mock_load.return_value = []

            orch.submit(req)
            wait_for(lambda: registry.notify.called, timeout=3)

        # 应至少调用 notify 一次（pending 状态）
        assert registry.notify.called, '应调用 registry.notify'
    finally:
        orch.shutdown()


# === 辅助方法测试 ===

def test_parse_formats_all():
    """_parse_formats 'all' 返回 'all'"""
    orch = ScanOrchestrator()
    assert orch._parse_formats('all') == 'all'


def test_parse_formats_list():
    """_parse_formats 解析格式列表"""
    orch = ScanOrchestrator()
    result = orch._parse_formats('html,json,csv')
    assert result == ['html', 'json', 'csv']


def test_parse_formats_invalid_filtered():
    """_parse_formats 过滤无效格式"""
    orch = ScanOrchestrator()
    result = orch._parse_formats('html,invalid,csv')
    assert result == ['html', 'csv']


def test_parse_formats_empty():
    """_parse_formats 空字符串返回 None"""
    orch = ScanOrchestrator()
    assert orch._parse_formats('') is None


def test_host_of():
    """_host_of 从 URL 提取主机名"""
    orch = ScanOrchestrator()
    assert orch._host_of('http://example.com/path') == 'example.com'
    assert orch._host_of('https://target:8080/') == 'target'
    assert orch._host_of('http://1.2.3.4/') == '1.2.3.4'


def test_parse_ports_default():
    """_parse_ports 空字符串返回默认"""
    orch = ScanOrchestrator()
    default = [80, 443]
    assert orch._parse_ports('', default) == default


def test_parse_ports_custom():
    """_parse_ports 自定义端口"""
    orch = ScanOrchestrator()
    result = orch._parse_ports('80,443,8080', [80])
    assert result == [80, 443, 8080]


def test_build_waf_bypass_no_waf():
    """_build_waf_bypass 无 WAF 返回 None"""
    orch = ScanOrchestrator()
    req = ScanRequest(target='http://x.com/', bypass_waf='auto')
    waf_result = {'waf': '', 'display': '', 'bypass_hint': ''}
    session = MagicMock()
    coord = orch._build_waf_bypass(req, waf_result, 'http://x.com/', session)
    assert coord is None


def test_build_waf_bypass_waf_detected():
    """_build_waf_bypass 检测到 WAF 返回协调器"""
    orch = ScanOrchestrator()
    req = ScanRequest(target='http://x.com/', bypass_waf='auto')
    waf_result = {'waf': 'cloudflare', 'display': 'Cloudflare', 'bypass_hint': ''}
    session = MagicMock()
    coord = orch._build_waf_bypass(req, waf_result, 'http://x.com/', session)
    assert coord is not None


def test_build_waf_bypass_force_on():
    """_build_waf_bypass bypass_waf=on 无 WAF 也启用"""
    orch = ScanOrchestrator()
    req = ScanRequest(target='http://x.com/', bypass_waf='on')
    waf_result = {'waf': '', 'display': '', 'bypass_hint': ''}
    session = MagicMock()
    coord = orch._build_waf_bypass(req, waf_result, 'http://x.com/', session)
    assert coord is not None


# === shutdown 测试 ===

def test_shutdown_closes_pool():
    """shutdown 关闭线程池"""
    orch = ScanOrchestrator()
    try:
        # 触发懒加载
        with patch('core.orchestrator.detect_cms') as mock_cms, \
             patch('core.orchestrator.detect_waf') as mock_waf, \
             patch('core.orchestrator.load_plugins') as mock_load:
            mock_cms.return_value = MagicMock(cms='', version='', confidence=0, matched=[])
            mock_waf.return_value = {'waf': '', 'display': '', 'bypass_hint': ''}
            mock_load.return_value = []
            req = ScanRequest(target='http://x.com/', mode='p')
            orch.submit(req)
            # 等待线程池被创建（submit 会懒加载 _pool）
            wait_for(lambda: orch._pool is not None, timeout=3)
    finally:
        orch.shutdown()
    assert orch._pool is None


if __name__ == '__main__':
    test_scan_request_defaults()
    test_scan_request_full()
    test_scan_task_to_dict()
    test_scan_task_to_dict_empty_results()
    test_run_sync_returns_results()
    test_run_sync_with_event_callback()
    test_run_sync_status_running_first()
    test_run_sync_complete_event_has_duration()
    test_run_sync_error_handling()
    test_submit_returns_task_id()
    test_submit_registers_with_registry()
    test_submit_notifies_pending_status()
    test_parse_formats_all()
    test_parse_formats_list()
    test_parse_formats_invalid_filtered()
    test_parse_formats_empty()
    test_host_of()
    test_parse_ports_default()
    test_parse_ports_custom()
    test_build_waf_bypass_no_waf()
    test_build_waf_bypass_waf_detected()
    test_build_waf_bypass_force_on()
    test_shutdown_closes_pool()
    print('All D9.1 orchestrator tests passed!')
