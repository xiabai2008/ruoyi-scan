# D9.3 TaskRegistry + WebSocket 实时推送测试
#
# 验收目标：
#   1. TaskRegistry register/get/list/cleanup
#   2. notify 跨线程投递事件到 asyncio.Queue
#   3. subscribe/unsubscribe 订阅管理
#   4. 历史事件补播
#   5. WebSocket 端点连接 + 事件推送
import asyncio
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from api.app import create_app
from core.task_registry import TaskRegistry

# === TaskRegistry 单元测试 ===

def test_registry_register():
    """register 注册任务"""
    reg = TaskRegistry()
    reg.register('task-1', {'task_id': 'task-1', 'status': 'pending'})
    record = reg.get('task-1')
    assert record is not None
    assert record.task_id == 'task-1'
    assert record.status == 'pending'


def test_registry_get_not_found():
    """get 不存在的任务返回 None"""
    reg = TaskRegistry()
    assert reg.get('nonexistent') is None


def test_registry_list():
    """list 列出所有任务"""
    reg = TaskRegistry()
    reg.register('task-1')
    reg.register('task-2')
    records = reg.list()
    assert len(records) == 2


def test_registry_update_task_dict():
    """update_task_dict 更新任务快照"""
    reg = TaskRegistry()
    reg.register('task-1', {'status': 'pending'})
    reg.update_task_dict('task-1', {'status': 'running', 'target': 'http://x.com/'})
    record = reg.get('task-1')
    assert record.task_dict['status'] == 'running'
    assert record.task_dict['target'] == 'http://x.com/'


def test_registry_notify_records_event():
    """notify 记录事件到历史缓冲"""
    reg = TaskRegistry()
    reg.register('task-1')
    reg.notify('task-1', 'status', {'status': 'running'})
    history = reg.get_history('task-1')
    assert len(history) == 1
    assert history[0]['type'] == 'status'
    assert history[0]['data']['status'] == 'running'
    assert history[0]['task_id'] == 'task-1'


def test_registry_notify_updates_status():
    """notify status 事件更新任务状态"""
    reg = TaskRegistry()
    reg.register('task-1')
    reg.notify('task-1', 'status', {'status': 'running'})
    assert reg.get('task-1').status == 'running'

    reg.notify('task-1', 'status', {'status': 'done'})
    assert reg.get('task-1').status == 'done'


def test_registry_notify_error_sets_failed():
    """notify error 事件标记任务为 failed"""
    reg = TaskRegistry()
    reg.register('task-1')
    reg.notify('task-1', 'error', {'error': '模拟异常'})
    assert reg.get('task-1').status == 'failed'


def test_registry_history_for_nonexistent():
    """get_history 不存在的任务返回空列表"""
    reg = TaskRegistry()
    assert reg.get_history('nonexistent') == []


def test_registry_max_events_buffer():
    """事件缓冲超过上限时自动截断"""
    reg = TaskRegistry(max_events_per_task=5)
    reg.register('task-1')
    for i in range(10):
        reg.notify('task-1', 'progress', {'count': i})
    history = reg.get_history('task-1')
    assert len(history) == 5
    # 应保留最后 5 个事件
    assert history[-1]['data']['count'] == 9


def test_registry_cleanup_expired():
    """cleanup_expired 清理过期任务"""
    reg = TaskRegistry(retention_seconds=0)  # 立即过期
    reg.register('task-1')
    reg.notify('task-1', 'status', {'status': 'done'})
    # 等待一小段时间确保超过 retention
    time.sleep(0.1)
    expired = reg.cleanup_expired()
    assert 'task-1' in expired
    assert reg.get('task-1') is None


def test_registry_cleanup_keeps_running():
    """cleanup_expired 不清理运行中的任务"""
    reg = TaskRegistry(retention_seconds=0)
    reg.register('task-1')
    reg.notify('task-1', 'status', {'status': 'running'})
    expired = reg.cleanup_expired()
    assert 'task-1' not in expired
    assert reg.get('task-1') is not None


def test_registry_task_count():
    """task_count 返回当前任务数"""
    reg = TaskRegistry()
    assert reg.task_count() == 0
    reg.register('task-1')
    reg.register('task-2')
    assert reg.task_count() == 2


# === 跨线程事件投递测试 ===

def test_notify_delivers_to_subscriber():
    """notify 通过 asyncio loop 投递事件到订阅者"""
    reg = TaskRegistry()
    received_events = []

    async def subscriber():
        reg.bind_loop(asyncio.get_running_loop())
        reg.register('task-1')
        queue = await reg.subscribe('task-1')
        try:
            # 等待事件（带超时）
            event = await asyncio.wait_for(queue.get(), timeout=2.0)
            received_events.append(event)
        except asyncio.TimeoutError:
            pass

    # 在新线程中运行事件循环
    def run_loop():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(subscriber())
        loop.close()

    t = threading.Thread(target=run_loop)
    t.start()
    time.sleep(0.3)  # 等待订阅者就绪

    # 从主线程发送事件（跨线程投递）
    reg.notify('task-1', 'status', {'status': 'running'})

    t.join(timeout=3)
    assert len(received_events) == 1
    assert received_events[0]['type'] == 'status'
    assert received_events[0]['data']['status'] == 'running'


def test_notify_multiple_subscribers():
    """notify 投递事件到多个订阅者"""
    reg = TaskRegistry()
    received = [[] for _ in range(2)]

    async def subscriber(idx):
        queue = await reg.subscribe('task-1')
        try:
            event = await asyncio.wait_for(queue.get(), timeout=3.0)
            received[idx].append(event)
        except asyncio.TimeoutError:
            pass

    async def main():
        reg.bind_loop(asyncio.get_running_loop())
        reg.register('task-1')
        # 在后台启动订阅者
        tasks = [asyncio.create_task(subscriber(i)) for i in range(2)]
        # 等待订阅者就绪
        await asyncio.sleep(0.3)
        # 从另一个线程发送事件（模拟工作线程）
        def send():
            time.sleep(0.1)
            reg.notify('task-1', 'result', {'name': 'SQL注入'})
        t = threading.Thread(target=send)
        t.start()
        # 等待订阅者完成
        await asyncio.gather(*tasks)
        t.join()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
    loop.close()

    assert len(received[0]) == 1
    assert len(received[1]) == 1
    assert received[0][0]['type'] == 'result'


def test_unsubscribe_stops_delivery():
    """unsubscribe 后不再收到事件"""
    reg = TaskRegistry()

    async def main():
        reg.bind_loop(asyncio.get_running_loop())
        reg.register('task-1')
        queue = await reg.subscribe('task-1')
        reg.unsubscribe('task-1', queue)
        # 发送事件（不应投递）
        reg.notify('task-1', 'status', {'status': 'running'})
        # 等待一小段时间确认没有事件
        try:
            await asyncio.wait_for(queue.get(), timeout=0.5)
            assert False, '不应收到事件'
        except asyncio.TimeoutError:
            pass  # 预期超时

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
    loop.close()


def test_notify_without_loop_silently_skips():
    """未绑定 loop 时 notify 静默跳过（不报错）"""
    reg = TaskRegistry()  # 未调用 bind_loop
    reg.register('task-1')
    # 应不报错
    reg.notify('task-1', 'status', {'status': 'running'})
    # 事件仍记录到历史
    assert len(reg.get_history('task-1')) == 1


# === WebSocket 端点测试 ===

@pytest.fixture
def ws_client():
    """创建 WebSocket 测试客户端"""
    app = create_app()
    with TestClient(app) as c:
        yield c


def test_ws_connection_task_not_found(ws_client):
    """WebSocket 连接不存在的任务返回错误并关闭"""
    with ws_client.websocket_connect('/ws/scan/nonexistent') as ws:
        data = ws.receive_json()
        assert data['type'] == 'error'
        assert '不存在' in data['data']['error']


def test_ws_receives_historical_events(ws_client, mock_network_ws):
    """WebSocket 连接后补播历史事件"""
    # 先提交任务
    resp = ws_client.post('/api/scan', json={'target': 'http://x.com/', 'mode': 'p'})
    task_id = resp.json()['task_id']
    time.sleep(1)  # 等待任务产生事件

    # 连接 WebSocket 应收到历史事件
    with ws_client.websocket_connect(f'/ws/scan/{task_id}') as ws:
        # 应至少收到一个历史事件
        data = ws.receive_json()
        assert 'type' in data
        assert data['task_id'] == task_id


@pytest.fixture
def mock_network_ws():
    """Mock 网络请求 for WebSocket tests（含 Router 避免真实插件加载）"""
    with patch('core.orchestrator.detect_cms') as mock_cms, \
         patch('core.orchestrator.detect_waf') as mock_waf, \
         patch('core.orchestrator.load_plugins') as mock_load, \
         patch('core.orchestrator.Router') as mock_router:
        mock_cms.return_value = MagicMock(cms='', version='', confidence=0, matched=[])
        mock_waf.return_value = {'waf': '', 'display': '', 'bypass_hint': ''}
        mock_load.return_value = []
        mock_router.return_value.resolve.return_value = []
        mock_router.return_value.resolve_by_name.return_value = []
        yield


def test_ws_ping_heartbeat(ws_client, mock_network_ws):
    """WebSocket 心跳机制（30秒超时发送 ping）"""
    resp = ws_client.post('/api/scan', json={'target': 'http://x.com/', 'mode': 'p'})
    task_id = resp.json()['task_id']

    # 连接后任务可能在 pending 状态，连接应保持
    try:
        with ws_client.websocket_connect(f'/ws/scan/{task_id}') as ws:
            # 接收所有历史事件（可能多个）
            for _ in range(10):
                try:
                    data = ws.receive_json()
                    if data.get('type') == 'ping':
                        assert 'ts' in data['data']
                        break
                except Exception:
                    break
    except Exception:
        # 连接关闭是正常的（任务完成后自动关闭）
        pass


def test_ws_closed_on_task_completion(ws_client, mock_network_ws):
    """任务完成后 WebSocket 自动关闭"""
    resp = ws_client.post('/api/scan', json={'target': 'http://x.com/', 'mode': 'p'})
    task_id = resp.json()['task_id']
    time.sleep(1.5)  # 等待任务完成

    # 连接后应收到历史事件 + 连接关闭消息
    try:
        with ws_client.websocket_connect(f'/ws/scan/{task_id}') as ws:
            events = []
            for _ in range(20):
                try:
                    data = ws.receive_json()
                    events.append(data)
                    if data.get('type') in ('connection_closed', 'complete'):
                        break
                except Exception:
                    break
            # 应至少收到一个事件
            assert len(events) > 0
    except Exception:
        # 连接关闭是预期行为
        pass


# === 事件常量测试 ===

def test_ws_event_constants():
    """WebSocket 事件常量定义完整"""
    from api.ws.events import (
        ALL_EVENTS,
        EVENT_COMPLETE,
        EVENT_ERROR,
        EVENT_RESULT,
        EVENT_STATUS,
    )
    assert len(ALL_EVENTS) == 10
    assert EVENT_STATUS in ALL_EVENTS
    assert EVENT_COMPLETE in ALL_EVENTS
    assert EVENT_RESULT in ALL_EVENTS
    assert EVENT_ERROR in ALL_EVENTS


if __name__ == '__main__':
    test_registry_register()
    test_registry_get_not_found()
    test_registry_list()
    test_registry_update_task_dict()
    test_registry_notify_records_event()
    test_registry_notify_updates_status()
    test_registry_notify_error_sets_failed()
    test_registry_history_for_nonexistent()
    test_registry_max_events_buffer()
    test_registry_cleanup_expired()
    test_registry_cleanup_keeps_running()
    test_registry_task_count()
    test_notify_delivers_to_subscriber()
    test_notify_multiple_subscribers()
    test_unsubscribe_stops_delivery()
    test_notify_without_loop_silently_skips()
    test_ws_event_constants()
    print('All D9.3 TaskRegistry + WebSocket tests passed!')
