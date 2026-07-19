# D9.2 API 路由测试（FastAPI TestClient）
#
# 验收目标：
#   1. POST /api/scan 提交任务返回 task_id
#   2. GET /api/scan 列出任务
#   3. GET /api/scan/{task_id} 查询状态
#   4. DELETE /api/scan/{task_id} 取消任务
#   5. GET /api/scan/{task_id}/results 获取结果
#   6. GET /api/plugins 列出插件
#   7. GET /api/system/health 健康检查
#   8. GET /api/system/version 版本信息
#   9. GET /api/report/{task_id} 报告元数据
#  10. /docs 和 /openapi.json 可访问
import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from api.app import create_app


@pytest.fixture
def client():
    """创建测试客户端，自动管理生命周期（startup/shutdown）"""
    app = create_app()
    with TestClient(app) as c:
        yield c
    # 退出 with 后自动触发 shutdown，清理 orchestrator 线程池


@pytest.fixture
def mock_network():
    """Mock 网络请求（避免真实 HTTP 调用）"""
    with patch('core.orchestrator.detect_cms') as mock_cms, \
         patch('core.orchestrator.detect_waf') as mock_waf, \
         patch('core.orchestrator.load_plugins') as mock_load:
        mock_cms.return_value = MagicMock(cms='', version='', confidence=0, matched=[])
        mock_waf.return_value = {'waf': '', 'display': '', 'bypass_hint': ''}
        mock_load.return_value = []
        yield


# === 扫描任务 API 测试 ===

def test_submit_scan_returns_task_id(client, mock_network):
    """POST /api/scan 返回 task_id"""
    resp = client.post('/api/scan', json={
        'target': 'http://example.com/',
        'mode': 'p',
    })
    assert resp.status_code == 200
    data = resp.json()
    assert 'task_id' in data
    assert len(data['task_id']) == 12
    assert data['status'] == 'pending'


def test_submit_scan_with_full_params(client, mock_network):
    """POST /api/scan 完整参数"""
    resp = client.post('/api/scan', json={
        'target': 'http://target:8080/',
        'mode': 'u',
        'cms': 'ruoyi',
        'threads': 5,
        'rate': 10,
        'timeout': 15,
        'bypass_waf': 'on',
        'portscan': True,
        'ports': '80,443',
    })
    assert resp.status_code == 200
    assert 'task_id' in resp.json()


def test_list_scans(client, mock_network):
    """GET /api/scan 列出任务"""
    client.post('/api/scan', json={'target': 'http://x.com/', 'mode': 'p'})
    time.sleep(0.5)
    resp = client.get('/api/scan')
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_get_scan_status(client, mock_network):
    """GET /api/scan/{task_id} 查询状态"""
    r = client.post('/api/scan', json={'target': 'http://x.com/', 'mode': 'p'})
    task_id = r.json()['task_id']
    time.sleep(0.5)
    resp = client.get(f'/api/scan/{task_id}')
    assert resp.status_code == 200
    data = resp.json()
    assert data['task_id'] == task_id


def test_get_scan_not_found(client):
    """GET /api/scan/不存在 返回 404"""
    resp = client.get('/api/scan/nonexistent123')
    assert resp.status_code == 404


def test_cancel_scan(client, mock_network):
    """DELETE /api/scan/{task_id} 取消任务"""
    r = client.post('/api/scan', json={'target': 'http://x.com/', 'mode': 'p'})
    task_id = r.json()['task_id']
    resp = client.delete(f'/api/scan/{task_id}')
    assert resp.status_code == 200
    assert resp.json()['status'] == 'cancelled'


def test_get_scan_results(client, mock_network):
    """GET /api/scan/{task_id}/results 获取结果"""
    r = client.post('/api/scan', json={'target': 'http://x.com/', 'mode': 'p'})
    task_id = r.json()['task_id']
    time.sleep(1)
    resp = client.get(f'/api/scan/{task_id}/results')
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# === 插件 API 测试 ===

def test_list_plugins(client):
    """GET /api/plugins 列出插件"""
    resp = client.get('/api/plugins')
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    if data:
        assert 'name' in data[0]
        assert 'severity' in data[0]


def test_get_plugin_not_found(client):
    """GET /api/plugins/不存在 返回 404"""
    resp = client.get('/api/plugins/不存在的插件xyz')
    assert resp.status_code == 404


# === 系统 API 测试 ===

def test_health_check(client):
    """GET /api/system/health 健康检查"""
    resp = client.get('/api/system/health')
    assert resp.status_code == 200
    data = resp.json()
    assert data['status'] == 'ok'
    assert 'version' in data
    assert 'uptime' in data


def test_version_info(client):
    """GET /api/system/version 版本信息"""
    resp = client.get('/api/system/version')
    assert resp.status_code == 200
    data = resp.json()
    assert 'version' in data
    assert 'author' in data
    assert 'python_version' in data


def test_fingerprint_probe(client):
    """GET /api/system/fingerprint 在线指纹探测"""
    with patch('api.routes.system.detect_cms') as mock_cms, \
         patch('api.routes.system.detect_waf') as mock_waf:
        mock_cms.return_value = MagicMock(cms='ruoyi', version='4.7', confidence=0.9, matched=['header'])
        mock_waf.return_value = {'waf': '', 'display': '', 'bypass_hint': ''}
        resp = client.get('/api/system/fingerprint', params={'target': 'http://example.com/'})
    assert resp.status_code == 200
    data = resp.json()
    assert data['target'] == 'http://example.com/'
    assert data['cms'] == 'ruoyi'


# === 报告 API 测试 ===

def test_get_report_metadata_not_found(client):
    """GET /api/report/{task_id} 任务不存在返回 404"""
    resp = client.get('/api/report/nonexistent123')
    assert resp.status_code == 404


def test_get_report_metadata(client, mock_network):
    """GET /api/report/{task_id} 报告元数据"""
    r = client.post('/api/scan', json={'target': 'http://x.com/', 'mode': 'p'})
    task_id = r.json()['task_id']
    time.sleep(0.5)
    resp = client.get(f'/api/report/{task_id}')
    assert resp.status_code == 200
    data = resp.json()
    assert data['task_id'] == task_id
    assert 'formats' in data


def test_download_html_report_not_found(client):
    """GET /api/report/{task_id}/html 报告未生成返回 404"""
    resp = client.get('/api/report/nonexistent123/html')
    assert resp.status_code == 404


def test_download_xlsx_report_not_found(client):
    """GET /api/report/{task_id}/xlsx 报告未生成返回 501（D8 依赖）"""
    resp = client.get('/api/report/nonexistent123/xlsx')
    assert resp.status_code in (404, 501)


def test_download_report_with_existing_file(client, mock_network, tmp_path):
    """GET /api/report/{task_id}/html 任务存在 + 报告文件存在 → 200 下载"""
    import os
    # 提交扫描任务（任务进入 registry）
    r = client.post('/api/scan', json={'target': 'http://x.com/', 'mode': 'p'})
    task_id = r.json()['task_id']
    time.sleep(0.5)
    # 创建模拟报告文件（reports/api/report.html）
    report_dir = os.path.join('reports', 'api')
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir, 'report.html')
    had_file = os.path.exists(report_file)
    if not had_file:
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write('<html><body>test report</body></html>')
    try:
        resp = client.get(f'/api/report/{task_id}/html')
        assert resp.status_code == 200
    finally:
        if not had_file and os.path.exists(report_file):
            os.remove(report_file)


# === OpenAPI 文档测试 ===

def test_docs_accessible(client):
    """GET /docs OpenAPI 文档可访问"""
    resp = client.get('/docs')
    assert resp.status_code == 200


def test_openapi_schema(client):
    """GET /openapi.json OpenAPI Schema 可访问"""
    resp = client.get('/openapi.json')
    assert resp.status_code == 200
    data = resp.json()
    assert data['info']['title'] == '若依综合漏洞检测 API'
    paths = data['paths']
    assert '/api/scan' in paths
    assert '/api/system/health' in paths
    assert '/api/plugins' in paths
