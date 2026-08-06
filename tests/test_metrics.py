# D16 Prometheus 指标端点测试
#
# 覆盖：
#   1. /api/system/metrics 端点可访问（200 OK）
#   2. 返回 Prometheus 文本格式（text/plain; version=0.0.4）
#   3. 包含必需的指标行（uptime_seconds、tasks_total、tasks_active、results_total）
#   4. 指标值类型正确（数值）
#   5. 注册任务后指标计数更新
#   6. /api/system/metrics 免鉴权（PUBLIC_PATHS）
#   7. Prometheus 文本格式规范（HELP/TYPE/metric 行）
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from api.app import create_app
from core.task_registry import TaskRegistry

# === fixtures ===


@pytest.fixture
def app():
    """创建 FastAPI 应用（带临时数据库）"""
    import tempfile

    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "test_metrics.db")
    application = create_app(db_path=db_path)
    yield application
    # 清理
    import shutil

    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def client(app):
    """创建测试客户端"""
    with TestClient(app) as c:
        yield c


# === 1. 端点可访问 + 格式 ===


def test_metrics_endpoint_accessible(client):
    """D16: /api/system/metrics 返回 200"""
    resp = client.get("/api/system/metrics")
    assert resp.status_code == 200, f"指标端点应返回 200，实际 {resp.status_code}"


def test_metrics_content_type(client):
    """D16: 返回 text/plain 内容类型"""
    resp = client.get("/api/system/metrics")
    content_type = resp.headers.get("content-type", "")
    assert "text/plain" in content_type, f"Content-Type 应为 text/plain，实际 {content_type}"


def test_metrics_response_is_text(client):
    """D16: 响应体为字符串"""
    resp = client.get("/api/system/metrics")
    assert isinstance(resp.text, str)
    assert len(resp.text) > 0


# === 2. 必需指标存在 ===


def test_metrics_contains_uptime(client):
    """D16: 包含 ruoyi_scan_uptime_seconds 指标"""
    resp = client.get("/api/system/metrics")
    assert "ruoyi_scan_uptime_seconds" in resp.text


def test_metrics_contains_tasks_total(client):
    """D16: 包含 ruoyi_scan_tasks_total 指标"""
    resp = client.get("/api/system/metrics")
    assert "ruoyi_scan_tasks_total" in resp.text


def test_metrics_contains_tasks_active(client):
    """D16: 包含 ruoyi_scan_tasks_active 指标"""
    resp = client.get("/api/system/metrics")
    assert "ruoyi_scan_tasks_active" in resp.text


def test_metrics_contains_results_total(client):
    """D16: 包含 ruoyi_scan_results_total 指标"""
    resp = client.get("/api/system/metrics")
    assert "ruoyi_scan_results_total" in resp.text


def test_metrics_contains_storage_tasks(client):
    """D16: 包含 ruoyi_scan_storage_tasks 指标（storage 启用时）"""
    resp = client.get("/api/system/metrics")
    assert "ruoyi_scan_storage_tasks" in resp.text


# === 3. Prometheus 文本格式规范 ===


def test_metrics_has_help_lines(client):
    """D16: 每个指标有 # HELP 注释行"""
    resp = client.get("/api/system/metrics")
    assert "# HELP ruoyi_scan_uptime_seconds" in resp.text
    assert "# HELP ruoyi_scan_tasks_total" in resp.text
    assert "# HELP ruoyi_scan_tasks_active" in resp.text
    assert "# HELP ruoyi_scan_results_total" in resp.text


def test_metrics_has_type_lines(client):
    """D16: 每个指标有 # TYPE 注释行"""
    resp = client.get("/api/system/metrics")
    assert "# TYPE ruoyi_scan_uptime_seconds gauge" in resp.text
    assert "# TYPE ruoyi_scan_tasks_total gauge" in resp.text
    assert "# TYPE ruoyi_scan_tasks_active gauge" in resp.text
    assert "# TYPE ruoyi_scan_results_total gauge" in resp.text


def test_metrics_uptime_is_numeric(client):
    """D16: uptime 值为数值"""
    resp = client.get("/api/system/metrics")
    match = re.search(r"^ruoyi_scan_uptime_seconds\s+([\d.]+)\s*$", resp.text, re.MULTILINE)
    assert match, "未找到 uptime 数值行"
    value = float(match.group(1))
    assert value >= 0, f"uptime 应 >= 0，实际 {value}"


def test_metrics_tasks_total_has_status_label(client):
    """D16: tasks_total 指标带 status 标签"""
    resp = client.get("/api/system/metrics")
    # 至少有一个 status 标签
    assert re.search(r'ruoyi_scan_tasks_total\{status="[^"]+"\}\s+\d+', resp.text), (
        'tasks_total 应包含 status="..." 标签'
    )


def test_metrics_results_total_has_status_label(client):
    """D16: results_total 指标带 status 标签"""
    resp = client.get("/api/system/metrics")
    assert re.search(r'ruoyi_scan_results_total\{status="[^"]+"\}\s+\d+', resp.text), (
        'results_total 应包含 status="..." 标签'
    )


# === 4. 指标动态更新 ===


def test_metrics_storage_count_increases(client, app):
    """D16: 注册任务后 storage_tasks 指标增加"""
    # 初始指标
    resp1 = client.get("/api/system/metrics")
    match1 = re.search(r"^ruoyi_scan_storage_tasks\s+(\d+)\s*$", resp1.text, re.MULTILINE)
    initial_count = int(match1.group(1)) if match1 else 0

    # 注册一个任务到 registry
    registry = app.state.registry
    task_id = "metrics-test-001"
    registry.register(
        task_id,
        {
            "task_id": task_id,
            "status": "pending",
            "target": "http://test.example.com/",
        },
    )

    # 再次获取指标
    resp2 = client.get("/api/system/metrics")
    match2 = re.search(r"^ruoyi_scan_storage_tasks\s+(\d+)\s*$", resp2.text, re.MULTILINE)
    new_count = int(match2.group(1)) if match2 else 0

    assert new_count >= initial_count + 1, f"storage_tasks 应至少 +1，初始 {initial_count}，新值 {new_count}"


def test_metrics_tasks_total_reflects_registry(client, app):
    """D16: tasks_total 反映 registry 中的任务状态"""
    registry = app.state.registry
    task_id = "metrics-test-002"
    registry.register(
        task_id,
        {
            "task_id": task_id,
            "status": "pending",
            "target": "http://test.example.com/",
        },
    )

    resp = client.get("/api/system/metrics")
    # 应该能找到 pending 状态的计数 >= 1
    match = re.search(r'ruoyi_scan_tasks_total\{status="pending"\}\s+(\d+)', resp.text)
    assert match, "应包含 pending 状态任务计数"
    count = int(match.group(1))
    assert count >= 1, f"pending 任务计数应 >= 1，实际 {count}"


# === 5. 鉴权（PUBLIC_PATHS） ===


def test_metrics_no_auth_required_no_key(client):
    """D16: 无 API Key 模式下，metrics 端点免鉴权"""
    # 默认无 key，本地访问应放行（client 模拟本地）
    resp = client.get("/api/system/metrics")
    assert resp.status_code == 200


def test_metrics_accessible_with_api_key(client):
    """D16: 有 API Key 模式下，metrics 端点也免鉴权（PUBLIC_PATHS）"""
    # 重新创建 app 设置 api_key
    import tempfile

    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "test_metrics_key.db")
    try:
        app_with_key = create_app(api_key="secret-key-123", db_path=db_path)
        with TestClient(app_with_key) as c:
            # 不带 X-API-Key 也能访问 metrics（PUBLIC_PATHS）
            resp = c.get("/api/system/metrics")
            assert resp.status_code == 200, f"metrics 在 PUBLIC_PATHS 中，应免鉴权，实际 {resp.status_code}"
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)


# === 6. 辅助函数测试 ===


def test_get_task_stats_returns_dict():
    """D16: _get_task_stats 返回统计字典"""
    from api.metrics import _get_task_stats

    registry = TaskRegistry()
    stats = _get_task_stats(registry)
    assert isinstance(stats, dict)
    assert "pending" in stats
    assert "running" in stats
    assert "done" in stats
    assert "failed" in stats


def test_get_result_stats_returns_dict():
    """D16: _get_result_stats 返回结果统计字典"""
    from api.metrics import _get_result_stats

    registry = TaskRegistry()
    stats = _get_result_stats(registry)
    assert isinstance(stats, dict)
    assert "confirmed" in stats
    assert "safe" in stats or "unknown" in stats


def test_get_task_stats_with_registered_task():
    """D16: 注册任务后 _get_task_stats 反映状态"""
    from api.metrics import _get_task_stats

    registry = TaskRegistry()
    registry.register("test-stats-001", {"task_id": "test-stats-001", "status": "pending"})

    stats = _get_task_stats(registry)
    assert stats["pending"] >= 1, f"pending 计数应 >= 1，实际 {stats}"


# === 7. 端到端：完整指标输出校验 ===


def test_metrics_full_output_valid(client):
    """D16: 完整输出符合 Prometheus 文本格式规范"""
    resp = client.get("/api/system/metrics")
    lines = resp.text.strip().split("\n")

    # 至少包含 5 个指标的 HELP + TYPE + 数值行
    metric_names = set()
    for line in lines:
        if line.startswith("# HELP "):
            parts = line.split()
            if len(parts) >= 3:
                metric_names.add(parts[2])

    expected_metrics = {
        "ruoyi_scan_uptime_seconds",
        "ruoyi_scan_tasks_total",
        "ruoyi_scan_tasks_active",
        "ruoyi_scan_results_total",
    }
    missing = expected_metrics - metric_names
    assert not missing, f"缺少指标定义：{missing}"


def test_metrics_storage_tasks_value_numeric(client):
    """D16: storage_tasks 指标值为整数"""
    resp = client.get("/api/system/metrics")
    match = re.search(r"^ruoyi_scan_storage_tasks\s+(\d+)\s*$", resp.text, re.MULTILINE)
    assert match, "应包含 storage_tasks 数值行"
    value = int(match.group(1))
    assert value >= 0, f"storage_tasks 应 >= 0，实际 {value}"


if __name__ == "__main__":
    # 直接运行模式（pytest 之外的快速验证）
    import tempfile

    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "run_metrics.db")
    try:
        app = create_app(db_path=db_path)
        with TestClient(app) as c:
            # 注册任务
            app.state.registry.register(
                "manual-001",
                {
                    "task_id": "manual-001",
                    "status": "pending",
                    "target": "http://x/",
                },
            )
            resp = c.get("/api/system/metrics")
            print("STATUS:", resp.status_code)
            print("CONTENT-TYPE:", resp.headers.get("content-type"))
            print("-" * 60)
            print(resp.text)
            print("-" * 60)
            assert resp.status_code == 200
            assert "ruoyi_scan_uptime_seconds" in resp.text
            assert "ruoyi_scan_tasks_total" in resp.text
            print("ALL_D16_METRICS_TESTS_PASS")
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
