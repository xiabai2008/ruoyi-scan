# 桌面端测评修复的回归用例（v1.5.3）
#
# 覆盖：
#   1. 重启后事件回放字段归一化（P0-1）
#   2. 重启后结果明细从 findings 表兜底（P0-3）
#   3. 报告按 task_id 命名、不再回退共享 report.*（P0-2）
#   4. 非法目标 422 / 无协议自动补全（P1-6）
#   5. 取消后列表状态以 record.status 为准（P1-9）
#   6. 预检失败直接 failed 并给出原因（P1-10）
#   7. 定时任务 UUID / 历史 id 可删除（P1-8）
#   8. CVE 占位符归一化（P1-11）
#   9. 旧任务报告重建（追加）
import time
from pathlib import Path

from tests.helpers import wait_for_task_done


def _mk_storage_registry(tmp_path):
    from core.storage import Storage
    from core.task_registry import TaskRegistry

    storage = Storage(str(tmp_path / "ux.db"))
    registry = TaskRegistry(storage=storage)
    return storage, registry


def _report_dir(tmp_path: Path) -> Path:
    """测试报告目录固定落在 tmp_path 内，避免写仓库工作区"""
    target = tmp_path / "reports" / "api"
    target.mkdir(parents=True, exist_ok=True)
    return target


def test_restore_events_are_canonical(tmp_path):
    """P0-1：恢复出的事件必须是 type/data，不能再是 event_type/payload"""
    storage, registry = _mk_storage_registry(tmp_path)
    storage.save_task("evt1", {"task_id": "evt1", "status": "done", "target": "http://a/"})
    storage.save_event("evt1", "status", {"status": "done"})
    storage.save_event("evt1", "result", {"name": "x", "status": "CONFIRMED"})

    registry.restore_from_storage(storage)
    history = registry.get_history("evt1")

    assert len(history) == 2
    assert history[0]["type"] == "status"
    assert history[0]["data"]["status"] == "done"
    assert "event_type" not in history[0]
    assert "payload" not in history[0]


def test_restore_running_task_becomes_interrupted(tmp_path):
    """重启后 pending/running 任务不能继续显示 RUNNING，且状态要回写"""
    storage, registry = _mk_storage_registry(tmp_path)
    started = time.time()
    storage.save_task(
        "run1",
        {"task_id": "run1", "status": "running", "target": "http://a/", "started_at": started},
    )
    storage.save_event("run1", "status", {"status": "running"})

    registry.restore_from_storage(storage)

    assert registry.get("run1").status == "interrupted"
    assert storage.get_task("run1")["status"] == "interrupted"
    assert "中断" in storage.get_task("run1")["error"]


def test_results_fallback_to_findings(client):
    """P0-3：事件为空时 /results 从 findings 表返回完整明细"""
    reg = client.app.state.registry
    storage = client.app.state.storage
    reg.register("res1", {"task_id": "res1", "status": "done", "target": "http://a/", "mode": "u"})
    storage.save_results(
        "res1",
        [
            {
                "kind": "vuln",
                "name": "Swagger 未授权",
                "status": "CONFIRMED",
                "severity": "high",
                "url": "http://a/v3/api-docs",
                "evidence": "HTTP 200",
                "extra": {"status": 200},
                "reproduce": "curl http://a/v3/api-docs",
            }
        ],
    )

    data = client.get("/api/scan/res1/results").json()
    assert len(data) == 1
    assert data[0]["name"] == "Swagger 未授权"
    assert data[0]["evidence"] == "HTTP 200"
    assert data[0]["reproduce"] == "curl http://a/v3/api-docs"


def test_report_does_not_fallback_to_shared_file(tmp_path, monkeypatch):
    """P0-2：共享 report.html 不得被任意任务命中；按 task_id 命名的文件可命中"""
    shared = _report_dir(tmp_path) / "report.html"
    shared.write_text("shared report", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    from api.routes.report import _find_report_file
    from core.task_registry import TaskRegistry

    registry = TaskRegistry()
    registry.register(
        "abc123",
        {"task_id": "abc123", "target": "http://a/", "report_paths": [str(shared)]},
    )

    assert _find_report_file("abc123", "html", registry) == ""

    own = _report_dir(tmp_path) / "abc123.html"
    own.write_text("own report", encoding="utf-8")
    found = _find_report_file("abc123", "html", registry)
    assert found.endswith("abc123.html")


def test_invalid_target_rejected(client):
    """P1-6：file:// / 畸形端口在入口 422；无协议自动补 http://"""
    bad = client.post("/api/scan", json={"target": "file:///etc/passwd", "mode": "u"})
    assert bad.status_code == 422

    bad_port = client.post("/api/scan", json={"target": "http://host:99999/", "mode": "u"})
    assert bad_port.status_code == 422

    ok = client.post("/api/scan", json={"target": "127.0.0.1:8080", "mode": "u"})
    assert ok.status_code == 200
    task_id = ok.json()["task_id"]
    task = client.get(f"/api/scan/{task_id}").json()
    assert task["target"] == "http://127.0.0.1:8080/"


def test_list_scans_uses_record_status(client):
    """P1-9：取消只改 record.status 时，列表不能继续显示 running"""
    reg = client.app.state.registry
    reg.register("st1", {"task_id": "st1", "status": "running", "target": "http://a/", "mode": "u"})
    reg.mark_status("st1", "cancelled")

    rows = client.get("/api/scan").json()
    row = next(r for r in rows if r["task_id"] == "st1")
    assert row["status"] == "cancelled"


def test_preflight_failure_marks_task_failed(client, mock_network, monkeypatch):
    """P1-10：目标不可达时直接 failed + 可读原因，而不是 0/0 干等"""
    monkeypatch.setattr(
        "core.orchestrator.preflight",
        lambda url, timeout=5.0: (False, "tcp", "连接 127.0.0.1:19109 失败（Connection refused）"),
    )
    resp = client.post("/api/scan", json={"target": "http://127.0.0.1:19109/", "mode": "u"})
    task_id = resp.json()["task_id"]
    assert wait_for_task_done(client, task_id, timeout=10)

    task = client.get(f"/api/scan/{task_id}").json()
    assert task["status"] == "failed"
    assert "目标不可达" in task["error"]


def test_scheduler_uuid_and_legacy_delete(tmp_path):
    """P1-8/P1-12：新 job_id 不含路径分隔符；历史含 / 的 id 仍可删除"""
    from core.storage import Storage
    from lib.scheduler import ScanScheduler

    storage = Storage(str(tmp_path / "sched.db"))
    sched = ScanScheduler(storage=storage)
    job_id = sched.add_job("*/30 * * * *", "http://a/")
    assert "/" not in job_id and "*" not in job_id

    legacy = "job_*/30_*_*_*_*_http_127.0.0.1:19109_"
    storage.save_schedule(legacy, "*/30 * * * *", "http://b/")
    sched2 = ScanScheduler(storage=storage)
    sched2.start()
    assert any(j["job_id"] == legacy for j in sched2.list_jobs())

    assert sched2.remove_job(legacy) is True
    assert storage.get_schedule(legacy) is None
    sched2.shutdown()


def test_plugin_cve_placeholder_normalized():
    """P1-11：N/A 不能再被前端当成有 CVE"""
    from api.routes.plugin import _clean_meta

    assert _clean_meta("N/A") == ""
    assert _clean_meta("n/a") == ""
    assert _clean_meta("—") == ""
    assert _clean_meta("CVE-2025-46174") == "CVE-2025-46174"


def test_probe_endpoint(client, monkeypatch):
    """S3：连通性检查端点返回结构化结果，非法目标 400"""
    monkeypatch.setattr("api.routes.system.preflight", lambda url, timeout=5.0: (True, "", ""))
    ok = client.get("/api/system/probe", params={"target": "127.0.0.1:8080"})
    assert ok.status_code == 200
    body = ok.json()
    assert body["ok"] is True
    assert body["target"] == "http://127.0.0.1:8080/"

    bad = client.get("/api/system/probe", params={"target": "ftp://x/"})
    assert bad.status_code == 400


def test_schedule_delete_via_query(client):
    """P1-8：通过查询参数删除调度（前端使用的路径），并确认新 id 是 UUID"""
    created = client.post(
        "/api/schedule",
        json={"cron": "every:300", "target": "http://x.com/", "mode": "u"},
    )
    assert created.status_code == 200, created.text
    job_id = created.json()["job_id"]
    assert "/" not in job_id and "*" not in job_id

    deleted = client.delete("/api/schedule", params={"job_id": job_id})
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["status"] == "removed"


def test_cancel_stops_engine_and_frees_slot(monkeypatch):
    """P1-9：取消必须让执行线程退出，后续任务可立即执行"""
    from unittest.mock import patch

    from common.models import FingerprintResult, ScanResult
    from core.orchestrator import ScanOrchestrator, ScanRequest
    from core.task_registry import TaskRegistry
    from tests.helpers import wait_for

    class SlowPlugin:
        name = "slow"
        category = "vuln"
        severity = "low"

        def verify(self, target, session):
            time.sleep(0.3)
            return ScanResult(kind="vuln", name="slow", status="UNKNOWN", evidence="demo")

    registry = TaskRegistry()
    orch = ScanOrchestrator(registry=registry)
    monkeypatch.setattr("core.orchestrator.preflight", lambda *a, **k: (True, "", ""))
    with patch("core.orchestrator.Router") as router, patch(
        "core.orchestrator.detect_cms",
        return_value=FingerprintResult(cms="ruoyi", version="", confidence=1.0, matched=[]),
    ), patch(
        "core.orchestrator.detect_waf",
        return_value={"waf": "", "display": "", "bypass_hint": ""},
    ), patch(
        "core.orchestrator.load_plugins",
        side_effect=lambda pkg: [SlowPlugin] * 10 if pkg == "plugins.ruoyi" else [],
    ), patch(
        "lib.plugin_repo.load_user_installed_plugins", return_value=[]
    ), patch(
        "lib.reachability.detect_blocked", return_value={"blocked": False}
    ), patch(
        "lib.reachability.detect_auth_wall", return_value={"wall": False, "reason": "", "status": 0}
    ), patch(
        "core.basepath.detect_api_base", return_value=""
    ):
        router.return_value.resolve.return_value = [SlowPlugin] * 10
        router.return_value.resolve_by_name.return_value = [SlowPlugin] * 10

        task_id = orch.submit(ScanRequest(target="http://x/", mode="p", threads=1))
        assert wait_for(lambda: registry.get(task_id).status == "running", timeout=3)
        assert orch.cancel(task_id) is True
        assert wait_for(lambda: registry.get(task_id).status == "cancelled", timeout=3)
        # 执行线程应已在一次插件超时内退出
        assert wait_for(lambda: not orch.is_task_active(task_id), timeout=3)

        # 线程池槽位释放后，新任务可以正常跑完
        second = orch.submit(ScanRequest(target="http://x/", mode="p", threads=1, report_dir=""))
        assert wait_for(lambda: registry.get(second).status == "done", timeout=8)

    orch.shutdown()


def test_rebuild_report_from_events_for_old_tasks(client, tmp_path, monkeypatch):
    """旧任务没有 findings 行时，重建报告应回退到已恢复的 result 事件"""
    report_dir = _report_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    reg = client.app.state.registry
    reg.register(
        "rb2",
        {
            "task_id": "rb2",
            "status": "done",
            "target": "http://target2/",
            "mode": "u",
            "started_at": time.time(),
            "duration": 2.0,
            "request_count": 5,
        },
    )
    reg.notify(
        "rb2",
        "result",
        {
            # 旧版本 result 事件只有这 6 个字段，没有 kind
            "name": "事件回退用例",
            "status": "CONFIRMED",
            "severity": "medium",
            "url": "http://target2/y",
            "evidence": "from event",
            "extra": {},
        },
    )

    resp = client.post("/api/report/rb2/rebuild")
    assert resp.status_code == 200, resp.text
    assert (report_dir / "rb2.html").exists()


def test_rebuild_report_from_findings(client, tmp_path, monkeypatch):
    """追加：旧任务可以从 findings 重建按 task_id 命名的报告"""
    report_dir = _report_dir(tmp_path)
    monkeypatch.chdir(tmp_path)
    reg = client.app.state.registry
    storage = client.app.state.storage
    reg.register(
        "rb1",
        {
            "task_id": "rb1",
            "status": "done",
            "target": "http://target/",
            "mode": "u",
            "started_at": time.time(),
            "duration": 1.5,
            "request_count": 3,
        },
    )
    storage.save_results(
        "rb1",
        [
            {
                "kind": "vuln",
                "name": "重建用例",
                "status": "CONFIRMED",
                "severity": "high",
                "url": "http://target/x",
                "evidence": "demo",
                "extra": {},
            }
        ],
    )

    resp = client.post("/api/report/rb1/rebuild")
    assert resp.status_code == 200, resp.text
    paths = resp.json()["paths"]
    assert paths and all("rb1" in Path(p).name for p in paths)
    assert (report_dir / "rb1.html").exists()
