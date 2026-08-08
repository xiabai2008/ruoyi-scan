# E9 团队版 API 测试：权限分级 / 定时扫描 / storage schedules / 共享链接
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.auth import _required_scope, parse_api_keys


# === 权限分级单元测试 ===


def test_parse_api_keys():
    """多 Key 解析：key:scope 格式 + 单 key 默认 admin"""
    parsed = parse_api_keys("key1:read,key2:scan,key3:admin")
    assert parsed == {"key1": "read", "key2": "scan", "key3": "admin"}, parsed
    # 单 key 无 scope → admin（向后兼容）
    assert parse_api_keys("single-key") == {"single-key": "admin"}
    # 无效 scope → admin
    assert parse_api_keys("k:x") == {"k": "admin"}
    # 空 → 空
    assert parse_api_keys("") == {}
    print("PASS test_parse_api_keys")


def test_required_scope():
    """路径 → 所需权限映射"""
    assert _required_scope("GET", "/api/scan") == "read"
    assert _required_scope("GET", "/api/scan/abc123") == "read"
    assert _required_scope("GET", "/api/report/abc/html") == "read"
    assert _required_scope("POST", "/api/scan") == "scan"
    assert _required_scope("DELETE", "/api/scan/abc") == "scan"
    assert _required_scope("GET", "/api/plugin") == "admin"
    assert _required_scope("POST", "/api/schedule") == "admin"
    print("PASS test_required_scope")


def test_auth_middleware_scopes(client_factory):
    """中间件：read 不能发扫描（403），scan 可以；共享链接 ?api_key= 可下载报告元数据"""
    with client_factory(api_key="k1:read,k2:scan,k3:admin") as client:
        # read：查询允许
        resp = client.get("/api/scan", headers={"X-API-Key": "k1"})
        assert resp.status_code == 200, resp.status_code
        # read：POST 扫描 → 403
        resp = client.post("/api/scan", headers={"X-API-Key": "k1"}, json={"target": "http://x.com/", "mode": "p"})
        assert resp.status_code == 403, resp.status_code
        # scan：POST 允许
        resp = client.post("/api/scan", headers={"X-API-Key": "k2"}, json={"target": "http://x.com/", "mode": "p"})
        assert resp.status_code == 200, resp.status_code
        # scan：插件管理 → 403
        resp = client.get("/api/plugins", headers={"X-API-Key": "k2"})
        assert resp.status_code == 403, resp.status_code
        # admin：插件管理允许
        resp = client.get("/api/plugins", headers={"X-API-Key": "k3"})
        assert resp.status_code == 200, resp.status_code
        # 无效 key → 401
        resp = client.get("/api/scan", headers={"X-API-Key": "wrong"})
        assert resp.status_code == 401, resp.status_code
    print("PASS test_auth_middleware_scopes")


def test_shared_link_query_key(client_factory):
    """共享链接：?api_key= 查询参数（无头）访问只读端点"""
    with client_factory(api_key="k1:read,k2:admin") as client:
        resp = client.get("/api/scan?api_key=k1")
        assert resp.status_code == 200, resp.status_code
        # 共享链接不能越权发扫描
        resp = client.post("/api/scan?api_key=k1", json={"target": "http://x.com/", "mode": "p"})
        assert resp.status_code == 403, resp.status_code
    print("PASS test_shared_link_query_key")


# === 定时扫描调度器测试 ===


def test_parse_schedule_expr():
    """调度表达式解析：cron + interval"""
    from lib.scheduler import parse_schedule_expr

    p = parse_schedule_expr("*/5 * * * *")
    assert p["type"] == "cron", p
    p2 = parse_schedule_expr("every:300")
    assert p2["type"] == "interval" and p2["seconds"] == 300, p2
    try:
        parse_schedule_expr("bad-expr")
        assert False, "应抛 ValueError"
    except ValueError:
        pass
    print("PASS test_parse_schedule_expr")


def test_scheduler_interval_trigger(monkeypatch):
    """interval 模式：到点触发 orchestrator.submit"""
    from lib.scheduler import ScanScheduler

    triggers = []

    class FakeOrch:
        def submit(self, req):
            triggers.append(req)

    scheduler = ScanScheduler(orchestrator=FakeOrch(), storage=None)
    scheduler.start()
    scheduler.add_job("every:1", "http://target/", mode="p")  # 1 秒触发（最小 5 秒内防误配）
    time.sleep(1.5)
    scheduler.shutdown()
    # 最小间隔 5 秒 → 1.5 秒内不应触发（验证下限保护）
    assert len(triggers) == 0, f"5 秒内不应触发，实际 {len(triggers)}"
    print("PASS test_scheduler_interval_trigger (min-interval guard)")


def test_scheduler_on_trigger(monkeypatch):
    """interval 模式：on_trigger 回调触发"""
    from lib.scheduler import ScanScheduler

    triggers = []

    def on_trigger(target, mode, payload):
        triggers.append((target, mode))

    scheduler = ScanScheduler(on_trigger=on_trigger)
    # 直接调用内部触发（模拟 5 秒后的 tick，不等待真实时间）
    job_id = scheduler.add_job("every:5", "http://target/", mode="p")
    scheduler._trigger(job_id, scheduler._jobs[job_id])
    assert triggers == [("http://target/", "p")], triggers
    print("PASS test_scheduler_on_trigger")


def test_scheduler_storage_persist(tmp_path):
    """定时任务落库 + 恢复"""
    from core.storage import Storage
    from lib.scheduler import ScanScheduler

    db = str(tmp_path / "sched.db")
    storage = Storage(db)
    sched = ScanScheduler(storage=storage)
    sched.add_job("*/10 * * * *", "http://a/", mode="u")
    recs = storage.list_schedules()
    assert len(recs) == 1 and recs[0]["cron"] == "*/10 * * * *", recs

    # 新调度器从 storage 恢复
    sched2 = ScanScheduler(storage=storage)
    sched2.start()
    jobs = sched2.list_jobs()
    assert any(j["target"] == "http://a/" for j in jobs), jobs
    sched2.shutdown()

    # 删除
    sched.remove_job(recs[0]["job_id"])
    assert storage.list_schedules() == []
    print("PASS test_scheduler_storage_persist")


def test_schedule_api(client_factory):
    """API：创建/列出/删除定时任务（admin 权限）"""
    with client_factory(api_key="k:admin") as client:
        resp = client.post("/api/schedule", headers={"X-API-Key": "k"},
                           json={"cron": "every:300", "target": "http://x.com/", "mode": "u"})
        assert resp.status_code == 200, resp.status_code
        data = resp.json()
        assert "job_id" in data and data["status"] == "scheduled"
        # 非法表达式 → 400
        resp = client.post("/api/schedule", headers={"X-API-Key": "k"},
                           json={"cron": "bad", "target": "http://x.com/"})
        assert resp.status_code == 400, resp.status_code
        # 列出
        resp = client.get("/api/schedule", headers={"X-API-Key": "k"})
        assert resp.status_code == 200
        assert any(j["target"] == "http://x.com/" for j in resp.json())
        # 删除
        resp = client.delete("/api/schedule/%s" % data["job_id"], headers={"X-API-Key": "k"})
        assert resp.status_code == 200
    print("PASS test_schedule_api")


if __name__ == "__main__":
    test_parse_api_keys()
    test_required_scope()
    test_parse_schedule_expr()
    test_scheduler_interval_trigger()
    test_scheduler_on_trigger()
    test_scheduler_storage_persist()
    print("ALL_E9_TESTS_PASS (API 测试需 client_fixture)")
