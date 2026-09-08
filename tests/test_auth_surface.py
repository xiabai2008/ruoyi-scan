# G1：认证后深度扫描测试（资产盘点 + 越权矩阵 + lab 签名区集成）
# 运行：python -m pytest tests/test_auth_surface.py -q
import json
import os
import socket
import sys
import threading
import time
import urllib.request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from lib.auth_surface import (
    AuthSurfaceScanner,
    _candidate_paths,
    _extract_paths_from_page,
    _looks_denied,
)


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}


class FakeSession:
    """按 URL 映射返回固定响应的 mock session（支持按会话角色区分）"""

    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))

    def post(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))


def _close_stream():
    """匿名会话 mock（核心会另建 SessionManager，测试中替换为可控 Fake）"""
    return FakeSession({})


# ============================================================
# 单元测试：端点发现与判定原语
# ============================================================


def test_candidate_paths_prefix_variants():
    """字典候选自动生成 /prod-api 前缀变体且去重"""
    paths = _candidate_paths()
    assert "/system/user/list" in paths
    assert "/prod-api/system/user/list" in paths
    # 字典 13 条 × 2 前缀 = 26，无重复
    assert len(paths) == len(set(paths)) == 26, len(paths)


def test_extract_paths_from_page():
    """页面提取：管理类路径命中、静态资源/单段路径过滤"""
    html = (
        '<script>fetch("/system/operlog/list")</script>'
        '<a href="/monitor/job/detail">x</a>'
        '<script src="/static/js/app.js"></script>'
        '<a href="/about">about</a>'
    )
    paths = _extract_paths_from_page(html)
    assert "/system/operlog/list" in paths
    assert "/monitor/job/detail" in paths
    assert "/static/js/app.js" not in paths
    assert "/about" not in paths


def test_looks_denied_semantics():
    """拒绝判定：HTTP 401/403、HTTP 200+业务码 401/403、拒绝关键字三路覆盖"""
    assert _looks_denied(401, "")
    assert _looks_denied(403, "")
    # RuoYi 风格：HTTP 200 但业务 401（关键场景）
    assert _looks_denied(200, '{"code":401,"msg":"请先登录"}')
    assert _looks_denied(200, '{"code":403,"msg":"权限不足"}')
    assert _looks_denied(200, "无权限访问")
    # 正常业务数据不误判
    assert not _looks_denied(200, '{"code":200,"rows":[{"id":1}]}')
    assert not _looks_denied(404, "not found")


# ============================================================
# 单元测试：盘点 + 越权矩阵三态
# ============================================================


class TestAuthzMatrix:
    """越权矩阵三态判定（FakeSession 隔离网络）"""

    def _scanner(self, admin_map, low_map=None):
        admin = FakeSession(admin_map)
        low = FakeSession(low_map) if low_map is not None else None
        scanner = AuthSurfaceScanner("http://t", admin, low_session=low)
        # 替换匿名会话构造，避免真实 SessionManager 发网络请求
        scanner._anon_session = lambda: FakeSession({})
        return scanner

    def test_inventory_admin_only(self):
        """盘点：admin 200 入资产，401/异常不入"""
        admin = FakeSession(
            {
                "http://t/system/user/list": FakeResp('{"code":200,"rows":[]}', 200),
                "http://t/system/role/list": FakeResp("", 401),
            }
        )
        scanner = AuthSurfaceScanner("http://t", admin)
        assets = scanner.inventory([("/system/user/list", "dict"), ("/system/role/list", "dict")])
        assert [a.url for a in assets] == ["http://t/system/user/list"]
        assert assets[0].admin_size > 0

    def test_anon_200_confirmed(self):
        """匿名 200 业务数据 → CONFIRMED 未授权访问"""
        scanner = self._scanner(
            {"http://t/system/user/list": FakeResp('{"code":200,"rows":[]}', 200)},
            low_map={"http://t/system/user/list": FakeResp("", 403)},
        )
        assets = scanner.inventory([("/system/user/list", "dict")])
        # 匿名会话 mock 替换：匿名也 200
        scanner._anon_session = lambda: FakeSession(
            {"http://t/system/user/list": FakeResp('{"code":200,"rows":[]}', 200)}
        )
        assets, vulns = scanner.authz_matrix(assets)
        assert assets[0].verdict == "confirmed"
        assert any(v.vuln_type == "unauthorized_access" for v in vulns)

    def test_anon_401_safe(self):
        """匿名 401 → SAFE，不产漏洞（未授权访问不误报）"""
        scanner = self._scanner({"http://t/system/user/list": FakeResp('{"code":200,"rows":[]}', 200)})
        scanner._anon_session = lambda: FakeSession({"http://t/system/user/list": FakeResp("", 401)})
        assets = scanner.inventory([("/system/user/list", "dict")])
        assets, vulns = scanner.authz_matrix(assets)
        assert assets[0].verdict == "safe"
        assert assets[0].anon_code == 401
        assert vulns == []

    def test_anon_200_but_biz_401_safe(self):
        """HTTP 200 但业务码 401（RuoYi AjaxResult 风格）→ SAFE 不误报"""
        scanner = self._scanner({"http://t/system/user/list": FakeResp('{"code":200,"rows":[]}', 200)})
        scanner._anon_session = lambda: FakeSession(
            {"http://t/system/user/list": FakeResp('{"code":401,"msg":"请先登录"}', 200)}
        )
        assets = scanner.inventory([("/system/user/list", "dict")])
        assets, vulns = scanner.authz_matrix(assets)
        assert assets[0].verdict == "safe"
        assert vulns == []

    def test_low_privilege_escalation_confirmed(self):
        """低权 200 → CONFIRMED 垂直越权"""
        scanner = self._scanner(
            {"http://t/system/role/list": FakeResp('{"code":200,"rows":[]}', 200)},
            low_map={"http://t/system/role/list": FakeResp('{"code":200,"rows":[]}', 200)},
        )
        scanner._anon_session = lambda: FakeSession({"http://t/system/role/list": FakeResp("", 401)})
        assets = scanner.inventory([("/system/role/list", "dict")])
        assets, vulns = scanner.authz_matrix(assets)
        assert assets[0].verdict == "confirmed"
        assert assets[0].low_code == 200
        assert any(v.vuln_type == "privilege_escalation" for v in vulns)

    def test_low_403_safe(self):
        """低权 403 → SAFE（RBAC 正常）"""
        scanner = self._scanner(
            {"http://t/system/role/list": FakeResp('{"code":200,"rows":[]}', 200)},
            low_map={"http://t/system/role/list": FakeResp('{"code":403,"msg":"权限不足"}', 403)},
        )
        scanner._anon_session = lambda: FakeSession({"http://t/system/role/list": FakeResp("", 401)})
        assets = scanner.inventory([("/system/role/list", "dict")])
        assets, vulns = scanner.authz_matrix(assets)
        assert assets[0].verdict == "safe"
        assert vulns == []

    def test_anon_error_unknown(self):
        """匿名网络异常 → UNKNOWN（三态纪律：异常绝不判 SAFE）"""

        class BoomSession:
            def get(self, url, **kw):
                raise ConnectionError("refused")

        scanner = self._scanner({"http://t/system/user/list": FakeResp('{"code":200,"rows":[]}', 200)})
        scanner._anon_session = lambda: BoomSession()
        assets = scanner.inventory([("/system/user/list", "dict")])
        assets, vulns = scanner.authz_matrix(assets)
        assert assets[0].verdict == "unknown"
        assert assets[0].anon_code is None
        assert vulns == []

    def test_run_end_to_end_with_page_discovery(self):
        """run 全流程：页面提取端点 + 盘点 + 矩阵（无低权会话，只跑匿名维度）"""
        admin = FakeSession(
            {
                "http://t/": FakeResp('<script>fetch("/system/operlog/detail")</script>', 200),
                "http://t/index": FakeResp("", 404),
                "http://t/prod-api/": FakeResp("", 404),
                "http://t/system/user": FakeResp("", 404),
                # 字典之外的页面提取端点 → 验证 page 来源真实进入盘点
                "http://t/system/operlog/detail": FakeResp('{"code":200,"rows":[]}', 200),
                # 字典其余条目 404 → 不入资产
            }
        )
        scanner = AuthSurfaceScanner("http://t", admin)
        scanner._anon_session = lambda: FakeSession(
            {"http://t/system/operlog/detail": FakeResp('{"code":200,"rows":[]}', 200)}
        )
        assets, vulns = scanner.run()
        assert [a.url for a in assets] == ["http://t/system/operlog/detail"]
        assert assets[0].source == "page"
        assert len(vulns) == 1 and vulns[0].vuln_type == "unauthorized_access"


# ============================================================
# lab 签名区集成测试（进程内 werkzeug server，真实 HTTP）
# ============================================================


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_lab(mode):
    """进程内启动 lab 签名靶场（werkzeug make_server 线程，跨 CI 稳定）

    subprocess 方式在 GitHub windows runner 上启动不可靠（健康检查超时），
    改为直接挂载 lab.server.app：MODE 通过模块全局量切换（dispatch 内 is_vuln() 读取）。

    Returns:
        (port, server)：调用方 finally 中 server.shutdown()
    """
    from werkzeug.serving import make_server

    import lab.server as lab_mod

    lab_mod.MODE = mode
    port = _free_port()
    server = make_server("127.0.0.1", port, lab_mod.app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    # 就绪等待（进程内启动无冷启动开销）
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as resp:
                if resp.status == 200:
                    return port, server
        except Exception:
            time.sleep(0.1)
    server.shutdown()
    raise AssertionError("进程内 lab 启动失败")


def _login_token(port, username, password):
    """POST /prod-api/auth/login 获取 token（urllib 直连，避免 session 依赖）"""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/prod-api/auth/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    assert body["code"] == 200, body
    return body["token"]


def _lab_scanner(port):
    """构造对接 lab 签名区的扫描器（admin/user 会话各持 token）"""
    from core.session import SessionManager

    target = f"http://127.0.0.1:{port}"
    admin = SessionManager(timeout=5)
    admin.session.headers["Authorization"] = "Bearer " + _login_token(port, "admin", "admin123")
    low = SessionManager(timeout=5)
    low.session.headers["Authorization"] = "Bearer " + _login_token(port, "user", "user123")
    scanner = AuthSurfaceScanner(target, admin, low_session=low)
    scanner._anon_session = lambda: SessionManager(timeout=5)
    return scanner


def test_lab_auth_surface_vuln_mode():
    """lab vuln 模式：垂直越权 CONFIRMED + 未授权 SAFE（不误报）"""
    port, server = _start_lab("vuln")
    try:
        scanner = _lab_scanner(port)
        # 聚焦 /prod-api 签名区：旧签名区端点（unauth_batch 等）本就是匿名可达的洞，
        # 全字典扫描会产生预期内的 unauthorized_access 发现，与本测试断言无关
        candidates = [
            ("/prod-api/system/user/list", "dict"),
            ("/prod-api/system/role/list", "dict"),
        ]
        assets = scanner.inventory(candidates)
        assets, vulns = scanner.authz_matrix(assets)

        urls = {a.url for a in assets}
        assert f"http://127.0.0.1:{port}/prod-api/system/user/list" in urls
        assert f"http://127.0.0.1:{port}/prod-api/system/role/list" in urls

        # 垂直越权洞：低权 token 可读 user/list 与 role/list 两个管理接口
        escalated = [v for v in vulns if v.vuln_type == "privilege_escalation"]
        assert len(escalated) == 2, [v.name for v in vulns]
        assert any("/prod-api/system/role/list" in v.url for v in escalated)

        # 正常鉴权接口不误报：匿名 401 → SAFE
        user_asset = [a for a in assets if a.url.endswith("/prod-api/system/user/list")][0]
        assert user_asset.verdict in ("safe", "confirmed")
        unauthorized = [v for v in vulns if v.vuln_type == "unauthorized_access"]
        # vuln lab 的 user/list 匿名不可达（401），unauthorized_access 只可能来自其他资产
        assert all("/prod-api/system/user/list" not in v.url for v in unauthorized)
    finally:
        server.shutdown()
        server.server_close()


def test_lab_auth_surface_safe_mode():
    """lab safe 模式：越权矩阵零误报（全部 SAFE）"""
    port, server = _start_lab("safe")
    try:
        scanner = _lab_scanner(port)
        candidates = [
            ("/prod-api/system/user/list", "dict"),
            ("/prod-api/system/role/list", "dict"),
        ]
        assets = scanner.inventory(candidates)
        assets, vulns = scanner.authz_matrix(assets)
        # safe 模式零误报：RBAC 正常（role/list 低权 403）、鉴权正常（无 token 401）
        assert vulns == [], [v.name for v in vulns]
        role_asset = [a for a in assets if a.url.endswith("/prod-api/system/role/list")]
        assert role_asset and role_asset[0].verdict == "safe"
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v", "--tb=short"])
