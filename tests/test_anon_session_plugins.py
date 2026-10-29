# 2026-10-29 R6（RuoYi-Vue 3.9.2）靶场假阳性回归：未授权类插件必须走匿名会话
#
# 三处缺陷同源：插件判定的是「未授权可达」，却复用了调用方注入的高权会话
# （--auth / --auth-login），于是把「管理员正常访问」当成「未授权暴露」。
# 与 2026-10-29 上午 job_rce 的修复是同一类，此处补齐 file_upload / unauth_batch，
# 并修掉部门树插件在前后端分离版上的两处形态盲区。
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN  # noqa: E402
from plugins.ruoyi.cve_2025_70986_select_dept_tree import (  # noqa: E402
    Cve202570986SelectDeptTreePlugin,
)
from plugins.ruoyi.file_upload import FileUploadPlugin  # noqa: E402
from plugins.ruoyi.unauth_batch import UnauthBatchPlugin  # noqa: E402

AUTH_FAIL_UPLOAD = '{"msg":"请求访问：/common/upload，认证失败，无法访问系统资源","code":401}'
AUTH_FAIL_LIST = '{"msg":"请求访问：/system/user/list，认证失败，无法访问系统资源","code":401}'
UPLOAD_OK = '{"code":200,"msg":"操作成功","fileName":"/profile/upload/2026/10/29/probe.txt","newFileName":"probe.txt"}'
USER_LIST_OK = '{"total":1,"code":200,"msg":"查询成功","rows":[{"userId":1,"admin":true,"userName":"admin"}]}'
MISSING_RESOURCE = '{"msg":"No static resource system/dept/treeData/0 for request","code":500}'
JSON_DENIED = '{"msg":"没有权限，请联系管理员授权","code":403}'


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "application/json"}

    def json(self):
        return json.loads(self.text)


class FakeSession:
    """模拟注入了高权凭据的共享会话：认证请求成功，匿名克隆被拦（真实服务端行为）"""

    def __init__(self, authed=True, authed_body="", anon_body=""):
        self.authed = authed
        self.authed_body = authed_body
        self.anon_body = anon_body
        self.closed = False

    def _resp(self):
        return FakeResp(self.authed_body if self.authed else self.anon_body, 200)

    def get(self, url, **kw):
        return self._resp()

    def post(self, url, **kw):
        return self._resp()

    def anonymous(self):
        clone = FakeSession(authed=False, authed_body=self.authed_body, anon_body=self.anon_body)
        return clone

    def close(self):
        self.closed = True


def test_file_upload_uses_anonymous_session():
    """带 admin 凭据时上传会成功，但匿名 401 ⇒ 不得判 CONFIRMED（R6 实测假阳性）"""
    sess = FakeSession(authed_body=UPLOAD_OK, anon_body=AUTH_FAIL_UPLOAD)
    res = FileUploadPlugin().verify("http://target/", sess)
    assert res.status != STATUS_CONFIRMED, "匿名会话被 401 拦截时不应判未授权上传"
    assert res.status in (STATUS_SAFE, STATUS_UNKNOWN), res.status
    print("PASS test_file_upload_uses_anonymous_session: %s" % res.status)


def test_unauth_batch_uses_anonymous_session():
    """带 admin 凭据时 /system/user/list 返回业务 JSON，匿名 401 ⇒ 不得判 CONFIRMED"""
    sess = FakeSession(authed_body=USER_LIST_OK, anon_body=AUTH_FAIL_LIST)
    res = UnauthBatchPlugin().verify("http://target/", sess)
    assert res.status != STATUS_CONFIRMED, "认证态下的正常业务响应不应算未授权暴露"
    assert res.status == STATUS_SAFE, res.status
    print("PASS test_unauth_batch_uses_anonymous_session: %s" % res.status)


class _FakeAnonSession:
    def __init__(self, *a, **kw):
        pass

    def get(self, url, **kw):
        return FakeResp(AUTH_FAIL_LIST, 200)

    def close(self):
        pass


def _patch_isolation(monkeypatch, bodies, login_ok=True):
    """把 dept_tree 的登录隔离与匿名基线换成假实现"""
    import contextlib

    import plugins.ruoyi.cve_2025_70986_select_dept_tree as mod

    class LowSess:
        def get(self, url, **kw):
            key = "treeData" if "treeData" in url else "selectDeptTree"
            return FakeResp(bodies[key], 200)

    @contextlib.contextmanager
    def fake_isolation(*a, **kw):
        yield (LowSess() if login_ok else None, login_ok, "" if login_ok else "captcha")

    monkeypatch.setattr(mod, "isolated_auth_session", fake_isolation)
    monkeypatch.setattr(mod, "SessionManager", _FakeAnonSession)


def test_dept_tree_missing_resource_is_unknown(monkeypatch):
    """RuoYi-Vue 3.9.2 无 treeData/selectDeptTree 端点 → 200 + code:500 包装页 ⇒ UNKNOWN

    R6 实测：该版本 SysDeptController 只有 /list、/list/exclude/{deptId}、/{deptId}，
    插件探头的两个路径都不存在；旧守卫只查 HTTP 404，漏掉若依的 500 包装页 ⇒ 误判 CONFIRMED。
    """
    _patch_isolation(monkeypatch, {"treeData": MISSING_RESOURCE, "selectDeptTree": MISSING_RESOURCE})
    res = Cve202570986SelectDeptTreePlugin().verify("http://target/", FakeSession())
    assert res.status == STATUS_UNKNOWN, res.status
    print("PASS test_dept_tree_missing_resource_is_unknown: %s" % res.status)


def test_dept_tree_vue_json_denied_is_safe(monkeypatch):
    """前后端分离版的权限拒绝是 JSON code=403（不是单机版 RuoYi - 403 页面）⇒ SAFE"""
    _patch_isolation(monkeypatch, {"treeData": JSON_DENIED, "selectDeptTree": JSON_DENIED})
    res = Cve202570986SelectDeptTreePlugin().verify("http://target/", FakeSession())
    assert res.status == STATUS_SAFE, res.status
    print("PASS test_dept_tree_vue_json_denied_is_safe: %s" % res.status)


def test_dept_tree_auth_failure_is_unknown(monkeypatch):
    """探针会话失效（401 认证失败 JSON）不等于被权限门拒绝 ⇒ UNKNOWN"""
    _patch_isolation(monkeypatch, {"treeData": AUTH_FAIL_LIST, "selectDeptTree": AUTH_FAIL_LIST})
    res = Cve202570986SelectDeptTreePlugin().verify("http://target/", FakeSession())
    assert res.status == STATUS_UNKNOWN, res.status
    print("PASS test_dept_tree_auth_failure_is_unknown: %s" % res.status)


if __name__ == "__main__":
    test_file_upload_uses_anonymous_session()
    test_unauth_batch_uses_anonymous_session()
