# 芋道 yudao 插件（v1.6 WP-F1）
#
# 依据真实站 Y1（2026-11-03 实测，Spring Boot 2.7.18 / 2026.10-jdk8-SNAPSHOT）：
#   /admin-api/system/tenant/simple-list → 200 {"code":0,"data":[4 个租户]}
#   /druid/datasource.json               → 200 {"ResultCode":1,"Content":[...]}
#   /admin-api/system/user/list          → 200 {"code":401,"msg":"账号未登录"}
#
# 注意芋道的业务码是 **0**（不是若依的 200），这是两家最明显的区别。
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN  # noqa: E402


class _Resp:
    def __init__(self, body, status=200, ct="application/json"):
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.status_code = status
        self.headers = {"Content-Type": ct}
        self.content = self.text.encode()

    def json(self):
        return json.loads(self.text)


class _Session:
    """按 URL 路径返回预设响应；记录是否调了 anonymous()"""

    def __init__(self, routes):
        self.routes = routes
        self.anonymous_called = False

    def get(self, url, **kw):
        for key, resp in self.routes.items():
            if key in url:
                return resp
        return _Resp('{"code":401,"msg":"账号未登录"}', 200)

    def anonymous(self):
        self.anonymous_called = True
        return self


# ============================================================
# 1. 租户列表未授权
# ============================================================


def test_tenant_unauth_confirms_on_real_response():
    """真实芋道响应：code=0 + data 是非空租户数组"""
    from plugins.yudao.tenant_unauth import YudaoTenantUnauthPlugin

    body = '{"code":0,"msg":"","data":[{"id":1,"name":"芋道源码"},{"id":2,"name":"测试租户"}]}'
    sess = _Session({"tenant/simple-list": _Resp(body)})
    res = YudaoTenantUnauthPlugin().verify("http://t/", sess)
    assert res.status == STATUS_CONFIRMED, res.evidence
    assert "2 个租户" in res.evidence
    assert sess.anonymous_called, "必须用匿名会话（anonymous_probe 语义）"


def test_tenant_unauth_rejects_code_401():
    """401 是「账号未登录」，不是泄露——不能因为接口可达就 CONFIRMED"""
    from plugins.yudao.tenant_unauth import YudaoTenantUnauthPlugin

    body = '{"code":401,"msg":"账号未登录","data":null}'
    res = YudaoTenantUnauthPlugin().verify("http://t/", _Session({"tenant": _Resp(body)}))
    assert res.status == STATUS_SAFE, res.evidence


def test_tenant_unauth_rejects_empty_data():
    """空数组只说明「查不到」，不是泄露

    实测依据：/tenant/get-id-by-name 也返回 {"code":0,"data":null}，
    只判 code==0 会被这类「空成功响应」骗到。
    """
    from plugins.yudao.tenant_unauth import YudaoTenantUnauthPlugin

    for body in ('{"code":0,"data":[]}', '{"code":0,"data":null}'):
        res = YudaoTenantUnauthPlugin().verify("http://t/", _Session({"tenant": _Resp(body)}))
        assert res.status == STATUS_SAFE, f"{body} 应判 SAFE，实际 {res.status}"


def test_tenant_unauth_rejects_non_tenant_array():
    """数组元素没有 id+name 就不是租户结构"""
    from plugins.yudao.tenant_unauth import YudaoTenantUnauthPlugin

    body = '{"code":0,"data":[{"foo":"bar"}]}'
    res = YudaoTenantUnauthPlugin().verify("http://t/", _Session({"tenant": _Resp(body)}))
    assert res.status == STATUS_SAFE, res.evidence


def test_tenant_unauth_unknown_on_network_error():
    """全部请求失败 → UNKNOWN（三态纪律）"""
    from plugins.yudao.tenant_unauth import YudaoTenantUnauthPlugin

    class _Dead:
        def get(self, url, **kw):
            raise OSError("connection refused")

        def anonymous(self):
            return self

    res = YudaoTenantUnauthPlugin().verify("http://t/", _Dead())
    assert res.status == STATUS_UNKNOWN, res.evidence


# ============================================================
# 2. Druid 监控未授权
# ============================================================


def test_druid_confirms_on_real_response():
    """真实 Druid 数据接口：ResultCode=1 + Content 非空"""
    from plugins.yudao.druid_monitor_unauth import YudaoDruidMonitorUnauthPlugin

    body = '{"ResultCode":1,"Content":[{"Name":"master","DbType":"mysql"}]}'
    sess = _Session({"druid/datasource.json": _Resp(body)})
    res = YudaoDruidMonitorUnauthPlugin().verify("http://t/", sess)
    assert res.status == STATUS_CONFIRMED, res.evidence
    assert "datasource.json" in res.evidence


def test_druid_rejects_empty_content():
    """Content 为空 = 暂无数据，不构成泄露"""
    from plugins.yudao.druid_monitor_unauth import YudaoDruidMonitorUnauthPlugin

    body = '{"ResultCode":1,"Content":[]}'
    res = YudaoDruidMonitorUnauthPlugin().verify("http://t/", _Session({"druid": _Resp(body)}))
    assert res.status == STATUS_SAFE, res.evidence


def test_druid_rejects_wrong_result_code():
    """ResultCode 不是 1 就不是有效数据响应（芋道错误页也是 200）"""
    from plugins.yudao.druid_monitor_unauth import YudaoDruidMonitorUnauthPlugin

    for body in ('{"code":401,"msg":"账号未登录"}', '{"ResultCode":0,"Content":[{"a":1}]}'):
        res = YudaoDruidMonitorUnauthPlugin().verify("http://t/", _Session({"druid": _Resp(body)}))
        assert res.status == STATUS_SAFE, f"{body} 应判 SAFE，实际 {res.status}"


def test_druid_counts_multiple_endpoints():
    """多个数据接口同时可读时，证据里要列出全部"""
    from plugins.yudao.druid_monitor_unauth import YudaoDruidMonitorUnauthPlugin

    sess = _Session(
        {
            "druid/datasource.json": _Resp('{"ResultCode":1,"Content":[{"Name":"master"}]}'),
            "druid/sql.json": _Resp('{"ResultCode":1,"Content":[{"SQL":"select 1"},{"SQL":"select 2"}]}'),
        }
    )
    res = YudaoDruidMonitorUnauthPlugin().verify("http://t/", sess)
    assert res.status == STATUS_CONFIRMED
    assert "datasource.json" in res.evidence and "sql.json" in res.evidence


# ============================================================
# 3. 注册与路由（这两个坑都实际踩过）
# ============================================================


def test_yudao_plugins_registered():
    """插件必须在 plugin_list 里显式登记（loader 读清单，不是目录扫描）"""
    from core.loader import load_plugins

    names = [cls.name for cls in load_plugins("plugins.yudao")]
    assert "芋道租户列表未授权" in names
    assert "芋道 Druid 监控未授权" in names


def test_yudao_routing_resolves():
    """cms=yudao 必须路由到 plugins.yudao 的非空插件集

    回归史（2026-11-03）：插件最初声明了 variant="yudao"，而 yudao 是 **cms** 不是
    variant——Router.candidates() 拿 fingerprint.variant（空串）比对，整个包被过滤掉，
    resolve() 返回 []，插件一个都不跑。实测表现为「指纹识别对了但插件不执行」。
    """
    from common.models import FingerprintResult
    from core.router import Router

    fp = FingerprintResult(cms="yudao", version="", confidence=0.5, matched=[])
    plugins = Router().resolve(fp)
    assert plugins, "cms=yudao 必须能路由到插件，否则整个包形同虚设"
    names = [cls.name for cls in plugins]
    assert "芋道租户列表未授权" in names


def test_yudao_plugins_do_not_set_variant():
    """yudao 是 cms 不是 variant，插件不得声明 variant（否则被路由过滤掉）"""
    from plugins.yudao.druid_monitor_unauth import YudaoDruidMonitorUnauthPlugin
    from plugins.yudao.tenant_unauth import YudaoTenantUnauthPlugin

    for cls in (YudaoTenantUnauthPlugin, YudaoDruidMonitorUnauthPlugin):
        assert getattr(cls, "variant", "") == "", f"{cls.__name__} 不应声明 variant"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)
