"""RocketMQ Dashboard 探测路径回归：真实控制台在根路径，不在 /rocketmq/。

背景（2026-11-01 C4-3 靶场实测）
--------------------------------
`rocketmq-console-ng`（现名 rocketmq-dashboard）是**独立的 Spring Boot Web 应用**，
官方发布包默认 `context-path` 为空 —— 控制台直接挂在 `/`。

旧实现只探三条「猜出来的前缀」：

    /rocketmq/  /dashboard/  /rocketmq-console-ng/

真实部署一条都命中不了。C4-3 靶场复刻真实路由后实测：

    GET /                     → 200，正文含 mqnamesrv / RocketMQ Dashboard
    GET /rocketmq/            → 404
    GET /dashboard/           → 404
    GET /rocketmq-console-ng/ → 404
    → 旧实现判 SAFE **漏报**

这也解释了该插件在历史产物里从未 CONFIRMED 过的原因：不是判定逻辑错，
是**从来没探到过**任何真实控制台。

修复：把 "/" 加入候选且置于首位。根路径命中依赖 RocketMQ 专有标识
（rocketmq / mqnamesrv），配合 negatives=["login","sign in"] 排除登录页，
不会把普通站点误判成未授权控制台。
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.common.rocketmq_unauth import RocketmqUnauthPlugin  # noqa: E402

# 真实 dashboard 首页的最小特征（含标题与全局 JS 变量）
DASHBOARD_HTML = """<!DOCTYPE html>
<html><head><title>RocketMQ Dashboard</title>
<script>
  var mqnamesrv = "10.20.30.41:9876";
  var rocketmqCluster = "rocketmq-cluster-prod";
</script></head>
<body><h1>RocketMQ Dashboard</h1>
<div>NameServer 地址：10.20.30.41:9876</div>
</body></html>"""

LOGIN_HTML = """<html><head><title>RocketMQ Dashboard - Login</title></head>
<body><form action="/login"><input name="username"><button>Sign In</button></form></body></html>"""


class _Resp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


class _Session:
    """按 URL 返回预设响应；未登记的 URL 一律 404。"""

    def __init__(self, mapping):
        self.mapping = mapping
        self.requested = []

    def get(self, url, **kw):
        self.requested.append(url)
        for suffix, resp in self.mapping.items():
            if url.endswith(suffix):
                return resp
        return _Resp("not found", 404)


TARGET = "http://dashboard.test/"


def test_dashboard_at_root_is_confirmed():
    """控制台挂在根路径（真实部署形态）→ 必须 CONFIRMED。

    这是缺陷的直接回归：修复前 "/" 不在候选里，同一份响应会判 SAFE。
    """
    sess = _Session({"/": _Resp(DASHBOARD_HTML, 200)})
    result = RocketmqUnauthPlugin().verify(TARGET, sess)
    assert result.status == "CONFIRMED", f"根路径控制台漏报：{result.evidence}"
    assert result.url == TARGET


def test_root_probe_in_candidate_list():
    """探测候选里必须包含根路径，且不只依赖前缀猜测。"""
    from plugins.common.rocketmq_unauth import RocketmqUnauthPlugin as P

    # 通过实际行为断言，而不是读源码里的常量
    sess = _Session({"/": _Resp(DASHBOARD_HTML, 200)})
    P().verify(TARGET, sess)
    assert TARGET in sess.requested, f"未探测根路径，实际请求：{sess.requested}"


def test_login_page_at_root_is_not_confirmed():
    """根路径是控制台**登录页**时不算未授权。

    新增 "/" 候选最大的风险就在这里：带鉴权的控制台根路径也会返回 200，
    必须靠 negatives=["login","sign in"] 挡住。
    """
    sess = _Session({"/": _Resp(LOGIN_HTML, 200)})
    result = RocketmqUnauthPlugin().verify(TARGET, sess)
    assert result.status != "CONFIRMED", "登录页被误判为未授权控制台"


def test_plain_site_is_safe():
    """普通站点（无 RocketMQ 标识）→ SAFE，不因新增根路径探测而误报。"""
    plain = "<html><head><title>明德教务管理系统</title></head><body>课程管理</body></html>"
    sess = _Session({"/": _Resp(plain, 200)})
    result = RocketmqUnauthPlugin().verify(TARGET, sess)
    assert result.status == "SAFE"


def test_prefix_deployment_still_works():
    """少数反向代理按前缀挂载时，旧的 /rocketmq/ 候选仍要能命中。"""
    sess = _Session({"/rocketmq/": _Resp(DASHBOARD_HTML, 200)})
    result = RocketmqUnauthPlugin().verify(TARGET, sess)
    assert result.status == "CONFIRMED"


def test_prefix_deployment_still_works_even_when_root_is_404():
    """只有前缀有内容、根路径 404 时，仍要命中（不能因为加了 / 就提前放弃）。"""
    sess = _Session({"/rocketmq-console-ng/": _Resp(DASHBOARD_HTML, 200)})
    result = RocketmqUnauthPlugin().verify(TARGET, sess)
    assert result.status == "CONFIRMED", f"前缀部署漏报：{result.evidence}"


@pytest.mark.parametrize("marker", ["rocketmq", "mqnamesrv"])
def test_each_proprietary_marker_suffices(marker):
    """rocketmq 与 mqnamesrv 任一出现即可命中（两个都是专有标识）。"""
    html = f"<html><head><title>console</title></head><body>{marker} 控制台</body></html>"
    sess = _Session({"/": _Resp(html, 200)})
    result = RocketmqUnauthPlugin().verify(TARGET, sess)
    assert result.status == "CONFIRMED", f"专有标识 {marker} 未命中"
