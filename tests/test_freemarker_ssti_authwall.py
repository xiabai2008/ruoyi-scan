"""JeecgBoot 报表 SSTI：鉴权墙不该判 SAFE + 真实模板求值能 CONFIRMED。

两个独立问题（2026-11-01 C4-4 靶场 + R10 实测）
=============================================

## 问题一：鉴权拒绝被当成「不存在」（假阴性）

真实 JeecgBoot（实测 3.6.3）对无 Token 的 `/jeecg-boot/jmreport/**` 返回：

    HTTP 200
    {"code":500,"success":false,"message":"Token校验失败，无权限访问！","timestamp":...}

三个特征叠在一起，让通用兜底 `lib/reachability._DENY_RE` 全部抓不到：

| 特征 | 通用兜底的期望 | 真实情况 |
|---|---|---|
| HTTP 状态码 | 401 / 403 / 429 | **200** |
| body code | 401 | **500** |
| 文案 | "认证失败" | "无权限访问" |

于是旧实现按"没命中 SSTI 特征"判 SAFE —— 把「没资格测」写成了「确认不存在」。
这是本插件历史上从未 CONFIRMED 的直接原因之一。

## 问题二：真实模板求值必须能命中

C4-4 靶场用**真实 Freemarker 引擎**渲染 connUrl（不是 marker 桩）：
`connUrl="...?query=${7*7}"` → 响应里出现 `49`。

扫描器必须真的构造出会被求值的表达式才可能命中，无法靠猜字符串过。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.jeecgboot.freemarker_ssti import (  # noqa: E402
    JeecgFreemarkerSstiPlugin,
    _jmreport_auth_wall,
)


class _Resp:
    def __init__(self, text="", status_code=200, content_type="application/json;charset=utf-8"):
        self.text = text
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}


class _Session:
    def __init__(self, resp):
        self.resp = resp
        self.posted = []

    def post(self, url, **kw):
        self.posted.append((url, kw.get("data")))
        return self.resp

    def get(self, url, **kw):
        return self.resp


TARGET = "http://jeecg.test/"

# 真实 R10 抓到的原文
AUTH_WALL_BODY = '{"code":500,"success":false,"message":"Token校验失败，无权限访问！","timestamp":1793524111561}'
# 真实 C4-4 抓到的原文（${7*7} 被求值成 49）
SSTI_HIT_BODY = '{"code":200,"success":true,"connUrl":"jdbc:mysql://127.0.0.1:3306/test?query=49","dbType":"MYSQL","message":"连接成功"}'


# ── 鉴权墙判定 ────────────────────────────────────────────


def test_auth_wall_detected_on_real_body():
    """真实的 Token 校验失败响应必须被识别为鉴权墙。"""
    reason = _jmreport_auth_wall(_Resp(AUTH_WALL_BODY))
    assert reason, "真实鉴权拒绝响应未被识别"
    assert "Token校验失败" in reason or "无权限" in reason


def test_auth_wall_returns_unknown_not_safe():
    """鉴权墙 → UNKNOWN，不能是 SAFE（测不到 ≠ 不存在）。"""
    result = JeecgFreemarkerSstiPlugin().verify(TARGET, _Session(_Resp(AUTH_WALL_BODY)))
    assert result.status == "UNKNOWN", f"鉴权拒绝被判成 {result.status}，应为 UNKNOWN"
    assert "鉴权" in result.evidence or "Token" in result.evidence


def test_auth_wall_variants_all_detected():
    """不同版本/网关的鉴权文案都要覆盖（不能只认一句）。"""
    bodies = [
        '{"code":500,"message":"Token校验失败，无权限访问！"}',
        '{"success":false,"message":"请先登录"}',
        '{"code":401,"message":"unauthorized"}',
        '{"code":401,"message":"认证失败，无法访问系统资源"}',
        '{"message":"Access Denied"}',
    ]
    for body in bodies:
        assert _jmreport_auth_wall(_Resp(body)), f"未识别鉴权响应: {body}"


def test_html_error_page_not_treated_as_auth_wall():
    """HTML 页面里偶然出现 access denied 不算鉴权墙（避免误判）。"""
    html = "<html><body><h1>404</h1><p>The requested URL was not found</p></body></html>"
    assert not _jmreport_auth_wall(_Resp(html, content_type="text/html"))


# ── 真实模板求值 ──────────────────────────────────────────


def test_real_template_evaluation_is_confirmed():
    """真实 Freemarker 求值（49 + JSON + 无 7*7 回显）→ CONFIRMED。"""
    result = JeecgFreemarkerSstiPlugin().verify(TARGET, _Session(_Resp(SSTI_HIT_BODY)))
    assert result.status == "CONFIRMED", f"真实求值漏报：{result.evidence}"


def test_number_boundary_not_fooled_by_490():
    """490/1490 里的 49 不算求值结果（正则数字边界）。"""
    body = '{"code":200,"success":true,"connUrl":"query=1490","message":"ok"}'
    result = JeecgFreemarkerSstiPlugin().verify(TARGET, _Session(_Resp(body)))
    assert result.status != "CONFIRMED", "1490 被误判为 ${7*7}=49"


def test_raw_payload_echo_is_not_confirmed():
    """载荷被原样回显（仍含 7*7）→ 不算求值。"""
    body = '{"code":200,"success":true,"connUrl":"query=${7*7}","message":"ok"}'
    result = JeecgFreemarkerSstiPlugin().verify(TARGET, _Session(_Resp(body)))
    assert result.status != "CONFIRMED", "载荷原样回显被当成求值成功"


def test_plain_site_is_safe():
    """普通站点（非 JSON 或不含求值迹象）→ SAFE。"""
    body = '{"code":200,"success":true,"connUrl":"jdbc:mysql://h/db","message":"连接成功"}'
    result = JeecgFreemarkerSstiPlugin().verify(TARGET, _Session(_Resp(body)))
    assert result.status == "SAFE"


# ── 顺序：鉴权墙判定必须先于求值判定 ──────────────────────


def test_auth_wall_checked_before_ssti_evidence():
    """响应同时含鉴权文案与 49 时，应以鉴权墙为准判 UNKNOWN。

    真实场景：WAF 拒绝页正文里可能带页码/时间戳里的 49，
    若先跑 SSTI 判定会误报 CONFIRMED。
    """
    body = '{"code":500,"success":false,"message":"Token校验失败，无权限访问！","timestamp":1793524114950}'
    result = JeecgFreemarkerSstiPlugin().verify(TARGET, _Session(_Resp(body)))
    assert result.status == "UNKNOWN", f"含鉴权文案的响应被判成 {result.status}"
