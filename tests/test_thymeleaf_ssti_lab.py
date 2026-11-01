"""Thymeleaf/SpEL 视图名注入：C4-6 真实靶场验证 + 判定纪律。

背景
====
该插件的判定要求「求值结果 49 + 引擎强特征」同时出现，这是正确的保守策略：
只有 49 会误报（页码/时间戳/行号），只有引擎特征也无法证明表达式被执行。

C4-6 靶场用真实 SpelExpressionParser 复刻 __${}__ 求值，返回的 500 报错页
同时含 `49` 与 `org.thymeleaf` —— 正好是判定所需的最小组合。

本测试锁住三件事：
1. 真实靶场形态（49 + 引擎特征）能 CONFIRMED
2. 只有 49 没引擎特征 → 不 CONFIRMED
3. 登录墙 → UNKNOWN（不判 SAFE）
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.ruoyi.thymeleaf_ssti import ThymeleafSstiPlugin  # noqa: E402

TARGET = "http://thymeleaf.test/"

# C4-6 真实响应（500 报错页）
LAB_RESPONSE = """<html><body><h1>Whitelabel Error Page</h1>
<p>org.thymeleaf.exceptions.TemplateInputException: Error resolving template [49::.x],
template might not exist or might not be accessible by any of the configured Template Resolvers</p>
<p>TemplateProcessingException: could not parse template [49::.x]</p>
<pre>SpEL 求值: ${7*7} = 49</pre></body></html>"""

# 只有 49、没有引擎特征（普通页面上恰好出现的数字）
PLAIN_WITH_49 = "<html><body><p>共 49 条记录</p></body></html>"

# 登录墙（单机版未认证）
LOGIN_PAGE = """<html><head><title>登录若依系统</title></head><body>
<form id="loginForm"><input name="password" type="password"></form>
<img src="/captcha/captchaImage"/></body></html>"""


class _Resp:
    def __init__(self, text="", status_code=200, location=""):
        self.text = text
        self.status_code = status_code
        self.headers = {"Location": location} if location else {}


class _Session:
    def __init__(self, resp):
        self.resp = resp
        self.urls = []

    def get(self, url, **kw):
        self.urls.append(url)
        return self.resp


# ── 真实靶场形态 ────────────────────────────────────────


def test_real_spel_evaluation_is_confirmed():
    """C4-6 真实求值响应（49 + org.thymeleaf）→ CONFIRMED。"""
    result = ThymeleafSstiPlugin().verify(TARGET, _Session(_Resp(LAB_RESPONSE, 500)))
    assert result.status == "CONFIRMED", f"真实 SSTI 漏报：{result.evidence}"


# ── 判定纪律：缺一不可 ──────────────────────────────────


def test_49_without_engine_evidence_is_not_confirmed():
    """只有 49、无引擎特征 → 不 CONFIRMED（防页码/计数类误报）。"""
    result = ThymeleafSstiPlugin().verify(TARGET, _Session(_Resp(PLAIN_WITH_49, 200)))
    assert result.status != "CONFIRMED", f"仅有 49 就判 CONFIRMED：{result.evidence}"


def test_engine_evidence_without_49_is_not_confirmed():
    """只有引擎报错、没有求值结果 → 不 CONFIRMED（表达式没被执行）。"""
    no_eval = LAB_RESPONSE.replace("49", "0")
    result = ThymeleafSstiPlugin().verify(TARGET, _Session(_Resp(no_eval, 500)))
    assert result.status != "CONFIRMED", "无求值结果却判 CONFIRMED"


def test_login_wall_is_unknown_not_safe():
    """登录墙拦截 → UNKNOWN（测不到 ≠ 不存在）。"""
    result = ThymeleafSstiPlugin().verify(TARGET, _Session(_Resp(LOGIN_PAGE, 200)))
    assert result.status == "UNKNOWN", f"登录墙被判成 {result.status}，应为 UNKNOWN"


def test_plain_site_is_safe():
    """普通站点（无 49 无引擎特征）→ SAFE。"""
    plain = "<html><body><h2>明德职教管理系统</h2></body></html>"
    result = ThymeleafSstiPlugin().verify(TARGET, _Session(_Resp(plain, 200)))
    assert result.status == "SAFE"


# ── 探针构造 ────────────────────────────────────────────


def test_probe_is_url_encoded():
    """探测路径里的 ${} 必须做百分号编码，否则 Tomcat 会剥离花括号。

    与 C4-6 靶场侧同一个坑：裸 ${7*7} 在路径中会被当成路径变量边界吃掉，
    服务端收到的表达式失去求值能力。
    """
    sess = _Session(_Resp(PLAIN_WITH_49, 200))
    ThymeleafSstiPlugin().verify(TARGET, sess)
    assert sess.urls, "未发出任何请求"
    # 至少有一条请求带编码后的表达式
    encoded_hits = [u for u in sess.urls if "%24%7B" in u or "%24%7b" in u]
    assert encoded_hits, f"探针未做编码，实际请求：{sess.urls[:3]}"


def test_probe_tries_multiple_candidates():
    """多个候选路径都要试（任一命中即判存在）。"""
    sess = _Session(_Resp(LAB_RESPONSE, 500))
    ThymeleafSstiPlugin().verify(TARGET, sess)
    # 命中第一个就该停，所以只断言至少发过请求且带了预期后缀
    assert any("::.x" in u or "%3A%3A.x" in u for u in sess.urls)
