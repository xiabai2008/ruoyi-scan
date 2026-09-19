# -*- coding: utf-8 -*-
"""误报基线门禁：把「确定不含漏洞」的响应喂给全部插件，断言零 CONFIRMED。

存在意义
========
本仓库此前的误报测试只有 tests/test_fp_lab.py，而它仅覆盖**指纹识别层**的假阳率
（11 个靶场页面是否被误判为若依），完全不覆盖**插件判定层**。

实测结果（2026-09-16 审计）：51 个插件中有 5 个会对一个完全正常的 200 HTML
页面返回 CONFIRMED，即约 9.8% 的插件存在「基线误报」。而当时的测试套件
（1,180 个测试函数）对此零告警，因为其中只有 102 处真正调用过 verify()。

本文件把插件判定层的误报基线固化为 CI 门禁：任何插件在良性语料上返回
CONFIRMED，测试立即失败并列出责任插件。

维护约定
========
1. 新增语料前先自问：「一个完全健康的若依站点，会不会返回这个响应？」
   会 → 该语料合格；不会 → 它不是良性语料，请放到 attack-fixture 目录而不要放这里。
2. 不得为了让测试通过而删除语料、加 skip 或放宽断言。
3. 某些插件若确实需要放宽判定，必须同时在 KNOWN_FALSE_POSITIVES 中登记，
   并写明原因与跟进计划——让技术债可见，而不是藏起来。
"""

import os
import sys

import pytest
import requests_mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED  # noqa: E402
from core.loader import discover_plugin_packages, load_plugins  # noqa: E402
from core.session import SessionManager  # noqa: E402

# 已登记的已知误报（插件全名 → 原因/跟进计划）。
# 目标状态是空字典。新增条目必须在 PR 描述中说明，并在报告中同步记录。
KNOWN_FALSE_POSITIVES = {}


# ---------------------------------------------------------------------------
# 良性语料：这些响应都来自「不存在漏洞」的正常站点
# ---------------------------------------------------------------------------

BENIGN_CASES = {
    # 1. 通用业务页面。特意包含「49」与「template」——这两个字符串历史上
    #    曾分别误触发 Thymeleaf SSTI 插件的求值判定与引擎特征判定。
    "generic_html": (
        "<!DOCTYPE html><html><head><title>若依后台管理系统</title>"
        "<meta name='description' content='template for enterprise management'>"
        "</head><body><div id='app'><p>共 49 条记录</p><p>当前版本 4.7.8</p>"
        "</div></body></html>"
    ),
    # 2. Vue 前端壳页：SSR 前的空壳，很多若依前端部署后会命中这个形态
    "spa_shell": (
        "<!DOCTYPE html><html><head><title>若依后台管理系统</title></head>"
        "<body><div id='app'></div><script src='/js/app.js'></script></body></html>"
    ),
    # 3. 软 404：状态码 200 但内容表示页面不存在（目录扫描/未授权判定的经典陷阱）
    "soft_404": (
        "<!DOCTYPE html><html><head><title>页面不存在</title></head>"
        "<body><h1>抱歉，您访问的页面不存在</h1></body></html>"
    ),
    # 4. 非若依站点的常见欢迎页：确认插件不会在异质目标上乱喊
    "nginx_welcome": (
        "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head>"
        "<body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web "
        "server is successfully installed.</p></body></html>"
    ),
    # 5. 空壳 200：最小响应体，考验插件是否仅凭状态码就下结论
    "empty_shell": "<html><head></head><body></body></html>",
    # 6. 真若依登录页形态：含验证码字段名 code 与 msg 字样。
    #    来源：2026-09-17 多版本矩阵在真实的 RuoYi 4.7.8 实例上发现的误报——
    #    plus_auth_login 跟随 302 落到此页后，用 `match_positive(text, ["code","msg"])`
    #    子串匹配把「验证码字段名」当成「业务 JSON 特征」而误报 CONFIRMED。
    #    该用例锁定「HTML 文案不得当作 JSON 业务特征」这一约束。
    "ruoyi_login_page": (
        "<!DOCTYPE html><html><head><title>登录若依系统</title></head><body>"
        '<form id="formLogin"><input name="username" type="text">'
        '<input name="password" type="password">'
        '<input name="code" type="text" placeholder="验证码">'
        '<img id="codeImg"><span class="msg"></span>'
        '<button type="submit">登 录</button></form></body></html>'
    ),
}


# ---------------------------------------------------------------------------
# 误报陷阱语料：这些响应的设计目的是「诱惑弱判定规则误报」，但目标本身无漏洞
# ---------------------------------------------------------------------------

FALSE_POSITIVE_TRAPS = {
    # WAF 拦截页原样回显了请求报文。载荷原文里必然含 database() 与 extractvalue(1,，
    # 历史上 SQL 注入插件用 `'database()' in text` 判定，会在此处「自证命中」。
    "attack_reflection": (
        "<html><body><h1>403 Forbidden</h1>"
        "<p>您的请求包含可疑字符，已拦截：</p>"
        "<pre>params[dataScope]=and extractvalue(1, concat(0x7e,(select database()),0x7e))</pre>"
        "<p>如有疑问请联系管理员</p></body></html>"
    ),
    # 框架通用异常页：只有「运行时异常」这类泛化文案，没有任何注入证据
    "generic_error_page": (
        "<html><body><h1>500 Internal Server Error</h1>"
        "<p>运行时异常，请稍后重试</p></body></html>"
    ),
}


def _all_plugin_classes():
    """枚举全部已发现插件包中的插件类"""
    classes = []
    for pkg in discover_plugin_packages():
        try:
            for cls in load_plugins(pkg):
                classes.append((pkg, cls))
        except Exception:
            # 单个插件包加载失败不阻断基线测试，由其他测试负责报告
            continue
    return classes


def _run_baseline(body: str, content_type: str = "text/html; charset=utf-8"):
    """把同一份响应喂给全部插件，返回谎报 CONFIRMED 的插件清单

    使用 requests_mock 拦截任意方法 + 任意 URL，因此插件对路径/方法的差异
    不会影响结论——真正做到「无论请求什么，目标就是正常的」。
    """
    offenders = []
    errors = []
    with requests_mock.Mocker() as m:
        m.register_uri(
            requests_mock.ANY,
            requests_mock.ANY,
            text=body,
            status_code=200,
            headers={"Content-Type": content_type},
        )
        for pkg, cls in _all_plugin_classes():
            full_name = f"{pkg}.{cls.__module__.rsplit('.', 1)[-1]}"
            if full_name in KNOWN_FALSE_POSITIVES:
                continue
            try:
                # 每个插件独立会话，避免相互污染计数与 Cookie
                result = cls().verify("http://fp-baseline.test", SessionManager())
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{full_name} :: {type(exc).__name__}: {exc}")
                continue
            if getattr(result, "status", None) == STATUS_CONFIRMED:
                evidence = (getattr(result, "evidence", "") or "")[:100]
                offenders.append(f"{full_name} :: {evidence}")
    return offenders, errors


def _assert_baseline_clean(case_name: str, body: str, content_type: str = "text/html; charset=utf-8") -> None:
    offenders, errors = _run_baseline(body, content_type)
    assert not offenders, (
        f"[{case_name}] 良性响应被误判为 CONFIRMED——插件判定层的误报基线被破坏。\n"
        f"这些插件需要加固判定逻辑，而不是把本用例删掉：\n  - " + "\n  - ".join(offenders)
    )
    assert not errors, (
        f"[{case_name}] 以下插件在良性响应上抛异常（插件应容错并返回 UNKNOWN，不得抛出）：\n  - " + "\n  - ".join(errors)
    )


@pytest.mark.parametrize("case_name,body", sorted(BENIGN_CASES.items()))
def test_no_false_positive_on_benign_response(case_name, body):
    """良性响应：任何插件都不得判 CONFIRMED"""
    _assert_baseline_clean(case_name, body)


@pytest.mark.parametrize("case_name,body", sorted(FALSE_POSITIVE_TRAPS.items()))
def test_no_false_positive_on_trap_response(case_name, body):
    """误报陷阱响应：目标本身无漏洞，任何插件都不得判 CONFIRMED"""
    _assert_baseline_clean(case_name, body)


def test_baseline_corpus_not_empty():
    """护栏：语料被清空时本门禁会静默失效，必须显式拦截"""
    assert len(BENIGN_CASES) >= 5, "良性语料不得少于 5 条"
    assert len(FALSE_POSITIVE_TRAPS) >= 2, "误报陷阱语料不得少于 2 条"
