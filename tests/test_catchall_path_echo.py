"""catch-all 路径回显：不能把「页面里出现请求路径」当成组件存在。

背景（2026-11-01 盲测 v2 C4-6 实测）
====================================
靶场用 `/**` 路由兜底时，任意路径都返回 200 HTML，页面标题/正文里带着请求路径：

    GET /rocketmq/        → <html><body><h2>页面: rocketmq/</h2></body></html>
    GET /swagger-ui.html  → <html><body><h2>页面: swagger-ui.html</h2></body></html>
    GET /index.bak        → <html><body><h2>页面: index.bak</h2></body></html>

组件探测类插件拿路径名当关键字（"rocketmq" / "swagger-ui"），于是 100% 误判：

| 插件 | 修复前 |
|---|---|
| RocketMQ Dashboard 未授权 | 误报 |
| RuoYi Swagger 未授权访问 | 误报 |
| 未授权访问（批量） | 误报 |
| 备份文件泄露 | **60 个假备份** |

更麻烦的是：这类 catch-all **每个路径响应长度都不同**（路径越长，长度越长），
所以长度比对、逐字节摘要、归一化摘要全部失效 —— 只能靠「页面里出现了路径」识别。

修复：`lib/matcher.is_path_echo_page()` + `lib/soft404._html_echoes_path()`，
并在 rocketmq_unauth / ruoyi_swagger_unauth / unauth_batch / soft404 基线里接入。

实测效果（C4-6）：目录扫描命中 68 → 5，CONFIRMED 4 → 1（只剩真的 Thymeleaf SSTI）。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.matcher import is_path_echo_page  # noqa: E402
from lib.soft404 import _html_echoes_path  # noqa: E402

# ── 路径回显判据 ─────────────────────────────────────────


def test_echo_page_with_full_path_is_detected():
    """页面回显完整请求路径 → 判定为 catch-all。"""
    body = "<html><body><h2>页面: rocketmq/</h2></body></html>"
    assert is_path_echo_page(body, "/rocketmq/") is True


def test_echo_page_with_basename_is_detected():
    """只回显文件名也算（有些框架只回显 basename）。"""
    body = "<html><body><h2>页面: swagger-ui.html</h2></body></html>"
    assert is_path_echo_page(body, "/swagger-ui.html") is True


def test_real_swagger_ui_is_not_echo():
    """真实 Swagger UI 页面不能被误判。

    它是个几十 KB 的页面，远超短页面阈值，且正文不含请求路径。
    """
    real = "<html><head><title>Swagger UI</title></head><body>" + "x" * 5000 + "</body></html>"
    assert is_path_echo_page(real, "/swagger-ui.html") is False


def test_real_git_head_is_not_echo():
    """真实 .git/HEAD 内容是 ref 引用，不含请求路径。"""
    assert is_path_echo_page("ref: refs/heads/master\n", "/.git/HEAD") is False


def test_real_env_file_is_not_echo():
    """真实 .env 是配置行，不含请求路径。"""
    body = "APP_ENV=prod\nDB_HOST=10.20.30.21\nDB_PASSWORD=secret123"
    assert is_path_echo_page(body, "/.env") is False


def test_empty_request_path_is_conservative():
    """没给请求路径时不误杀 —— 老调用方没传 path 的情况必须保持旧行为。"""
    body = "<html><body><h2>页面: rocketmq/</h2></body></html>"
    assert is_path_echo_page(body, "") is False


def test_non_html_body_is_not_echo():
    """非 HTML 响应不走这条判据（JSON/纯文本由其它规则处理）。"""
    assert is_path_echo_page('{"code":200,"msg":"ok"}', "/rocketmq/") is False


# ── soft404 基线侧的同款判据 ─────────────────────────────


def test_soft404_detects_backup_echo():
    """backup_scan 的 60 个假备份就是这个形态。"""
    body = "<html><body><h2>页面: index.bak</h2></body></html>".encode("utf-8")
    assert _html_echoes_path(body, "/index.bak") is True


def test_soft404_does_not_flag_real_backup():
    """真实备份 SQL 内容不该被判成回显。"""
    body = b"-- MySQL dump\nCREATE TABLE sys_user (id int);\nINSERT INTO sys_user VALUES (1);"
    assert _html_echoes_path(body, "/backup/ry.sql") is False


def test_soft404_ignores_large_html():
    """大 HTML 页面不走这条判据（避免误杀真实页面）。"""
    body = ("<html><body>" + "x" * 2000 + "index.bak</body></html>").encode()
    assert _html_echoes_path(body, "/index.bak") is False


def test_soft404_handles_empty_input():
    """空输入不崩。"""
    assert _html_echoes_path(b"", "/index.bak") is False
    assert _html_echoes_path(b"<html></html>", "") is False


def test_real_short_druid_monitor_is_not_echo():
    """真实短页面（不足 150 字节）不能被按整页长度误判成回显。

    2026-11-02 实测：regression_ruoyi 的 Druid 监控用例（88 字节页面）被
    "残留 < 整页一半" 算法误判成路径回显 → CONFIRMED 退化为 SAFE。
    修正为按「残留 / 正文有效内容」比例判断。
    """
    body = (
        "<html><head><title>Druid Stat Index</title></head>"
        "<body>Druid Monitor View</body></html>"
    )
    assert is_path_echo_page(body, "druid/index.html") is False


def test_soft404_short_real_page_is_not_echo():
    """soft404 同款判据：88 字节的真实 Druid 页不是路径回显。"""
    body = (
        "<html><head><title>Druid Stat Index</title></head>"
        "<body>Druid Monitor View</body></html>"
    ).encode()
    assert _html_echoes_path(body, "/druid/index.html") is False
