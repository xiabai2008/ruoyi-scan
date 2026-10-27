# 全站拦截探测与 SAFE 降级：审计发现「全站 403 时 22 条误判为 SAFE」，此处锁定修复
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult  # noqa: E402
from lib.reachability import (  # noqa: E402
    detect_blocked,
    downgrade_safe_results,
    upgrade_denied_safe_to_unknown,
)


class _Resp:
    def __init__(self, status=404, server="nginx"):
        self.status_code = status
        self.headers = {"Server": server}


class _Session:
    """按 URL 后缀返回预设状态码的最小会话替身。"""

    def __init__(self, root_status=200, probe_status=404, raise_on_probe=False):
        self.root_status = root_status
        self.probe_status = probe_status
        self.raise_on_probe = raise_on_probe
        self.calls = []

    def get(self, url, **_kw):
        self.calls.append(url)
        if "__ruoyi_scan_block_probe_" in url:
            if self.raise_on_probe:
                raise RuntimeError("connection reset")
            return _Resp(self.probe_status)
        return _Resp(self.root_status)


def _result(name, status):
    return ScanResult(kind="vuln", name=name, status=status, url="http://t/", evidence=f"{name} 原始证据")


def test_blocked_when_random_path_returns_403():
    """随机路径返回 403（而不是 404）说明拦截发生在路由之前"""
    info = detect_blocked(_Session(root_status=403, probe_status=403), "http://t")
    assert info["blocked"] is True
    assert info["status"] == 403
    assert "疑似" in info["reason"]


def test_not_blocked_on_normal_404():
    info = detect_blocked(_Session(root_status=200, probe_status=404), "http://t")
    assert info["blocked"] is False
    assert info["status"] == 404


@pytest.mark.parametrize("code", [401, 403, 429, 503])
def test_blocked_status_codes(code):
    assert detect_blocked(_Session(root_status=code, probe_status=code), "http://t")["blocked"] is True


def test_not_blocked_when_probe_errors_but_root_ok():
    """探测请求本身失败（网络抖动）不算拦截，交给插件判 UNKNOWN"""
    info = detect_blocked(_Session(root_status=200, probe_status=0, raise_on_probe=True), "http://t")
    assert info["blocked"] is False


def test_downgrade_only_safe():
    results = [
        _result("确认项", STATUS_CONFIRMED),
        _result("不存在项", STATUS_SAFE),
        _result("未知项", STATUS_UNKNOWN),
    ]
    n = downgrade_safe_results(results, {"blocked": True, "reason": "随机路径返回 403", "status": 403})
    assert n == 1
    assert results[0].status == STATUS_CONFIRMED  # 有证据的确认项不受影响
    assert results[1].status == STATUS_UNKNOWN
    assert results[2].status == STATUS_UNKNOWN
    assert "目标疑似被拦截" in results[1].evidence
    assert results[1].extra.get("blocked") is True
    assert results[1].extra.get("blocked_status") == 403


def test_downgrade_noop_when_not_blocked():
    results = [_result("不存在项", STATUS_SAFE)]
    assert downgrade_safe_results(results, {"blocked": False}) == 0
    assert results[0].status == STATUS_SAFE


def test_downgrade_noop_on_empty_block_info():
    results = [_result("不存在项", STATUS_SAFE)]
    assert downgrade_safe_results(results, {}) == 0
    assert results[0].status == STATUS_SAFE


def test_denied_safe_becomes_unknown():
    """接口返回 401/403/429 时不能判 SAFE（审计实测：401 下 SQLi/上传被判 SAFE）"""
    results = [
        _result("带 401 的 SAFE", STATUS_SAFE),
        _result("带认证失败的 SAFE", STATUS_SAFE),
        _result("正常否定", STATUS_SAFE),
    ]
    results[0].evidence = '响应未含上传字段：{"code": 401, "msg": "认证失败"}'
    results[1].evidence = "认证失败，无法访问系统资源"
    results[2].evidence = "状态码=404, 未检测到 .git 泄露特征"
    n = upgrade_denied_safe_to_unknown(results)
    assert n == 2
    assert results[0].status == STATUS_UNKNOWN and results[0].extra.get("denied") is True
    assert results[1].status == STATUS_UNKNOWN
    assert results[2].status == STATUS_SAFE  # 真正的 404 否定不受影响


def test_denied_marker_not_fooled_by_incidental_numbers():
    """证据里的 1403 字节 / 路径含 403 不应触发降级"""
    r = _result("长度含 1403", STATUS_SAFE)
    r.evidence = "状态码=404, 长度=1403"
    assert upgrade_denied_safe_to_unknown([r]) == 0
    assert r.status == STATUS_SAFE


def test_login_wall_redirect_and_page():
    """302->/login 与 200 登录页都算登录墙；普通 404 不算（真实 4.7.8 的认证墙是 302 不是 401）"""
    from lib.reachability import login_wall_reason

    class _LoginRedirect:
        status_code = 302
        headers = {"Location": "/login"}
        text = ""

    class _LoginPage:
        status_code = 200
        headers = {}
        text = '<html><title>若依后台管理</title><input name="password"><img src="/captcha/captchaImage"></html>'

    class _Normal:
        status_code = 404
        headers = {}
        text = "404 Not Found"

    assert "登录" in login_wall_reason(_LoginRedirect())
    assert "登录" in login_wall_reason(_LoginPage())
    assert login_wall_reason(_Normal()) == ""


def test_blocked_ignores_plain_rate_limit_and_5xx():
    """随机路径 429/500 但根路径正常 = 限流/应用错误，不是全站拦截（对抗审计实测误报）"""
    assert detect_blocked(_Session(root_status=200, probe_status=429), "http://t")["blocked"] is False
    assert detect_blocked(_Session(root_status=200, probe_status=500), "http://t")["blocked"] is False
    assert detect_blocked(_Session(root_status=200, probe_status=502), "http://t")["blocked"] is False
    assert detect_blocked(_Session(root_status=429, probe_status=429), "http://t")["blocked"] is True


def test_denied_regex_ignores_negated_or_positive_evidence():
    """「未含 Forbidden」「没有权限访问用户数据（防护生效）」不应被降级"""
    results = [
        _result("未含关键词", STATUS_SAFE),
        _result("防护生效", STATUS_SAFE),
    ]
    results[0].evidence = "响应未含 Forbidden 关键字，未发现目录列表"
    results[1].evidence = "没有权限访问用户数据（防护生效）"
    assert upgrade_denied_safe_to_unknown(results) == 0


def test_detect_auth_wall_and_downgrade_only_200_evidence():
    """真实 4.7.8 的登录墙是 200 登录页；只有缺少 4xx 证据的 SAFE 才降级"""
    from lib.reachability import detect_auth_wall, downgrade_auth_wall_safe

    class _LoginSession:
        def get(self, url, **_kw):
            r = _Resp(200)
            r.text = '<html><title>若依后台管理</title><input name="password"><img src="/captcha/captchaImage"></html>'
            r.url = url
            return r

    wall = detect_auth_wall(_LoginSession(), "http://t")
    assert wall["wall"] is True

    results = [
        _result("登录页上判 SAFE", STATUS_SAFE),
        _result("404 判 SAFE", STATUS_SAFE),
        _result("确认项", STATUS_CONFIRMED),
    ]
    results[0].evidence = "状态码=200 但未命中环境变量关键字"
    results[1].evidence = "状态码=404, 未发现 .git 泄露特征"
    assert downgrade_auth_wall_safe(results, wall) == 1
    assert results[0].status == STATUS_UNKNOWN
    assert results[0].extra.get("auth_wall") is True
    assert results[1].status == STATUS_SAFE
    assert results[2].status == STATUS_CONFIRMED


def test_unreachable_safe_becomes_unknown():
    """SAFE 证据显示基线探测/连接失败：网络异常不能冒充 SAFE"""
    r = _result("备份文件泄露", STATUS_SAFE)
    r.evidence = "基线探测未取得响应"
    assert upgrade_denied_safe_to_unknown([r]) == 1
    assert r.status == STATUS_UNKNOWN
    assert r.extra.get("unreachable") is True
