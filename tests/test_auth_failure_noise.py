# 登录墙「认证失败」回显噪声回归测试（2026-10-29 R7 实测）
#
# RuoYi-Vue 未认证访问任意受保护路径返回 HTTP 200 +
#   {"msg":"请求访问：<路径>，认证失败，无法访问系统资源","code":401}
# 正文回显请求路径 → 各类「按路径名/文件名当作存在证据」的判定全部误命中。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.matcher import is_auth_failure_page, match_positive  # noqa: E402
from lib.soft404 import Soft404Baseline  # noqa: E402


def _auth_fail(path):
    return '{"msg":"请求访问：%s，认证失败，无法访问系统资源","code":401}' % path


class FakeResp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.content = text.encode("utf-8")
        self.status_code = status_code


class EchoSession:
    """任意路径都返回 200 + 认证失败 JSON（回显路径），模拟若依登录墙"""

    def get(self, url, **kw):
        path = url.split("//", 1)[-1].split("/", 1)[-1]
        return FakeResp(_auth_fail("/" + path))


def test_is_auth_failure_page():
    assert is_auth_failure_page(_auth_fail("/getInfo"))
    assert not is_auth_failure_page('{"code":200,"rows":[]}')
    assert not is_auth_failure_page("<html>ok</html>")


def test_match_positive_rejects_component_name_in_auth_failure_echo():
    """组件探测：/rocketmq/ 的 401 回显含 "rocketmq" 不能算「RocketMQ 存在」"""
    body = _auth_fail("/rocketmq/")
    assert match_positive(body, ["rocketmq", "RocketMQ"]) is False


def test_match_positive_keeps_auth_block_detection():
    """未授权类插件用「认证失败」作为「已鉴权」正特征，这条必须保留"""
    body = _auth_fail("/system/user/list")
    assert match_positive(body, ["认证失败", "无法访问系统资源"]) is True


def test_soft404_auth_failure_not_a_real_file():
    """登录墙回显对每个路径都不同，仍不能被判成「独立文件」"""
    sess = EchoSession()
    baseline = Soft404Baseline.probe("http://target/", sess)
    assert baseline.is_catch_all
    probe = FakeResp(_auth_fail("/index.bak"))
    assert baseline.looks_like_real_file(probe) is False


def test_soft404_real_file_still_detected():
    """真正存在的文件（非登录墙 JSON）仍要能判出来，避免修复引入漏报"""

    class MixedSession:
        def get(self, url, **kw):
            if "does-not-exist" in url or "__ruoyi_scan_soft404_probe__" in url:
                return FakeResp("<html>not found</html>", 404)
            return FakeResp("PK\x03\x04zip-bytes-here", 200)

    baseline = Soft404Baseline.probe("http://target/", MixedSession())
    assert baseline.looks_like_real_file(FakeResp("PK\x03\x04zip-bytes-here", 200)) is True
