"""WAF 行为识别与报告字段：R12/R13 自定义网关没有静态签名。"""

from core.fingerprint import detect_waf


class _Resp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _WafSession:
    timeout = 5

    def __init__(self, block_attacks=True):
        self.block_attacks = block_attacks

    def get(self, url, **kwargs):
        if self.block_attacks and ("union%20select" in url or "etc%2Fpasswd" in url):
            return _Resp(403, "访问被拒绝")
        return _Resp(200, "ok")


def test_behavioral_waf_detects_custom_gateway():
    result = detect_waf("http://target/", _WafSession(block_attacks=True))
    assert result["waf"] == "generic-http-filter"
    assert "行为识别" in result["display"]


def test_behavioral_waf_does_not_flag_normal_app():
    result = detect_waf("http://target/", _WafSession(block_attacks=False))
    assert result["waf"] == ""


def test_behavioral_waf_skips_when_benign_already_denied():
    class _Denied(_WafSession):
        def get(self, url, **kwargs):
            return _Resp(403, "forbidden")

    assert detect_waf("http://target/", _Denied())["waf"] == ""
