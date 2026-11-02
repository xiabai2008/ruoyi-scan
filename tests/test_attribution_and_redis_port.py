# 归属判定 + Redis 端口可配（v1.5.6 WP2/WP6）回归测试
#
# 两条独立的能力，共同解决同一类问题：
#   1. WP2 Redis 端口可配——中间件常跑在非默认端口，写死 6379 时恒判 UNKNOWN；
#   2. WP6 归属判定——探「目标主机的另一个端口」拿到的漏洞属于这台主机，
#      不属于被扫的这个站点。不标注时批量扫描会给每份站点报告都塞同一条宿主漏洞。
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN  # noqa: E402
from lib.attribution import (  # noqa: E402
    ATTR_KEY,
    SCOPE_HOST,
    SCOPE_SITE,
    annotate,
    classify,
    scope_of,
)


class _Result:
    """最小 ScanResult 替身：归属层只读 status/url/extra"""

    def __init__(self, url, status=STATUS_CONFIRMED, name="某插件"):
        self.url = url
        self.status = status
        self.name = name
        self.extra = {}


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}


class _FakeSession:
    def get(self, url, **_kw):
        return _Resp()


class _FakeSocket:
    def __init__(self, recv_data=b"# Server\r\nredis_version:5.0.14\r\n"):
        self.recv_data = recv_data

    def sendall(self, data):
        pass

    def settimeout(self, t):
        pass

    def recv(self, n):
        data, self.recv_data = self.recv_data[:n], self.recv_data[n:]
        return data

    def close(self):
        pass


# ============================================================
# 1. 归属判定：探测坐标的端口轴才是判据
# ============================================================


def test_same_origin_is_site_level():
    """同源同端口 → 站点级（含 base-path 前缀，前缀不改变归属）"""
    assert classify("http://10.0.0.5:8080/", "http://10.0.0.5:8080/login")["scope"] == SCOPE_SITE
    assert classify("http://10.0.0.5:8080/", "http://10.0.0.5:8080/prod-api/v3/api-docs")["scope"] == SCOPE_SITE


def test_other_port_is_host_level():
    """站点在 8080、探的是 6379 → 宿主级（这正是 2026-11-02 R1/C4-1 的实测场景）"""
    info = classify("http://127.0.0.1:19101/", "127.0.0.1:16379")
    assert info["scope"] == SCOPE_HOST
    assert "16379" in info["reason"]


def test_default_port_is_normalized():
    """显式 :80 与不带端口等价；:443 与 https 方案等价（不能因写法不同误判归属）"""
    assert classify("http://a.test/", "http://a.test:80/x")["scope"] == SCOPE_SITE
    assert classify("https://a.test/", "https://a.test:443/x")["scope"] == SCOPE_SITE
    # https 站点探 http:80 是另一个端口：
    assert classify("https://a.test/", "http://a.test:80/x")["scope"] == SCOPE_HOST


def test_other_host_is_not_attributable():
    """完全不同主机也不能归属该站点（CDN 回源/子域等其他情况）"""
    info = classify("http://a.test/", "http://b.test:8080/x")
    assert info["scope"] == SCOPE_HOST
    assert "不同" in info["reason"]


def test_empty_url_does_not_invent_attribution():
    """结果没给探测地址时按站点级处理——归属是附加信息，不能凭空造标记"""
    assert classify("http://a.test/", "")["scope"] == SCOPE_SITE


def test_malformed_url_is_tolerated():
    """畸形探测地址不能让扫描崩掉，退回站点级"""
    assert classify("http://a.test/", "http://[::bad")["scope"] == SCOPE_SITE


def test_annotate_only_marks_confirmed():
    """只标注 CONFIRMED：SAFE/UNKNOWN 不进报告漏洞表，打标记只是噪声"""
    results = [
        _Result("10.0.0.9:6379", STATUS_CONFIRMED),
        _Result("10.0.0.9:6379", STATUS_SAFE),
        _Result("10.0.0.9:6379", STATUS_UNKNOWN),
    ]
    stats = annotate(results, "http://10.0.0.9:8080/")
    assert stats == {"host_level": 1, "site_level": 0}
    assert results[0].extra[ATTR_KEY]["scope"] == SCOPE_HOST
    assert ATTR_KEY not in results[1].extra
    assert ATTR_KEY not in results[2].extra


def test_scope_of_defaults_to_site_for_legacy_results():
    """历史报告/手搓结果没有 attribution 字段 → 按站点级（向后兼容）"""
    r = _Result("http://10.0.0.9:8080/x")
    r.extra = {"plugin_name": "x"}
    assert scope_of(r) == SCOPE_SITE
    assert scope_of(_Result("")) == SCOPE_SITE


# ============================================================
# 2. 报告口径：host_level 是 total 的子集，不动 total
# ============================================================


def test_risk_distribution_separates_host_level():
    """host_level 计入 total（漏洞确实存在），但单独计数供读者区分责任方"""
    from core.report import ReportBuilder

    site = _Result("http://10.0.0.9:8080/x")
    host = _Result("10.0.0.9:6379")
    site.severity = host.severity = "high"
    for r in (site, host):
        r.fix = r.evidence = r.cve = r.cvss_score = r.cvss_vector = ""
        r.compliance = {}
        r.fix_detail = r.reproduce = ""
    annotate([site, host], "http://10.0.0.9:8080/")

    dist = ReportBuilder(results=[site, host], target="http://10.0.0.9:8080/").risk_distribution()
    assert dist["total"] == 2
    assert dist["host_level"] == 1


def test_report_csv_and_json_carry_attribution():
    """CSV/JSON 都要有归属信息：CSV 一列，JSON 的 summary + 每条 extra"""
    from core.report import ReportBuilder

    r = _Result("10.0.0.9:6379", name="Redis 未授权访问")
    r.severity = "high"
    r.fix = r.evidence = r.cve = ""
    r.cvss_score = 0.0
    r.cvss_vector = ""
    r.compliance = {}
    r.fix_detail = r.reproduce = ""
    annotate([r], "http://10.0.0.9:8080/")

    rb = ReportBuilder(results=[r], target="http://10.0.0.9:8080/")
    csv_text = rb.to_csv()
    assert "归属" in csv_text.split("\n")[0]
    assert "宿主级" in csv_text

    data = rb.to_dict()
    assert data["host_level_count"] == 1
    assert data["results"][0]["extra"][ATTR_KEY]["scope"] == SCOPE_HOST


def test_report_html_has_attribution_banner():
    """HTML 报告必须有归属横幅，否则读者会把宿主漏洞当成站点漏洞"""
    from core.report import ReportBuilder

    r = _Result("10.0.0.9:6379", name="Redis 未授权访问")
    r.severity = "high"
    r.fix = r.evidence = r.cve = ""
    r.cvss_score = 0.0
    r.cvss_vector = ""
    r.compliance = {}
    r.fix_detail = r.reproduce = ""
    annotate([r], "http://10.0.0.9:8080/")

    html = ReportBuilder(results=[r], target="http://10.0.0.9:8080/").to_html()
    assert "归属提示" in html
    assert "宿主级资产" in html


def test_batch_report_separates_host_level():
    """批量汇总必须单列宿主级：否则同一宿主 Redis 会在每行「合计」里各算一次

    这是交付物层面最容易误导的地方——读者按「合计」列横向汇总，会把同一个
    主机漏洞当成 N 个站点的漏洞。
    """
    from core.report import BatchReport, ReportBuilder

    def _builder(target, url):
        r = _Result(url, name="Redis 未授权访问")
        r.severity = "high"
        r.fix = r.evidence = r.cve = ""
        r.cvss_score = 0.0
        r.cvss_vector = ""
        r.compliance = {}
        r.fix_detail = r.reproduce = ""
        annotate([r], target)
        return ReportBuilder(results=[r], target=target, summary={"target": target})

    br = BatchReport(
        builders=[
            _builder("http://10.0.0.9:8080/", "10.0.0.9:6379"),
            _builder("http://10.0.0.9:9090/", "10.0.0.9:6379"),
        ]
    )
    csv_text = br.to_csv()
    assert "其中宿主级" in csv_text.split("\n")[0]
    # 两行合计都是 1，宿主级也都是 1（同一个主机漏洞，两个站点各报一次）
    rows = [line.split(",") for line in csv_text.strip().split("\n")[1:]]
    assert all(row[5] == "1" and row[6] == "1" for row in rows), rows

    html = br.to_html()
    assert "归属说明" in html
    assert "共 2 项" in html


# ============================================================
# 3. Redis 端口可配
# ============================================================


def test_redis_port_default_is_6379():
    """未配置时行为不变：仍探官方默认 6379"""
    from plugins.common.redis_unauth import RedisUnauthPlugin

    captured = {}

    def _fake_create(addr, timeout=None):
        captured["addr"] = addr
        return _FakeSocket()

    with patch("socket.create_connection", side_effect=_fake_create):
        RedisUnauthPlugin().verify("http://target/", _FakeSession())
    assert captured["addr"] == ("target", 6379)


def test_redis_port_override_is_used():
    """--redis-port / RUOYI_SCAN_REDIS_PORT 生效：探的是配置端口"""
    from config import settings
    from plugins.common.redis_unauth import RedisUnauthPlugin

    captured = {}

    def _fake_create(addr, timeout=None):
        captured["addr"] = addr
        return _FakeSocket()

    old = settings.REDIS_PORT
    settings.REDIS_PORT = 16379
    try:
        with patch("socket.create_connection", side_effect=_fake_create):
            res = RedisUnauthPlugin().verify("http://target/", _FakeSession())
    finally:
        settings.REDIS_PORT = old
    assert captured["addr"] == ("target", 16379)
    assert res.status == STATUS_CONFIRMED
    # 证据/URL 必须带端口：否则用户看到 CONFIRMED 不知道打的是哪个端口
    assert "16379" in res.url


def test_redis_connection_failure_mentions_port_option():
    """连不上时证据里要提示端口可配，否则用户无法区分「没开」和「端口传错」"""
    from plugins.common.redis_unauth import RedisUnauthPlugin

    def _raise(*_a, **_kw):
        raise OSError("connection refused")

    with patch("socket.create_connection", side_effect=_raise):
        res = RedisUnauthPlugin().verify("http://target/", _FakeSession())
    assert res.status == STATUS_UNKNOWN  # 三态纪律不变：连不上 ≠ 安全
    assert "--redis-port" in res.evidence


def test_port_override_rejects_invalid_values():
    """非法端口静默回退 None：端口是可选增强，写错不该让整次扫描崩掉"""
    from config.settings import _parse_port_override

    assert _parse_port_override("16379") == 16379
    assert _parse_port_override(" 6379 ") == 6379
    assert _parse_port_override(None) is None
    assert _parse_port_override("") is None
    assert _parse_port_override("abc") is None
    assert _parse_port_override("0") is None
    assert _parse_port_override("70000") is None


def test_redis_plugin_declares_default_port():
    """默认端口写在类属性上（文档/测试可引用，避免 verify 内的魔法数字）"""
    from plugins.common.redis_unauth import RedisUnauthPlugin

    assert RedisUnauthPlugin.default_port == 6379


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)
