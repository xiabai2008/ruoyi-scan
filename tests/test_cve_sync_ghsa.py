# G1：CVE 双源查询测试（NVD 主源 + GHSA 回退源）
# 全部 mock 网络，不真实联网；运行：python -m pytest tests/test_cve_sync_ghsa.py -q
import json
import os
import sys
import unittest
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from lib.cve_sync import (
    GHSA_TOKEN_ENV,
    CVEInfo,
    lookup_cve,
    parse_ghsa_response,
    query_ghsa,
)


def _ghsa_advisory(**overrides):
    """构造一条 GHSA REST API advisory 样例"""
    base = {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cve_id": "CVE-2021-43798",
        "summary": "Grafana directory traversal",
        "description": "Grafana 8.0.0-beta1 through 8.3.0 is vulnerable to directory traversal.",
        "severity": "HIGH",
        "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "published_at": "2021-12-08T20:45:31Z",
        "updated_at": "2022-01-06T21:52:31Z",
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-43798"}],
        "cwes": [{"cwe_id": "CWE-22", "name": "Path Traversal"}],
    }
    base.update(overrides)
    return base


def _mock_urlopen(payload, status=200):
    """构造 urllib.request.urlopen 的 mock（返回 JSON 字节流）"""
    body = json.dumps(payload).encode("utf-8")
    ctx = mock.MagicMock()
    ctx.__enter__.return_value = mock.MagicMock(read=lambda: body)
    ctx.__exit__.return_value = False
    return ctx


class TestParseGhsa(unittest.TestCase):
    """GHSA 响应解析"""

    def test_parse_full_advisory(self):
        info = parse_ghsa_response(_ghsa_advisory())
        self.assertEqual(info.cve_id, "CVE-2021-43798")
        self.assertEqual(info.source, "ghsa")
        self.assertEqual(info.cvss_score, 7.5)
        self.assertEqual(info.severity, "HIGH")
        self.assertEqual(info.cwe, ["CWE-22"])
        self.assertTrue(info.description.startswith("Grafana 8.0.0"))
        self.assertEqual(info.references[0], "https://nvd.nist.gov/vuln/detail/CVE-2021-43798")

    def test_parse_summary_fallback(self):
        """缺 description 时回退 summary"""
        info = parse_ghsa_response(_ghsa_advisory(description=""))
        self.assertEqual(info.description, "Grafana directory traversal")

    def test_parse_severity_map(self):
        """GHSA moderate → NVD 词汇 MEDIUM"""
        info = parse_ghsa_response(_ghsa_advisory(severity="moderate"))
        self.assertEqual(info.severity, "MEDIUM")

    def test_parse_missing_cve_id(self):
        """无 cve_id 的 advisory 返回 None"""
        self.assertIsNone(parse_ghsa_response(_ghsa_advisory(cve_id="")))

    def test_parse_bad_cvss(self):
        """CVSS score 异常值回退 0.0 不抛异常"""
        info = parse_ghsa_response(_ghsa_advisory(cvss={"score": "bad"}))
        self.assertEqual(info.cvss_score, 0.0)

    def test_cwe_string_list(self):
        """cwes 为字符串列表时兼容解析"""
        info = parse_ghsa_response(_ghsa_advisory(cwes=["CWE-79"]))
        self.assertEqual(info.cwe, ["CWE-79"])

    def test_compliance_tag_from_ghsa(self):
        """GHSA 来源的 CVEInfo 也能生成合规标签（复用现有管线）"""
        info = parse_ghsa_response(_ghsa_advisory(cwes=["CWE-22"]))
        tag = info.to_compliance_tag()
        self.assertIn("OWASP:A01:2021", tag)
        self.assertIn("等保2.0", tag)


class TestQueryGhsa(unittest.TestCase):
    """GHSA API 查询（mock urlopen）"""

    def test_query_match_by_cve_id(self):
        """返回多条 advisory 时按 cve_id 精确匹配"""
        payload = [
            _ghsa_advisory(cve_id="CVE-0000-0000"),  # 干扰项
            _ghsa_advisory(),
        ]
        with mock.patch("urllib.request.urlopen", return_value=_mock_urlopen(payload)):
            info = query_ghsa("CVE-2021-43798")
        self.assertIsNotNone(info)
        self.assertEqual(info.cve_id, "CVE-2021-43798")
        self.assertEqual(info.source, "ghsa")

    def test_query_no_match_returns_none(self):
        payload = [_ghsa_advisory(cve_id="CVE-1111-2222")]
        with mock.patch("urllib.request.urlopen", return_value=_mock_urlopen(payload)):
            self.assertIsNone(query_ghsa("CVE-2021-43798"))

    def test_query_network_error_returns_none(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            self.assertIsNone(query_ghsa("CVE-2021-43798"))

    def test_query_token_from_env(self):
        """缺省 token 时读取环境变量（Bearer 头）"""
        payload = [_ghsa_advisory()]
        captured = {}

        def fake_urlopen(req, timeout=0):
            captured["auth"] = req.headers.get("Authorization", "")
            return _mock_urlopen(payload)

        with mock.patch.dict(os.environ, {GHSA_TOKEN_ENV: "ghp_test"}):
            with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                query_ghsa("CVE-2021-43798")
        self.assertEqual(captured["auth"], "Bearer ghp_test")


class TestLookupFallback(unittest.TestCase):
    """lookup_cve 双源回退逻辑"""

    def setUp(self):
        # 隔离缓存：指向临时目录，避免污染/读取真实 data/cve_cache
        import tempfile

        self._tmpdir = tempfile.mkdtemp(prefix="cve_cache_test_")
        self._cache_patch = mock.patch("lib.cve_sync.CACHE_DIR", self._tmpdir)
        self._cache_patch.start()
        self.addCleanup(self._cache_patch.stop)

    def test_nvd_miss_falls_back_to_ghsa(self):
        """NVD 返回空（未收录）→ 回退 GHSA"""
        with mock.patch("lib.cve_sync.query_nvd_api", return_value=None):
            with mock.patch("lib.cve_sync.query_ghsa", return_value=CVEInfo(cve_id="CVE-2024-1", source="ghsa")) as g:
                info = lookup_cve("CVE-2024-1", use_cache=False)
        self.assertEqual(info.source, "ghsa")
        g.assert_called_once_with("CVE-2024-1")

    def test_nvd_hit_skips_ghsa(self):
        """NVD 命中时不请求 GHSA"""
        nvd_info = CVEInfo(cve_id="CVE-2024-2", source="nvd", cvss_score=9.8)
        with mock.patch("lib.cve_sync.query_nvd_api", return_value=nvd_info):
            with mock.patch("lib.cve_sync.query_ghsa") as g:
                info = lookup_cve("CVE-2024-2", use_cache=False)
        self.assertEqual(info.source, "nvd")
        g.assert_not_called()

    def test_both_miss_returns_none(self):
        with mock.patch("lib.cve_sync.query_nvd_api", return_value=None):
            with mock.patch("lib.cve_sync.query_ghsa", return_value=None):
                self.assertIsNone(lookup_cve("CVE-2024-3", use_cache=False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
