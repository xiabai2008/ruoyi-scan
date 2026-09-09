# G1：离线 CVE 库 + CNVD 源测试
# 全部 mock 网络；运行：python -m pytest tests/test_cve_offline_cnvd.py -q
import json
import os
import sys
import unittest
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import lib.cve_sync as cve_sync
from lib.cve_sync import (
    OFFLINE_CVE_PATH,
    lookup_cve,
    lookup_offline,
    parse_cnvd_response,
    query_cnvd,
    search_offline,
)


def _mock_urlopen(payload: bytes):
    ctx = mock.MagicMock()
    ctx.__enter__.return_value = mock.MagicMock(read=lambda: payload)
    ctx.__exit__.return_value = False
    return ctx


class TestOfflineCve(unittest.TestCase):
    """离线库加载 / 查询 / 搜索（真实 data/cve_offline.json）"""

    def test_offline_file_exists_and_schema(self):
        """随包分发的离线库存在且 schema 正确"""
        self.assertTrue(os.path.exists(OFFLINE_CVE_PATH))
        with open(OFFLINE_CVE_PATH, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(doc["schema"], "ruoyi-scan-offline-cve")
        self.assertGreaterEqual(len(doc["entries"]), 15)

    def test_lookup_offline_by_cve(self):
        info = lookup_offline("CVE-2021-44228")
        self.assertIsNotNone(info)
        self.assertEqual(info.source, "offline")
        self.assertEqual(info.cvss_score, 10.0)
        self.assertEqual(info.severity, "CRITICAL")
        self.assertTrue(info.description, "离线条目应携带描述")

    def test_lookup_offline_miss(self):
        self.assertIsNone(lookup_offline("CVE-9999-0001"))

    def test_search_offline_by_component(self):
        results = search_offline(component="tomcat")
        self.assertGreaterEqual(len(results), 1)
        ids = {r.cve_id for r in results}
        self.assertIn("CVE-2020-1938", ids)
        # CVSS 降序
        scores = [r.cvss_score for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_search_offline_all(self):
        self.assertGreaterEqual(len(search_offline()), 15)


class TestLookupChainFallback(unittest.TestCase):
    """查询链兜底：NVD → GHSA → CNVD → offline"""

    def setUp(self):
        # 隔离缓存目录
        import tempfile

        self._tmpdir = tempfile.mkdtemp(prefix="cve_cache_test2_")
        self._patch = mock.patch("lib.cve_sync.CACHE_DIR", self._tmpdir)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_fallback_to_offline(self):
        """上游三源全部不可达 → 离线库兜底命中"""
        with mock.patch("lib.cve_sync.query_nvd_api", return_value=None), mock.patch(
            "lib.cve_sync.query_ghsa", return_value=None
        ), mock.patch("lib.cve_sync.query_cnvd", return_value=None), mock.patch(
            "lib.cve_sync.save_to_cache", lambda c: None
        ):
            info = lookup_cve("CVE-2021-29441", use_cache=False)
        self.assertIsNotNone(info)
        self.assertEqual(info.source, "offline")
        self.assertEqual(info.cve_id, "CVE-2021-29441")
        self.assertEqual(info.cvss_score, 10.0)

    def test_online_hit_skips_offline(self):
        """NVD 命中时不走离线库"""
        nvd_info = cve_sync.CVEInfo(cve_id="CVE-2024-99", source="nvd")
        with mock.patch("lib.cve_sync.query_nvd_api", return_value=nvd_info), mock.patch(
            "lib.cve_sync.query_cnvd"
        ) as cnvd, mock.patch("lib.cve_sync.lookup_offline") as offline, mock.patch(
            "lib.cve_sync.save_to_cache", lambda c: None
        ):
            info = lookup_cve("CVE-2024-99", use_cache=False)
        self.assertEqual(info.source, "nvd")
        cnvd.assert_not_called()
        offline.assert_not_called()


class TestCnvdSource(unittest.TestCase):
    """CNVD best-effort 源（HTML 解析 + 网络异常静默）"""

    SAMPLE_HTML = (
        '<table><tr><td><a href="/flaw/show/CNVD-2021-21563">'
        "Oracle WebLogic Server 远程代码执行漏洞</a></td></tr></table>"
    )

    def test_parse_cnvd_list_page(self):
        info = parse_cnvd_response(self.SAMPLE_HTML, keyword="CNVD-2021-21563")
        self.assertIsNotNone(info)
        self.assertEqual(info.cve_id, "CNVD-2021-21563")
        self.assertEqual(info.source, "cnvd")

    def test_parse_cnvd_no_result(self):
        self.assertIsNone(parse_cnvd_response("<html>无结果</html>"))

    def test_query_cnvd_network_error_silent(self):
        """反爬/网络不可达 → 静默 None（不阻断查询链）"""
        with mock.patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            self.assertIsNone(query_cnvd("CVE-2021-44228"))

    def test_query_cnvd_parses_page(self):
        with mock.patch("urllib.request.urlopen", return_value=_mock_urlopen(self.SAMPLE_HTML.encode("utf-8"))):
            info = query_cnvd("CVE-2021-44228")
        self.assertIsNotNone(info)
        self.assertEqual(info.cve_id, "CNVD-2021-21563")


if __name__ == "__main__":
    unittest.main(verbosity=2)
