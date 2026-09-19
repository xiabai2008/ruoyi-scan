# D2 多版本 POC 适配单元测试
# 运行：python tests/test_ruoyi_versions.py 或 python -m pytest tests/test_ruoyi_versions.py -q
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import requests_mock
except ImportError:
    print("缺少依赖 requests_mock，请先执行：pip install requests_mock")
    sys.exit(1)

from common.models import FingerprintResult
from core.router import Router
from core.ruoyi_versions import (
    detect_version,
    extract_version,
    parse_version,
    version_in_range,
)
from core.session import SessionManager

MOCK_TARGET = "http://ruoyi-version.test"


class TestExtractVersion(unittest.TestCase):
    """版本号提取"""

    def test_extract_from_login_page(self):
        """从 /login 页面 HTML 提取版本号"""
        html = "<html><head><title>登录若依系统</title></head><body><footer>RuoYi 4.7.8</footer></body></html>"
        self.assertEqual(extract_version(html), "4.7.8")

    def test_extract_multiple_matches(self):
        """多个版本号取第一个"""
        html = "version 4.2.0 and 4.7.8"
        self.assertEqual(extract_version(html), "4.2.0")

    def test_extract_v5(self):
        """v5 版本号"""
        html = "RuoYi-Vue 5.1.0"
        self.assertEqual(extract_version(html), "5.1.0")

    def test_extract_no_version(self):
        """无版本号返回空串"""
        self.assertEqual(extract_version("<html>无版本</html>"), "")
        self.assertEqual(extract_version(""), "")


    def test_extract_version_by_copyright_year(self):
            """Thymeleaf 单机版登录页无明文版本号，靠版权年份识别版本

            数据来源：官方各 tag 的 templates/login.html（2026-09-19 逐一核对，
            v4.6.2~v4.8.3 五个版本年份互不相同）。未收录年份返回空串（保守：不做版本过滤）。
            """
            from core.ruoyi_versions import extract_version, extract_version_by_copyright

            cases = {
                "Copyright © 2018-2021 ruoyi.vip All Rights Reserved.": "4.6.2",
                "Copyright © 2018-2023 ruoyi.vip All Rights Reserved.": "4.7.8",
                "Copyright © 2018-2024 ruoyi.vip All Rights Reserved.": "4.8.0",
                "Copyright © 2018-2025 ruoyi.vip All Rights Reserved.": "4.8.2",
                "Copyright © 2018-2026 ruoyi.vip All Rights Reserved.": "4.8.3",
            }
            for html, want in cases.items():
                got = extract_version(html)
                assert got == want, f"版权年份应映射到 {want}，实际 {got!r}（HTML: {html[:40]}）"
            # 起始年份不同也应命中（只锚定结束年份）；大小写不敏感；(c) 写法
            assert extract_version_by_copyright("Copyright © 2019-2025") == "4.8.2"
            assert extract_version_by_copyright("copyright (c) 2018-2023") == "4.7.8"
            # 未收录年份 / 无版权行 → 空串（不过滤，等价旧行为）
            assert extract_version_by_copyright("Copyright © 2018-2019") == ""
            assert extract_version("no copyright here") == ""
            # 明文版本号优先（旧管线优先级更高）
            assert extract_version("RuoYi 4.7.8 <br> Copyright © 2018-2021") == "4.7.8"


class TestParseVersion(unittest.TestCase):
    """版本号解析"""

    def test_parse_4_7_8(self):
        self.assertEqual(parse_version("4.7.8"), (4, 7, 8))

    def test_parse_4_7(self):
        self.assertEqual(parse_version("4.7"), (4, 7, 0))

    def test_parse_empty(self):
        self.assertEqual(parse_version(""), (0, 0, 0))

    def test_parse_invalid(self):
        self.assertEqual(parse_version("abc"), (0, 0, 0))


class TestVersionInRange(unittest.TestCase):
    """版本范围判定"""

    def test_empty_range_all_versions(self):
        """空范围 → 全版本适用"""
        self.assertTrue(version_in_range("4.7.8", ""))
        self.assertTrue(version_in_range("4.2.0", ""))
        self.assertTrue(version_in_range("5.0.0", ""))

    def test_empty_version_all_ranges(self):
        """版本未识别 → 不过滤（保守策略：跑 POC）"""
        self.assertTrue(version_in_range("", ">=4.2,<4.6"))
        self.assertTrue(version_in_range("", ">=4.7"))

    def test_range_ge_lt(self):
        """>=4.0,<4.6"""
        spec = ">=4.0,<4.6"
        self.assertTrue(version_in_range("4.2.0", spec))
        self.assertTrue(version_in_range("4.5.9", spec))
        self.assertFalse(version_in_range("4.6.0", spec))
        self.assertFalse(version_in_range("4.7.8", spec))

    def test_range_ge_only(self):
        """>=4.7"""
        spec = ">=4.7"
        self.assertTrue(version_in_range("4.7.0", spec))
        self.assertTrue(version_in_range("4.7.8", spec))
        self.assertTrue(version_in_range("5.0.0", spec))
        self.assertFalse(version_in_range("4.6.9", spec))

    def test_range_le_only(self):
        """<=4.5"""
        spec = "<=4.5"
        self.assertTrue(version_in_range("4.2.0", spec))
        self.assertTrue(version_in_range("4.5.0", spec))
        self.assertFalse(version_in_range("4.6.0", spec))


class TestDetectVersion(unittest.TestCase):
    """版本探测（mock HTTP）"""

    @requests_mock.Mocker()
    def test_detect_from_login_page(self, m):
        """从 /login 页面探测版本号"""
        m.get(
            MOCK_TARGET + "/login",
            text="<html><footer>RuoYi 4.7.8</footer></html>",
            headers={"Content-Type": "text/html"},
        )
        version = detect_version(MOCK_TARGET, SessionManager())
        self.assertEqual(version, "4.7.8")

    @requests_mock.Mocker()
    def test_detect_from_root(self, m):
        """/login 无版本号，根路径 HTML 含 ?v=4.7"""
        m.get(MOCK_TARGET + "/login", text="<html>登录</html>", headers={"Content-Type": "text/html"})
        m.get(
            MOCK_TARGET,
            text='<html><script src="/static/js/main.js?v=4.7"></script></html>',
            headers={"Content-Type": "text/html"},
        )
        version = detect_version(MOCK_TARGET, SessionManager())
        self.assertEqual(version, "4.7.0")

    @requests_mock.Mocker()
    def test_detect_not_found(self, m):
        """所有探测点都无版本号 → 返回空串"""
        m.get(MOCK_TARGET + "/login", text="<html>登录</html>", headers={"Content-Type": "text/html"})
        m.get(MOCK_TARGET, text="<html>首页</html>", headers={"Content-Type": "text/html"})
        m.get(MOCK_TARGET + "/actuator/info", status_code=404)
        version = detect_version(MOCK_TARGET, SessionManager())
        self.assertEqual(version, "")


class TestRouterVersionFilter(unittest.TestCase):
    """Router 按版本过滤 POC"""

    def test_filter_by_version_4_2(self):
        """4.2.0 版本：应包含 <4.6 和 <4.7 的 POC，不包含 >=4.7 的"""
        fp = FingerprintResult(cms="ruoyi", version="4.2.0", confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        # 4.2.0 应跑全部 16 个 POC（所有 <4.6 和 <4.7 都满足，全版本的也满足）
        self.assertEqual(len(plugins), 18, f"4.2.0 应跑全部 18 个 POC，实际 {len(plugins)}")

    def test_filter_by_version_4_7_8(self):
        """4.7.8 版本：应过滤掉 <4.6 和 <4.7 的 POC（6 个），只跑全版本的（10 个）"""
        fp = FingerprintResult(cms="ruoyi", version="4.7.8", confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        # 4.7.8 应过滤掉 sql_inject_role/dept(2) + file_read/file_read_path(2) +
        # file_upload + job_rce + file_read_time(3) = 7 个，剩 9 个全版本
        # 实际：affected_versions=<4.7 的有 sql_inject_role/dept/file_read/file_read_path/file_upload/job_rce/file_read_time = 7 个
        self.assertEqual(len(plugins), 11, f"4.7.8 应过滤掉 7 个 <4.7 的 POC，剩 11 个，实际 {len(plugins)}")

    def test_filter_by_version_4_6_0(self):
        """4.6.0 版本：<4.6 的 POC 被过滤（sql_inject_role/dept），<4.7 的保留"""
        fp = FingerprintResult(cms="ruoyi", version="4.6.0", confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        # 4.6.0 应过滤掉 sql_inject_role/dept(2)，剩 14 个
        self.assertEqual(len(plugins), 16, f"4.6.0 应过滤掉 2 个 <4.6 的 POC，剩 16 个，实际 {len(plugins)}")

    def test_no_version_runs_all(self):
        """版本未识别 → 跑全部 POC（保守策略）"""
        fp = FingerprintResult(cms="ruoyi", version="", confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        self.assertEqual(len(plugins), 18, f"版本未识别应跑全部 18 个 POC，实际 {len(plugins)}")

    def test_filterd_out_plugins(self):
        """4.7.8 过滤掉的 POC 类名正确（sql_inject_role/dept 等）"""
        fp = FingerprintResult(cms="ruoyi", version="4.7.8", confidence=1.0, matched=[])
        plugins = Router().resolve(fp)
        plugin_names = [cls.name for cls in plugins]
        # 4.7.8 不应跑的 POC
        self.assertNotIn("POST型报错注入（role）", plugin_names)
        self.assertNotIn("第二种POST型报错注入（dept）", plugin_names)
        self.assertNotIn("任意文件上传漏洞", plugin_names)
        # 4.7.8 应跑的 POC
        self.assertIn("Thymeleaf/SpEL 模板注入", plugin_names)


    def test_router_candidates_not_version_filtered(self):
        """回归：candidates() 返回**未按版本过滤**的候选集，resolve() 才是过滤后的

        版本对照矩阵必须用 candidates 构造——若用 resolve（已过滤），
        所有条目 applicable 恒为 True，对照表失去意义。
        2026-09-19 实测：CLI 报告里的 version_matrix 一度恒为空/全适用。
        """
        from common.models import FingerprintResult
        from core.router import Router
        from core.ruoyi_versions import version_in_range

        fp = FingerprintResult(cms="ruoyi", version="4.8.3", confidence=1.0, matched=[])
        cands = Router().candidates(fp)
        resolved = Router().resolve(fp)
        self.assertGreater(len(cands), len(resolved), "candidates 应包含被版本过滤掉的插件")
        skipped = [c for c in cands if c not in resolved]
        self.assertTrue(skipped, "4.8.3 上应存在因版本不适用被跳过的插件")
        for cls in skipped:
            self.assertFalse(
                version_in_range("4.8.3", getattr(cls, "affected_versions", "") or ""),
                f"{cls.__name__} 被跳过但其版本范围仍适用，candidates/resolve 语义不一致",
            )

    def test_build_version_matrix_marks_skipped(self):
        """回归：矩阵必须标出 applicable=False 的条目（否则版本对照表没信息量）"""
        from common.models import FingerprintResult
        from core.router import Router
        from core.ruoyi_versions import build_version_matrix

        fp = FingerprintResult(cms="ruoyi", version="4.8.3", confidence=1.0, matched=[])
        matrix = build_version_matrix("4.8.3", Router().candidates(fp))
        self.assertTrue(matrix, "矩阵不应为空")
        self.assertTrue(
            any(not item["applicable"] for item in matrix),
            "4.8.3 上应存在 applicable=False 的条目（<4.7 与 <=4.8.0 的插件）",
        )
        # 无版本 → 空矩阵（不做对照）
        self.assertEqual(build_version_matrix("", Router().candidates(fp)), [])


class TestVariantInfo(unittest.TestCase):
    """G1：变体元数据与变体感知版本探测"""

    def test_variant_info_plus(self):
        """plus 变体：Sa-Token 鉴权 + /prod-api 前缀"""
        from core.ruoyi_versions import get_variant_info

        info = get_variant_info("ruoyi-plus")
        self.assertEqual(info["auth"], "Sa-Token")
        self.assertIn("/prod-api", info["api_prefixes"])
        self.assertIn("Sa-Token", info["notes"])

    def test_variant_info_all_registered(self):
        """7 个变体全部有元数据且字段完整"""
        from core.ruoyi_versions import RUOYI_VARIANT_INFO, get_variant_info

        self.assertEqual(len(RUOYI_VARIANT_INFO), 7)
        for v in ("ruoyi", "ruoyi-vue", "ruoyi-vue3", "ruoyi-app", "ruoyi-plus", "ruoyi-cloud", "ruoyi-cloud-plus"):
            info = get_variant_info(v)
            for key in ("name", "auth", "api_prefixes", "version_sources", "notes"):
                self.assertTrue(info.get(key), f"{v} 缺少 {key}")

    def test_variant_unknown_returns_empty(self):
        """未知变体：元数据空 dict、前缀回退裸路径"""
        from core.ruoyi_versions import get_variant_api_prefixes, get_variant_info

        self.assertEqual(get_variant_info("no-such-variant"), {})
        self.assertEqual(get_variant_api_prefixes("no-such-variant"), [""])

    def test_variant_api_prefixes(self):
        """cloud 微服务版多前缀，单体版裸路径"""
        from core.ruoyi_versions import get_variant_api_prefixes

        self.assertEqual(get_variant_api_prefixes("ruoyi-cloud"), ["/prod-api", "/auth", "/system", "/gen"])
        self.assertEqual(get_variant_api_prefixes("ruoyi"), [""])

    @requests_mock.Mocker()
    def test_detect_version_variant_source_priority(self, m):
        """指定 plus 变体时优先探测 /actuator/info（变体特征来源）"""
        m.get(MOCK_TARGET + "/login", text="<html>login</html>")
        m.get(MOCK_TARGET, text="<html>index</html>")
        m.get(MOCK_TARGET + "/actuator/info", text='{"version":"4.7.8"}')
        version = detect_version(MOCK_TARGET, SessionManager(), variant="ruoyi-plus")
        self.assertEqual(version, "4.7.8")

    @requests_mock.Mocker()
    def test_detect_version_without_variant_backward_compat(self, m):
        """不指定 variant 时行为与旧版一致（login → 根路径 → actuator/info）"""
        m.get(MOCK_TARGET + "/login", text="<html>RuoYi 4.2.0</html>")
        version = detect_version(MOCK_TARGET, SessionManager())
        self.assertEqual(version, "4.2.0")

    @requests_mock.Mocker()
    def test_detect_version_variant_skips_default_sources_when_hit(self, m):
        """变体来源已命中时不重复探测默认路径（cloud + /nacos/ 指纹）"""
        m.get(MOCK_TARGET + "/nacos/", text="Nacos console RuoYi 4.7.8")
        m.get(MOCK_TARGET + "/login", status_code=500)  # 若被探测到则版本提取失败也不影响
        version = detect_version(MOCK_TARGET, SessionManager(), variant="ruoyi-cloud")
        self.assertEqual(version, "4.7.8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
