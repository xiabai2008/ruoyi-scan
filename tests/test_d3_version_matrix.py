# E3 POC 版本适配矩阵测试：版本过滤 + v3.9.x 回归 + 版本对照报告
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import FingerprintResult
from core.loader import load_plugins
from core.router import Router
from core.ruoyi_versions import version_in_range


def _ruoyi_plugins():
    """加载全部若依插件（与 plugin_list 声明一致）"""
    return load_plugins("plugins.ruoyi")


def test_all_ruoyi_plugins_have_versions():
    """16 个 ruoyi POC 全部携带 affected_versions（显式值或注释说明）"""
    plugins = _ruoyi_plugins()
    assert len(plugins) == 16, f"应有 16 个若依插件，实际 {len(plugins)}"
    for cls in plugins:
        # 类属性必须存在（None 视为未定义 → 失败）
        assert hasattr(cls, "affected_versions"), f"{cls.__name__} 缺少 affected_versions"
    print("PASS test_all_ruoyi_plugins_have_versions: %d 个插件均有 affected_versions" % len(plugins))


def test_versioned_pocs_defined():
    """已知有版本限制的 7 个 POC 范围正确"""
    expected = {
        "任意文件读取": ">=4.0,<4.7",
        "定时任务任意文件读取": ">=4.0,<4.7",
        "POST型报错注入（role）": ">=4.0,<4.6",
        "POST型报错注入（dept）": ">=4.0,<4.6",
        "任意文件上传": ">=4.0,<4.7",
        "任意文件读取（路径穿越）": ">=4.0,<4.7",
        "定时任务 RCE（未授权访问）": ">=4.0,<4.7",
    }
    plugins = {getattr(cls, "name", ""): cls for cls in _ruoyi_plugins()}
    for name, spec in expected.items():
        cls = plugins.get(name)
        assert cls is not None, f"缺少插件 {name}"
        assert getattr(cls, "affected_versions", "") == spec, (
            f"{name} 版本范围应为 {spec}，实际 {getattr(cls, 'affected_versions', '')}"
        )
    print("PASS test_versioned_pocs_defined: 7 个带版本范围的 POC 校验通过")


def test_old_version_filter():
    """检测到 v4.5（旧版）→ 全部 POC 适用（在 >=4.0,<4.6 区间内）"""
    fp = FingerprintResult(cms="ruoyi", version="4.5.0", confidence=1.0, matched=["test"])
    plugins = Router().resolve(fp)
    assert len(plugins) == 16, f"v4.5 应跑全部 16 个插件，实际 {len(plugins)}"
    print("PASS test_old_version_filter: v4.5 → %d 个插件" % len(plugins))


def test_new_version_skip_old_pocs():
    """检测到 v4.7.8（新版）→ 修复漏洞的 POC 被跳过"""
    fp = FingerprintResult(cms="ruoyi", version="4.7.8", confidence=1.0, matched=["test"])
    plugins = Router().resolve(fp)
    names = [getattr(cls, "name", "") for cls in plugins]
    # 4.6 已修复 SQL 注入 → 应跳过
    assert "POST型报错注入（role）" not in names, f"v4.7.8 不应包含 role 注入 POC: {names}"
    assert "POST型报错注入（dept）" not in names
    # 4.7 已修复文件读取 → 应跳过
    assert "任意文件读取" not in names
    assert "定时任务任意文件读取" not in names
    # 全版本 POC 保留
    assert "后台默认口令" in "".join(names), names
    print("PASS test_new_version_skip_old_pocs: v4.7.8 → %d 个插件" % len(plugins))


def test_latest_version_matrix():
    """v3.9.2（RuoYi-Vue 最新版，版本号 3.9.2）→ 全部旧版 POC 被跳过"""
    fp = FingerprintResult(cms="ruoyi", version="3.9.2", confidence=1.0, matched=["test"])
    plugins = Router().resolve(fp)
    names = [getattr(cls, "name", "") for cls in plugins]
    # 版本号 3.x 不在 >=4.0 区间 → 带范围 POC 全部跳过，仅剩全版本 POC
    assert "任意文件读取" not in names, f"v3.9.2 不应包含 4.x 版 POC: {names}"
    # 全版本 POC 保留（默认口令/目录扫描/未授权等）
    assert any("默认口令" in n for n in names), names
    print("PASS test_latest_version_matrix: v3.9.2 → %d 个插件（全版本 POC 保留）" % len(plugins))


def test_version_in_range_semantics():
    """版本区间语义：空串=全版本；未识别版本=不过滤"""
    assert version_in_range("3.9.2", "") is True
    assert version_in_range("", ">=4.0,<4.7") is True  # 版本未识别不过滤
    assert version_in_range("4.5.0", ">=4.0,<4.6") is True
    assert version_in_range("4.7.8", ">=4.0,<4.7") is False
    assert version_in_range("4.7.8", ">=4.0,<4.6") is False
    print("PASS test_version_in_range_semantics")


def test_report_version_matrix_field():
    """JSON 报告含 version_matrix（版本对照矩阵）"""
    from core.report import ReportBuilder

    summary = {
        "fingerprint": {"cms": "ruoyi", "version": "4.7.8", "confidence": 1.0, "matched": []},
        "version_matrix": [
            {"name": "任意文件读取", "category": "vuln", "affected_versions": ">=4.0,<4.7", "applicable": False},
            {"name": "后台默认口令", "category": "brute", "affected_versions": "全版本", "applicable": True},
        ],
    }
    builder = ReportBuilder(results=[], target="http://target/", summary=summary)
    data = json.loads(builder.to_json())
    assert data["fingerprint"]["version"] == "4.7.8"
    vm = data["version_matrix"]
    assert len(vm) == 2
    assert vm[0]["applicable"] is False and vm[1]["applicable"] is True
    print("PASS test_report_version_matrix_field")


def test_report_html_version_table():
    """HTML 报告含版本对照表（检测版本 + 适用/跳过标记）"""
    from core.report import ReportBuilder

    summary = {
        "fingerprint": {"cms": "ruoyi", "version": "4.7.8", "confidence": 1.0, "matched": []},
        "version_matrix": [
            {"name": "任意文件读取", "category": "vuln", "affected_versions": ">=4.0,<4.7", "applicable": False},
        ],
    }
    builder = ReportBuilder(results=[], target="http://target/", summary=summary)
    html = builder.to_html()
    assert "版本对照" in html
    assert "检测版本：4.7.8" in html
    assert "任意文件读取" in html
    assert "跳过" in html
    print("PASS test_report_html_version_table")


if __name__ == "__main__":
    test_all_ruoyi_plugins_have_versions()
    test_versioned_pocs_defined()
    test_old_version_filter()
    test_new_version_skip_old_pocs()
    test_latest_version_matrix()
    test_version_in_range_semantics()
    test_report_version_matrix_field()
    test_report_html_version_table()
    print("ALL_E3_TESTS_PASS")
