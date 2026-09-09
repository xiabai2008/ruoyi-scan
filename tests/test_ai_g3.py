# G3 AI 闭环 v2 测试：生成即验证（签名靶场三态）+ UNKNOWN 降噪
# 运行：python -m pytest tests/test_ai_g3.py -q
import os
import sys
import tempfile
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.ai_triage import DISCLAIMER, _rule_classify, cluster_unknowns, triage_unknowns
from lib.ai_validate import (
    VERDICT_FAIL,
    VERDICT_PASS,
    VERDICT_UNVERIFIED,
    decide_install_path,
    validate_ai_plugin,
)

# 已知签名插件模板（针对 lab 的 /common/download/resource 签名）
_PLUGIN_TPL = """
from plugins.base import PluginBase
from common.models import ScanResult, STATUS_CONFIRMED, STATUS_UNKNOWN

class {cls}(PluginBase):
    name = "{name}"
    category = "vuln"

    def verify(self, target, session):
        from core.http import join_url
        try:
            resp = session.get(join_url(target, "{path}"))
            if {cond}:
                return ScanResult(kind="vuln", name=self.name, severity="high",
                                  status=STATUS_CONFIRMED, url=resp.url, evidence="命中")
        except Exception:
            pass
        return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, evidence="未命中")
"""


def _write_plugin(source: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(source)
    return path


class TestGenerateValidate:
    """生成即验证：签名靶场三态判定（真实进程内 lab）"""

    def test_pass_on_known_signature(self):
        """vuln 命中签名 + safe 不误报 → pass"""
        path = _write_plugin(
            _PLUGIN_TPL.format(
                cls="AiFileRead",
                name="AI任意文件读取",
                path="/common/download/resource",
                cond='"root" in (resp.text or "")',
            )
        )
        report = validate_ai_plugin(path)
        assert report["verdict"] == VERDICT_PASS, report
        assert report["vuln_status"] == "CONFIRMED"
        assert report["safe_status"] != "CONFIRMED"

    def test_fail_on_safe_false_positive(self):
        """红线：safe 模式误报 CONFIRMED → fail，拒绝入库"""
        path = _write_plugin(
            _PLUGIN_TPL.format(cls="AiAlwaysConfirm", name="AI误报插件", path="/common/download/resource", cond="True")
        )
        report = validate_ai_plugin(path)
        assert report["verdict"] == VERDICT_FAIL, report
        assert report["safe_status"] == "CONFIRMED"

    def test_unverified_on_unknown_signature(self):
        """靶场未覆盖的签名 → unverified（隔离待人工复核）"""
        path = _write_plugin(
            _PLUGIN_TPL.format(
                cls="AiInvented", name="AI未覆盖探测", path="/ai/invented/path", cond="resp.status_code == 599"
            )
        )
        report = validate_ai_plugin(path)
        assert report["verdict"] == VERDICT_UNVERIFIED, report

    def test_no_plugin_class_unverified(self):
        """无 PluginBase 子类 → unverified + 原因说明"""
        path = _write_plugin("X = 1\n")
        report = validate_ai_plugin(path)
        assert report["verdict"] == VERDICT_UNVERIFIED
        assert any("PluginBase" in r for r in report["reasons"])

    def test_decide_install_path_discipline(self):
        """落盘纪律：pass→正式目录 / unverified→隔离目录 / fail→不落盘"""
        assert decide_install_path("a/foo.py", "ruoyi", VERDICT_PASS).endswith(
            "plugins\\ruoyi\\foo.py"
        ) or decide_install_path("a/foo.py", "ruoyi", VERDICT_PASS).endswith("plugins/ruoyi/foo.py")
        q = decide_install_path("a/foo.py", "ruoyi", VERDICT_UNVERIFIED)
        assert "_quarantine" in q
        assert decide_install_path("a/foo.py", "ruoyi", VERDICT_FAIL) is None


class TestTriageUnknowns:
    """UNKNOWN 降噪：规则降级 + LLM mock + 三态纪律"""

    def _results(self):
        return [
            ScanResult(
                kind="info", name="file_read", status=STATUS_UNKNOWN, url="http://x/1", evidence="connection timeout"
            ),
            ScanResult(
                kind="info", name="file_read", status=STATUS_UNKNOWN, url="http://x/2", evidence="connection refused"
            ),
            ScanResult(
                kind="info",
                name="druid_brute",
                status=STATUS_UNKNOWN,
                url="http://x/3",
                evidence="403 Forbidden WAF blocked",
            ),
            ScanResult(
                kind="info",
                name="captcha_probe",
                status=STATUS_UNKNOWN,
                url="http://x/4",
                evidence="请先登录 验证码错误",
            ),
            ScanResult(
                kind="info", name="sql_inject", status=STATUS_UNKNOWN, url="http://x/5", evidence="响应形态未知"
            ),
            ScanResult(kind="vuln", name="confirmed_one", status=STATUS_CONFIRMED, url="http://x/6", evidence="命中"),
            ScanResult(kind="info", name="safe_one", status=STATUS_SAFE, url="http://x/7", evidence="无漏洞"),
        ]

    def test_cluster_only_unknowns(self):
        """聚类只收 UNKNOWN（CONFIRMED/SAFE 不进分流）"""
        groups = cluster_unknowns(self._results())
        assert set(groups.keys()) == {"file_read", "druid_brute", "captcha_probe", "sql_inject"}
        assert len(groups["file_read"]) == 2

    def test_rule_fallback_labels(self):
        """规则降级：network_error / suspected_waf / captcha_or_auth / 默认人工复核"""
        report = triage_unknowns(self._results(), llm_fn=None)
        by_plugin = {g["plugin"]: g["label"] for g in report["groups"]}
        assert by_plugin["file_read"] == "network_error"
        assert by_plugin["druid_brute"] == "suspected_waf"
        assert by_plugin["captcha_probe"] == "captcha_or_auth"
        assert by_plugin["sql_inject"] == "needs_manual_review"
        assert report["summary"]["total_unknown"] == 5

    def test_llm_label_respected(self):
        """LLM 标签合法时被采用"""

        def fake_llm(prompt):
            return '{"label": "suspected_waf", "reason": "响应包含拦截特征"}'

        report = triage_unknowns(self._results()[:1], llm_fn=fake_llm)
        assert report["groups"][0]["label"] == "suspected_waf"
        assert "拦截特征" in report["groups"][0]["reason"]

    def test_llm_invalid_label_falls_back(self):
        """LLM 输出非法标签（含三态判定）→ 降级规则——三态纪律红线"""

        def bad_llm(prompt):
            return '{"label": "CONFIRMED", "reason": "我认为存在漏洞"}'

        report = triage_unknowns(self._results()[:1], llm_fn=bad_llm)
        # 非法标签不被采用，降级规则分类（connection timeout → network_error）
        assert report["groups"][0]["label"] == "network_error"

    def test_llm_garbage_falls_back(self):
        """LLM 输出非 JSON → 降级规则"""
        report = triage_unknowns(self._results()[:1], llm_fn=lambda p: "我觉得是网络问题")
        assert report["groups"][0]["label"] == "network_error"

    def test_disclaimer_present(self):
        """输出必带三态纪律免责声明"""
        report = triage_unknowns(self._results())
        assert report["disclaimer"] == DISCLAIMER
        assert "CONFIRMED" in report["disclaimer"]

    def test_rule_classify_order(self):
        """规则优先级：网络错误优先于 WAF 关键字"""
        assert _rule_classify("timeout when fetching 403 page") == "network_error"
        assert _rule_classify("403 forbidden by waf") == "suspected_waf"


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v", "--tb=short"])
