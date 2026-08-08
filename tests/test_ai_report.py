# E8 AI 报告解读测试：prompt 构建 / mock LLM / 模板降级 / 文件输出
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE
from lib.ai_report import _build_prompt, _template_summary, generate_analysis, run_ai_report_mode


def _sample_report() -> dict:
    """构造样例报告字典（2 高危 CONFIRMED + 1 SAFE）"""
    return {
        "target": "http://target/",
        "scan_time": "2026-08-08 10:00:00",
        "vuln_count": 2,
        "risk_distribution": {"high": 2, "medium": 0, "low": 0, "total": 2},
        "fingerprint": {"cms": "ruoyi", "version": "4.7.8", "confidence": 1.0, "matched": []},
        "results": [
            {
                "name": "任意文件读取",
                "severity": "high",
                "status": STATUS_CONFIRMED,
                "url": "http://target/common/download/resource",
                "cve": "",
                "cvss_score": 7.5,
                "compliance": {"等保2.0": "8.1.4", "OWASP": "A01:2021"},
                "fix_detail": "升级若依至 4.7+\n拦截 resource 参数",
                "reproduce": 'curl "http://target/common/download/resource?resource=../../../../etc/passwd"',
            },
            {
                "name": "SQL注入",
                "severity": "high",
                "status": STATUS_CONFIRMED,
                "url": "http://target/system/role/list",
                "cve": "CVE-2023-XXXX",
                "cvss_score": 9.8,
                "compliance": {"等保2.0": "8.1.3", "OWASP": "A03:2021"},
                "fix_detail": "参数化查询",
                "reproduce": "python poc.py",
            },
            {
                "name": "目录扫描",
                "severity": "low",
                "status": STATUS_SAFE,
                "url": "",
                "evidence": "未命中",
                "cvss_score": 0,
                "compliance": {},
                "fix_detail": "",
                "reproduce": "",
            },
        ],
    }


def test_build_prompt():
    """prompt 构建：仅含 CONFIRMED 漏洞 + 关键字段"""
    prompt = _build_prompt(_sample_report(), "zh")
    assert "任意文件读取" in prompt
    assert "SQL注入" in prompt
    assert "目录扫描" not in prompt, "SAFE 结果不应进入 prompt"
    assert "cvss_score" in prompt
    print("PASS test_build_prompt")


def test_template_summary_zh():
    """模板降级：中文摘要含 TOP3/修复/复现/合规缺口"""
    summary = _template_summary(_sample_report(), "zh")
    assert "总体结论" in summary
    assert "2" in summary.split("确认漏洞总数")[1][:30]
    assert "高危漏洞 TOP3" in summary
    assert "任意文件读取" in summary
    assert "SQL注入" in summary
    assert "复现" in summary
    assert "合规缺口" in summary
    assert "8.1.3" in summary
    print("PASS test_template_summary_zh")


def test_template_summary_en():
    """模板降级：英文摘要"""
    summary = _template_summary(_sample_report(), "en")
    assert "Summary" in summary
    assert "Top 3 Critical Findings" in summary
    print("PASS test_template_summary_en")


def test_generate_analysis_no_key():
    """无 API Key → 模板降级"""
    analysis = generate_analysis(_sample_report(), lang="zh", api_key="")
    assert "总体结论" in analysis or "AI 分析" in analysis
    print("PASS test_generate_analysis_no_key")


def test_generate_analysis_mock_llm(monkeypatch):
    """mock LLM → 返回 LLM 输出"""
    import lib.ai_report as ar

    def fake_complete(messages, model, api_key, base_url):
        assert len(messages) == 2
        assert "system" == messages[0]["role"]
        return "# LLM 分析\n- 高危漏洞：任意文件读取"

    monkeypatch.setattr(ar, "_llm_complete", fake_complete)
    analysis = generate_analysis(_sample_report(), lang="zh", api_key="test-key")
    assert "# LLM 分析" in analysis
    assert "任意文件读取" in analysis
    print("PASS test_generate_analysis_mock_llm")


def test_run_ai_report_mode(monkeypatch):
    """入口模式：生成 md 文件"""
    import lib.ai_report as ar

    def fake_complete(messages, model, api_key, base_url):
        return "# 分析"

    monkeypatch.setattr(ar, "_llm_complete", fake_complete)
    monkeypatch.setattr(ar, "AI_API_KEY", "test-key")
    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_airpt_")
    try:
        path = run_ai_report_mode(tmp, _sample_report(), lang="zh", )
        assert os.path.isfile(path)
        assert path.endswith("report.analysis.zh.md")
        with open(path, encoding="utf-8") as f:
            assert "# 分析" in f.read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS test_run_ai_report_mode")


if __name__ == "__main__":
    test_build_prompt()
    test_template_summary_zh()
    test_template_summary_en()
    test_generate_analysis_no_key()
    test_generate_analysis_mock_llm()
    test_run_ai_report_mode()
    print("ALL_E8_TESTS_PASS")
