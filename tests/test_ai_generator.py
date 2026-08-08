# E7 AI POC 生成器测试：mock LLM / 规则降级 / 自验证循环 / 落盘格式
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.ai_generator import _clean_code, _rule_fallback, generate_ai_plugin, _write_source


def test_rule_fallback_sql():
    """规则降级：SQL 关键词 → high + SQL 合规"""
    source = _rule_fallback("检测登录接口的SQL注入漏洞", "SQL注入测试", "ruoyi")
    assert "class " in source
    assert "SQL" in source
    assert "severity = 'high'" in source
    assert "OWASP:A03:2021" in source
    print("PASS test_rule_fallback_sql")


def test_rule_fallback_file_read():
    """规则降级：文件读取关键词 → 对应 CVSS/合规"""
    source = _rule_fallback("任意文件读取漏洞", "文件读取测试", "ruoyi")
    assert "severity = 'high'" in source
    assert "OWASP:A01:2021" in source
    print("PASS test_rule_fallback_file_read")


def test_clean_code_markdown():
    """清洗 markdown 代码块标记"""
    raw = '```python\n# comment\nx = 1\n```'
    cleaned = _clean_code(raw)
    assert "```" not in cleaned
    assert cleaned.startswith("# comment")
    print("PASS test_clean_code_markdown")


def _mock_llm(source_to_return):
    """构造 mock LLM 回调"""
    def fake_complete(messages, model, api_key, base_url):
        return source_to_return
    return fake_complete


_VALID_PLUGIN_SOURCE = '''# AI 生成的测试插件
from plugins.base import PluginBase
from common.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from core.http import join_url


class AiTestPlugin(PluginBase):
    """AI 测试插件"""
    name = "AI测试插件"
    cve = "N/A"
    severity = "high"
    category = "vuln"
    description = "AI 生成的测试插件"
    fix = "修复漏洞"
    affected_versions = ""

    def verify(self, target, session):
        try:
            resp = session.get(join_url(target, "/test"))
            if resp.status_code == 200:
                return self._build_result(STATUS_CONFIRMED, join_url(target, "/test"), "命中")
            return self._build_result(STATUS_SAFE)
        except Exception:
            return self._build_result(STATUS_UNKNOWN)
'''


def test_generate_ai_plugin_with_mock_llm(monkeypatch):
    """mock LLM 成功路径：生成 + 验证通过"""
    import lib.ai_generator as ag

    monkeypatch.setattr(ag, "_llm_complete", _mock_llm(_VALID_PLUGIN_SOURCE))
    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_ai_")
    try:
        filepath, ok, errors = generate_ai_plugin(
            "AI 测试插件", "AI测试插件", category="ruoyi",
            api_key="test-key", output_dir=tmp,
        )
        assert ok, errors
        assert os.path.isfile(filepath)
        with open(filepath, encoding="utf-8") as f:
            content = f.read()
        assert "class AiTestPlugin(PluginBase)" in content
        assert "STATUS_UNKNOWN" in content
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS test_generate_ai_plugin_with_mock_llm")


def test_generate_ai_plugin_retry_loop(monkeypatch):
    """mock LLM 首轮失败 → 错误回灌 → 二轮成功"""
    import lib.ai_generator as ag

    calls = []

    def fake_complete(messages, model, api_key, base_url):
        calls.append(messages)
        # 首轮返回残缺代码（缺 verify 方法）→ check 失败；二轮返回完整代码
        if len(calls) == 1:
            return "# broken\nclass AiRetryPlugin(PluginBase):\n    pass\n"
        return _VALID_PLUGIN_SOURCE

    monkeypatch.setattr(ag, "_llm_complete", fake_complete)
    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_ai_")
    try:
        filepath, ok, errors = generate_ai_plugin(
            "AI 重试插件", "AI重试插件", category="ruoyi",
            api_key="test-key", output_dir=tmp,
        )
        assert ok, errors
        assert len(calls) >= 2, f"应至少 2 轮调用，实际 {len(calls)}"
        # 第二轮 user 消息应含错误回灌
        assert "验证失败" in calls[1][-1]["content"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS test_generate_ai_plugin_retry_loop")


def test_generate_ai_plugin_no_key_fallback():
    """无 API Key → 规则降级（不调用 LLM）"""
    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_ai_")
    try:
        filepath, ok, errors = generate_ai_plugin(
            "检测默认口令漏洞", "默认口令AI", category="ruoyi",
            api_key="", output_dir=tmp,
        )
        assert ok, errors
        assert os.path.isfile(filepath)
        with open(filepath, encoding="utf-8") as f:
            content = f.read()
        assert "TODO" in content, "规则模式应含 TODO 提示"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS test_generate_ai_plugin_no_key_fallback")


def test_write_source_exists():
    """文件已存在 → FileExistsError"""
    tmp = tempfile.mkdtemp(prefix="ruoyi_scan_ai_")
    try:
        p = _write_source("重名插件", "ruoyi", "# x\n", tmp)
        assert os.path.isfile(p)
        try:
            _write_source("重名插件", "ruoyi", "# x\n", tmp)
            assert False, "应抛 FileExistsError"
        except FileExistsError:
            pass
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS test_write_source_exists")


if __name__ == "__main__":
    test_rule_fallback_sql()
    test_rule_fallback_file_read()
    test_clean_code_markdown()
    test_generate_ai_plugin_with_mock_llm()
    test_generate_ai_plugin_retry_loop()
    test_generate_ai_plugin_no_key_fallback()
    test_write_source_exists()
    print("ALL_E7_TESTS_PASS")
