# E4 nuclei YAML 模板兼容层测试：解析/校验/三态判定/过滤/适配器
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.nuclei_loader import (
    build_template_plugin,
    load_nuclei_templates,
    parse_nuclei_template,
    validate_template,
)

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "nuclei")


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}


class FakeSession:
    """按 URL 映射返回固定响应的 mock session"""

    def __init__(self, responses):
        self.responses = responses

    def request(self, method, url, headers=None, data=None):
        return self.responses.get(url, FakeResp("", 404))


def test_parse_example_template():
    """内置示例模板可解析（id/info/http/matchers）"""
    tpl = parse_nuclei_template(os.path.join(EXAMPLES, "ruoyi-login-page.yaml"))
    assert tpl.id == "ruoyi-login-page"
    assert tpl.name
    assert len(tpl.requests) == 1
    assert tpl.requests[0].method == "GET"
    assert "{{BaseURL}}" in tpl.requests[0].path
    assert len(tpl.matchers) == 1
    assert tpl.matchers[0].mtype == "word"
    print("PASS test_parse_example_template: id=%s" % tpl.id)


def test_parse_matchers_condition():
    """swagger 示例含 matchers-condition: or + 多类型 matcher"""
    tpl = parse_nuclei_template(os.path.join(EXAMPLES, "swagger-ui-exposed.yaml"))
    assert tpl.matchers_condition == "or"
    mtypes = {m.mtype for m in tpl.matchers}
    assert "word" in mtypes and "status" in mtypes
    print("PASS test_parse_matchers_condition: %s %s" % (tpl.matchers_condition, mtypes))


def test_validate_examples():
    """内置 5 个示例模板全部校验通过"""
    files = [
        "ruoyi-login-page.yaml",
        "spring-actuator-exposed.yaml",
        "druid-monitor-page.yaml",
        "ruoyi-file-read-probe.yaml",
        "swagger-ui-exposed.yaml",
    ]
    for f in files:
        errors = validate_template(os.path.join(EXAMPLES, f))
        assert errors == [], f"{f} 校验失败: {errors}"
    print("PASS test_validate_examples: 5 个示例模板全部通过")


def test_validate_missing_id():
    """缺少 id → 校验失败"""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        f.write("info:\n  name: no-id-template\nhttp:\n  - method: GET\n    path:\n      - \"/\"\n")
        path = f.name
    try:
        errors = validate_template(path)
        assert any("id" in e for e in errors), errors
    finally:
        os.unlink(path)
    print("PASS test_validate_missing_id")


def test_unsupported_protocol_skipped():
    """不支持协议（tcp）→ 无请求块，加载时跳过"""
    import tempfile

    content = (
        'id: tcp-probe\n'
        'info:\n  name: tcp\n  severity: low\n'
        'tcp:\n  - host:\n      - "{{Hostname}}"\n    inputs:\n      - data: "hello"\n'
    )
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        f.write(content)
        path = f.name
    try:
        tpl = parse_nuclei_template(path)
        assert tpl.requests == [], "tcp 协议模板不应产生 http 请求"
        plugins = load_nuclei_templates([path])
        assert plugins == [], "tcp 协议模板应被跳过"
    finally:
        os.unlink(path)
    print("PASS test_unsupported_protocol_skipped")


def test_template_plugin_confirm():
    """模板 matcher 命中 → CONFIRMED"""
    tpl = parse_nuclei_template(os.path.join(EXAMPLES, "ruoyi-login-page.yaml"))
    Plugin = build_template_plugin(tpl)
    inst = Plugin(tpl)
    sess = FakeSession(
        {
            "http://target/login": FakeResp("<html><title>若依管理系统</title></html>", 200),
        }
    )
    res = inst.verify("http://target/", sess)
    assert res.status == STATUS_CONFIRMED, res.status
    assert res.kind == "vuln"
    print("PASS test_template_plugin_confirm")


def test_template_plugin_safe():
    """模板无匹配 → SAFE"""
    tpl = parse_nuclei_template(os.path.join(EXAMPLES, "ruoyi-login-page.yaml"))
    Plugin = build_template_plugin(tpl)
    inst = Plugin(tpl)
    sess = FakeSession({})  # 全部 404
    res = inst.verify("http://target/", sess)
    assert res.status == STATUS_SAFE, res.status
    print("PASS test_template_plugin_safe")


def test_template_plugin_unknown():
    """网络异常 → UNKNOWN（不判 SAFE）"""

    class ErrSession(FakeSession):
        def request(self, method, url, headers=None, data=None):
            raise Exception("connection refused")

    tpl = parse_nuclei_template(os.path.join(EXAMPLES, "ruoyi-login-page.yaml"))
    Plugin = build_template_plugin(tpl)
    res = Plugin(tpl).verify("http://target/", ErrSession({}))
    assert res.status == STATUS_UNKNOWN, res.status
    print("PASS test_template_plugin_unknown")


def test_template_plugin_regex_extract():
    """regex matcher + extractor 提取证据"""
    import tempfile

    content = (
        'id: test-extractor\n'
        'info:\n  name: Extract Test\n  severity: info\n'
        'http:\n'
        '  - method: GET\n'
        '    path:\n      - "{{BaseURL}}/x"\n'
        '    matchers:\n'
        '      - type: regex\n'
        '        regex:\n'
        '          - "version: ([0-9.]+)"\n'
        '    extractors:\n'
        '      - type: regex\n'
        '        name: version\n'
        '        regex:\n'
        '          - "version: ([0-9.]+)"\n'
    )
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        f.write(content)
        path = f.name
    try:
        tpl = parse_nuclei_template(path)
        Plugin = build_template_plugin(tpl)
        sess = FakeSession({"http://target/x": FakeResp("version: 1.2.3", 200)})
        res = Plugin(tpl).verify("http://target/", sess)
        assert res.status == STATUS_CONFIRMED
        assert "1.2.3" in res.evidence, res.evidence
    finally:
        os.unlink(path)
    print("PASS test_template_plugin_regex_extract")


def test_load_with_filters():
    """按 tags/severity 过滤加载"""
    plugins = load_nuclei_templates([EXAMPLES])
    # 5 个示例全部加载（含 info/low/medium/high）
    assert len(plugins) == 5, f"应加载 5 个模板，实际 {len(plugins)}"

    # 仅 tag=ruoyi
    plugins_ruoyi = load_nuclei_templates([EXAMPLES], tags=["ruoyi"])
    assert len(plugins_ruoyi) >= 3, f"ruoyi tag 模板应 >= 3，实际 {len(plugins_ruoyi)}"

    # 仅 high
    plugins_high = load_nuclei_templates([EXAMPLES], severities=["high"])
    assert len(plugins_high) == 1, f"high 模板应为 1 个，实际 {len(plugins_high)}"
    assert plugins_high[0].severity == "high"

    # 排除 swagger
    plugins_no_swagger = load_nuclei_templates([EXAMPLES], exclude_tags=["swagger"])
    assert len(plugins_no_swagger) == 4, f"排除 swagger 后应为 4 个，实际 {len(plugins_no_swagger)}"
    print("PASS test_load_with_filters")


def test_meta_contract():
    """模板插件 meta() 符合插件契约（含 name/cve/severity/cvss）"""
    tpl = parse_nuclei_template(os.path.join(EXAMPLES, "ruoyi-file-read-probe.yaml"))
    Plugin = build_template_plugin(tpl)
    meta = Plugin(tpl).meta()
    assert meta["name"] and meta["severity"] == "high"
    assert "cvss_score" in meta
    print("PASS test_meta_contract")


def test_dsl_matcher_whitelist():
    """dsl matcher 白名单求值（status_code + contains）"""
    from lib.nuclei_loader import _eval_dsl

    assert _eval_dsl("status_code == 200", 200, "hello", "") is True
    assert _eval_dsl("status_code == 200 && contains(body, 'hello')", 200, "hello world", "") is True
    assert _eval_dsl("status_code == 200 && contains(body, 'hello')", 200, "world", "") is False
    # 危险表达式被拒
    assert _eval_dsl("__import__('os').system('x')", 200, "", "") is False
    print("PASS test_dsl_matcher_whitelist")


if __name__ == "__main__":
    test_parse_example_template()
    test_parse_matchers_condition()
    test_validate_examples()
    test_validate_missing_id()
    test_unsupported_protocol_skipped()
    test_template_plugin_confirm()
    test_template_plugin_safe()
    test_template_plugin_unknown()
    test_template_plugin_regex_extract()
    test_load_with_filters()
    test_meta_contract()
    test_dsl_matcher_whitelist()
    print("ALL_E4_TESTS_PASS")
