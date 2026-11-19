# v1.7 WP-3 插件数门禁（scripts/check_plugin_count_ssot.py）的豁免边界测试
#
# 为什么需要：该门禁原先对「含中文引号的行」整行豁免，导致 README「口径声明」一行
# 引号内的旧说法把引号外的旧总数（56）一起带过去了，门禁长期报绿。
# 这里锁定收窄后的行为：只豁免引号内部，引号外的数字照样检查。

from scripts.check_plugin_count_ssot import _check_line

RUNTIME = 62
PKG = {21, 14, 13, 8, 2}


def _errors(line: str):
    return _check_line("T.md", 1, line, RUNTIME, PKG, False)


def test_stale_total_in_quote_line_is_caught():
    """引号外的旧总数必须报错——这是曾经的真实漏检点。"""
    line = "> **口径声明**：上表是「覆盖率代理指标」，也不覆盖 v1.6.0 之后的 56 个插件。"
    errs = _errors(line)
    assert len(errs) == 1
    assert "56" in errs[0]


def test_historical_phrase_inside_quote_is_allowed():
    """引号内的历史表述不判错（wiki 的「已修正」表依赖此行为）。"""
    assert _errors("wiki 表：README「若依 18 个插件」已修正为 20") == []


def test_current_total_is_allowed():
    assert _errors("引擎与 62 个 POC 全部编译进同一个可执行文件") == []


def test_package_level_counts_are_allowed():
    """分项行允许出现包级数字（21/14/13/8/2）。"""
    assert _errors("ruoyi 21 / spring 14 / common 13 / jeecgboot 8 / yudao 2") == []


def test_ratio_with_wrong_denominator_is_caught():
    errs = _errors("本轮产出 46/54 插件命中")
    assert len(errs) == 1
    assert "54" in errs[0]


def test_history_context_line_is_exempt():
    """带明确历史上下文的整行豁免仍然保留（盲测基线表依赖此行为）。"""
    assert _errors("盲测 v3 产出 46/54，也不覆盖 56 个插件") == []
