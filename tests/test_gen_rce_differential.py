"""若依代码生成 SSTI：必须做差分，不能只探可达性。

旧实现的问题（2026-11-01 C4-5 靶场实测）
======================================
旧 `ruoyi_gen_rce.verify` 只 GET `/tool/gen/edit`：

- 有 SSTI 的真站 → 200 HTML
- 没 SSTI 的真站 → 200 HTML

两者拿到的东西一模一样，无法区分，于是旧实现「一律返回 UNKNOWN」。这不是保守，
是**有洞也报不出来** —— 该插件历史上从未 CONFIRMED 的直接原因。

另有一条 `X-Ruoyi-Vuln: gen-ssti` 签名头快速路径，那是给自建靶场开的后门，
真实站点永远不会返回这个头。测试里也一并守住它不该再是唯一能命中的路径。

修法：对 `/tool/gen/preview/{tableId}` 做「无 payload 基线 vs 注入 payload」差分。

三个缺一不可的条件：
  1. 基线（tableName=sys_user）**不含**求值结果
  2. 注入（tableName=sys_user_${7*7}）**含**独立数字 49
  3. 注入响应**不含**原始表达式 7*7（排除载荷原样回显）

只满足 2 的判定会误报 —— 页码、时间戳、行号里到处是 49。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.ruoyi.ruoyi_gen_rce import RuoyiGenRcePlugin  # noqa: E402

TARGET = "http://ruoyi.test/"

# 真实若依代码生成预览的响应形态（XML mapper 源码）
BASELINE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="com.ruoyi.system.mapper.sys_userMapper">
    <resultMap type="com.ruoyi.system.domain.sys_user" id="BaseResultMap"/>
</mapper>"""

INJECTED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="com.ruoyi.system.mapper.sys_user_49Mapper">
    <resultMap type="com.ruoyi.system.domain.sys_user_49" id="BaseResultMap"/>
</mapper>"""


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self._json = None

    def json(self):
        raise ValueError("not json")


class _Session:
    """按 URL 里的 tableName 返回基线或注入响应。"""

    def __init__(self, baseline="", injected="", edit_status=200, preview_status=200):
        self.baseline = baseline
        self.injected = injected
        self.edit_status = edit_status
        self.preview_status = preview_status
        self.urls = []

    def get(self, url, **kw):
        self.urls.append(url)
        if "preview" in url:
            if "7*7" in url or "%24%7B" in url:
                return _Resp(self.injected, self.preview_status)
            return _Resp(self.baseline, self.preview_status)
        # /tool/gen/edit 或 /tool/gen
        return _Resp('{"code":200,"msg":"ok"}', self.edit_status)


# ── 差分成立 → CONFIRMED ────────────────────────────────


def test_differential_probe_confirms_real_ssti():
    """基线无 49、注入有 49、无载荷回显 → CONFIRMED。"""
    sess = _Session(baseline=BASELINE_XML, injected=INJECTED_XML)
    result = RuoyiGenRcePlugin().verify(TARGET, sess)
    assert result.status == "CONFIRMED", f"真实 SSTI 漏报：{result.evidence}"
    assert "差分" in result.evidence


# ── 三个条件缺一不可 ────────────────────────────────────


def test_baseline_containing_49_blocks_confirmation():
    """基线本身就含 49（页码/时间戳）→ 差分不成立，不能 CONFIRMED。

    这是最关键的防误报：不加这条，任何页面含 49 的真站都会误报。
    """
    baseline_with_49 = BASELINE_XML + "\n<!-- page 49 of 1200 -->"
    sess = _Session(baseline=baseline_with_49, injected=INJECTED_XML)
    result = RuoyiGenRcePlugin().verify(TARGET, sess)
    assert result.status != "CONFIRMED", "基线含 49 时差分不成立，却仍判 CONFIRMED"


def test_injection_without_eval_result_is_not_confirmed():
    """注入后响应没有 49（模板没被求值）→ 不 CONFIRMED。"""
    sess = _Session(baseline=BASELINE_XML, injected=BASELINE_XML)
    result = RuoyiGenRcePlugin().verify(TARGET, sess)
    assert result.status != "CONFIRMED"


def test_raw_payload_reflection_is_not_confirmed():
    """注入响应原样回显 7*7（未求值）→ 不算命中。"""
    reflected = BASELINE_XML + "\n<!-- table=sys_user_${7*7} -->"
    sess = _Session(baseline=BASELINE_XML, injected=reflected)
    result = RuoyiGenRcePlugin().verify(TARGET, sess)
    assert result.status != "CONFIRMED", "载荷原样回显被当成求值成功"


def test_number_boundary_not_fooled_by_490():
    """490 / 1490 里的 49 不算求值结果。"""
    injected = BASELINE_XML.replace("sys_user", "sys_user_1490")
    sess = _Session(baseline=BASELINE_XML, injected=injected)
    result = RuoyiGenRcePlugin().verify(TARGET, sess)
    assert result.status != "CONFIRMED", "1490 被误判为 ${7*7}=49"


# ── 不可达 / 非若依 ────────────────────────────────────


def test_gen_module_404_is_safe():
    """代码生成模块不存在（404）→ SAFE。"""
    sess = _Session(edit_status=404)
    result = RuoyiGenRcePlugin().verify(TARGET, sess)
    assert result.status == "SAFE"


def test_edit_reachable_without_ssti_is_unknown_not_confirmed():
    """模块可达但没有 SSTI 迹象 → UNKNOWN（不猜），绝不能是 CONFIRMED。"""
    sess = _Session(baseline=BASELINE_XML, injected=BASELINE_XML)
    result = RuoyiGenRcePlugin().verify(TARGET, sess)
    assert result.status != "CONFIRMED"
    assert result.status in ("UNKNOWN", "SAFE")


# ── 探针确实发出了注入请求 ─────────────────────────────


def test_probe_actually_sends_injection():
    """确认探针真的发了两条 preview 请求（基线 + 注入），不是只看可达性。"""
    sess = _Session(baseline=BASELINE_XML, injected=INJECTED_XML)
    RuoyiGenRcePlugin().verify(TARGET, sess)
    preview_urls = [u for u in sess.urls if "preview" in u]
    assert len(preview_urls) >= 2, f"只发了 {len(preview_urls)} 条 preview 请求，差分不成立"
    assert any("%24%7B" in u or "7*7" in u for u in preview_urls), "未发出注入载荷"
