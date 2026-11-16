# v1.7 WP-1：UNKNOWN 原因码的兼容归类器
#
# 设计边界（重要）
# ================
# 首选路径永远是**产生点写入的结构化字段**：
#   - 降级链：lib/reachability.py 在写 status=UNKNOWN 时写 extra 布尔标记；
#   - 引擎：core/engine.py 在预算/认证降级/异常兜底时直接写 unknown_reason；
#   - 编排层：core/orchestrator.py::fill_unknown_reasons() 只读 extra 标记补齐；
#   - 组件：lib/component_detect.py::to_scan_result() 按自身固定句式映射。
#
# 但 v1.7 之前的历史插件（以及第三方插件）直接构造 `ScanResult(status=UNKNOWN)`
# 时没有原因码，且这些字符串是**扫描器自己的代码生成的固定前缀**（不是目标
# 响应里的任意文本）。为了在「不重跑全部靶场」的前提下回答 567 条 UNKNOWN 的
# 构成，本模块提供一个**受控前缀白名单**：
#   - 只在没有结构化原因时作为兜底；
#   - 只匹配本仓库代码写出的固定句式，匹配不到一律返回空串（上层记 unclassified）；
#   - 不做通用关键词/正则猜测，新增前缀必须同时补测试。
#
# 这与 v1.6 的教训不冲突：那次错在「用目标响应文本猜降级是否正确」；这里分类的
# 是扫描器自身的判定原因文案，且不改变任何 status。
from __future__ import annotations

from typing import Tuple

# (原因码, 固定前缀元组)。顺序即优先级：先认证类，再网络/拦截类，最后证据不足。
_LEGACY_PREFIX_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        "no_session",
        (
            "未取得高权会话",
            "未取得高权",
            "高权会话",
            "动态口令",
            "OTP",
            "MFA",
            "二次验证",
        ),
    ),
    ("no_lowpriv", ("缺少低权账号", "surface-account", "低权账号")),
    ("auth_wall", ("请求被登录墙拦截", "登录墙", "200 登录页")),
    ("budget_exceeded", ("超出扫描时间预算", "time-budget")),
    ("denied", ("响应被拒绝", "认证失败", "Token校验失败")),
    (
        "unreachable",
        (
            "未取得有效响应",
            "网络异常",
            "连接失败",
            "Max retries",
            "timed out",
            "Timeout",
            "目标不可达",
            "不可达",
            "WinError",
            "拒绝",
        ),
    ),
    ("no_evidence", ("缺少判定证据", "SAFE 缺少判定证据")),
    ("blocked", ("目标疑似被拦截", "全站拦截", "WAF 拦截")),
    (
        "endpoint_absent",
        (
            "端点不存在",
            "接口不存在",
            "业务 code=404",
            "HTTP 404",
            "HTTP 405",
            "已迁移",
            "SnailJob",
        ),
    ),
    (
        "insufficient_evidence",
        (
            "无法判定",
            "证据不足",
            "无法识别",
            "无法确认",
            "需人工",
            "无法对应",
            "静态资源",
            "指纹",
            "未探测到",
            "探测异常",
            "未收到回调",
            "未启用",
            "扫描 696",
            "目录扫描",
            "JSON 响应",
            "未渲染",
            "编辑页",
            "Shiro",
            "表单端点可达",
            "HTTP 200",
            "HTTP 501",
            "code=500",
        ),
    ),
)


def classify_legacy_unknown(evidence: str) -> str:
    """按扫描器自身的固定证据前缀归类历史 UNKNOWN；无法归类返回空串。

    Args:
        evidence: ScanResult.evidence 文本（可能包含目标响应片段）

    Returns:
        原因码字符串；空串表示未命中白名单，调用方应记 unclassified。
    """
    text = evidence or ""
    if not text:
        return ""
    for code, prefixes in _LEGACY_PREFIX_RULES:
        for prefix in prefixes:
            if prefix in text:
                return code
    return ""
