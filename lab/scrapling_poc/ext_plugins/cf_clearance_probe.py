"""lab 探针插件：判定目标页面是否被 Cloudflare JS 挑战阻断。

非交付插件，仅供 lab 端到端验证「对抗型传输层」在真实 ScanEngine 下是否生效：
    - 参数 session 是引擎传入的会话（首轮为原始 SessionManager，绕过重试时为 BypassSession）
    - 被挑战拦截 → UNKNOWN（三态铁律：不可判定不判 SAFE），引擎据此触发 WAF 绕过
    - 拿到 200 且非挑战页 → CONFIRMED，证明请求真正穿透到了源站内容
"""

import re

from common.models import SEVERITY_LOW, STATUS_CONFIRMED, STATUS_UNKNOWN, ScanResult
from plugins.base import PluginBase

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)

# Cloudflare Interstitial / Turnstile 挑战页的典型标题（小写匹配）
_CHALLENGE_TITLES = (
    "just a moment",
    "attention required",
    "verifying you are human",
    "checking your browser",
    "one more step",
)

# 挑战响应体的稳定标记：本地化标题/新版挑战类型不会出现在 _CHALLENGE_TITLES 中，
# 但这类脚本/平台标记通常保留（比 title 更稳）
_CHALLENGE_BODY_MARKERS = (
    "__cf_chl",
    "cf-chl-",
    "challenge-platform",
    "challenges.cloudflare.com",
    "cf-challenge",
)


def _challenge_reason(resp, body: str, title: str) -> str:
    """返回挑战命中原因（未命中返回空串）

    仅凭 <title> 子串判定过于脆弱：叠加响应头（cf-mitigated）与响应体标记
    交叉佐证，避免本地化/新版挑战页被漏判为「未拿到有效页面」。
    """
    low_title = title.lower()
    for sig in _CHALLENGE_TITLES:
        if sig in low_title:
            return f"标题含挑战特征 {sig!r}"
    headers = getattr(resp, "headers", None) or {}
    try:
        mitigated = str(headers.get("cf-mitigated", "") or "")
    except Exception:  # noqa: BLE001 - 非常规 headers 对象不得影响判定
        mitigated = ""
    if "challenge" in mitigated.lower():
        return "响应头 cf-mitigated: challenge"
    low_body = body.lower()
    for sig in _CHALLENGE_BODY_MARKERS:
        if sig in low_body:
            return f"响应体含挑战标记 {sig!r}"
    return ""


class CfClearanceProbePlugin(PluginBase):
    """CF 挑战穿透探针（lab）"""

    name = "CF 挑战穿透探针"
    cve = "N/A"
    severity = SEVERITY_LOW
    category = "vuln"
    description = "实验室探针：判断目标页面是否被 Cloudflare JS 挑战阻断，用于验证对抗型传输层"
    fix = "（lab 探针插件，无修复建议）"
    # D7：绕过策略按 vuln_type 匹配；info_leak 这类「读页面」的探测同样适用
    vuln_type = "info_leak"
    supports_waf_bypass = True

    @staticmethod
    def _title_of(body: str) -> str:
        m = _TITLE_RE.search(body or "")
        return m.group(1).strip() if m else ""

    def verify(self, target, session) -> ScanResult:
        try:
            resp = session.get(target)
        except Exception as e:  # noqa: BLE001 - 网络异常不得判 SAFE
            return ScanResult(
                kind="error",
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=target,
                evidence=f"请求异常：{type(e).__name__}: {e}",
            )

        body = getattr(resp, "text", "") or ""
        status = int(getattr(resp, "status_code", 0) or 0)
        title = self._title_of(body)
        reason = _challenge_reason(resp, body, title)

        if reason:
            return self._build_result(
                STATUS_UNKNOWN,
                url=target,
                evidence=f"被 Cloudflare 挑战拦截（{reason}）：HTTP {status}，title={title!r}，{len(body)} bytes",
            )

        if status == 200:
            return self._build_result(
                STATUS_CONFIRMED,
                url=target,
                evidence=f"穿透成功：HTTP 200，title={title!r}，{len(body)} bytes（非挑战页）",
                extra={"vuln_type": self.vuln_type, "probe": "cf_clearance"},
            )

        return self._build_result(
            STATUS_UNKNOWN,
            url=target,
            evidence=f"未拿到有效页面：HTTP {status}，title={title!r}，{len(body)} bytes",
        )


plugin_list = [CfClearanceProbePlugin]
