# 插件抽象基类（agents.md §5：每漏洞一插件，继承 PluginBase）
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Optional

from core.models import STATUS_CONFIRMED, ScanResult

if TYPE_CHECKING:
    from core.session import SessionManager

# === D12：CVSS v3.1 评分计算 + 合规标签解析 ===

# CVSS v3.1 指标权重表（Base Metric）
_CVSS_WEIGHTS = {
    # Attack Vector (AV)
    "AV:N": 0.85,
    "AV:A": 0.62,
    "AV:L": 0.55,
    "AV:P": 0.2,
    # Attack Complexity (AC)
    "AC:L": 0.77,
    "AC:H": 0.44,
    # Privileges Required (PR) — Scope Unchanged
    "PR:N": 0.85,
    "PR:L": 0.62,
    "PR:H": 0.27,
    # User Interaction (UI)
    "UI:N": 0.85,
    "UI:P": 0.62,
    # Confidentiality / Integrity / Availability Impact
    "C:H": 0.56,
    "C:L": 0.22,
    "C:N": 0.0,
    "I:H": 0.56,
    "I:L": 0.22,
    "I:N": 0.0,
    "A:H": 0.56,
    "A:L": 0.22,
    "A:N": 0.0,
}

# Scope Changed 时 PR 权重
_CVSS_PR_SC = {"PR:N": 0.85, "PR:L": 0.68, "PR:H": 0.5}


def cvss_score(vector: str) -> float:
    """从 CVSS v3.1 向量字符串计算 Base Score

    Args:
        vector: CVSS v3.1 向量，如 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

    Returns:
        Base Score（0.0~10.0），空向量返回 0.0
    """
    if not vector:
        return 0.0
    # 标准化：去掉 CVSS:3.1/ 前缀
    v = vector.strip().lstrip("CVSS:3.1/").lstrip("CVSS:3.0/")
    parts = [p.strip() for p in v.split("/") if p.strip()]
    metrics = {}
    for p in parts:
        if ":" in p:
            k, val = p.split(":", 1)
            metrics[k.strip()] = val.strip()

    # 必须有所有 8 个基础指标
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    if not all(k in metrics for k in required):
        return 0.0

    scope_changed = metrics["S"] == "C"

    # ISS (Impact Sub-Score)
    c = _CVSS_WEIGHTS.get(f"C:{metrics['C']}", 0.0)
    i = _CVSS_WEIGHTS.get(f"I:{metrics['I']}", 0.0)
    a = _CVSS_WEIGHTS.get(f"A:{metrics['A']}", 0.0)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    # Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    # Exploitability
    av = _CVSS_WEIGHTS.get(f"AV:{metrics['AV']}", 0.0)
    ac = _CVSS_WEIGHTS.get(f"AC:{metrics['AC']}", 0.0)
    pr_key = f"PR:{metrics['PR']}"
    pr = _CVSS_PR_SC.get(pr_key, _CVSS_WEIGHTS.get(pr_key, 0.0)) if scope_changed else _CVSS_WEIGHTS.get(pr_key, 0.0)
    ui = _CVSS_WEIGHTS.get(f"UI:{metrics['UI']}", 0.0)
    exploitability = 8.22 * av * ac * pr * ui

    # Base Score
    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    # CVSS v3.1 规范要求向上取整到 0.1（Roundup，非四舍五入）
    import math

    return math.ceil(base * 10) / 10.0


def parse_compliance(tag: str) -> Dict[str, str]:
    """解析合规映射标签字符串为结构化字典

    格式：'等保2.0:8.1.3;OWASP:A03:2021'
    返回：{'等保2.0': '8.1.3', 'OWASP': 'A03:2021'}

    Args:
        tag: 合规标签字符串

    Returns:
        结构化字典，空标签返回空字典
    """
    if not tag:
        return {}
    result = {}
    for part in tag.split(";"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        k, v = part.split(":", 1)
        result[k.strip()] = v.strip()
    return result


class PluginBase(ABC):
    """插件基类：所有漏洞检测插件继承此类"""

    # 插件元信息（子类覆盖）
    name = ""  # 中文漏洞名
    cve = ""  # CVE 编号（无 CVE 时填 CNVD 编号或 N/A）
    severity = "low"  # high/medium/low
    category = ""  # 分类
    description = ""  # 漏洞描述
    fix = ""  # 修复建议（一句话概要）
    # D18：修复详情（具体代码/配置 diff、升级版本号、操作步骤）
    # 格式建议：多行字符串，每行一条具体操作（代码片段/配置项/升级命令）
    fix_detail = ""
    # D24：复现命令（curl/Python PoC 脚本，报告"复现步骤"列用）
    # 格式建议：多行字符串，可直接复制执行的 curl 命令或 Python 代码片段
    reproduce = ""
    # D2：影响版本范围（空串表示全版本适用，如 '>=4.2,<4.6'）
    affected_versions = ""
    # D12：CVSS 评分与合规映射
    cvss_vector = ""  # CVSS v3.1 向量字符串（如 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'）
    compliance = ""  # 合规映射标签（如 '等保2.0:8.1.3;OWASP:A03:2021'）

    # D7：WAF 绕过支持（子类按需覆盖）
    vuln_type = ""  # 漏洞类型标识（sqli/xss/rce/file_read/auth），供绕过策略匹配
    supports_waf_bypass = False  # 是否支持 WAF 绕过（True 则引擎在 WAF 命中后调用 verify_with_bypass）
    bypass_max_attempts = 3  # 最大绕过尝试次数（每种策略算一次）

    @abstractmethod
    def verify(self, target: str, session: "SessionManager") -> ScanResult:
        """执行检测，返回 ScanResult（三态判定）

        网络异常等不可判定情形必须返回 status=UNKNOWN，不得判为 SAFE。
        """
        raise NotImplementedError

    def verify_with_bypass(self, target: str, bypass_session: "SessionManager", bypass_ctx: Any) -> ScanResult:
        """WAF 绕过验证（D7）：子类覆盖以实现绕过逻辑

        默认实现：复用 verify()，但使用 BypassSession（已应用传输层变换）。
        子类可覆盖此方法，利用 bypass_ctx.original_payload 和策略变形函数
        构造绕过 payload。

        Args:
            target: 扫描目标 URL
            bypass_session: BypassSession 实例（已应用传输层变换）
            bypass_ctx: BypassContext（含 waf_type/vuln_type/strategy 等）

        Returns:
            ScanResult（三态判定，与 verify() 一致）
        """
        # 默认实现：直接用 BypassSession 调用 verify
        # 子类应覆盖此方法以应用 payload 变形
        return self.verify(target, bypass_session)

    def _build_result(
        self, status: str, url: str = "", evidence: str = "", extra: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """辅助方法：构造 ScanResult 并自动填充 kind/name/severity/fix

        插件在 verify() 中可直接用此方法构建结果，自动继承插件类属性，
        减少样板代码。extra 可包含 vuln_type/payload_class 供 D8 去重聚合。
        D12：自动填充 cve/cvss_score/cvss_vector/compliance。
        D18/D24：自动填充 fix_detail/reproduce。
        """
        return ScanResult(
            kind="vuln" if status == STATUS_CONFIRMED else "info",
            name=self.name,
            severity=self.severity,
            status=status,
            url=url,
            evidence=evidence,
            extra=extra or {},
            fix=self.fix or "",
            fix_detail=self.fix_detail or "",
            reproduce=self.reproduce or "",
            cve=self.cve or "",
            cvss_score=cvss_score(self.cvss_vector) if self.cvss_vector else 0.0,
            cvss_vector=self.cvss_vector or "",
            compliance=parse_compliance(self.compliance) if self.compliance else {},
        )

    def meta(self) -> Dict[str, str]:
        """返回插件元信息字典"""
        return {
            "name": self.name,
            "cve": self.cve,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "fix": self.fix,
            "fix_detail": self.fix_detail,
            "reproduce": self.reproduce,
            "cvss_vector": self.cvss_vector,
            "cvss_score": cvss_score(self.cvss_vector),
            "compliance": parse_compliance(self.compliance),
            "affected_versions": self.affected_versions,
        }
