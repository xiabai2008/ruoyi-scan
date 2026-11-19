# common/models.py — 扫描结果数据模型（共享基础层，供 core/lib/api/cli/plugins 共同依赖）
# ScanResult / FingerprintResult
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Tuple

# 判定三态（agents.md §5）：网络异常归 UNKNOWN，绝不判 SAFE
STATUS_CONFIRMED = "CONFIRMED"  # 确认存在
STATUS_SAFE = "SAFE"  # 确认不存在
STATUS_UNKNOWN = "UNKNOWN"  # 无法判定（网络异常等）


class UnknownReason(str, Enum):
    """UNKNOWN 的结构化原因码（v1.7 WP-1）。

    为什么是一等字段而不是从 evidence 猜：
      v1.6 复盘证明「按证据文本关键字事后归类」会把正确的登录墙降级误判成误降级。
      原因必须由产生点在写 status=UNKNOWN 的同时写入，报告只做展示。

    值是可序列化的短字符串，JSON/CSV/SARIF 直接输出；新增原因码只允许追加，
    不允许改动既有值（旧报告与旧消费者依赖它做统计）。
    """

    AUTH_WALL = "auth_wall"  # 登录墙拦截（302→/login 或 200 登录页）
    NO_SESSION = "no_session"  # 声明 requires_auth 但未取得高权会话
    NO_LOWPRIV = "no_lowpriv"  # 越权类缺低权账号（--surface-account）
    DENIED = "denied"  # 401/403/429，端点存在但拒绝
    UNREACHABLE = "unreachable"  # 网络异常/超时
    OAST_NO_CALLBACK = "oast_no_callback"  # 带外 payload 已发出但未收到回调（不能判不存在）
    NO_LOGIN_PAGE = "no_login_page"  # 目标无登录页，爆破类未执行（避免无意义字典请求）
    NO_EVIDENCE = "no_evidence"  # SAFE 缺判定证据被降级
    BLOCKED = "blocked"  # 全站 WAF 拦截
    BUDGET_EXCEEDED = "budget_exceeded"  # 超出 --time-budget，本项未执行
    ENDPOINT_ABSENT = "endpoint_absent"  # 端点不存在（版本/架构差异，属正确行为）
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # 插件自判证据不足
    UNCLASSIFIED = "unclassified"  # 兜底：必须可计数，目标 <5%


ALL_UNKNOWN_REASONS: Tuple[str, ...] = tuple(r.value for r in UnknownReason)

# 报告展示用中文标签。未登记的新码回退原值，避免报告因枚举缺失而崩溃。
UNKNOWN_REASON_LABELS: Dict[str, str] = {
    UnknownReason.AUTH_WALL.value: "登录墙拦截",
    UnknownReason.NO_SESSION.value: "缺少高权会话",
    UnknownReason.NO_LOWPRIV.value: "缺少低权账号",
    UnknownReason.DENIED.value: "端点拒绝访问",
    UnknownReason.UNREACHABLE.value: "目标不可达",
    UnknownReason.OAST_NO_CALLBACK.value: "带外未回调",
    UnknownReason.NO_LOGIN_PAGE.value: "无登录页跳过爆破",
    UnknownReason.NO_EVIDENCE.value: "缺少判定证据",
    UnknownReason.BLOCKED.value: "全站 WAF 拦截",
    UnknownReason.BUDGET_EXCEEDED.value: "超出时间预算",
    UnknownReason.ENDPOINT_ABSENT.value: "端点不存在",
    UnknownReason.INSUFFICIENT_EVIDENCE.value: "证据不足",
    UnknownReason.UNCLASSIFIED.value: "未归类",
}

# 给用户的解锁提示（CLI/报告用）。空串表示该原因不需要用户额外操作。
UNKNOWN_REASON_HINTS: Dict[str, str] = {
    UnknownReason.AUTH_WALL.value: "加 --auth-login 提供高权会话；未授权类插件须用匿名视角复核",
    UnknownReason.NO_SESSION.value: "加 --auth-login 提供高权账号后重扫",
    UnknownReason.NO_LOWPRIV.value: "加 --surface-account user:pass（可多次）提供低权账号",
    UnknownReason.DENIED.value: "端点存在但拒绝访问，不能据此判「不存在」",
    UnknownReason.UNREACHABLE.value: "检查目标连通性/代理后重试",
    UnknownReason.OAST_NO_CALLBACK.value: "确认 --oast-host 目标是可达的；无回调不能判不存在",
    UnknownReason.NO_LOGIN_PAGE.value: "目标无登录页，无需跑口令字典",
    UnknownReason.NO_EVIDENCE.value: "插件判定缺少可复核证据，需人工复核",
    UnknownReason.BLOCKED.value: "尝试 --bypass-waf 或降低速率后重扫",
    UnknownReason.BUDGET_EXCEEDED.value: "调大 --time-budget",
    UnknownReason.ENDPOINT_ABSENT.value: "版本/架构差异导致端点不存在，属正确行为",
    UnknownReason.INSUFFICIENT_EVIDENCE.value: "需人工复核证据",
    UnknownReason.UNCLASSIFIED.value: "未归类，需补充产生点",
}


def unknown_reason_label(code: str) -> str:
    """把原因码转成报告展示用中文；未知码原样返回。"""
    return UNKNOWN_REASON_LABELS.get(code, code)


# 危害等级
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# 中文等级映射（报告展示用）
SEVERITY_CN = {
    SEVERITY_HIGH: "高",
    SEVERITY_MEDIUM: "中",
    SEVERITY_LOW: "低",
}


@dataclass
class ScanResult:
    """单次插件扫描结果"""

    kind: str  # 结果类别：vuln / brute / dir / info
    name: str  # 漏洞/项名称（中文）
    severity: str = SEVERITY_LOW  # high/medium/low
    status: str = STATUS_UNKNOWN  # CONFIRMED/SAFE/UNKNOWN
    url: str = ""  # 触发 URL
    evidence: str = ""  # 证据（关键字/响应片段）
    extra: Dict[str, Any] = field(default_factory=dict)  # 附加字段
    fix: str = ""  # 修复建议（一句话概要）
    # D18：修复详情（具体代码/配置 diff、升级版本号、操作步骤，多行字符串）
    fix_detail: str = ""
    # D24：复现命令（curl/Python PoC 脚本，多行字符串，可直接复制执行）
    reproduce: str = ""
    # D12：CVE / CVSS / 合规映射（向后兼容，默认空）
    cve: str = ""  # CVE 编号
    cvss_score: float = 0.0  # CVSS v3.1 Base Score
    cvss_vector: str = ""  # CVSS v3.1 向量
    compliance: Dict[str, str] = field(default_factory=dict)  # 合规映射 {'等保2.0': '8.1.3', 'OWASP': 'A03:2021'}
    # v1.7 WP-1：UNKNOWN 的结构化原因码（见 UnknownReason）。非 UNKNOWN 时为空。
    unknown_reason: str = ""

    @property
    def is_vuln(self) -> bool:
        """是否确认存在漏洞"""
        return self.status == STATUS_CONFIRMED

    def to_dict(self) -> Dict[str, Any]:
        """转为字典（报告渲染用）"""
        # 手写键序而非 dataclasses.asdict：注入 severity_cn 展示字段并显式控制序列化形状
        return {
            "kind": self.kind,
            "name": self.name,
            "severity": self.severity,
            "severity_cn": SEVERITY_CN.get(self.severity, self.severity),
            "status": self.status,
            "url": self.url,
            "evidence": self.evidence,
            "extra": self.extra,
            "fix": self.fix,
            "fix_detail": self.fix_detail,
            "reproduce": self.reproduce,
            "cve": self.cve,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "compliance": self.compliance,
            "unknown_reason": self.unknown_reason,
        }


@dataclass
class FingerprintResult:
    """指纹识别结果"""

    cms: str = ""  # CMS 标识（如 ruoyi）
    version: str = ""
    confidence: float = 0.0  # 0~1
    matched: List[str] = field(default_factory=list)  # 命中的特征列表
    # E1：变体标识（如 ruoyi-vue3 / ruoyi-plus；空串=通用版或未细分，向后兼容）
    variant: str = ""


@dataclass
class ComponentVersionResult:
    """E2：组件版本检测结果（fastjson/SpringBoot/Shiro/Nacos/Log4j）

    由 lib/component_detect.py 产出，经 orchestrator 转换为 ScanResult
    （category='component'）进入统一报告管线。
    """

    component: str = ""  # 组件名（fastjson/spring-boot/shiro/nacos/log4j）
    detected_version: str = ""  # 已识别版本（'' = 无法识别）
    status: str = STATUS_UNKNOWN  # 三态判定
    cve: str = ""  # 命中的 CVE（有则 CONFIRMED 依据）
    fix_version: str = ""  # 建议升级版本
    evidence: str = ""  # 探测证据
    url: str = ""  # 探测 URL
    severity: str = SEVERITY_MEDIUM
    cvss_score: float = 0.0
    compliance: Dict[str, str] = field(default_factory=dict)  # 合规映射
    # v1.7 WP-1：组件检测同样可能产 UNKNOWN，原因码与 ScanResult 对齐。
    unknown_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转为字典（报告渲染用）"""
        return {
            "component": self.component,
            "detected_version": self.detected_version,
            "status": self.status,
            "cve": self.cve,
            "fix_version": self.fix_version,
            "evidence": self.evidence,
            "url": self.url,
            "severity": self.severity,
            # 与 ScanResult.to_dict() 保持同形状：注入中文等级展示字段
            "severity_cn": SEVERITY_CN.get(self.severity, self.severity),
            "cvss_score": self.cvss_score,
            "compliance": self.compliance,
            "unknown_reason": self.unknown_reason,
        }
