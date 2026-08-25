# common/models.py — 扫描结果数据模型（共享基础层，供 core/lib/api/cli/plugins 共同依赖）
# ScanResult / FingerprintResult
from dataclasses import dataclass, field
from typing import Any, Dict, List

# 判定三态（agents.md §5）：网络异常归 UNKNOWN，绝不判 SAFE
STATUS_CONFIRMED = "CONFIRMED"  # 确认存在
STATUS_SAFE = "SAFE"  # 确认不存在
STATUS_UNKNOWN = "UNKNOWN"  # 无法判定（网络异常等）

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
            "cvss_score": self.cvss_score,
            "compliance": self.compliance,
        }
