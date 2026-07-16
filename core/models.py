# 扫描结果数据模型：ScanResult / FingerprintResult
from dataclasses import dataclass, field
from typing import Any, Dict, List

# 判定三态（agents.md §5）：网络异常归 UNKNOWN，绝不判 SAFE
STATUS_CONFIRMED = 'CONFIRMED'  # 确认存在
STATUS_SAFE = 'SAFE'            # 确认不存在
STATUS_UNKNOWN = 'UNKNOWN'      # 无法判定（网络异常等）

# 危害等级
SEVERITY_HIGH = 'high'
SEVERITY_MEDIUM = 'medium'
SEVERITY_LOW = 'low'

# 中文等级映射（报告展示用）
SEVERITY_CN = {
    SEVERITY_HIGH: '高',
    SEVERITY_MEDIUM: '中',
    SEVERITY_LOW: '低',
}


@dataclass
class ScanResult:
    """单次插件扫描结果"""
    kind: str                                        # 结果类别：vuln / brute / dir / info
    name: str                                        # 漏洞/项名称（中文）
    severity: str = SEVERITY_LOW                     # high/medium/low
    status: str = STATUS_UNKNOWN                     # CONFIRMED/SAFE/UNKNOWN
    url: str = ''                                    # 触发 URL
    evidence: str = ''                               # 证据（关键字/响应片段）
    extra: Dict[str, Any] = field(default_factory=dict)   # 附加字段
    fix: str = ''                                    # 修复建议

    @property
    def is_vuln(self):
        """是否确认存在漏洞"""
        return self.status == STATUS_CONFIRMED

    def to_dict(self):
        """转为字典（报告渲染用）"""
        return {
            'kind': self.kind,
            'name': self.name,
            'severity': self.severity,
            'severity_cn': SEVERITY_CN.get(self.severity, self.severity),
            'status': self.status,
            'url': self.url,
            'evidence': self.evidence,
            'extra': self.extra,
            'fix': self.fix,
        }


@dataclass
class FingerprintResult:
    """指纹识别结果"""
    cms: str = ''                                    # CMS 标识（如 ruoyi）
    version: str = ''
    confidence: float = 0.0                         # 0~1
    matched: List[str] = field(default_factory=list)    # 命中的特征列表
