# 插件抽象基类（agents.md §5：每漏洞一插件，继承 PluginBase）
from abc import ABC, abstractmethod

from core.models import ScanResult


class PluginBase(ABC):
    """插件基类：所有漏洞检测插件继承此类"""

    # 插件元信息（子类覆盖）
    name = ''          # 中文漏洞名
    cve = ''           # CVE 编号
    severity = 'low'   # high/medium/low
    category = ''      # 分类
    description = ''   # 漏洞描述
    fix = ''           # 修复建议

    @abstractmethod
    def verify(self, target, session) -> ScanResult:
        """执行检测，返回 ScanResult（三态判定）

        网络异常等不可判定情形必须返回 status=UNKNOWN，不得判为 SAFE。
        """
        raise NotImplementedError

    def meta(self):
        """返回插件元信息字典"""
        return {
            'name': self.name,
            'cve': self.cve,
            'severity': self.severity,
            'category': self.category,
            'description': self.description,
            'fix': self.fix,
        }
