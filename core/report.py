# 报告渲染：HTML / JSON / CSV（Step 4 完整实装）
from core.models import ScanResult


class ReportBuilder:
    """扫描报告构建器（Step 4 完整实装 HTML/JSON/CSV 三格式）"""

    def __init__(self, results=None, target='', summary=None):
        self.results = results or []
        self.target = target
        self.summary = summary or {}

    def add(self, result):
        self.results.append(result)

    def render(self, fmt='json', path=None):
        """渲染报告（Step 4 完整实装）"""
        raise NotImplementedError('报告渲染将在 Step 4 实装')
