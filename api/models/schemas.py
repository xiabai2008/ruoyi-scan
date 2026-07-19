# D9 API 请求/响应模型（Pydantic）
from typing import Optional, List, Any
from pydantic import BaseModel, Field, HttpUrl


# === 扫描任务模型 ===

class ScanCreateRequest(BaseModel):
    """提交扫描任务请求"""
    target: str = Field(..., description='目标 URL（如 http://example.com:8080/）')
    mode: str = Field('u', description='扫描模式：u=综合/m=目录/p=漏洞/l=爆破')
    cms: str = Field('', description='手动指定 CMS（ruoyi/spring，空=自动识别）')
    threads: int = Field(1, ge=1, le=50, description='并发线程数')
    rate: int = Field(0, ge=0, description='限速（每秒请求数，0=不限）')
    proxy: str = Field('', description='代理地址（如 http://127.0.0.1:8080）')
    timeout: int = Field(10, ge=1, le=120, description='请求超时秒数')
    report_format: str = Field('all', description='报告格式：html/json/csv/pdf/docx/xlsx，逗号分隔；all=全部')
    no_dedup: bool = Field(False, description='关闭结果去重聚合')
    pass_level: str = Field('full', description='口令字典级别：top100/top1000/full')
    portscan: bool = Field(False, description='扫描前执行端口扫描')
    ports: str = Field('', description='自定义端口（逗号分隔，如 80,443,8080）')
    bypass_waf: str = Field('auto', description='WAF 绕过：auto=自动/on=强制/off=禁用')
    plugins: Optional[List[str]] = Field(None, description='指定插件名列表（空=全部）')


class ScanCreateResponse(BaseModel):
    """提交扫描任务响应"""
    task_id: str
    status: str = 'pending'


class ScanTaskDTO(BaseModel):
    """扫描任务详情 DTO"""
    task_id: str
    status: str
    target: str
    mode: str = 'u'
    started_at: float = 0
    finished_at: float = 0
    duration: float = 0
    request_count: int = 0
    result_count: int = 0
    confirmed_count: int = 0
    error: str = ''
    fingerprint: Optional[dict] = None
    waf: Optional[dict] = None
    report_paths: List[str] = []


class ScanResultDTO(BaseModel):
    """扫描结果 DTO"""
    name: str
    status: str
    severity: str = 'low'
    url: str = ''
    evidence: str = ''
    extra: dict = {}


# === 报告模型 ===

class ReportMetadataDTO(BaseModel):
    """报告元数据"""
    task_id: str
    formats: List[str] = []
    paths: List[str] = []


# === 插件模型 ===

class PluginDTO(BaseModel):
    """插件元数据"""
    name: str = ''
    cms: str = ''
    category: str = ''
    severity: str = 'low'
    description: str = ''
    cve: str = ''
    affected_versions: str = ''
    vuln_type: str = ''
    supports_waf_bypass: bool = False


# === 系统模型 ===

class HealthDTO(BaseModel):
    """健康检查响应"""
    status: str = 'ok'
    version: str = ''
    uptime: float = 0


class VersionDTO(BaseModel):
    """版本信息"""
    version: str = ''
    author: str = ''
    github: str = ''
    python_version: str = ''


class FingerprintDTO(BaseModel):
    """指纹探测结果"""
    target: str
    cms: str = ''
    version: str = ''
    confidence: float = 0
    matched: List[str] = []
    waf: str = ''
    waf_display: str = ''


# === WebSocket 事件模型 ===

class WSEvent(BaseModel):
    """WebSocket 事件"""
    type: str
    data: Any = None
    task_id: str = ''
    timestamp: float = 0
