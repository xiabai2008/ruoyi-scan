# 结果去重聚合：同目标内多插件命中同一漏洞时合并为一条（D8.1）
#
# 指纹构成：sha1(normalized_endpoint | vuln_type | payload_class)[:16]
# 聚合层位置：ReportBuilder 渲染前（不破坏 ScanEngine 契约，可 --no-dedup 绕过）
# 鸭子类型：AggregatedVuln 暴露与 ScanResult 相同属性名，ReportBuilder 零改动即可接受
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit, urlunsplit

from core.models import (STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN,
                          SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW)

# 严重度排序（数值越大越严重）
_SEVERITY_ORDER = {SEVERITY_LOW: 0, SEVERITY_MEDIUM: 1, SEVERITY_HIGH: 2}
# 状态排序（数值越大越"差"，CONFIRMED 最严重）
_STATUS_ORDER = {STATUS_SAFE: 0, STATUS_UNKNOWN: 1, STATUS_CONFIRMED: 2}

# vuln_type → 中文名映射（聚合时优先使用语义化名称）
VULN_TYPE_CN = {
    'arbitrary_file_read': '任意文件读取',
    'sql_injection_error_based': 'SQL注入(报错型)',
    'sql_injection_boolean_based': 'SQL注入(布尔型)',
    'sql_injection_time_based': 'SQL注入(时间盲注)',
    'rce': '远程代码执行',
    'unauth_access': '未授权访问',
    'default_password': '默认口令',
    'file_upload': '任意文件上传',
    'ssrf': 'SSRF服务端请求伪造',
    'xxe': 'XXE外部实体注入',
    'xss': 'XSS跨站脚本',
    'lfi': '本地文件包含',
    'rfi': '远程文件包含',
    'deserialization': '反序列化漏洞',
    'info_leak': '信息泄露',
    'weak_password': '弱口令',
}


def _normalize_endpoint(url: str) -> str:
    """URL 端点归一化：去查询串 + 去片段 + 路径归一化

    示例：
        http://x.com/a?b=1 → http://x.com/a
        http://x.com/a#frag → http://x.com/a
        http://x.com//a//b → http://x.com/a/b
        http://x.com/a/ → http://x.com/a
    """
    if not url:
        return ''
    parts = urlsplit(url)
    path = parts.path or '/'
    # 合并连续斜杠
    while '//' in path:
        path = path.replace('//', '/')
    # 去除末尾斜杠（保留根路径 /）
    if len(path) > 1 and path.endswith('/'):
        path = path.rstrip('/')
    return urlunsplit((parts.scheme, parts.netloc, path, '', ''))


def _strip_parens(text: str) -> str:
    """去除中文括号和英文括号及其内容

    示例：'任意文件读取（路径穿越）' → '任意文件读取'
          'SQL注入(Error-based)' → 'SQL注入'
    """
    if not text:
        return ''
    text = re.sub(r'（[^）]*）', '', text)
    text = re.sub(r'\([^)]*\)', '', text)
    return text.strip()


def fingerprint(result) -> str:
    """计算漏洞指纹：sha1(normalized_endpoint | vuln_type | payload_class)[:16]

    Args:
        result: ScanResult 或鸭子类型兼容对象（需有 url/extra/kind/name 属性）
    Returns:
        16 字符十六进制指纹
    """
    endpoint = _normalize_endpoint(getattr(result, 'url', ''))

    extra = getattr(result, 'extra', {}) or {}
    vuln_type = extra.get('vuln_type', '')
    if not vuln_type:
        # 回退：kind + name 去括号
        kind = getattr(result, 'kind', '')
        name = _strip_parens(getattr(result, 'name', ''))
        vuln_type = f'{kind}:{name}' if kind else name

    payload_class = extra.get('payload_class', '')

    raw = f'{endpoint}|{vuln_type}|{payload_class}'
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]


@dataclass
class AggregatedVuln:
    """聚合后的漏洞条目（鸭子类型兼容 ScanResult）

    暴露与 ScanResult 相同的属性名（kind/name/severity/status/url/evidence/fix/extra），
    使 ReportBuilder 现有方法（to_html/to_csv/risk_distribution/sorted_results）零改动即可接受。
    额外属性：fingerprint（指纹哈希）、hit_count（命中插件数）。
    """
    name: str
    severity: str
    status: str
    url: str
    evidence: str
    fix: str
    kind: str
    extra: Dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ''
    hit_count: int = 1
    # D12：CVE/CVSS/合规映射（从首个 ScanResult 继承）
    cve: str = ''
    cvss_score: float = 0.0
    cvss_vector: str = ''
    compliance: Dict[str, str] = field(default_factory=dict)
    # D18/D24：修复详情 + 复现命令（从首个 ScanResult 继承）
    fix_detail: str = ''
    reproduce: str = ''

    @property
    def is_vuln(self):
        """是否确认存在漏洞（与 ScanResult.is_vuln 兼容）"""
        return self.status == STATUS_CONFIRMED

    def to_dict(self):
        """转为字典（与 ScanResult.to_dict() 字段对齐 + 聚合扩展字段）"""
        from core.models import SEVERITY_CN
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
            'fix_detail': self.fix_detail,
            'reproduce': self.reproduce,
            'cve': self.cve,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'compliance': self.compliance,
            # 聚合扩展字段
            'fingerprint': self.fingerprint,
            'hit_count': self.hit_count,
        }


@dataclass
class DedupReport:
    """去重统计报告"""
    original_count: int = 0    # 原始结果数
    aggregated_count: int = 0  # 聚合后结果数
    merged_groups: int = 0     # 发生合并的组数（原始数 > 1 的组）


def _resolve_name(group: List[Any]) -> str:
    """解析聚合组名称：优先取 vuln_type 中文名；否则取组内最短去括号名"""
    for r in group:
        extra = getattr(r, 'extra', {}) or {}
        vt = extra.get('vuln_type', '')
        if vt and vt in VULN_TYPE_CN:
            return VULN_TYPE_CN[vt]
    # 回退：组内最短的去括号名
    names = [_strip_parens(getattr(r, 'name', '')) for r in group]
    names = [n for n in names if n]
    if names:
        return min(names, key=len)
    return ''


def _merge_evidence(group: List[Any]) -> str:
    """合并证据：去重后用 ' | ' 连接"""
    seen = []
    for r in group:
        ev = getattr(r, 'evidence', '')
        if ev and ev not in seen:
            seen.append(ev)
    return ' | '.join(seen)


def _merge_extra(group: List[Any], primary_url: str) -> Dict[str, Any]:
    """合并 extra 字段：sources/hit_count/urls/cve/vuln_type + 透传其他字段"""
    merged = {}
    sources = []
    urls = set()
    cve = ''

    for r in group:
        extra = getattr(r, 'extra', {}) or {}
        # 收集插件名
        pn = extra.get('plugin_name', '')
        if pn and pn not in sources:
            sources.append(pn)
        # 收集 URL（非主 URL）
        u = getattr(r, 'url', '')
        if u and u != primary_url:
            urls.add(u)
        # 收集 CVE（取首个非空）
        if extra.get('cve') and not cve:
            cve = extra['cve']
        # 透传其他非约定字段
        for k, v in extra.items():
            if k not in ('vuln_type', 'payload_class', 'plugin_name', 'cve'):
                if k not in merged:
                    merged[k] = v

    merged['sources'] = sources
    merged['hit_count'] = len(group)
    if urls:
        merged['urls'] = sorted(urls)
    if cve:
        merged['cve'] = cve
    # 保留 vuln_type（用于报告展示）
    for r in group:
        extra = getattr(r, 'extra', {}) or {}
        if extra.get('vuln_type'):
            merged['vuln_type'] = extra['vuln_type']
            break
    return merged


def aggregate(results: List[Any]) -> Tuple[List[AggregatedVuln], DedupReport]:
    """聚合去重：同指纹的结果合并为一条 AggregatedVuln

    聚合规则：
        severity: 取最高（high > medium > low）
        status:   取最差（CONFIRMED > UNKNOWN > SAFE）
        name:     优先 vuln_type 中文名；否则组内最短去括号名
        url:      首个为主 URL，其余进 extra['urls']
        evidence: 去重后用 ' | ' 连接
        fix:      取最长
        extra:    sources=所有插件名, hit_count=命中数, urls=去重URL列表

    Args:
        results: ScanResult 列表（或鸭子类型兼容对象）
    Returns:
        (聚合后 AggregatedVuln 列表, 去重统计报告)
    """
    if not results:
        return [], DedupReport(0, 0, 0)

    # 按指纹分组（保持插入顺序）
    groups = {}
    order = []
    for r in results:
        fp = fingerprint(r)
        if fp not in groups:
            groups[fp] = []
            order.append(fp)
        groups[fp].append(r)

    aggregated = []
    merged_groups = 0
    for fp in order:
        group = groups[fp]
        if len(group) > 1:
            merged_groups += 1

        # severity: 取最高
        severity = max((getattr(r, 'severity', SEVERITY_LOW) for r in group),
                       key=lambda s: _SEVERITY_ORDER.get(s, -1))
        # status: 取最差
        status = max((getattr(r, 'status', STATUS_UNKNOWN) for r in group),
                     key=lambda s: _STATUS_ORDER.get(s, -1))
        # name: 语义化名称
        name = _resolve_name(group)
        # url: 首个为主 URL
        primary_url = getattr(group[0], 'url', '')
        # evidence: 合并去重
        evidence = _merge_evidence(group)
        # fix: 取最长
        fix = max((getattr(r, 'fix', '') for r in group), key=len) if group else ''
        # kind: 取首个
        kind = getattr(group[0], 'kind', '')
        # extra: 字段级合并
        extra = _merge_extra(group, primary_url)

        aggregated.append(AggregatedVuln(
            name=name,
            severity=severity,
            status=status,
            url=primary_url,
            evidence=evidence,
            fix=fix,
            kind=kind,
            extra=extra,
            fingerprint=fp,
            hit_count=len(group),
            # D12：从首个结果继承 CVE/CVSS/合规映射
            cve=getattr(group[0], 'cve', ''),
            cvss_score=getattr(group[0], 'cvss_score', 0.0),
            cvss_vector=getattr(group[0], 'cvss_vector', ''),
            compliance=getattr(group[0], 'compliance', {}) or {},
            # D18/D24：从首个结果继承修复详情 + 复现命令
            fix_detail=getattr(group[0], 'fix_detail', ''),
            reproduce=getattr(group[0], 'reproduce', ''),
        ))

    # 排序：CONFIRMED 优先，同状态按 severity high→medium→low，同 severity 按名称
    _sev_sort = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
    _status_sort = {STATUS_CONFIRMED: 0, STATUS_UNKNOWN: 1, STATUS_SAFE: 2}
    aggregated.sort(key=lambda v: (
        _status_sort.get(v.status, 99),
        _sev_sort.get(v.severity, 99),
        v.name,
    ))

    report = DedupReport(
        original_count=len(results),
        aggregated_count=len(aggregated),
        merged_groups=merged_groups,
    )
    return aggregated, report
