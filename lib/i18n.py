# D23：国际化（i18n，中英文报告）
#
# 支持中英文报告输出，方便国际团队使用
#
# 使用方式：
#   python main.py -u http://target/ --lang en --report reports/
#   python main.py -u http://target/ --lang zh --report reports/  # 默认
#
# 翻译范围：
#   1. 报告标题/表头/标签（"扫描报告" → "Scan Report"）
#   2. 状态/严重度（"确认存在" → "Confirmed"）
#   3. 摘要字段（"目标" → "Target"）
#   4. 不翻译：漏洞名称、URL、CVE、证据内容
from typing import Dict, Any

# 支持的语言
SUPPORTED_LANGS = {'zh', 'en'}

# 默认语言
DEFAULT_LANG = 'zh'

# ============================================================
# 翻译字典
# ============================================================

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    'zh': {
        # 报告标题
        'report_title': '扫描报告',
        'scan_report': 'Ruoyi-Scan 扫描报告',
        'diff_report': '差异报告',
        # 摘要字段
        'target': '目标',
        'scan_time': '扫描时间',
        'duration': '耗时',
        'seconds': '秒',
        'request_count': '请求数',
        'mode': '扫描模式',
        'fingerprint': '指纹识别',
        'cms': 'CMS',
        'confidence': '置信度',
        # 风险分布
        'risk_distribution': '风险分布',
        'confirmed_vulns': '确认漏洞',
        'high': '高',
        'medium': '中',
        'low': '低',
        'total': '总计',
        # 表头
        'col_severity': '危害等级',
        'col_name': '漏洞名称',
        'col_url': 'URL',
        'col_status': '状态',
        'col_cve': 'CVE',
        'col_cvss': 'CVSS',
        'col_compliance': '合规映射',
        'col_evidence': '证据',
        'col_fix': '修复建议',
        'col_fix_detail': '修复详情',
        'col_reproduce': '复现命令',
        # 状态
        'status_confirmed': '确认存在',
        'status_safe': '不存在',
        'status_unknown': '未知',
        # 严重度
        'severity_high': '高',
        'severity_medium': '中',
        'severity_low': '低',
        # 差异报告
        'diff_new': '新增',
        'diff_fixed': '已修复',
        'diff_persisted': '未变',
        'diff_changed': '状态变化',
        'new_vulns': '新增漏洞',
        'fixed_vulns': '已修复漏洞',
        'persisted_vulns': '未变漏洞',
        'changed_vulns': '状态变化漏洞',
        'old_scan': '旧扫描',
        'new_scan': '新扫描',
        # 其他
        'no_results': '无扫描结果',
        'show_confirmed_only': '仅显示确认存在的漏洞',
        'hide_non_confirmed': '隐藏 不存在/未知 行',
    },
    'en': {
        # Report title
        'report_title': 'Scan Report',
        'scan_report': 'Ruoyi-Scan Scan Report',
        'diff_report': 'Diff Report',
        # Summary fields
        'target': 'Target',
        'scan_time': 'Scan Time',
        'duration': 'Duration',
        'seconds': 'seconds',
        'request_count': 'Requests',
        'mode': 'Mode',
        'fingerprint': 'Fingerprint',
        'cms': 'CMS',
        'confidence': 'Confidence',
        # Risk distribution
        'risk_distribution': 'Risk Distribution',
        'confirmed_vulns': 'Confirmed Vulns',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'total': 'Total',
        # Table headers
        'col_severity': 'Severity',
        'col_name': 'Vulnerability',
        'col_url': 'URL',
        'col_status': 'Status',
        'col_cve': 'CVE',
        'col_cvss': 'CVSS',
        'col_compliance': 'Compliance',
        'col_evidence': 'Evidence',
        'col_fix': 'Fix',
        'col_fix_detail': 'Fix Details',
        'col_reproduce': 'Reproduce',
        # Status
        'status_confirmed': 'Confirmed',
        'status_safe': 'Safe',
        'status_unknown': 'Unknown',
        # Severity
        'severity_high': 'High',
        'severity_medium': 'Medium',
        'severity_low': 'Low',
        # Diff report
        'diff_new': 'New',
        'diff_fixed': 'Fixed',
        'diff_persisted': 'Persisted',
        'diff_changed': 'Changed',
        'new_vulns': 'New Vulnerabilities',
        'fixed_vulns': 'Fixed Vulnerabilities',
        'persisted_vulns': 'Persisted Vulnerabilities',
        'changed_vulns': 'Changed Vulnerabilities',
        'old_scan': 'Old Scan',
        'new_scan': 'New Scan',
        # Other
        'no_results': 'No results',
        'show_confirmed_only': 'Show confirmed vulnerabilities only',
        'hide_non_confirmed': 'Hide Safe/Unknown rows',
    },
}


def get_text(key: str, lang: str = DEFAULT_LANG) -> str:
    """获取翻译文本

    Args:
        key: 翻译 key（如 'report_title'）
        lang: 语言代码（zh/en）
    Returns:
        翻译后的文本，未找到时返回 key 本身
    """
    if lang not in TRANSLATIONS:
        lang = DEFAULT_LANG
    return TRANSLATIONS[lang].get(key, TRANSLATIONS[DEFAULT_LANG].get(key, key))


def get_status_cn(status: str, lang: str = DEFAULT_LANG) -> str:
    """状态码 → 本地化文本

    Args:
        status: 状态码（CONFIRMED/SAFE/UNKNOWN）
        lang: 语言代码
    Returns:
        本地化状态文本
    """
    mapping = {
        'CONFIRMED': 'status_confirmed',
        'SAFE': 'status_safe',
        'UNKNOWN': 'status_unknown',
    }
    key = mapping.get(status, status)
    return get_text(key, lang)


def get_severity_cn(severity: str, lang: str = DEFAULT_LANG) -> str:
    """严重度 → 本地化文本

    Args:
        severity: 严重度（high/medium/low）
        lang: 语言代码
    Returns:
        本地化严重度文本
    """
    mapping = {
        'high': 'severity_high',
        'medium': 'severity_medium',
        'low': 'severity_low',
    }
    key = mapping.get(severity, severity)
    return get_text(key, lang)


def get_csv_header(lang: str = DEFAULT_LANG) -> list:
    """获取 CSV 表头（本地化）

    Args:
        lang: 语言代码
    Returns:
        CSV 表头列表
    """
    return [
        get_text('col_name', lang),
        get_text('col_url', lang),
        get_text('col_severity', lang),
        get_text('col_status', lang),
        get_text('col_cve', lang),
        get_text('col_cvss', lang),
        get_text('col_compliance', lang),
        get_text('col_evidence', lang),
        get_text('col_fix', lang),
        get_text('col_fix_detail', lang),
        get_text('col_reproduce', lang),
    ]


def get_html_title(cms: str = '', lang: str = DEFAULT_LANG) -> str:
    """获取 HTML 报告标题

    Args:
        cms: CMS 名称（如 'ruoyi'），为空时用默认标题
        lang: 语言代码
    Returns:
        本地化报告标题
    """
    if cms:
        cms_display = cms.capitalize()
        return f'{get_text("report_title", lang)} - {cms_display}'
    return get_text('scan_report', lang)


def localize_report_dict(report_dict: Dict[str, Any], lang: str = DEFAULT_LANG) -> Dict[str, Any]:
    """本地化报告字典（JSON 输出用）

    仅翻译字段名和枚举值，不翻译漏洞名称/URL/证据

    Args:
        report_dict: 原始报告字典
        lang: 语言代码
    Returns:
        本地化后的报告字典
    """
    if lang == DEFAULT_LANG:
        return report_dict  # 中文不需转换

    import copy
    result = copy.deepcopy(report_dict)

    # 翻译风险分布的 key
    if 'risk_distribution' in result:
        rd = result['risk_distribution']
        result['risk_distribution'] = {
            get_text('high', lang): rd.get('high', 0),
            get_text('medium', lang): rd.get('medium', 0),
            get_text('low', lang): rd.get('low', 0),
            get_text('total', lang): rd.get('total', 0),
        }

    # 翻译结果中的 status 和 severity
    for r in result.get('results', []):
        if 'status' in r:
            r['status_cn'] = get_status_cn(r['status'], lang)
        if 'severity' in r:
            r['severity_cn'] = get_severity_cn(r['severity'], lang)

    return result


def is_supported(lang: str) -> bool:
    """检查语言是否受支持"""
    return lang in SUPPORTED_LANGS
