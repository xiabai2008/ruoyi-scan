# D33：SIEM 集成（ECS/CEF 格式导出）
#
# 将扫描结果导出为 SIEM（安全信息与事件管理）系统兼容格式，支持安全运营中心
# 联动、威胁狩猎、合规审计等场景。
#
# 支持格式：
#   1. ECS (Elastic Common Schema) - Elasticsearch/Kibana 标准
#   2. CEF (Common Event Format) - ArcSight/Splunk 标准
#   3. LEEF (Log Event Extended Format) - IBM QRadar 标准
#   4. JSON (通用 JSON Lines，便于自定义集成)
#
# 使用方式：
#   # 导出 ECS 格式到文件
#   python main.py -u http://target/ --siem-export ecs --siem-output events.json
#
#   # 扫描后自动发送到 SIEM
#   python main.py -u http://target/ --siem-export cef --siem-syslog 10.0.0.1:514
#
#   # 同时导出多格式
#   python main.py -u http://target/ --siem-export ecs,cef --siem-output reports/
import datetime
import json
import socket
from typing import Any, Dict, List

from common.logger import get_logger

# 复用现有模型
from common.models import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, STATUS_CONFIRMED

logger = get_logger(__name__)

# ============================================================
# 严重度映射
# ============================================================

SEVERITY_TO_SIEM = {
    SEVERITY_HIGH: 9,  # 0-10 严重度评分
    SEVERITY_MEDIUM: 6,
    SEVERITY_LOW: 3,
}

SEVERITY_TO_CEF = {
    SEVERITY_HIGH: "High",
    SEVERITY_MEDIUM: "Medium",
    SEVERITY_LOW: "Low",
}

SEVERITY_TO_LEEF = {
    SEVERITY_HIGH: "Critical",
    SEVERITY_MEDIUM: "Warning",
    SEVERITY_LOW: "Minor",
}


# ============================================================
# ECS (Elastic Common Schema) 格式
# ============================================================


def to_ecs_event(result, target: str = "", scan_time: str = "") -> Dict[str, Any]:
    """将单个 ScanResult 转换为 ECS 事件

    ECS 标准字段：https://www.elastic.co/guide/en/ecs/current/

    Args:
        result: ScanResult 实例
        target: 扫描目标
        scan_time: 扫描时间 ISO 格式

    Returns:
        ECS 格式字典
    """
    # 从 URL 提取 host 和 path
    from urllib.parse import urlparse

    parsed = urlparse(result.url or "")
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # CVSS 评分
    cvss_score = getattr(result, "cvss_score", 0.0) or 0.0

    # 合规映射
    compliance = getattr(result, "compliance", {}) or {}

    event = {
        "@timestamp": scan_time or datetime.datetime.now().isoformat(),
        "event": {
            "category": ["vulnerability"],
            "type": ["info"],
            "severity": SEVERITY_TO_SIEM.get(result.severity, 3),
            "risk_score": cvss_score,
            "kind": "alert",
            "module": "ruoyi-scan",
            "dataset": "vulnerability.scan",
            "action": "vulnerability-detected",
        },
        "vulnerability": {
            "id": getattr(result, "cve", "") or "",
            "category": [result.name] if result.name else [],
            "description": getattr(result, "description", "") or "",
            "severity": SEVERITY_TO_CEF.get(result.severity, "Low"),
            "score": cvss_score,
            "reference": getattr(result, "cvss_vector", "") or "",
        },
        "rule": {
            "name": result.name,
            "ruleset": "Ruoyi-Scan",
            "severity": SEVERITY_TO_CEF.get(result.severity, "Low"),
        },
        "observer": {
            "product": "Ruoyi-Scan",
            "vendor": "shengtou-tools",
            "version": "2.0",
        },
        "host": {
            "name": host,
        },
        "url": {
            "full": result.url or "",
            "domain": host,
            "path": parsed.path or "",
            "port": port,
        },
        "message": f"{result.name}: {result.evidence}" if result.evidence else result.name,
    }

    # 仅 CONFIRMED 漏洞作为 alert
    if result.status != STATUS_CONFIRMED:
        event["event"]["type"] = ["info"]
        event["event"]["kind"] = "event"

    # 合规标签
    if compliance:
        event["vulnerability"]["compliance"] = [f"{k}:{v}" for k, v in compliance.items()]

    # 修复信息
    fix_detail = getattr(result, "fix_detail", "") or ""
    if fix_detail:
        event["vulnerability"]["remediation"] = {
            "description": getattr(result, "fix", ""),
            "detail": fix_detail,
        }

    return event


def render_ecs(results, target: str = "", scan_time: str = "") -> str:
    """渲染扫描结果为 ECS JSON Lines 格式

    Args:
        results: ScanResult 列表
        target: 扫描目标
        scan_time: 扫描时间

    Returns:
        JSON Lines 字符串（每行一个 JSON 对象）
    """
    lines = []
    for r in results:
        event = to_ecs_event(r, target, scan_time)
        lines.append(json.dumps(event, ensure_ascii=False))
    return "\n".join(lines)


# ============================================================
# CEF (Common Event Format) 格式
# ============================================================


def to_cef_event(result, target: str = "") -> str:
    """将单个 ScanResult 转换为 CEF 事件字符串

    CEF 格式：CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension

    Args:
        result: ScanResult 实例
        target: 扫描目标

    Returns:
        CEF 格式字符串
    """
    cve_id = getattr(result, "cve", "") or "N/A"
    severity_num = SEVERITY_TO_SIEM.get(result.severity, 3)

    # 扩展字段
    extensions = {
        "src": target,
        "request": result.url or "",
        "msg": getattr(result, "description", "") or result.name,
        "cs1": getattr(result, "fix", "") or "",
        "cs1Label": "Remediation",
        "cs2": getattr(result, "fix_detail", "") or "",
        "cs2Label": "RemediationDetail",
        "cs3": getattr(result, "reproduce", "") or "",
        "cs3Label": "Reproduce",
        "cvss": f"{getattr(result, 'cvss_score', 0.0) or 0.0:.1f}",
        "cvssVector": getattr(result, "cvss_vector", "") or "",
    }

    # 合规映射
    compliance = getattr(result, "compliance", {}) or {}
    if compliance:
        extensions["cs4"] = ";".join(f"{k}:{v}" for k, v in compliance.items())
        extensions["cs4Label"] = "Compliance"

    # 证据
    if result.evidence:
        # CEF 值中的特殊字符需转义
        evidence = result.evidence.replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")
        extensions["cn1"] = evidence[:500]
        extensions["cn1Label"] = "Evidence"

    ext_str = " ".join(f"{k}={v}" for k, v in extensions.items() if v)

    # 名称中的特殊字符转义
    name = (result.name or "").replace("\\", "\\\\").replace("|", "\\|")

    return f"CEF:0|shengtou-tools|Ruoyi-Scan|2.0|{cve_id}|{name}|{severity_num}|{ext_str}"


def render_cef(results, target: str = "", scan_time: str = "") -> str:
    """渲染扫描结果为 CEF 格式（每行一个事件）"""
    lines = []
    for r in results:
        lines.append(to_cef_event(r, target))
    return "\n".join(lines)


# ============================================================
# LEEF (Log Event Extended Format) 格式
# ============================================================


def to_leef_event(result, target: str = "") -> str:
    """将单个 ScanResult 转换为 LEEF 事件字符串

    LEEF 格式：LEEF:Version|Vendor|Product|Version|EventID|key=value<tab>key=value...
    """
    cve_id = getattr(result, "cve", "") or "N/A"
    severity_str = SEVERITY_TO_LEEF.get(result.severity, "Minor")

    fields = {
        "sev": severity_str,
        "src": target,
        "url": result.url or "",
        "msg": result.name,
        "description": getattr(result, "description", "") or "",
        "cvss": f"{getattr(result, 'cvss_score', 0.0) or 0.0:.1f}",
        "cvssVector": getattr(result, "cvss_vector", "") or "",
        "remediation": getattr(result, "fix", "") or "",
        "evidence": (result.evidence or "")[:500],
    }

    # 合规
    compliance = getattr(result, "compliance", {}) or {}
    if compliance:
        fields["compliance"] = ";".join(f"{k}:{v}" for k, v in compliance.items())

    # 用 tab 分隔
    fields_str = "\t".join(f"{k}={v}" for k, v in fields.items() if v)

    return f"LEEF:2.0|shengtou-tools|Ruoyi-Scan|2.0|{cve_id}|^{fields_str}"


def render_leef(results, target: str = "", scan_time: str = "") -> str:
    """渲染扫描结果为 LEEF 格式"""
    lines = []
    for r in results:
        lines.append(to_leef_event(r, target))
    return "\n".join(lines)


# ============================================================
# JSON Lines 格式
# ============================================================


def to_json_event(result, target: str = "", scan_time: str = "") -> Dict[str, Any]:
    """将 ScanResult 转换为通用 JSON 事件"""
    return {
        "timestamp": scan_time or datetime.datetime.now().isoformat(),
        "target": target,
        "vulnerability": {
            "name": result.name,
            "cve": getattr(result, "cve", "") or "",
            "severity": result.severity,
            "status": result.status,
            "url": result.url,
            "evidence": result.evidence,
            "cvss_score": getattr(result, "cvss_score", 0.0) or 0.0,
            "cvss_vector": getattr(result, "cvss_vector", "") or "",
            "compliance": getattr(result, "compliance", {}) or {},
            "fix": getattr(result, "fix", "") or "",
            "fix_detail": getattr(result, "fix_detail", "") or "",
            "reproduce": getattr(result, "reproduce", "") or "",
        },
        "scanner": {
            "name": "Ruoyi-Scan",
            "version": "2.0",
        },
    }


def render_json(results, target: str = "", scan_time: str = "") -> str:
    """渲染扫描结果为 JSON Lines 格式"""
    lines = []
    for r in results:
        lines.append(json.dumps(to_json_event(r, target, scan_time), ensure_ascii=False))
    return "\n".join(lines)


# ============================================================
# 统一导出接口
# ============================================================

FORMAT_RENDERERS = {
    "ecs": render_ecs,
    "cef": render_cef,
    "leef": render_leef,
    "json": render_json,
}

SUPPORTED_FORMATS = list(FORMAT_RENDERERS.keys())


def render_siem(results, format: str, target: str = "", scan_time: str = "") -> str:
    """渲染扫描结果为指定 SIEM 格式

    Args:
        results: ScanResult 列表
        format: 格式（ecs/cef/leef/json）
        target: 扫描目标
        scan_time: 扫描时间

    Returns:
        格式化字符串

    Raises:
        ValueError: 不支持的格式
    """
    renderer = FORMAT_RENDERERS.get(format)
    if not renderer:
        raise ValueError(f"不支持的 SIEM 格式: {format}（支持: {SUPPORTED_FORMATS}）")
    return renderer(results, target, scan_time)


def parse_formats(fmt_str: str) -> List[str]:
    """解析格式字符串

    Args:
        fmt_str: 逗号分隔的格式字符串（如 'ecs,cef'）

    Returns:
        格式列表
    """
    if not fmt_str:
        return []
    parts = [f.strip().lower() for f in fmt_str.split(",") if f.strip()]
    return [p for p in parts if p in SUPPORTED_FORMATS]


def export_to_files(results, formats: List[str], output_dir: str, target: str = "", scan_time: str = "") -> List[str]:
    """导出多格式到文件

    Args:
        results: ScanResult 列表
        formats: 格式列表
        output_dir: 输出目录
        target: 扫描目标
        scan_time: 扫描时间

    Returns:
        生成的文件路径列表
    """
    import os

    os.makedirs(output_dir, exist_ok=True)
    paths = []

    for fmt in formats:
        content = render_siem(results, fmt, target, scan_time)
        filename = f"scan_events.{fmt}" if fmt != "json" else "scan_events.jsonl"
        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        paths.append(path)

    return paths


# ============================================================
# Syslog 转发
# ============================================================


def send_to_syslog(events: List[str], host: str, port: int = 514, protocol: str = "udp", timeout: float = 5.0) -> int:
    """发送事件到 Syslog 服务器

    Args:
        events: 事件字符串列表（每项一行）
        host: Syslog 服务器地址
        port: 端口（默认 514）
        protocol: 'udp' 或 'tcp'
        timeout: 超时秒数

    Returns:
        成功发送的事件数
    """
    sent = 0
    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(timeout)

        if protocol == "tcp":
            sock.connect((host, port))

        for event in events:
            # Syslog 消息格式：<priority>timestamp hostname message
            # priority = facility(4) * 8 + severity(5) = 37（告警）
            priority = 4 * 8 + 5  # auth | notice
            timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
            hostname = socket.gethostname()
            message = f"<{priority}>{timestamp} {hostname} {event}"

            data = message.encode("utf-8")
            if protocol == "tcp":
                sock.send(data + b"\n")
            else:
                sock.sendto(data, (host, port))
            sent += 1

    except OSError:
        logger.debug("发送事件到 Syslog 服务器失败", exc_info=True)
    finally:
        if sock:
            sock.close()

    return sent


def send_results_to_syslog(
    results, host: str, port: int = 514, format: str = "cef", protocol: str = "udp", target: str = ""
) -> int:
    """发送扫描结果到 Syslog 服务器

    Args:
        results: ScanResult 列表
        host: Syslog 服务器地址
        port: 端口
        format: SIEM 格式
        protocol: 协议
        target: 扫描目标

    Returns:
        成功发送的事件数
    """
    content = render_siem(results, format, target)
    events = content.split("\n")
    return send_to_syslog(events, host, port, protocol)


# ============================================================
# 模式入口
# ============================================================


def run_siem_export_mode(args, results, target: str = "", scan_time: str = "") -> int:
    """SIEM 导出模式入口

    Args:
        args: CLI 参数
        results: ScanResult 列表
        target: 扫描目标
        scan_time: 扫描时间

    Returns:
        0 表示成功
    """
    fmt_str = getattr(args, "siem_export", "") or ""
    formats = parse_formats(fmt_str)

    if not formats:
        print(f"[!]未指定有效的 SIEM 格式（支持: {SUPPORTED_FORMATS}）")
        return 1

    # 导出 Syslog
    syslog_target = getattr(args, "siem_syslog", None)
    if syslog_target:
        # 解析 host:port
        if ":" in syslog_target:
            host, port_str = syslog_target.rsplit(":", 1)
            port = int(port_str)
        else:
            host = syslog_target
            port = 514

        protocol = getattr(args, "siem_protocol", "udp") or "udp"
        print(f"[*]发送 {len(results)} 个事件到 Syslog {host}:{port} ({protocol})")

        sent = 0
        for fmt in formats:
            sent = send_results_to_syslog(results, host, port, fmt, protocol, target)
            print(f"[+]格式 {fmt}: 已发送 {sent} 个事件")

        return 0

    # 导出文件
    output = getattr(args, "siem_output", None) or "reports/siem/"
    print(f"[*]导出 {len(results)} 个事件到 {output}（格式: {', '.join(formats)}）")

    paths = export_to_files(results, formats, output, target, scan_time)
    print(f"[+]已生成 {len(paths)} 个文件:")
    for p in paths:
        print(f"    {p}")

    return 0
