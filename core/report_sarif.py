# D22：SARIF 2.1.0 报告格式
#
# SARIF（Static Analysis Results Interchange Format）是 OASIS 标准，
# 用于静态分析结果的交换。GitHub Code Scanning 原生支持 SARIF 格式上传。
#
# 用途：
#   1. 上传扫描结果到 GitHub Code Scanning
#   2. 与其他安全工具（SonarQube/DefectDojo）集成
#   3. CI/CD 流水线标准化安全报告
#
# 使用方式：
#   python main.py -u http://target/ --report reports/ --report-format sarif
#   # 生成 reports/report.sarif
#
# 上传到 GitHub：
#   gh code-scanning upload --sarif reports/report.sarif --repo owner/repo
#
# SARIF 2.1.0 规范：https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
import json
from typing import Dict, List

# SARIF 规范版本
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"

# GitHub Code Scanning 使用的 SARIF 规则
GITHUB_SECURITY_SEVERITY = {
    "high": "error",
    "medium": "warning",
    "low": "note",
}

# CVSS → GitHub Security Level 映射
# 表项必须按阈值降序排列：_cvss_to_level 从前向后取第一个满足的档位
CVSS_TO_LEVEL = [
    (9.0, "error"),  # Critical
    (7.0, "error"),  # High
    (4.0, "warning"),  # Medium
    (0.1, "note"),  # Low
    (0.0, "none"),
]


def _cvss_to_level(cvss_score: float) -> str:
    """CVSS 分数 → GitHub Security Level"""
    for threshold, level in CVSS_TO_LEVEL:
        if cvss_score >= threshold:
            return level
    return "none"


def _severity_to_level(severity: str) -> str:
    """严重度 → GitHub Security Level"""
    return GITHUB_SECURITY_SEVERITY.get(severity, "note")


def _build_rules(results: List) -> Dict[str, Dict]:
    """从扫描结果构建 SARIF rules 字典

    每个 POC 对应一条 rule，以 name 为 key
    """
    rules = {}
    for r in results:
        if r.status != "CONFIRMED":
            continue
        rule_id = r.name
        if rule_id in rules:
            continue

        # CVSS 分数
        cvss = getattr(r, "cvss_score", 0) or 0
        # 合规映射
        compliance = getattr(r, "compliance", {}) or {}
        compliance_str = "; ".join(f"{k}:{v}" for k, v in compliance.items()) if compliance else ""

        rules[rule_id] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": getattr(r, "evidence", "") or getattr(r, "name", "")},
            "help": {
                "text": (
                    f"修复建议: {getattr(r, 'fix', '')}\n"
                    f"修复详情: {getattr(r, 'fix_detail', '')}\n"
                    f"复现命令: {getattr(r, 'reproduce', '')}\n"
                    f"合规映射: {compliance_str}"
                )
            },
            "defaultConfiguration": {
                # cvss=0 视为未录入，回落按严重度映射（GITHUB_SECURITY_SEVERITY）
                "level": _cvss_to_level(cvss) if cvss > 0 else _severity_to_level(r.severity),
            },
            "properties": {
                "cve": getattr(r, "cve", "") or "",
                "cvss_score": cvss,
                "cvss_vector": getattr(r, "cvss_vector", "") or "",
                "severity": r.severity,
                "compliance": compliance_str,
                "tags": ["security", f"severity:{r.severity}"],
            },
        }
    return rules


def _build_results(results: List, rules: Dict[str, Dict]) -> List[Dict]:
    """构建 SARIF results 数组"""
    sarif_results = []
    for r in results:
        if r.status != "CONFIRMED":
            continue

        rule_id = r.name
        cvss = getattr(r, "cvss_score", 0) or 0
        level = _cvss_to_level(cvss) if cvss > 0 else _severity_to_level(r.severity)

        # 提取 URL 的 region 信息
        url = r.url or ""
        # 构建结果条目
        result_entry = {
            "ruleId": rule_id,
            # ruleIndex 必须与 rules 数组中该 rule 的下标一致（SARIF 规范），未知 rule 时兜底 0
            "ruleIndex": list(rules.keys()).index(rule_id) if rule_id in rules else 0,
            "level": level,
            "message": {
                "text": f"{r.name}: {getattr(r, 'evidence', '') or ''}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": url,
                        },
                    },
                }
            ],
            "partialFingerprints": {
                # 用 rule+url 组合哈希生成去重指纹；& 0xFFFFFFFF 截断为 8 位十六进制
                "primaryLocationLineHash": f"{rule_id}:{hash(url) & 0xFFFFFFFF:08x}",
            },
            "properties": {
                "severity": r.severity,
                "cve": getattr(r, "cve", "") or "",
                "cvss_score": cvss,
                "status": r.status,
            },
        }

        # 添加修复建议（GitHub Code Scanning 会显示）
        fix = getattr(r, "fix", "") or ""
        fix_detail = getattr(r, "fix_detail", "") or ""
        if fix or fix_detail:
            result_entry["fixes"] = [
                {
                    "description": {
                        "text": f"{fix}\n\n{fix_detail}",
                    },
                }
            ]

        sarif_results.append(result_entry)

    return sarif_results


def to_sarif(report_builder) -> str:
    """将 ReportBuilder 转为 SARIF 2.1.0 JSON 字符串

    Args:
        report_builder: ReportBuilder 实例
    Returns:
        SARIF JSON 字符串
    """
    # 复用报告构建器的去重结果，保证 SARIF 与 HTML/JSON 输出口径一致
    results = list(report_builder._effective_results())
    rules = _build_rules(results)
    sarif_results = _build_results(results, rules)

    # 工具信息
    tool_info = {
        "driver": {
            "name": "Ruoyi-Scan",
            "version": "2.0",
            "informationUri": "https://github.com/ruoyi-scan/ruoyi-scan",
            "rules": list(rules.values()),
        }
    }

    # 运行信息
    summary = report_builder.summary or {}
    run = {
        "tool": tool_info,
        "results": sarif_results,
        "invocations": [
            {
                "executionSuccessful": True,
                "endTimeUtc": summary.get("started_at", ""),
            }
        ],
        "properties": {
            "target": report_builder.target,
            "scan_time": summary.get("started_at", ""),
            "duration_sec": summary.get("duration", 0),
            "request_count": summary.get("request_count", 0),
            "mode": summary.get("mode", ""),
        },
    }

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }

    return json.dumps(sarif_doc, ensure_ascii=False, indent=2)


def render_sarif(report_builder, filepath: str):
    """渲染 SARIF 报告到文件

    Args:
        report_builder: ReportBuilder 实例
        filepath: 输出文件路径
    """
    sarif_content = to_sarif(report_builder)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(sarif_content)
