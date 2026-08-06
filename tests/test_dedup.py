# D8.1 结果去重聚合单元测试：指纹计算 + 聚合规则 + 鸭子类型兼容
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import (
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    STATUS_CONFIRMED,
    STATUS_SAFE,
    STATUS_UNKNOWN,
    ScanResult,
)
from core.dedup import (
    AggregatedVuln,
    aggregate,
    fingerprint,
)

# === 指纹计算 ===


def test_fingerprint_normalizes_url():
    """同 endpoint 不同 query 指纹相同"""
    r1 = ScanResult(
        kind="vuln",
        name="任意文件读取",
        url="http://x.com/a?b=1",
        extra={"vuln_type": "arbitrary_file_read", "payload_class": "p1"},
    )
    r2 = ScanResult(
        kind="vuln",
        name="任意文件读取",
        url="http://x.com/a?b=2",
        extra={"vuln_type": "arbitrary_file_read", "payload_class": "p1"},
    )
    assert fingerprint(r1) == fingerprint(r2)


def test_fingerprint_different_endpoint():
    """/system/role/list vs /system/dept/list 指纹不同"""
    r1 = ScanResult(
        kind="vuln",
        name="SQL注入",
        url="http://x.com/system/role/list",
        extra={"vuln_type": "sql_injection_error_based"},
    )
    r2 = ScanResult(
        kind="vuln",
        name="SQL注入",
        url="http://x.com/system/dept/list",
        extra={"vuln_type": "sql_injection_error_based"},
    )
    assert fingerprint(r1) != fingerprint(r2)


def test_fingerprint_vuln_type_fallback():
    """旧插件无 extra['vuln_type'],回退到 kind:name 去括号"""
    r = ScanResult(kind="vuln", name="任意文件读取（路径穿越）", url="http://x.com/a")
    fp = fingerprint(r)
    # 回退后 vuln_type 应为 'vuln:任意文件读取'（去括号）
    assert len(fp) == 16
    # 与有 vuln_type 的结果指纹不同
    r2 = ScanResult(
        kind="vuln", name="任意文件读取（路径穿越）", url="http://x.com/a", extra={"vuln_type": "arbitrary_file_read"}
    )
    assert fingerprint(r) != fingerprint(r2)


# === 聚合规则 ===


def test_aggregate_no_merge():
    """4 条不同漏洞,无合并"""
    results = [
        ScanResult(
            kind="vuln",
            name="漏洞A",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a",
            extra={"vuln_type": "rce"},
        ),
        ScanResult(
            kind="vuln",
            name="漏洞B",
            severity=SEVERITY_MEDIUM,
            status=STATUS_CONFIRMED,
            url="http://x.com/b",
            extra={"vuln_type": "ssrf"},
        ),
        ScanResult(
            kind="vuln",
            name="漏洞C",
            severity=SEVERITY_LOW,
            status=STATUS_SAFE,
            url="http://x.com/c",
            extra={"vuln_type": "xss"},
        ),
        ScanResult(
            kind="vuln",
            name="漏洞D",
            severity=SEVERITY_HIGH,
            status=STATUS_UNKNOWN,
            url="http://x.com/d",
            extra={"vuln_type": "xxe"},
        ),
    ]
    aggregated, report = aggregate(results)
    assert len(aggregated) == 4
    assert report.original_count == 4
    assert report.aggregated_count == 4
    assert report.merged_groups == 0


def test_aggregate_merge_file_read_pair():
    """file_read + file_read_path 聚合为 1 条"""
    extra = {"vuln_type": "arbitrary_file_read", "payload_class": "traversal_etc_passwd"}
    results = [
        ScanResult(
            kind="vuln",
            name="任意文件读取",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/common/download/resource?resource=/profile/../../../etc/passwd",
            evidence="响应含 root 与 :/ 特征",
            fix="限制 resource 参数",
            extra=extra,
        ),
        ScanResult(
            kind="vuln",
            name="任意文件读取（路径穿越）",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/common/download/resource?resource=../../../etc/passwd",
            evidence="读取到 /etc/passwd",
            fix="resource 参数白名单校验",
            extra=extra,
        ),
    ]
    aggregated, report = aggregate(results)
    assert len(aggregated) == 1
    assert report.original_count == 2
    assert report.aggregated_count == 1
    assert report.merged_groups == 1
    assert aggregated[0].hit_count == 2


def test_aggregate_keeps_highest_severity():
    """一条 high + 一条 medium → high"""
    extra = {"vuln_type": "rce", "payload_class": "cmd"}
    results = [
        ScanResult(
            kind="vuln",
            name="RCE",
            severity=SEVERITY_MEDIUM,
            status=STATUS_CONFIRMED,
            url="http://x.com/a",
            extra=extra,
        ),
        ScanResult(
            kind="vuln",
            name="RCE",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a?b=1",
            extra=extra,
        ),
    ]
    aggregated, _ = aggregate(results)
    assert len(aggregated) == 1
    assert aggregated[0].severity == SEVERITY_HIGH


def test_aggregate_keeps_worst_status():
    """一条 CONFIRMED + 一条 UNKNOWN → CONFIRMED"""
    extra = {"vuln_type": "rce"}
    results = [
        ScanResult(
            kind="vuln", name="RCE", severity=SEVERITY_HIGH, status=STATUS_UNKNOWN, url="http://x.com/a", extra=extra
        ),
        ScanResult(
            kind="vuln",
            name="RCE",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a?b=1",
            extra=extra,
        ),
    ]
    aggregated, _ = aggregate(results)
    assert len(aggregated) == 1
    assert aggregated[0].status == STATUS_CONFIRMED


def test_aggregate_evidence_merged_dedup():
    """两条 evidence 完全相同只保留一条"""
    extra = {"vuln_type": "rce"}
    results = [
        ScanResult(
            kind="vuln",
            name="RCE",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a",
            evidence="相同证据",
            extra=extra,
        ),
        ScanResult(
            kind="vuln",
            name="RCE",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a?b=1",
            evidence="相同证据",
            extra=extra,
        ),
    ]
    aggregated, _ = aggregate(results)
    assert aggregated[0].evidence == "相同证据"


def test_aggregate_evidence_joined():
    """两条 evidence 不同用 ' | ' 连接"""
    extra = {"vuln_type": "rce"}
    results = [
        ScanResult(
            kind="vuln",
            name="RCE",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a",
            evidence="证据A",
            extra=extra,
        ),
        ScanResult(
            kind="vuln",
            name="RCE",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a?b=1",
            evidence="证据B",
            extra=extra,
        ),
    ]
    aggregated, _ = aggregate(results)
    assert aggregated[0].evidence == "证据A | 证据B"


def test_aggregate_fix_longest():
    """两条 fix 取较长"""
    extra = {"vuln_type": "rce"}
    short_fix = "限制参数"
    long_fix = "限制参数并做白名单校验，升级到最新版本"
    results = [
        ScanResult(
            kind="vuln",
            name="RCE",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a",
            fix=short_fix,
            extra=extra,
        ),
        ScanResult(
            kind="vuln",
            name="RCE",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a?b=1",
            fix=long_fix,
            extra=extra,
        ),
    ]
    aggregated, _ = aggregate(results)
    assert aggregated[0].fix == long_fix


def test_aggregate_preserves_order():
    """聚合后按 CONFIRMED 优先 + severity 排序"""
    # 不标注 vuln_type，让 name 回退到原始名以验证排序
    results = [
        ScanResult(kind="vuln", name="Z漏洞", severity=SEVERITY_LOW, status=STATUS_SAFE, url="http://x.com/c"),
        ScanResult(kind="vuln", name="A漏洞", severity=SEVERITY_HIGH, status=STATUS_CONFIRMED, url="http://x.com/a"),
        ScanResult(kind="vuln", name="B漏洞", severity=SEVERITY_MEDIUM, status=STATUS_CONFIRMED, url="http://x.com/b"),
    ]
    aggregated, _ = aggregate(results)
    # CONFIRMED 在前，同 CONFIRMED 按 severity high→medium
    assert aggregated[0].name == "A漏洞"  # high + CONFIRMED
    assert aggregated[1].name == "B漏洞"  # medium + CONFIRMED
    assert aggregated[2].status == STATUS_SAFE  # SAFE 最后


def test_aggregated_vuln_duck_types_scanresult():
    """AggregatedVuln 与 ScanResult 接口兼容"""
    av = AggregatedVuln(
        name="测试漏洞",
        severity=SEVERITY_HIGH,
        status=STATUS_CONFIRMED,
        url="http://x.com/a",
        evidence="证据",
        fix="修复",
        kind="vuln",
        extra={"vuln_type": "rce"},
        fingerprint="abc123",
        hit_count=2,
    )
    # 验证与 ScanResult 相同的属性
    assert av.is_vuln is True
    assert av.status == STATUS_CONFIRMED
    assert av.severity == SEVERITY_HIGH
    assert av.name == "测试漏洞"
    assert av.url == "http://x.com/a"
    assert av.evidence == "证据"
    assert av.fix == "修复"
    assert av.kind == "vuln"
    # to_dict 包含 ScanResult 的所有键
    d = av.to_dict()
    for key in ("kind", "name", "severity", "status", "url", "evidence", "extra", "fix"):
        assert key in d, f"缺少 key: {key}"
    # 额外聚合字段
    assert d["hit_count"] == 2
    assert d["fingerprint"] == "abc123"


def test_dedup_report_stats():
    """6 条原始,合并为 4 条(2 组合并)"""
    # 组1: file_read 对(2条 → 1条)
    fr_extra = {"vuln_type": "arbitrary_file_read", "payload_class": "traversal_etc_passwd"}
    # 组2: 默认口令对(2条 → 1条)
    dp_extra = {"vuln_type": "default_password"}
    results = [
        ScanResult(kind="vuln", name="任意文件读取", url="http://x.com/a?b=1", extra=fr_extra),
        ScanResult(kind="vuln", name="任意文件读取（路径穿越）", url="http://x.com/a?b=2", extra=fr_extra),
        ScanResult(kind="vuln", name="默认口令", url="http://x.com/login", extra=dp_extra),
        ScanResult(kind="vuln", name="默认口令", url="http://x.com/login?redirect=1", extra=dp_extra),
        ScanResult(
            kind="vuln", name="SQL注入", url="http://x.com/sqli", extra={"vuln_type": "sql_injection_error_based"}
        ),
        ScanResult(kind="vuln", name="RCE", url="http://x.com/rce", extra={"vuln_type": "rce"}),
    ]
    aggregated, report = aggregate(results)
    assert report.original_count == 6
    assert report.aggregated_count == 4
    assert report.merged_groups == 2


def test_aggregate_empty_input():
    """空列表返回 ([], DedupReport(0,0,0))"""
    aggregated, report = aggregate([])
    assert aggregated == []
    assert report.original_count == 0
    assert report.aggregated_count == 0
    assert report.merged_groups == 0


def test_aggregate_single_result():
    """1 条结果不报错"""
    results = [
        ScanResult(
            kind="vuln",
            name="单条漏洞",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a",
            extra={"vuln_type": "rce"},
        ),
    ]
    aggregated, report = aggregate(results)
    assert len(aggregated) == 1
    assert aggregated[0].hit_count == 1
    assert report.original_count == 1
    assert report.aggregated_count == 1
    assert report.merged_groups == 0
