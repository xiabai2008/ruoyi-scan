# D8.2 PDF 报告生成单元测试
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, ScanResult
from core.report import ReportBuilder
from core.report_pdf import render_pdf


def _sample_results():
    return [
        ScanResult(
            kind="vuln",
            name="SQL注入",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/sqli",
            evidence="报错: You have an error in SQL syntax",
            fix="使用预编译语句，禁止拼接 SQL",
        ),
        ScanResult(
            kind="vuln",
            name="XSS",
            severity=SEVERITY_MEDIUM,
            status=STATUS_CONFIRMED,
            url="http://x.com/xss",
            evidence="<script>alert(1)</script>",
            fix="对输出做 HTML 转义",
        ),
        ScanResult(
            kind="info",
            name="端口扫描",
            severity=SEVERITY_LOW,
            status=STATUS_SAFE,
            url="http://x.com:8080",
            evidence="端口关闭",
        ),
    ]


def test_pdf_file_created():
    """PDF 文件生成成功"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "report.pdf")
        render_pdf(builder, pdf_path)
        assert os.path.exists(pdf_path)


def test_pdf_non_empty():
    """PDF 文件非空（>1000 字节）"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "report.pdf")
        render_pdf(builder, pdf_path)
        assert os.path.getsize(pdf_path) > 1000


def test_pdf_header_valid():
    """PDF 文件头部为 %PDF-"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "report.pdf")
        render_pdf(builder, pdf_path)
        with open(pdf_path, "rb") as f:
            header = f.read(5)
        assert header == b"%PDF-"


def test_pdf_no_confirmed():
    """无确认漏洞时不报错"""
    results = [
        ScanResult(
            kind="info",
            name="安全检查",
            severity=SEVERITY_LOW,
            status=STATUS_SAFE,
            url="http://x.com/safe",
            evidence="无漏洞",
        ),
    ]
    builder = ReportBuilder(results=results, target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "report.pdf")
        render_pdf(builder, pdf_path)
        assert os.path.getsize(pdf_path) > 0


def test_pdf_empty_results():
    """空结果不报错"""
    builder = ReportBuilder(results=[], target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "report.pdf")
        render_pdf(builder, pdf_path)
        assert os.path.exists(pdf_path)


def test_pdf_with_dedup():
    """去重后 PDF 生成正确（2 条同指纹 → 1 条）"""
    extra = {"vuln_type": "arbitrary_file_read", "payload_class": "traversal"}
    results = [
        ScanResult(
            kind="vuln",
            name="任意文件读取",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a?b=1",
            evidence="root:x:0",
            fix="限制参数",
            extra=extra,
        ),
        ScanResult(
            kind="vuln",
            name="任意文件读取",
            severity=SEVERITY_HIGH,
            status=STATUS_CONFIRMED,
            url="http://x.com/a?b=2",
            evidence="root:x:0",
            fix="限制参数",
            extra=extra,
        ),
    ]
    builder = ReportBuilder(results=results, target="http://x.com")
    assert len(builder.confirmed_results()) == 1  # 去重后 1 条
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "report.pdf")
        render_pdf(builder, pdf_path)
        assert os.path.getsize(pdf_path) > 1000


def test_pdf_multiple_confirmed():
    """多条确认漏洞 PDF 生成正确"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    assert len(builder.confirmed_results()) == 2
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "report.pdf")
        render_pdf(builder, pdf_path)
        assert os.path.getsize(pdf_path) > 2000


def test_pdf_with_summary():
    """带 summary 的 PDF 生成正确"""
    summary = {"started_at": 1718700000, "duration": 12.5, "mode": "all"}
    builder = ReportBuilder(results=_sample_results(), target="http://x.com", summary=summary)
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "report.pdf")
        render_pdf(builder, pdf_path)
        assert os.path.getsize(pdf_path) > 0
