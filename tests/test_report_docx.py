# D8.3 Word 报告生成单元测试
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, ScanResult
from core.report import ReportBuilder
from core.report_docx import render_docx


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


def test_docx_file_created():
    """Word 文件生成成功"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        assert os.path.exists(docx_path)


def test_docx_non_empty():
    """Word 文件非空（>2000 字节）"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        assert os.path.getsize(docx_path) > 2000


def test_docx_header_valid():
    """Word 文件头部为 PK（docx 本质是 zip）"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        with open(docx_path, "rb") as f:
            header = f.read(2)
        assert header == b"PK"


def test_docx_valid_zip():
    """Word 文件是合法 zip 且含 word/document.xml"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        with zipfile.ZipFile(docx_path) as zf:
            names = zf.namelist()
            assert "word/document.xml" in names, "docx 应含 word/document.xml"
            # 读取 document.xml 检查内容
            with zf.open("word/document.xml") as f:
                content = f.read().decode("utf-8")


def test_docx_contains_target_and_vulns():
    """Word 文档内容包含目标和漏洞名称"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        with zipfile.ZipFile(docx_path) as zf:
            with zf.open("word/document.xml") as f:
                content = f.read().decode("utf-8")
        assert "http://x.com" in content, "文档应含目标 URL"
        assert "SQL注入" in content, "文档应含漏洞名 SQL注入"
        assert "XSS" in content, "文档应含漏洞名 XSS"
        assert "预编译语句" in content, "文档应含修复建议"


def test_docx_no_confirmed():
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
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        assert os.path.getsize(docx_path) > 0


def test_docx_empty_results():
    """空结果不报错"""
    builder = ReportBuilder(results=[], target="http://x.com")
    with tempfile.TemporaryDirectory() as tmpdir:
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        assert os.path.exists(docx_path)


def test_docx_with_dedup():
    """去重后 Word 生成正确（2 条同指纹 → 1 条）"""
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
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        assert os.path.getsize(docx_path) > 2000
        # 验证去重统计信息出现在文档中
        with zipfile.ZipFile(docx_path) as zf:
            with zf.open("word/document.xml") as f:
                content = f.read().decode("utf-8")
        assert "去重统计" in content, "文档应含去重统计"


def test_docx_multiple_confirmed():
    """多条确认漏洞 Word 生成正确"""
    builder = ReportBuilder(results=_sample_results(), target="http://x.com")
    assert len(builder.confirmed_results()) == 2
    with tempfile.TemporaryDirectory() as tmpdir:
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        assert os.path.getsize(docx_path) > 5000


def test_docx_with_summary():
    """带 summary 的 Word 生成正确"""
    summary = {"started_at": 1718700000, "duration": 12.5, "mode": "all", "request_count": 100}
    builder = ReportBuilder(results=_sample_results(), target="http://x.com", summary=summary)
    with tempfile.TemporaryDirectory() as tmpdir:
        docx_path = os.path.join(tmpdir, "report.docx")
        render_docx(builder, docx_path)
        assert os.path.getsize(docx_path) > 0
        with zipfile.ZipFile(docx_path) as zf:
            with zf.open("word/document.xml") as f:
                content = f.read().decode("utf-8")
        assert "100" in content, "文档应含请求数"


if __name__ == "__main__":
    test_docx_file_created()
    test_docx_non_empty()
    test_docx_header_valid()
    test_docx_valid_zip()
    test_docx_contains_target_and_vulns()
    test_docx_no_confirmed()
    test_docx_empty_results()
    test_docx_with_dedup()
    test_docx_multiple_confirmed()
    test_docx_with_summary()
    print("All D8.3 Word tests passed!")
