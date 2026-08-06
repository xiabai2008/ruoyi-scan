# D8.5 CLI 集成 + 依赖管理 + 降级策略单元测试
import os
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.runner import _parse_report_formats
from common.models import SEVERITY_HIGH, SEVERITY_MEDIUM, STATUS_CONFIRMED, ScanResult
from core.report import ReportBuilder
from main import build_parser


def _sample_results():
    return [
        ScanResult(kind='vuln', name='SQL注入', severity=SEVERITY_HIGH,
                   status=STATUS_CONFIRMED, url='http://x.com/sqli',
                   evidence='报错: SQL syntax error',
                   fix='使用预编译语句'),
        ScanResult(kind='vuln', name='XSS', severity=SEVERITY_MEDIUM,
                   status=STATUS_CONFIRMED, url='http://x.com/xss',
                   evidence='<script>alert(1)</script>',
                   fix='对输出做 HTML 转义'),
    ]


# === _parse_report_formats 测试 ===

def test_parse_format_all():
    """'all' → 'all'"""
    assert _parse_report_formats('all') == 'all'


def test_parse_format_single():
    """'pdf' → ['pdf']"""
    assert _parse_report_formats('pdf') == ['pdf']


def test_parse_format_multiple():
    """'html,json,csv' → ['html', 'json', 'csv']"""
    result = _parse_report_formats('html,json,csv')
    assert result == ['html', 'json', 'csv']


def test_parse_format_empty():
    """空字符串 → None"""
    assert _parse_report_formats('') is None
    assert _parse_report_formats(None) is None


def test_parse_format_case_insensitive():
    """大小写不敏感：'PDF,HTML' → ['pdf', 'html']"""
    result = _parse_report_formats('PDF,HTML')
    assert result == ['pdf', 'html']


def test_parse_format_with_spaces():
    """带空格：'html, json , csv' → ['html', 'json', 'csv']"""
    result = _parse_report_formats('html, json , csv')
    assert result == ['html', 'json', 'csv']


def test_parse_format_invalid_filtered():
    """无效格式被过滤（不报错，仅警告）"""
    result = _parse_report_formats('html,invalid,pdf')
    assert 'html' in result
    assert 'pdf' in result
    assert 'invalid' not in result


# === build_parser 测试 ===

def test_parser_accepts_report_format():
    """解析器接受 --report-format 参数"""
    parser = build_parser()
    args = parser.parse_args(['-u', 'http://x.com', '--report-format', 'pdf'])
    assert args.report_format == 'pdf'


def test_parser_accepts_no_dedup():
    """解析器接受 --no-dedup 参数"""
    parser = build_parser()
    args = parser.parse_args(['-u', 'http://x.com', '--no-dedup'])
    assert args.no_dedup is True


def test_parser_default_report_format_all():
    """--report-format 默认值为 'all'"""
    parser = build_parser()
    args = parser.parse_args(['-u', 'http://x.com'])
    assert args.report_format == 'all'


def test_parser_default_no_dedup_false():
    """--no-dedup 默认为 False（去重默认开启）"""
    parser = build_parser()
    args = parser.parse_args(['-u', 'http://x.com'])
    assert args.no_dedup is False


# === render_all 集成测试 ===

def test_render_all_formats_all_generates_six_files():
    """render_all(formats='all') 生成 7 个文件（含 SARIF，全依赖已装）"""
    builder = ReportBuilder(results=_sample_results(), target='http://x.com')
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = builder.render_all(tmpdir, formats='all')
        assert len(paths) == 7, f'应生成 7 个文件，实际 {len(paths)}: {paths}'
        for p in paths:
            assert os.path.exists(p), f'文件应存在: {p}'
        # 验证文件名
        names = {os.path.basename(p) for p in paths}
        expected = {'report.json', 'report.html', 'report.csv',
                    'report.pdf', 'report.docx', 'report.xlsx', 'report.sarif'}
        assert names == expected, f'文件名不匹配: {names} vs {expected}'


def test_render_all_formats_subset():
    """render_all(formats=['pdf','docx']) 只生成 2 个文件"""
    builder = ReportBuilder(results=_sample_results(), target='http://x.com')
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = builder.render_all(tmpdir, formats=['pdf', 'docx'])
        assert len(paths) == 2
        names = {os.path.basename(p) for p in paths}
        assert names == {'report.pdf', 'report.docx'}


def test_render_all_default_three_formats():
    """render_all(formats=None) 默认生成 3 个文件（HTML/JSON/CSV）"""
    builder = ReportBuilder(results=_sample_results(), target='http://x.com')
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = builder.render_all(tmpdir)
        assert len(paths) == 3
        names = {os.path.basename(p) for p in paths}
        assert names == {'report.json', 'report.html', 'report.csv'}


def test_render_all_degradation_on_missing_pdf():
    """PDF 依赖缺失时降级（mock ImportError）"""
    builder = ReportBuilder(results=_sample_results(), target='http://x.com')
    with tempfile.TemporaryDirectory() as tmpdir:
        # mock report_pdf 导入失败
        with patch.dict(sys.modules, {'core.report_pdf': None}):
            paths = builder.render_all(tmpdir, formats=['html', 'pdf'])
            # HTML 正常生成，PDF 降级跳过
            assert len(paths) == 1
            assert os.path.basename(paths[0]) == 'report.html'


def test_render_all_degradation_on_missing_docx():
    """Word 依赖缺失时降级（mock ImportError）"""
    builder = ReportBuilder(results=_sample_results(), target='http://x.com')
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch.dict(sys.modules, {'core.report_docx': None}):
            paths = builder.render_all(tmpdir, formats=['html', 'docx'])
            assert len(paths) == 1
            assert os.path.basename(paths[0]) == 'report.html'


def test_render_all_degradation_on_missing_xlsx():
    """Excel 依赖缺失时降级（mock ImportError）"""
    builder = ReportBuilder(results=_sample_results(), target='http://x.com')
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch.dict(sys.modules, {'core.report_xlsx': None}):
            paths = builder.render_all(tmpdir, formats=['html', 'xlsx'])
            assert len(paths) == 1
            assert os.path.basename(paths[0]) == 'report.html'


# === dedup 集成测试 ===

def test_report_builder_dedup_default_true():
    """ReportBuilder 默认开启去重"""
    builder = ReportBuilder(results=_sample_results(), target='http://x.com')
    assert builder.dedup_enabled is True


def test_report_builder_no_dedup():
    """ReportBuilder(dedup=False) 关闭去重"""
    builder = ReportBuilder(results=_sample_results(), target='http://x.com', dedup=False)
    assert builder.dedup_enabled is False
    # 关闭去重时 dedup_report() 返回 None
    assert builder.dedup_report() is None


def test_report_builder_no_dedup_preserves_duplicates():
    """dedup=False 时保留重复漏洞（不合并）"""
    extra = {'vuln_type': 'arbitrary_file_read', 'payload_class': 'traversal'}
    results = [
        ScanResult(kind='vuln', name='任意文件读取', severity=SEVERITY_HIGH,
                   status=STATUS_CONFIRMED, url='http://x.com/a?b=1',
                   evidence='root:x:0', fix='限制参数', extra=extra),
        ScanResult(kind='vuln', name='任意文件读取', severity=SEVERITY_HIGH,
                   status=STATUS_CONFIRMED, url='http://x.com/a?b=2',
                   evidence='root:x:0', fix='限制参数', extra=extra),
    ]
    # 开启去重：合并为 1 条
    builder_dedup = ReportBuilder(results=results, target='http://x.com', dedup=True)
    assert len(builder_dedup.confirmed_results()) == 1
    # 关闭去重：保留 2 条
    builder_no_dedup = ReportBuilder(results=results, target='http://x.com', dedup=False)
    assert len(builder_no_dedup.confirmed_results()) == 2


if __name__ == '__main__':
    test_parse_format_all()
    test_parse_format_single()
    test_parse_format_multiple()
    test_parse_format_empty()
    test_parse_format_case_insensitive()
    test_parse_format_with_spaces()
    test_parse_format_invalid_filtered()
    test_parser_accepts_report_format()
    test_parser_accepts_no_dedup()
    test_parser_default_report_format_all()
    test_parser_default_no_dedup_false()
    test_render_all_formats_all_generates_six_files()
    test_render_all_formats_subset()
    test_render_all_default_three_formats()
    test_render_all_degradation_on_missing_pdf()
    test_render_all_degradation_on_missing_docx()
    test_render_all_degradation_on_missing_xlsx()
    test_report_builder_dedup_default_true()
    test_report_builder_no_dedup()
    test_report_builder_no_dedup_preserves_duplicates()
    print('All D8.5 CLI integration tests passed!')
