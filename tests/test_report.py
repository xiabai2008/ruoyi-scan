# Step 4 报告渲染单元验收：mock 含 CONFIRMED 漏洞的结果，断言三格式字段完整
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, SEVERITY_HIGH, SEVERITY_MEDIUM
from core.report import ReportBuilder


def _sample_results():
    """构造含 CONFIRMED / SAFE / UNKNOWN 三态的样本结果"""
    return [
        ScanResult(kind='vuln', name='任意文件读取', severity=SEVERITY_HIGH,
                   status=STATUS_CONFIRMED,
                   url='http://target//common/download/resource?resource=/etc/passwd',
                   evidence='响应含 root 与 :/ 特征（/etc/passwd）',
                   fix='限制 resource 参数路径，禁止 .. 目录穿越，下载接口强制鉴权'),
        ScanResult(kind='vuln', name='SQL报错注入', severity=SEVERITY_MEDIUM,
                   status=STATUS_CONFIRMED,
                   url='http://target//system/role/list',
                   evidence='响应含 database() 报错特征',
                   fix='对 dataScope 参数做白名单校验，使用参数化查询'),
        ScanResult(kind='vuln', name='不存在漏洞X', severity='low',
                   status=STATUS_SAFE, url='http://target/safe'),
        ScanResult(kind='vuln', name='网络异常项Y', status=STATUS_UNKNOWN,
                   url='http://target/err', evidence='ConnectionTimeout'),
    ]


def _sample_summary():
    return {
        'started_at': '2026-07-17 09:00:00',
        'duration': 12.34,
        'request_count': 42,
        'mode': '综合扫描',
        'fingerprint': {'cms': 'ruoyi', 'confidence': 0.7, 'matched': ['login:RuoYi']},
    }


def test_risk_distribution():
    rb = ReportBuilder(results=_sample_results(), target='http://target/', summary=_sample_summary())
    dist = rb.risk_distribution()
    assert dist['high'] == 1, f'高危应为 1，实际 {dist["high"]}'
    assert dist['medium'] == 1, f'中危应为 1，实际 {dist["medium"]}'
    assert dist['low'] == 0
    assert dist['total'] == 2, f'总计应为 2，实际 {dist["total"]}'
    print('PASS test_risk_distribution: %s' % dist)


def test_json_fields():
    rb = ReportBuilder(results=_sample_results(), target='http://target/', summary=_sample_summary())
    data = json.loads(rb.to_json())
    assert data['target'] == 'http://target/'
    assert data['duration_sec'] == 12.34
    assert data['request_count'] == 42
    assert data['mode'] == '综合扫描'
    assert data['fingerprint']['cms'] == 'ruoyi'
    assert data['risk_distribution']['total'] == 2
    assert data['vuln_count'] == 2
    assert len(data['results']) == 4
    # 第一个结果应含完整字段
    r0 = data['results'][0]
    assert r0['name'] == '任意文件读取'
    assert r0['severity_cn'] == '高'
    assert r0['status'] == 'CONFIRMED'
    assert 'root' in r0['evidence']
    assert '目录穿越' in r0['fix']
    print('PASS test_json_fields: vuln_count=%d results=%d' % (data['vuln_count'], len(data['results'])))


def test_csv_fields():
    rb = ReportBuilder(results=_sample_results(), target='http://target/', summary=_sample_summary())
    csv_text = rb.to_csv()
    assert '漏洞名称,URL,危害等级,状态,证据,修复建议' in csv_text
    assert '任意文件读取' in csv_text
    assert '高' in csv_text
    assert '目录穿越' in csv_text  # 修复建议
    assert 'CONFIRMED' in csv_text
    print('PASS test_csv_fields: %d 字符' % len(csv_text))


def test_html_fields():
    rb = ReportBuilder(results=_sample_results(), target='http://target/', summary=_sample_summary())
    html = rb.to_html()
    # 摘要字段
    assert 'http://target/' in html
    assert '综合扫描' in html
    assert '12.34' in html
    assert '请求数' in html and '42' in html
    # 风险分布着色（高=红 #d9534f，中=黄 #f0ad4e）
    assert '#d9534f' in html
    assert '#f0ad4e' in html
    assert '高 1' in html
    assert '中 1' in html
    # 漏洞名称与修复建议
    assert '任意文件读取' in html
    assert '目录穿越' in html
    # 证据
    assert 'root' in html
    # 状态中文化
    assert '确认存在' in html
    print('PASS test_html_fields: %d 字符' % len(html))


def test_render_all_writes_three_files():
    rb = ReportBuilder(results=_sample_results(), target='http://target/', summary=_sample_summary())
    with tempfile.TemporaryDirectory() as d:
        paths = rb.render_all(d)
        assert len(paths) == 3
        for p in paths:
            assert os.path.exists(p), f'文件应存在：{p}'
            assert os.path.getsize(p) > 0, f'文件不应为空：{p}'
        # 校验文件扩展名
        exts = {os.path.splitext(p)[1] for p in paths}
        assert exts == {'.json', '.html', '.csv'}, f'应有三格式，实际 {exts}'
    print('PASS test_render_all_writes_three_files: json/html/csv 均生成且非空')


if __name__ == '__main__':
    test_risk_distribution()
    test_json_fields()
    test_csv_fields()
    test_html_fields()
    test_render_all_writes_three_files()
    print('ALL_REPORT_TESTS_PASS')
