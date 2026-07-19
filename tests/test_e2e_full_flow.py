# e2e 全流程测试：CLI → 指纹 → 插件 → 报告
"""端到端集成测试：模拟完整扫描流程，验证 main.py CLI 入口到报告生成的端到端链路"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE
from core.runner import (
    _parse_report_formats, _print_scan_result,
    MODE_CATEGORIES, MODE_LABELS,
)


class TestE2EFullFlow(unittest.TestCase):
    """全流程 e2e 测试"""

    def test_cli_help_runs(self):
        """验证 main.py -h 正常运行"""
        from main import main
        with patch('sys.argv', ['main.py', '-h']):
            try:
                main()
            except SystemExit:
                pass
        # 不应该抛异常

    def test_mode_constants(self):
        """验证模式常量完整性"""
        self.assertIn('u', MODE_CATEGORIES)
        self.assertIn('p', MODE_CATEGORIES)
        self.assertIn('m', MODE_CATEGORIES)
        self.assertIn('l', MODE_CATEGORIES)
        self.assertEqual(MODE_CATEGORIES['u'], ['recon', 'vuln', 'brute'])
        self.assertEqual(MODE_CATEGORIES['p'], ['vuln'])
        self.assertIn('u', MODE_LABELS)

    def test_report_format_parsing(self):
        """验证报告格式解析"""
        self.assertEqual(_parse_report_formats('all'), 'all')
        self.assertEqual(_parse_report_formats('html,json'), ['html', 'json'])
        self.assertEqual(_parse_report_formats('pdf'), ['pdf'])
        self.assertEqual(_parse_report_formats(''), None)
        self.assertEqual(_parse_report_formats(None), None)
        # 含无效格式
        result = _parse_report_formats('html,invalid,csv')
        self.assertIn('html', result)
        self.assertIn('csv', result)
        self.assertNotIn('invalid', result)

    def test_print_scan_result_colors(self):
        """验证扫描结果输出着色语义"""
        import io
        buf = io.StringIO()

        with patch('sys.stdout', buf):
            _print_scan_result(ScanResult(
                kind='vuln', name='测试漏洞', severity='high',
                status=STATUS_CONFIRMED, url='http://test/', evidence='test'
            ))
        output = buf.getvalue()
        self.assertIn('测试漏洞', output)
        self.assertIn('[*]', output)

        buf = io.StringIO()
        with patch('sys.stdout', buf):
            _print_scan_result(ScanResult(
                kind='vuln', name='不存在漏洞', severity='low',
                status=STATUS_SAFE, url='http://test/', evidence='test'
            ))
        output = buf.getvalue()
        self.assertIn('不存在漏洞', output)
        self.assertIn('[/]', output)

    def test_main_imports(self):
        """验证 main.py 核心 import 链路"""
        from main import build_parser, print_banner, print_help
        parser = build_parser()
        self.assertIsNotNone(parser)
        # 验证核心参数存在
        args, _ = parser.parse_known_args(['-u', 'http://example.com/'])
        self.assertEqual(args.u, 'http://example.com/')

    def test_runner_imports(self):
        """验证 core/runner.py 所有公开函数可导入"""
        from core.runner import (
            run_mode, run_mode_batch, final_prompt,
            run_chain_mode, run_serve_mode, run_passive_mode,
            run_template_list_mode, run_diff_only_mode,
            run_plugin_init_mode, run_plugin_check_mode, run_plugin_list_mode,
            run_ci_init_mode, run_wiki_mode,
        )
        self.assertTrue(callable(run_mode))
        self.assertTrue(callable(run_chain_mode))
        self.assertTrue(callable(run_serve_mode))
        self.assertTrue(callable(run_passive_mode))
        self.assertTrue(callable(run_mode_batch))
        self.assertTrue(callable(final_prompt))

    def test_plugin_base_imports(self):
        """验证 PluginBase + type hints 正常"""
        from plugins.base import PluginBase, cvss_score, parse_compliance
        self.assertTrue(hasattr(PluginBase, 'verify'))
        self.assertTrue(hasattr(PluginBase, 'meta'))
        # CVSS 评分
        score = cvss_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
        self.assertAlmostEqual(score, 9.8, places=1)
        # 合规解析
        result = parse_compliance('等保2.0:安全计算环境-访问控制')
        self.assertIn('等保2.0', result)

    def test_core_imports_with_type_hints(self):
        """验证 core/ 模块 type hints 导入正常"""
        from core.engine import ScanEngine
        from core.models import ScanResult, FingerprintResult, STATUS_CONFIRMED
        from core.loader import load_plugins
        from core.router import Router
        from core.session import SessionManager

        # 实例化基本检查
        engine = ScanEngine(threads=1)
        self.assertEqual(engine.threads, 1)

        result = ScanResult(
            kind='vuln', name='test', severity='high',
            status=STATUS_CONFIRMED, url='http://test/', evidence='test'
        )
        self.assertTrue(result.is_vuln)

        fp = FingerprintResult(cms='ruoyi', version='4.7.8', confidence=0.9, matched=['favicon'])
        self.assertEqual(fp.cms, 'ruoyi')

    def test_report_builder_basic(self):
        """验证 ReportBuilder 基本功能"""
        from core.report import ReportBuilder
        results = [
            ScanResult(kind='vuln', name='SQL注入', severity='high',
                       status=STATUS_CONFIRMED, url='http://test/sql', evidence='error'),
            ScanResult(kind='vuln', name='文件读取', severity='medium',
                       status=STATUS_SAFE, url='http://test/file', evidence='n/a'),
        ]
        builder = ReportBuilder(results=results, target='http://test/',
                                summary={'mode': 'test', 'duration': 1.0})
        dist = builder.risk_distribution()
        self.assertEqual(dist['high'], 1)
        self.assertEqual(dist['total'], 1)  # risk_distribution 只统计 CONFIRMED

        confirmed = builder.confirmed_results()
        self.assertEqual(len(confirmed), 1)

        d = builder.to_dict()
        self.assertIn('results', d)
        self.assertIn('target', d)

        with tempfile.TemporaryDirectory() as tmp:
            paths = builder.render_all(tmp, formats=['json', 'csv'])
            self.assertGreater(len(paths), 0)
            for p in paths:
                self.assertTrue(os.path.exists(p))

    def test_engine_creation(self):
        """验证 ScanEngine 创建和运行"""
        from core.engine import ScanEngine
        from core.session import SessionManager

        engine = ScanEngine(threads=1, rate=100)
        self.assertEqual(engine.threads, 1)
        self.assertEqual(engine.rate, 100)

        # 使用空插件列表运行
        session = SessionManager(timeout=5)
        results = engine.run([], 'http://127.0.0.1:1/', session)
        self.assertEqual(len(results), 0)
        session.close()

    def test_distributed_rate_limiter_enhanced(self):
        """验证 P3 增强：DistributedRateLimiter burst + stats"""
        from lib.distributed import DistributedRateLimiter, RATE_STATS_KEY

        # 本地模式（无 Redis）
        limiter = DistributedRateLimiter(None, rate=10, burst=2, worker_id='test_worker')
        self.assertEqual(limiter.rate, 10)
        self.assertEqual(limiter.burst, 2)

        # 获取令牌（本地模式，应该能获取 rate+burst 个）
        import time
        t0 = time.time()
        for _ in range(12):  # rate=10 + burst=2 = 12
            limiter.acquire()
        elapsed = time.time() - t0
        # 12 个请求应该在 burst 范围内瞬时完成（< 1秒等待仅发生在超出后）
        self.assertLess(elapsed, 2.0)

        # get_stats 在本地模式下返回空
        stats = limiter.get_stats()
        self.assertEqual(stats, {})

    def test_scan_result_three_states(self):
        """验证三态判定常量"""
        self.assertEqual(STATUS_CONFIRMED, 'CONFIRMED')
        self.assertEqual(STATUS_SAFE, 'SAFE')
        from core.models import STATUS_UNKNOWN
        self.assertEqual(STATUS_UNKNOWN, 'UNKNOWN')

        # ScanResult.is_vuln 只对 CONFIRMED 返回 True
        confirmed = ScanResult(
            kind='vuln', name='test', severity='high',
            status=STATUS_CONFIRMED, url='http://t/', evidence='e'
        )
        safe = ScanResult(
            kind='vuln', name='test', severity='low',
            status=STATUS_SAFE, url='http://t/', evidence='e'
        )
        unknown = ScanResult(
            kind='vuln', name='test', severity='medium',
            status=STATUS_UNKNOWN, url='http://t/', evidence='e'
        )
        self.assertTrue(confirmed.is_vuln)
        self.assertFalse(safe.is_vuln)
        self.assertFalse(unknown.is_vuln)


if __name__ == '__main__':
    unittest.main()
