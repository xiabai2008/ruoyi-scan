# 全流程端到端测试（P1）：覆盖 CLI → 扫描 → 报告完整链路
"""端到端测试：启动 HTTP 签名靶场 → 执行扫描 → 验证报告输出"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest


# ── 简易签名靶场（模拟若依目标）──
class _MockRuoYiHandler(BaseHTTPRequestHandler):
    """模拟若依目标：返回特征响应供 POC 命中"""

    ROUTES = {
        '/': ('<title>若依管理系统</title>', 200),
        '/login': ('<title>若依管理系统</title>', 200),
        '/common/download/resource?resource=../../etc/passwd': ('root:x:0:0:root:/root:/bin/bash', 200),
        '/system/dept/list': ('运行时异常', 500),
        '/system/role/list': ('database()', 500),
        '/druid/submitLogin': ('success', 200),
        '/druid/index.html': ('Druid Stat Index', 200),
        '/profile': ('若依', 200),
    }

    def do_GET(self):
        self._respond('GET')

    def do_POST(self):
        self._respond('POST')

    def _respond(self, _method):
        path = self.path.split('?')[0] if '?' in self.path else self.path
        for route, (body, code) in self.ROUTES.items():
            if route.startswith(path) or path.startswith(route.split('?')[0]):
                self.send_response(code)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(body.encode('utf-8'))
                return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'Not Found')


def _start_server(port=18999):
    """启动模拟靶场，返回 (thread, url)"""
    server = HTTPServer(('127.0.0.1', port), _MockRuoYiHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    return t, server, f'http://127.0.0.1:{port}/'


class TestE2E:
    """全流程 E2E 测试"""

    def test_cli_help(self):
        """测试 -h 帮助输出"""
        result = subprocess.run(
            [sys.executable, 'main.py', '-h'],
            capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__))
        )
        assert result.returncode == 0
        assert '综合扫描' in result.stdout

    def test_vuln_scan_e2e(self):
        """全流程：启动靶场 → 漏洞扫描 → 验证报告"""
        t, server, target = _start_server(18999)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                result = subprocess.run(
                    [sys.executable, 'main.py', '-p', target,
                     '--cms', 'ruoyi', '--timeout', '5', '--report', tmpdir,
                     '--report-format', 'json'],
                    capture_output=True, text=True,
                    cwd=os.path.dirname(os.path.dirname(__file__)),
                    timeout=60
                )
                # 验证退出码
                assert result.returncode == 0, f'扫描失败: {result.stderr[:500]}'

                # 验证 JSON 报告
                json_path = os.path.join(tmpdir, 'report.json')
                assert os.path.exists(json_path), f'报告不存在: {json_path}'

                with open(json_path, 'r', encoding='utf-8') as f:
                    report = json.load(f)

                assert 'results' in report
                assert len(report['results']) > 0
                # 至少应有确认的漏洞（因为靶场返回了 file_read 的 etc/passwd 特征）
                confirmed = [r for r in report['results'] if r.get('status') == 'CONFIRMED']
                assert len(confirmed) > 0, f'应该有确认漏洞，实际: {report["results"]}'

        finally:
            server.shutdown()
            t.join(timeout=2)

    def test_chain_list(self):
        """测试 --chain list 列出可用链"""
        result = subprocess.run(
            [sys.executable, 'main.py', '--chain-list'],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
            timeout=30
        )
        assert result.returncode == 0
        assert 'ruoyi_sql_to_rce' in result.stdout

    def test_plugin_list(self):
        """测试 --plugin-list 列出插件"""
        result = subprocess.run(
            [sys.executable, 'main.py', '--plugin-list'],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(__file__)),
            timeout=30
        )
        assert result.returncode == 0
        assert '漏洞名称' in result.stdout


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
