# 全流程端到端测试（P1）：覆盖 CLI → 扫描 → 报告完整链路
"""端到端测试：启动 HTTP 签名靶场 → 执行扫描 → 验证报告输出"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


# ── 简易签名靶场（模拟若依目标）──
class _MockRuoYiHandler(BaseHTTPRequestHandler):
    """模拟一个「真实存在漏洞」的若依站点，供端到端扫描验证

    ── 2026-09-16 修正说明（重要）────────────────────────────────────────────
    旧实现的路由匹配为：

        if route.startswith(path) or path.startswith(route.split("?")[0]):

    由于 ROUTES 的第一项是 "/"，而 `path.startswith("/")` 对任何路径都成立，
    实际效果是 **所有请求都返回同一张首页 HTML**，注入点、passwd 读取点、
    Druid 登录点全部不可达。

    该缺陷使本测试长期处于「假绿」状态：扫描结果里出现的 CONFIRMED 唯一来源，
    是 backup_scan 在「任意路径都返回 200 且有内容」这一条件下的误报
    （报告 65 个备份文件泄露），与任何真实漏洞特征无关。
    修正插件误报后本测试立即变红，才暴露出靶场本身从未被真正打通。

    现改为三条原则：
      1. 路由精确匹配（先剥离查询串），不做前缀兼容；
      2. 注入点按请求体内容区分「基线请求」与「注入请求」，
         使插件能做差分判定（这正是加固后的判定方式）；
      3. 未命中路由一律 404，不再无差别返回 200。
    ─────────────────────────────────────────────────────────────────────
    """

    INDEX = "<html><head><title>若依管理系统</title></head><body></body></html>"
    PASSWD = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )
    NORMAL_LIST = '{"total":0,"rows":[],"code":200,"msg":"查询成功"}'
    # MySQL extractvalue 被真正求值后才会出现的报错文案
    INJECT_ERROR = "运行时异常：java.sql.SQLException: XPATH syntax error: '~ry~'"

    def do_GET(self):
        path, _, query = self.path.partition("?")

        if path in ("/", "/login", "/profile"):
            return self._send(200, self.INDEX, "text/html; charset=utf-8")
        # 任意文件读取点：仅当 resource 参数含目录穿越时返回 passwd（真实漏洞形态）
        if path == "/common/download/resource":
            if ".." in query and "etc/passwd" in query:
                return self._send(200, self.PASSWD, "text/plain; charset=utf-8")
            return self._send(403, "forbidden", "text/plain; charset=utf-8")
        # Druid 控制台暴露
        if path == "/druid/index.html":
            return self._send(200, "Druid Stat Index", "text/html; charset=utf-8")
        return self._send(404, "Not Found", "text/plain; charset=utf-8")

    def do_POST(self):
        path, _, _ = self.path.partition("?")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""

        # SQL 报错注入点：按请求体区分基线 / 注入。
        # 基线请求（无 payload）返回正常业务 JSON；注入请求返回 MySQL 真实报错。
        # 这样插件必须通过差分才能命中——单看「响应含某个词」无法通过本靶场。
        if path in ("/system/role/list", "/system/dept/list"):
            if "extractvalue" in body or "updatexml" in body:
                return self._send(500, self.INJECT_ERROR, "application/json; charset=utf-8")
            return self._send(200, self.NORMAL_LIST, "application/json; charset=utf-8")
        # Druid 弱口令：模拟未授权的 Druid 控制台（任意凭据均可登录）
        if path == "/druid/submitLogin":
            return self._send(200, '{"success":true}', "application/json; charset=utf-8")
        return self._send(404, "Not Found", "text/plain; charset=utf-8")

    def _send(self, code: int, body: str, content_type: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args, **kwargs):
        """静默 HTTP 日志：套件运行时无需逐请求噪声输出"""
        return


def _start_server(port=18999):
    """启动模拟靶场，返回 (thread, url)"""
    server = HTTPServer(("127.0.0.1", port), _MockRuoYiHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # 轮询等待服务器就绪，替代固定 sleep
    from tests.helpers import wait_for

    wait_for(lambda: _port_open("127.0.0.1", port), timeout=3)
    return t, server, f"http://127.0.0.1:{port}/"


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """检查端口是否可连接"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError):
        return False


class TestE2E:
    """全流程 E2E 测试"""

    def test_cli_help(self):
        """测试 -h 帮助输出"""
        result = subprocess.run(
            [sys.executable, "main.py", "-h"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        assert result.returncode == 0
        assert "综合扫描" in result.stdout

    def test_cli_help_cp1252_console(self):
        """英文 Windows（cp1252 控制台编码）下 -h 不崩溃（G2 可移植性回归）

        复现：GitHub windows runner 的 stdout 是 cp1252，banner 中文触发
        UnicodeEncodeError 使 CLI 退出码 1。main.py 入口强制 UTF-8 后应正常。
        PYTHONIOENCODING=cp1252 模拟该环境，跨平台可跑。
        """
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        result = subprocess.run(
            [sys.executable, "main.py", "-h"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=os.path.dirname(os.path.dirname(__file__)),
            env=env,
        )
        assert result.returncode == 0, result.stderr[-500:]
        assert "Ruoyi-Scan" in result.stdout

    def test_vuln_scan_e2e(self):
        """全流程：启动靶场 → 漏洞扫描 → 验证报告"""
        t, server, target = _start_server(18999)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                result = subprocess.run(
                    [
                        sys.executable,
                        "main.py",
                        "-p",
                        target,
                        "--cms",
                        "ruoyi",
                        "--timeout",
                        "5",
                        "--report",
                        tmpdir,
                        "--report-format",
                        "json",
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    cwd=os.path.dirname(os.path.dirname(__file__)),
                    timeout=60,
                )
                # 验证退出码
                assert result.returncode == 0, f"扫描失败: {result.stderr[:500]}"

                # 验证 JSON 报告
                json_path = os.path.join(tmpdir, "report.json")
                assert os.path.exists(json_path), f"报告不存在: {json_path}"

                with open(json_path, "r", encoding="utf-8") as f:
                    report = json.load(f)

                assert "results" in report
                assert len(report["results"]) > 0
                confirmed = [r for r in report["results"] if r.get("status") == "CONFIRMED"]
                confirmed_names = [r.get("name", "") for r in confirmed]
                assert confirmed, f"应该有确认漏洞，实际: {report['results']}"
                # 只断言「存在任意 CONFIRMED」是不够的：误报同样能满足该条件
                # （历史教训——本测试此前正是靠 backup_scan 的误报保持绿色）。
                # 因此必须点名验证靶场确实植入的漏洞特征。
                assert any("文件读取" in n for n in confirmed_names), (
                    f"应命中任意文件读取（/common/download/resource 目录穿越返回 passwd），"
                    f"实际确认项: {confirmed_names}"
                )

        finally:
            server.shutdown()
            t.join(timeout=2)

    def test_chain_list(self):
        """测试 --chain list 列出可用链"""
        result = subprocess.run(
            [sys.executable, "main.py", "--chain-list"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=os.path.dirname(os.path.dirname(__file__)),
            timeout=30,
        )
        assert result.returncode == 0
        assert "ruoyi_sql_to_rce" in result.stdout

    def test_plugin_list(self):
        """测试 --plugin-list 列出插件"""
        result = subprocess.run(
            [sys.executable, "main.py", "--plugin-list"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=os.path.dirname(os.path.dirname(__file__)),
            timeout=30,
        )
        assert result.returncode == 0
        assert "漏洞名称" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
