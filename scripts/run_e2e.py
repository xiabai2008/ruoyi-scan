#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CI 端到端验收脚本（跨平台，Windows/Linux 通用）

职责：
  1. 可选启动靶场（LAB_MODE / LAB_PORT 环境变量注入）
  2. 等待目标端口可达（超时前轮询）
  3. 调用 main.py 对目标扫描并生成报告
  4. 解析 report.json 做断言（CONFIRMED 下限 / 要求全部 CONFIRMED）
  5. finally 清理启动的靶场进程

被 GitHub Actions 各 job 复用（scripts/run_e2e.py），本地也能直接跑：
  python scripts/run_e2e.py --lab lab/server.py --lab-port 8080 \
      --target http://127.0.0.1:8080/ --scan-mode -p \
      --report-dir /tmp/e2e/ruoyi --name ruoyi-signature --require-all-confirmed

  # 真实靶场已由 Docker/service 起好，仅扫描+断言：
  python scripts/run_e2e.py --target http://127.0.0.1:8086/ \
      --scan-mode -p --report-dir /tmp/e2e/real-spring \
      --name real-spring --min-confirmed 11
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_CONFIRMED = "CONFIRMED"
STATUS_SAFE = "SAFE"
STATUS_UNKNOWN = "UNKNOWN"


def wait_port(host, port, timeout=30):
    """轮询 TCP 端口可达，超时返回 False"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def start_lab(lab_module, lab_port, lab_mode):
    """后台启动靶场，注入 LAB_PORT / LAB_MODE 环境变量

    注意：子进程 stdout/stderr 重定向到日志文件而非 PIPE，
    否则 Flask 开发服务器写满 PIPE 缓冲区会死锁扫描进程。
    """
    env = dict(os.environ)
    env["LAB_PORT"] = str(lab_port)
    env["LAB_MODE"] = lab_mode
    log_path = os.path.join(REPO_ROOT, f"lab_{lab_port}.log")
    logf = open(log_path, "w", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        [sys.executable, lab_module],
        env=env,
        cwd=REPO_ROOT,
        stdout=logf,
        stderr=subprocess.STDOUT,
    )
    print(f"[start_lab] {lab_module} pid={proc.pid} log={log_path}")
    return proc


def run_scan(target, mode, report_dir):
    """调用 main.py 扫描目标并输出报告到 report_dir

    Args:
        mode: 扫描模式字符 'u'/'p'/'m'/'l'（对应 main.py 的 -u/-p/-m/-l）
    """
    cmd = [sys.executable, "main.py", f"-{mode}", target, "--report", report_dir]
    print(f"[run_scan] {' '.join(cmd)}")
    # stdin=DEVNULL：避免 main.py 末尾 final_prompt() 的 input() 在 CI 非交互环境卡住
    subprocess.run(cmd, cwd=REPO_ROOT, check=True, stdin=subprocess.DEVNULL)


def check_report(json_path, name, min_confirmed, require_all):
    """解析 report.json 并断言，返回是否通过"""
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    results = data.get("results", [])
    confirmed = sum(1 for r in results if r.get("status") == STATUS_CONFIRMED)
    safe = sum(1 for r in results if r.get("status") == STATUS_SAFE)
    unknown = sum(1 for r in results if r.get("status") == STATUS_UNKNOWN)
    print(f"[{name}] total={len(results)} CONFIRMED={confirmed} SAFE={safe} UNKNOWN={unknown}")

    ok = True
    if require_all and (safe or unknown):
        print(f"[{name}] FAIL: 要求全部 CONFIRMED，但存在 SAFE={safe} UNKNOWN={unknown}")
        ok = False
    if confirmed < min_confirmed:
        print(f"[{name}] FAIL: CONFIRMED={confirmed} < 期望下限 min-confirmed={min_confirmed}")
        ok = False
    if ok:
        print(f"[{name}] PASS")
    return ok


def main(argv=None):
    p = argparse.ArgumentParser(description="CI 端到端验收：启靶场→扫描→断言")
    p.add_argument("--lab", default=None, help="靶场启动脚本相对路径（如 lab/server.py）；不传则跳过启动（靶场已运行）")
    p.add_argument("--lab-port", type=int, default=8080, help="注入靶场的 LAB_PORT 环境变量")
    p.add_argument("--lab-mode", default="vuln", help="注入靶场的 LAB_MODE 环境变量")
    p.add_argument("--target", required=True, help="扫描目标 URL，如 http://127.0.0.1:8080/")
    p.add_argument(
        "--mode",
        "--scan-mode",
        dest="mode",
        choices=["u", "p", "m", "l"],
        default="p",
        help="扫描模式字符（对应 main.py 的 -u/-p/-m/-l；--scan-mode 为兼容别名）",
    )
    p.add_argument("--report-dir", required=True, help="报告输出目录（生成 report.json 等）")
    p.add_argument("--name", required=True, help="标签（日志/失败时显示）")
    p.add_argument("--min-confirmed", type=int, default=0, help="CONFIRMED 数量下限（默认 0；真实靶场用此断言）")
    p.add_argument(
        "--require-all-confirmed",
        action="store_true",
        help="要求所有 result 均为 CONFIRMED（签名靶场 vuln 模式用此断言）",
    )
    p.add_argument("--timeout", type=int, default=30, help="等待端口可达的超时秒数")
    a = p.parse_args(argv)

    proc = None
    try:
        if a.lab:
            proc = start_lab(a.lab, a.lab_port, a.lab_mode)

        parsed = urlparse(a.target)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not wait_port(host, port, a.timeout):
            print(f"[{a.name}] FAIL: 端口 {host}:{port} 在 {a.timeout}s 内不可达")
            return 1

        run_scan(a.target, a.mode, a.report_dir)

        json_path = os.path.join(a.report_dir, "report.json")
        if not os.path.isfile(json_path):
            print(f"[{a.name}] FAIL: 报告未生成 {json_path}")
            return 1

        ok = check_report(json_path, a.name, a.min_confirmed, a.require_all_confirmed)
        return 0 if ok else 1
    except subprocess.CalledProcessError as e:
        print(f"[{a.name}] FAIL: 扫描进程异常退出 (returncode={e.returncode})")
        return 1
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
