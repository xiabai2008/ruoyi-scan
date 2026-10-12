# -*- coding: utf-8 -*-
"""Ruoyi-Scan 桌面端引擎入口（PyInstaller 打包专用）

职责：把 FastAPI sidecar（main.py --serve）冻结成独立 exe，随 Tauri 安装包分发。
用户机器无需安装 Python —— 本文件是 exe 的 __main__。

设计要点：
  1. 可写目录重定向：安装目录（Program Files / %LOCALAPPDATA%）只读或受限，
     报告输出与 SQLite 任务库统一放到 %USERPROFILE%\\Ruoyi-Scan\\ 下。
     通过环境变量（REPORT_DIR）+ 显式 --db-path 注入实现，不改业务代码。
  2. 参数注入：Tauri 壳（lib.rs）以 `engine.exe --serve --host 127.0.0.1 --port 8123 ...`
     方式调用；本入口补齐缺省参数后转交 cli.serve_runner.run_serve_mode。
  3. PyInstaller onefile 模式下 data/（字典）与 web/（控制台）解压到 _MEIPASS，
     config/settings.py 的 BASE_DIR 相对 __file__ 求值 → 自动指向解压目录，无需特判。

注意：console=True（spec）保留控制台 —— 无头 CI 冒烟与用户故障排查都依赖引擎日志。
"""

import os
import sys
from typing import List


def _has_flag(argv: List[str], flag: str) -> bool:
    """argv 中是否已显式给出该开关（同时匹配 `--flag` 与 `--flag=value` 两种写法）。

    精确匹配 flag 本身或 `flag + "="` 前缀，避免 `--port` 误吞 `--ports`。
    """
    return any(a == flag or a.startswith(flag + "=") for a in argv)


def _prepare_runtime() -> None:
    """冻结环境准备：可写目录重定向 + 缺省参数注入（仅 frozen 生效，源码运行零影响）"""
    if not getattr(sys, "frozen", False):
        return

    # 可写根目录：%USERPROFILE%\Ruoyi-Scan（报告 / 任务库 / 用户数据）
    home = os.path.expanduser("~")
    scan_home = os.environ.get("RUOYI_SCAN_HOME") or os.path.join(home, "Ruoyi-Scan")
    reports_dir = os.path.join(scan_home, "reports")
    try:
        os.makedirs(scan_home, exist_ok=True)
        os.makedirs(reports_dir, exist_ok=True)
    except OSError as exc:
        # 原始 traceback 对用户没有指导意义：指出具体目录与排查方向后非零退出
        print(f"[engine] 无法创建可写目录 {scan_home}: {exc}", file=sys.stderr)
        print(
            "[engine] 请检查 RUOYI_SCAN_HOME 指向的路径是否存在且当前用户可写；"
            "未设置时默认 %USERPROFILE%\\Ruoyi-Scan。",
            file=sys.stderr,
        )
        raise SystemExit(2)

    # config.settings 在 import 时求值 REPORT_DIR → 环境变量必须在 import 前落位
    os.environ.setdefault("RUOYI_SCAN_REPORT_DIR", reports_dir)

    # 缺省参数注入：--serve 模式必填项与任务库路径
    # 注意：用户显式传入的值优先（含 --flag=value 形式），仅在完全未给出时才补默认值
    argv = sys.argv[1:]
    if "--serve" not in argv:
        argv = ["--serve"] + argv
    if not _has_flag(argv, "--host"):
        argv += ["--host", "127.0.0.1"]
    if not _has_flag(argv, "--port"):
        argv += ["--port", "8123"]
    # SQLite 任务库放可写目录（exe 同目录不可写，相对路径 data/tasks.db 会失败）
    if not _has_flag(argv, "--db-path"):
        argv += ["--db-path", os.path.join(scan_home, "tasks.db")]
    sys.argv = [sys.argv[0]] + argv


def main() -> None:
    _prepare_runtime()

    # 复用 CLI 的 serve 模式（含 API Key 回退 / CORS / 定时任务等全部既有逻辑）
    from main import build_parser
    from cli.serve_runner import run_serve_mode

    parser = build_parser()
    args = parser.parse_args(sys.argv[1:])
    run_serve_mode(args)


if __name__ == "__main__":
    main()
