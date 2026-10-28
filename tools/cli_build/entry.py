# -*- coding: utf-8 -*-
"""Ruoyi-Scan 终端版单文件入口（PyInstaller 打包专用，不是 pip 包的入口）。

职责：把 `main.py` 的 CLI 冻结成一个可双击/可入 PATH 的 `ruoyi-scan.exe`，
用户机器不需要 Python。源码运行时本文件等价于 `python main.py`。

两个冻结环境专有处理：
  1. 可写报告目录：onefile 的 BASE_DIR 指向临时解压目录（_MEIPASS），程序退出即删。
     `--report` 未显式给出时，报告默认落到 `%USERPROFILE%\\Ruoyi-Scan\\reports`，
     可用 `RUOYI_SCAN_HOME` 改根目录、`RUOYI_SCAN_REPORT_DIR` 直接指定报告目录。
  2. multiprocessing.freeze_support()：onefile 下任何子进程都会重新执行本 exe，
     没有这行会无限递归拉起自己（桌面端引擎未用到进程池，CLI 这里提前防住）。

注意：config.settings 在 import 时求值 REPORT_DIR，所以环境变量必须在
`from main import main` 之前落位——顺序不能调换。
"""

import multiprocessing
import os
import sys


def _prepare_frozen_env() -> None:
    """冻结环境准备（源码运行直接返回，零副作用）"""
    if not getattr(sys, "frozen", False):
        return

    home = os.path.expanduser("~")
    scan_home = os.environ.get("RUOYI_SCAN_HOME") or os.path.join(home, "Ruoyi-Scan")
    reports_dir = os.path.join(scan_home, "reports")
    try:
        os.makedirs(reports_dir, exist_ok=True)
    except OSError as exc:
        print(f"[ruoyi-scan] 无法创建报告目录 {reports_dir}: {exc}", file=sys.stderr)
        print(
            "[ruoyi-scan] 请检查 RUOYI_SCAN_HOME 指向的路径是否存在且当前用户可写；"
            "未设置时默认 %USERPROFILE%\\Ruoyi-Scan。",
            file=sys.stderr,
        )
        raise SystemExit(2)
    os.environ.setdefault("RUOYI_SCAN_REPORT_DIR", reports_dir)


def main() -> None:
    _prepare_frozen_env()
    from main import main as cli_main

    cli_main()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
