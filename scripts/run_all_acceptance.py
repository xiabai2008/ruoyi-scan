#!/usr/bin/env python
"""时序盲注全套验收汇总入口（人工手动执行，禁止接入 pytest / CI）。

串行执行：
    1. acceptance_chaos_timing.py   （chaos slow 慢站干扰样本）
    2. acceptance_vuln_positive.py  （漏洞正样本）
    3. acceptance_vuln_negative.py  （干净负样本）

任一项失败，整体脚本返回非 0。子脚本各自负责临时报告与靶场进程清理，
本脚本不创建、不删除任何临时报告文件。

用法：
    Windows: .venv\\Scripts\\python.exe scripts\\run_all_acceptance.py
    Linux:   .venv/bin/python scripts/run_all_acceptance.py
"""

import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

ACCEPTANCE_SCRIPTS = [
    "acceptance_chaos_timing.py",
    "acceptance_vuln_positive.py",
    "acceptance_vuln_negative.py",
]


def _force_utf8_stdio():
    """Windows 控制台默认 GBK，强制 UTF-8 避免 ✅/❌ 与中文日志编码失败。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _project_python():
    """优先使用当前项目 venv 解释器；找不到时回退到当前运行解释器。"""
    if os.name == "nt":
        candidate = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = PROJECT_ROOT / ".venv" / "bin" / "python"
    if candidate.is_file():
        return candidate
    return Path(sys.executable)


def _run_script(python, script_name):
    """执行单个验收脚本，返回 (退出码, 错误描述)。子进程继承当前环境。"""
    script_path = PROJECT_ROOT / "scripts" / script_name
    if not script_path.is_file():
        return 127, "脚本文件不存在: %s" % script_path
    try:
        completed = subprocess.run(
            [str(python), str(script_path)],
            cwd=str(PROJECT_ROOT),
            env=os.environ.copy(),
            check=False,
        )
        return completed.returncode, ""
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001 - 汇总入口需要把启动异常转成失败项
        return 127, "%s: %s" % (type(exc).__name__, exc)


def main():
    """串行执行 3 个验收脚本并输出汇总表格，任一项失败则整体返回 1。"""
    _force_utf8_stdio()
    python = _project_python()

    results = []
    for index, script_name in enumerate(ACCEPTANCE_SCRIPTS, start=1):
        print("[%d/%d] 执行 %s ..." % (index, len(ACCEPTANCE_SCRIPTS), script_name), flush=True)
        code, error = _run_script(python, script_name)
        if error:
            print("    [!] %s" % error, file=sys.stderr)
        results.append({"name": script_name, "code": code, "error": error})

    print()
    print("===== 时序盲注全套验收汇总 =====")
    for index, item in enumerate(results, start=1):
        passed = item["code"] == 0
        status = "✅ PASS" if passed else "❌ FAIL"
        print("[%d] %-32s %s  Exit Code: %d" % (index, item["name"], status, item["code"]))
    print("--------------------------------")

    failed = [item for item in results if item["code"] != 0]
    if failed:
        print("存在失败项，请排查上面日志！")
        print("Exit Code: 1")
        return 1
    print("全部验收项通过！")
    print("===== 汇总结束 =====")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 用户中断，已停止后续验收。", file=sys.stderr)
        sys.exit(130)
