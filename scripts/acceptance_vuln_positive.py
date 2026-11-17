#!/usr/bin/env python
"""时序盲注验收：漏洞正样本（人工发布卡点，禁止接入 pytest / CI）。

靶场：复用 lab/server.py 的 vuln 模式（dept 注入签名靶场），并在临时目录生成一个
最小 WSGI 时序垫片：仅当 params[dataScope] 含 if(1=1,sleep(3),0) 时 sleep 3s，
用于忠实复现 MySQL 条件求值，不修改 lab/ 任何存量文件、不新增 Docker 依赖。

判定：至少 1 条 CONFIRMED = 通过；0 条 CONFIRMED = 失败（漏报，时序盲注检测失效）。

统一扫描参数语义（与 CLI 对齐）：
    --time-based --time-budget 120 --format json

说明：本版本 CLI 的 JSON 报告参数名为 --report-format json；验收脚本直接通过
ScanEngine + SqlBlindTimePlugin 执行同一套时序判定，避免指纹/WAF/API 前缀等
预检请求抢占 120s 预算。报告为临时 JSON，脚本结束自动删除。

用法：
    Windows: .venv\\Scripts\\python.exe scripts\\acceptance_vuln_positive.py
    Linux:   .venv/bin/python scripts/acceptance_vuln_positive.py
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCAN_TIMEOUT = 120
LAB_START_WAIT = 3.0
LAB_READY_TIMEOUT = 10.0
TIMING_PLUGIN = "时间盲注（dept）"
CONFIRMED = "CONFIRMED"
# 统一参数：--time-based --time-budget 120 --format json（报告落盘为 JSON）
SCAN_PARAMS = {"time_based": True, "time_budget": 120.0, "format": "json"}

# lab/server.py 是签名靶场，dataScope 只返回 500 错误页，不模拟 sleep()。
# 该垫片只补齐「条件为真 → 睡 3 秒」这一条时序语义：命中漏洞端点仍由 lab 处理，
# 不改状态码、不改响应体、不改任何签名判定。
POSITIVE_SHIM_SOURCE = r"""import importlib.util
import os
import sys
import time

from flask import request

ROOT = os.environ["ACCEPTANCE_ROOT"]
server_path = os.path.join(ROOT, "lab", "server.py")
spec = importlib.util.spec_from_file_location("_acceptance_lab_server", server_path)
module = importlib.util.module_from_spec(spec)
sys.modules["_acceptance_lab_server"] = module
spec.loader.exec_module(module)

_original_dispatch = module.dispatch


def _dispatch_with_timing(path, method):
    if path == "/system/dept/list" and method == "POST":
        scope = (request.form.get("params[dataScope]") or "").lower()
        if "if(1=1" in scope and "sleep(3)" in scope:
            time.sleep(3.0)
    return _original_dispatch(path, method)


module.dispatch = _dispatch_with_timing
module.app.run(
    host="127.0.0.1",
    port=int(os.environ["LAB_PORT"]),
    debug=False,
    threaded=True,
    use_reloader=False,
)
"""

RUNNER_SOURCE = r"""import json
import os
import sys
import time

ROOT = os.environ["ACCEPTANCE_ROOT"]
sys.path.insert(0, ROOT)

from core.engine import ScanEngine  # noqa: E402
from core.session import SessionManager  # noqa: E402
from lib.auth_scan import apply_auth_to_session  # noqa: E402
from plugins.ruoyi.sql_blind_time import SqlBlindTimePlugin  # noqa: E402

target = sys.argv[1]
out_path = sys.argv[2]
time_budget = float(os.environ.get("ACCEPTANCE_TIME_BUDGET", "120"))

session = SessionManager(timeout=10, pool_size=2)
apply_auth_to_session(session, {"cookies": {"JSESSIONID": "acceptance"}, "headers": {}})
# 靶场不校验会话；显式置真，避免引擎把 requires_auth 插件的结论降级为 UNKNOWN。
session.authenticated = True
deadline = time.monotonic() + time_budget
session.deadline = deadline

results = []
ScanEngine(threads=1, deadline=deadline).run(
    [SqlBlindTimePlugin], target, session, on_result=results.append
)

with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"target": target, "results": [r.to_dict() for r in results]}, f, ensure_ascii=False, indent=2)
"""


def _force_utf8_stdio():
    """Windows 控制台默认 GBK，强制 UTF-8 避免 ✅/❌ 与中文日志编码失败。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _free_port():
    """让系统分配一个本地空闲端口，避免固定端口被占用。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _popen_kwargs():
    """跨平台子进程参数：Windows 隐藏窗口并建进程组，Linux 建独立会话便于整组回收。"""
    kwargs = {}
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True
    return kwargs


def _start_process(args, env, workdir, log_name):
    """启动子进程，stdout/stderr 落到临时日志，返回 (进程, 日志句柄, 日志路径)。"""
    log_path = workdir / log_name
    log_file = open(log_path, "wb")
    try:
        proc = subprocess.Popen(
            args,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            **_popen_kwargs(),
        )
    except Exception:
        log_file.close()
        raise
    return proc, log_file, log_path


def _wait_ready(url, proc, timeout=LAB_READY_TIMEOUT):
    """轮询靶场就绪；进程提前退出时立即返回失败原因。"""
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False, "靶场进程提前退出（exit=%s）" % proc.returncode
        try:
            with urllib.request.urlopen(url, timeout=1.5) as resp:
                if 200 <= resp.status < 500:
                    return True, ""
        except urllib.error.HTTPError as exc:
            if 200 <= exc.code < 500:
                return True, ""
            last_error = "HTTP %s" % exc.code
        except Exception as exc:  # noqa: BLE001 - 启动阶段任何网络异常都视为未就绪
            last_error = "%s: %s" % (type(exc).__name__, exc)
        time.sleep(0.2)
    return False, last_error or "等待超时"


def _tail(path, limit=20):
    """读取临时日志尾部，失败时帮助定位根因。"""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    return "\n".join(lines[-limit:])


def _kill_process(proc):
    """强制回收进程树：Windows 用 taskkill /F /T，Linux 用 SIGTERM -> SIGKILL。"""
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
    except Exception:
        pass
    finally:
        if proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass


def _run_scan(target, workdir):
    """执行只含时序插件的扫描，返回 (results, stdout, stderr, timed_out, report_path)。"""
    runner_path = workdir / "timing_runner.py"
    runner_path.write_text(RUNNER_SOURCE, encoding="utf-8")
    report_path = workdir / "report.json"
    env = os.environ.copy()
    env.update(
        {
            "ACCEPTANCE_ROOT": str(PROJECT_ROOT),
            "ACCEPTANCE_TIME_BUDGET": str(SCAN_PARAMS["time_budget"]),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
        }
    )
    proc = subprocess.Popen(
        [sys.executable, str(runner_path), target, str(report_path)],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        **_popen_kwargs(),
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process(proc)
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except Exception:
            stdout, stderr = "", ""

    results = None
    if not timed_out and report_path.is_file():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            raw_results = data.get("results", [])
            if isinstance(raw_results, list):
                results = [item for item in raw_results if isinstance(item, dict)]
        except (OSError, ValueError) as exc:
            stderr = (stderr or "") + "\n报告解析失败: %s" % exc
    return results, stdout or "", stderr or "", timed_out, report_path


def _print_timing_result(results):
    """打印时序插件结论；正样本失败时必须能直接看到是 SAFE 还是 UNKNOWN。"""
    timing = [r for r in results if r.get("name") == TIMING_PLUGIN or "时间盲注" in str(r.get("name", ""))]
    if not timing:
        print("    [!] 未找到时间盲注插件结果")
        return
    for item in timing:
        print("    [时序插件] 状态=%s" % item.get("status", ""))
        evidence = item.get("evidence", "")
        if evidence:
            print("    [时序插件] 证据=%s" % evidence)


def _print_confirmed(results):
    """打印所有 CONFIRMED 详情，失败时一眼看出漏报/误报对象。"""
    confirmed = [r for r in results if r.get("status") == CONFIRMED]
    print("    CONFIRMED 数量=%d" % len(confirmed))
    for item in confirmed:
        print("      - %s | %s | severity=%s" % (item.get("name", ""), item.get("url", ""), item.get("severity", "")))
        evidence = item.get("evidence", "")
        if evidence:
            print("        evidence: %s" % evidence)
    return confirmed


def main():
    """启动 lab vuln 靶场 + 时序垫片，跑时序插件，按至少 1 CONFIRMED 门禁返回退出码。"""
    _force_utf8_stdio()
    print("=" * 78)
    print("时序盲注验收：漏洞正样本（dept 时序注入）")
    print("判定规则：至少 1 条 CONFIRMED 通过；0 条 CONFIRMED = 失败（漏报）")
    print("统一参数：--time-based --time-budget 120 --format json")
    print("=" * 78)

    workdir = Path(tempfile.mkdtemp(prefix="ruoyi_accept_positive_"))
    lab_proc = None
    lab_log = None
    try:
        shim_path = workdir / "lab_timing_shim.py"
        shim_path.write_text(POSITIVE_SHIM_SOURCE, encoding="utf-8")

        port = _free_port()
        base = "http://127.0.0.1:%d" % port
        env = os.environ.copy()
        env.update(
            {
                "ACCEPTANCE_ROOT": str(PROJECT_ROOT),
                "LAB_MODE": "vuln",
                "LAB_PORT": str(port),
                "LAB_HOST": "127.0.0.1",
                "PYTHONIOENCODING": "utf-8",
                "PYTHONUTF8": "1",
            }
        )
        print("[*] 启动 lab/server.py（vuln）+ 时序垫片: %s" % base)
        lab_proc, lab_log, lab_log_path = _start_process(
            [sys.executable, str(shim_path)],
            env,
            workdir,
            "lab.log",
        )
        time.sleep(LAB_START_WAIT)
        ready, reason = _wait_ready(base + "/", lab_proc)
        if not ready:
            print("❌ 失败：正样本靶场未就绪：%s" % reason)
            tail = _tail(lab_log_path)
            if tail:
                print("---- 靶场日志 ----")
                print(tail)
            return 2
        print("✅ 靶场已就绪（vuln：if(1=1,sleep(3),0) 将延迟 3s）")

        results, stdout, stderr, timed_out, report_path = _run_scan(base, workdir)
        if timed_out:
            print("❌ 失败：扫描超时（>%ss），已强制回收扫描进程" % SCAN_TIMEOUT)
            return 1
        if results is None:
            print("❌ 失败：扫描未生成可用 JSON 报告")
            if stderr.strip():
                print("---- 扫描错误 ----")
                print(stderr.strip())
            return 2

        if stdout.strip():
            print("---- 扫描输出 ----")
            print(stdout.strip())
        print("[*] 临时报告：%s（脚本结束自动删除）" % report_path)
        print("[*] 结果条数=%d" % len(results))
        _print_timing_result(results)
        confirmed = _print_confirmed(results)

        timing_confirmed = [
            r for r in confirmed if r.get("name") == TIMING_PLUGIN or "时间盲注" in str(r.get("name", ""))
        ]
        if not timing_confirmed:
            print("❌ 失败：正样本 0 条时序盲注 CONFIRMED（漏报，时序盲注检测失效）")
            return 1
        print("✅ 通过：正样本检出 %d 条时序盲注 CONFIRMED" % len(timing_confirmed))
        return 0
    except Exception as exc:  # noqa: BLE001 - 验收脚本需要把环境异常转成明确失败
        print("❌ 执行异常：%s: %s" % (type(exc).__name__, exc))
        return 2
    finally:
        _kill_process(lab_proc)
        if lab_log is not None:
            try:
                lab_log.close()
            except Exception:
                pass
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
