# 真实用户场景审计：把「陌生人 / 安服 / CI / 平台」的用法脚本化跑一遍，采集体验指标
#
# 设计目标：不是断言"功能对不对"，而是量化"用起来顺不顺"——
#   - 首次运行的挫败点（报错是否可读、输出是否刷屏、报告是否完整）
#   - 批量交付链路（多目标、不可达目标、汇总报告、整改复测）
#   - CI 接入（退出码、SARIF 有效性）
#   - 异常输入（无 scheme / 重定向环 / 401 / gzip / 超长 URL）
#   - 误报压力（11 个非若依站点必须零 CONFIRMED）
#   - 平台化（Web API 提交任务 → 轮询 → 下载报告）
#
# 用法：
#   python scripts/scenario_audit.py                 # 全跑
#   python scripts/scenario_audit.py --only s1,s3    # 只跑指定场景
#   python scripts/scenario_audit.py --json out.json --md out.md
import argparse
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
REPORT_DIR = Path(tempfile.mkdtemp(prefix="ruoyi-audit-"))
HOME_OVERRIDE = str(Path(tempfile.mkdtemp(prefix="ruoyi-home-")))


# ── 基础设施 ──────────────────────────────────────────────


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, timeout: float = 20.0) -> bool:
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except urllib.error.HTTPError:
            return True  # 有响应即可（403/404 也算存活）
        except Exception:
            time.sleep(0.3)
    return False


def start_lab(mode: str = "vuln", port: Optional[int] = None) -> Tuple[subprocess.Popen, str]:
    port = port or free_port()
    env = dict(os.environ, LAB_MODE=mode, LAB_PORT=str(port), PYTHONIOENCODING="utf-8")
    proc = subprocess.Popen(
        [PY, str(ROOT / "lab" / "server.py")],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    if not wait_http(url + "/", 25):
        proc.terminate()
        raise RuntimeError(f"靶场未就绪: {url}")
    return proc, url


def run_cli(args: List[str], timeout: int = 180) -> Dict[str, Any]:
    """跑一次 CLI，返回 rc / 输出 / 耗时 / 是否含 traceback。"""
    env = dict(os.environ)
    env.update({"PYTHONIOENCODING": "utf-8", "HOME": HOME_OVERRIDE, "USERPROFILE": HOME_OVERRIDE, "CI": ""})
    t0 = time.time()
    proc = subprocess.run(
        [PY, str(ROOT / "main.py")] + args,
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    out, err = proc.stdout or "", proc.stderr or ""
    return {
        "rc": proc.returncode,
        "dur": round(time.time() - t0, 2),
        "out": out,
        "err": err,
        "lines": len([line for line in out.splitlines() if line.strip()]),
        "traceback": "Traceback (most recent call last)" in (out + err),
    }


def verdicts(report_json: Path) -> Dict[str, int]:
    if not report_json.exists():
        return {}
    data = json.loads(report_json.read_text(encoding="utf-8"))
    counts: Dict[str, int] = {}
    for r in data.get("results", []):
        counts[r.get("status", "?")] = counts.get(r.get("status", "?"), 0) + 1
    return counts


class StubHandler(http.server.BaseHTTPRequestHandler):
    """异常目标桩：403 / 重定向环 / gzip / 401（用于检验扫描器的异常输入处理）。"""

    def log_message(self, *a):  # 静音
        pass

    def do_GET(self):
        if self.path.startswith("/403"):
            self.send_response(403)
            self.end_headers()
        elif self.path.startswith("/loop"):
            self.send_response(302)
            self.send_header("Location", "/loop2")
            self.end_headers()
        elif self.path.startswith("/loop2"):
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        elif self.path.startswith("/401"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="x"')
            self.end_headers()
        else:
            body = b"<html><title>stub</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def start_stub() -> Tuple[http.server.ThreadingHTTPServer, str]:
    port = free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), StubHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{port}"


# ── 场景 ──────────────────────────────────────────────────


def s1_first_run() -> Dict[str, Any]:
    """首装首跑：版本号、漏洞扫描、报告完整性、输出噪声。"""
    notes: List[str] = []
    ver = run_cli(["--version"], timeout=60)
    if ver["rc"] != 0 or "ruoyi-scan" not in ver["out"]:
        notes.append(f"--version 异常: rc={ver['rc']}")

    lab, url = start_lab("vuln")
    try:
        rep = REPORT_DIR / "s1"
        scan = run_cli(["-p", url + "/", "--report", str(rep), "--report-format", "html,json"])
        counts = verdicts(rep / "report.json")
        data = json.loads((rep / "report.json").read_text(encoding="utf-8")) if (rep / "report.json").exists() else {}
        missing_evidence = [
            r["name"] for r in data.get("results", []) if r["status"] == "CONFIRMED" and not r.get("evidence")
        ]
        missing_fix = [
            r["name"] for r in data.get("results", []) if r["status"] == "CONFIRMED" and not r.get("fix_detail")
        ]
        if missing_evidence:
            notes.append(f"{len(missing_evidence)} 条 CONFIRMED 缺 evidence")
        if missing_fix:
            notes.append(f"{len(missing_fix)} 条 CONFIRMED 缺 fix_detail")
        if scan["traceback"]:
            notes.append("首跑出现 traceback")
        # 阈值对齐 README/审计文档里的承诺：首跑 stdout 应 <= 60 行
        if scan["lines"] > 60:
            notes.append(f"-p 输出 {scan['lines']} 行（噪声偏高）")

        # 综合扫描的噪声量（真实用户最常用的 -u）
        u = run_cli(["-u", url + "/", "--no-cta"])
        noisy = u["lines"]
        if noisy > 200:
            notes.append(f"-u 输出 {noisy} 行，其中目录扫描明细刷屏")

        return {
            "ok": scan["rc"] == 0 and counts.get("CONFIRMED", 0) >= 15,
            "metrics": {
                "version_rc": ver["rc"],
                "scan_rc": scan["rc"],
                "scan_sec": scan["dur"],
                "scan_lines": scan["lines"],
                "u_lines": u["lines"],
                "request_count": data.get("request_count"),
                "verdicts": counts,
                "report_files": sorted(p.name for p in rep.glob("*")) if rep.exists() else [],
            },
            "notes": notes,
        }
    finally:
        lab.terminate()


def s2_batch_delivery() -> Dict[str, Any]:
    """安服交付：多目标批量（含不可达、403、重定向环）→ 汇总报告 + 整改复测。"""
    notes: List[str] = []
    lab_v, url_v = start_lab("vuln")
    lab_s, url_s = start_lab("safe")
    stub, url_stub = start_stub()
    try:
        targets = REPORT_DIR / "targets.txt"
        dead = f"http://127.0.0.1:{free_port()}/"
        targets.write_text(
            "\n".join([url_v + "/", url_s + "/", dead, url_stub + "/403", url_stub + "/loop"]) + "\n", encoding="utf-8"
        )
        rep = REPORT_DIR / "s2"
        batch = run_cli(["-f", str(targets), "-p", "--report", str(rep), "--report-format", "html,json"], timeout=420)

        # 整改复测：vuln 存基线 → safe 复测
        # 注意：--save-baseline 无路径参数，基线固定落在 --report 目录下的 baseline.json
        base = REPORT_DIR / "s2base" / "baseline.json"
        run_cli(["-p", url_v + "/", "--save-baseline", "--report", str(REPORT_DIR / "s2base")], timeout=240)
        remed = run_cli(
            ["-p", url_s + "/", "--remediation", str(base), "--report", str(REPORT_DIR / "s2remed")], timeout=240
        )
        if not base.exists():
            notes.append("--save-baseline 未产出基线文件")
        if remed["rc"] != 0:
            notes.append(f"整改复测退出码 {remed['rc']}")

        files = sorted(p.name for p in rep.glob("*")) if rep.exists() else []
        if not any(f.startswith("batch") or "summary" in f for f in files):
            notes.append(f"批量未产出汇总报告，实际文件: {files[:4]}")
        if "跳过" not in batch["out"]:
            notes.append("不可达目标未在输出中明确列出")
        return {
            "ok": batch["rc"] == 0 and bool(files),
            "metrics": {
                "batch_rc": batch["rc"],
                "batch_sec": batch["dur"],
                "batch_lines": batch["lines"],
                "report_files": len(files),
                "remediation_rc": remed["rc"],
                "remediation_lines": remed["lines"],
            },
            "notes": notes,
        }
    finally:
        for p in (lab_v, lab_s):
            p.terminate()
        stub.shutdown()


def s3_ci_sarif() -> Dict[str, Any]:
    """CI 接入：--ci 退出码 + SARIF 结构有效性。"""
    notes: List[str] = []
    lab, url = start_lab("vuln")
    try:
        rep = REPORT_DIR / "s3"
        r = run_cli(
            ["-p", url + "/", "--report", str(rep), "--report-format", "sarif", "--ci", "--severity-threshold", "high"]
        )
        sarif = rep / "report.sarif"
        problems = []
        if not sarif.exists():
            problems.append("未生成 SARIF")
        else:
            try:
                doc = json.loads(sarif.read_text(encoding="utf-8"))
                if doc.get("version") != "2.1.0":
                    problems.append(f"SARIF version={doc.get('version')}")
                if not doc.get("runs"):
                    problems.append("SARIF runs 为空")
                else:
                    results = doc["runs"][0].get("results", [])
                    if not results:
                        problems.append("SARIF results 为空（有 CONFIRMED 却无告警）")
                    if not doc["runs"][0].get("tool", {}).get("driver", {}).get("rules"):
                        problems.append("SARIF 缺 rules（GitHub Code Scanning 会拒收）")
            except Exception as e:  # noqa: BLE001
                problems.append(f"SARIF 解析失败: {e}")
        if r["rc"] == 0:
            problems.append("有高危漏洞时 --ci 退出码为 0（流水线不会失败）")
        notes.extend(problems)
        return {
            "ok": r["rc"] != 0 and not problems,
            "metrics": {"ci_rc": r["rc"], "sec": r["dur"], "sarif_exists": sarif.exists()},
            "notes": notes,
        }
    finally:
        lab.terminate()


def s4_weird_inputs() -> Dict[str, Any]:
    """异常输入：无 scheme、超长 URL、401、重定向环、403。要求不崩、不误判、报错可读。"""
    notes: List[str] = []
    stub, url_stub = start_stub()
    cases = {
        "no_scheme": "127.0.0.1:9",
        "long_url": "http://127.0.0.1:9/" + "a" * 3000,
        "redirect_loop": url_stub + "/loop",
        "unauth_401": url_stub + "/401",
        "forbidden": url_stub + "/403",
    }
    results = {}
    try:
        for name, target in cases.items():
            r = run_cli(["-p", target, "--no-cta"], timeout=120)
            results[name] = {"rc": r["rc"], "lines": r["lines"], "traceback": r["traceback"]}
            if r["traceback"]:
                notes.append(f"{name}: 出现 traceback（应给出可读错误）")
            # 3 = EXIT_UNREACHABLE（cli/preflight.py）：目标不可达属预期语义，
            # 与 2（参数/语法错误）一样是可判读的失败，不应算场景失败。
            if r["rc"] not in (0, 2, 3):
                notes.append(f"{name}: 非预期退出码 {r['rc']}")
        # 403（WAF 拦截）绝不能判 SAFE
        rep = REPORT_DIR / "s4"
        r403 = run_cli(["-p", url_stub + "/403", "--report", str(rep), "--report-format", "json", "--no-cta"])
        counts = verdicts(rep / "report.json")
        if counts.get("SAFE", 0) > 0 and "CONFIRMED" not in counts:
            notes.append(f"全站 403 时出现 {counts['SAFE']} 条 SAFE（WAF 拦截不得判 SAFE）")
        return {
            "ok": not notes,
            "metrics": {"cases": results, "403_verdicts": counts, "403_rc": r403["rc"]},
            "notes": notes,
        }
    finally:
        stub.shutdown()


def s5_fp_sweep() -> Dict[str, Any]:
    """误报压力：fp_lab 的 11 个非若依站点，断言零 CONFIRMED。"""
    notes: List[str] = []
    sys.path.insert(0, str(ROOT / "lab" / "fp_lab"))
    from server import TARGETS  # type: ignore  # noqa: E402

    total_confirmed = 0
    per: Dict[str, int] = {}
    env_base = dict(os.environ, PYTHONIOENCODING="utf-8")
    for tid in TARGETS:
        port = free_port()
        env = dict(env_base, FP_TARGET=tid, FP_PORT=str(port))
        proc = subprocess.Popen(
            [PY, str(ROOT / "lab" / "fp_lab" / "server.py")],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            if not wait_http(f"http://127.0.0.1:{port}/", 15):
                notes.append(f"{tid}: 靶场未就绪")
                continue
            rep = REPORT_DIR / f"fp_{tid}"
            run_cli(["-p", f"http://127.0.0.1:{port}/", "--report", str(rep), "--report-format", "json", "--no-cta"])
            counts = verdicts(rep / "report.json")
            n = counts.get("CONFIRMED", 0)
            per[tid] = n
            total_confirmed += n
            if n:
                notes.append(f"{tid}: 误报 {n} 条 CONFIRMED")
        finally:
            proc.terminate()
    return {
        "ok": total_confirmed == 0,
        "metrics": {"confirmed_per_target": per, "total": total_confirmed},
        "notes": notes,
    }


def s6_api_flow() -> Dict[str, Any]:
    """平台化：--serve 起服务 → POST /api/scan → 轮询 → 取结果 → 下载报告。"""
    notes: List[str] = []
    lab, url = start_lab("vuln")
    try:
        import requests
    except ImportError:  # pragma: no cover
        lab.terminate()
        return {"ok": False, "metrics": {}, "notes": ["requests 未安装（serve 依赖）"]}

    port = free_port()
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    srv = subprocess.Popen(
        [PY, str(ROOT / "main.py"), "--serve", "--host", "127.0.0.1", "--port", str(port), "--api-key", "audit:admin"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    base = f"http://127.0.0.1:{port}"
    try:
        if not wait_http(base + "/api/system/health", 30):
            # 服务可能因缺少 uvicorn 直接退出——把 stderr 带回去
            time.sleep(1)
            err = ""
            if srv.poll() is not None:
                err = (srv.stderr.read() or "")[-600:]
            lab.terminate()
            return {"ok": False, "metrics": {}, "notes": [f"--serve 未起来: {err.strip()[:300]}"]}

        h = {"X-API-Key": "audit"}
        r = requests.post(f"{base}/api/scan", json={"target": url + "/", "mode": "p"}, headers=h, timeout=30)
        tid = (r.json() or {}).get("task_id") or (r.json() or {}).get("id")
        if not tid:
            notes.append(f"POST /api/scan 响应异常: {r.status_code} {r.text[:200]}")
        deadline = time.time() + 180
        status = ""
        while tid and time.time() < deadline:
            s = requests.get(f"{base}/api/scan/{tid}", headers=h, timeout=20).json()
            status = s.get("status", "")
            if status in ("completed", "failed", "success", "done"):
                break
            time.sleep(2)
        results = requests.get(f"{base}/api/scan/{tid}/results", headers=h, timeout=30) if tid else None
        # GET /api/scan/{id}/results 的契约是「结果数组」（response_model=list），
        # 不是 {"results": [...]}；两种形态都兼容，避免审计脚本自身崩掉。
        payload = results.json() if results is not None and results.ok else []
        if isinstance(payload, dict):
            payload = payload.get("results", [])
        n = len(payload or [])
        # 报告下载端点在 /api/report/{task_id}/<fmt>（api/routes/report.py），
        # 不是 /api/scan/{task_id}/report —— 后者会 404，让 s6 误报「报告下载失败」。
        rep = requests.get(f"{base}/api/report/{tid}/html", headers=h, timeout=60) if tid else None
        rep_ok = bool(rep is not None and rep.ok and len(rep.content) > 1000)
        if not n:
            notes.append("API 任务结果为空")
        if not rep_ok:
            notes.append("报告下载失败或过小")
        return {
            "ok": bool(tid) and n > 0 and rep_ok,
            "metrics": {"task_id": tid, "status": status, "results": n, "report_bytes": len(rep.content) if rep else 0},
            "notes": notes,
        }
    finally:
        try:
            srv.terminate()
        except Exception:  # noqa: BLE001
            pass
        lab.terminate()


SCENARIOS = {
    "s1": ("首装首跑", s1_first_run),
    "s2": ("批量交付 + 整改复测", s2_batch_delivery),
    "s3": ("CI + SARIF", s3_ci_sarif),
    "s4": ("异常输入", s4_weird_inputs),
    "s5": ("误报压力（11 非若依站点）", s5_fp_sweep),
    "s6": ("Web API 平台化", s6_api_flow),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="逗号分隔的场景 id，如 s1,s3")
    ap.add_argument("--json", default="", help="结果写 JSON")
    ap.add_argument("--md", default="", help="结果写 Markdown")
    args = ap.parse_args()

    ids = [x.strip() for x in args.only.split(",") if x.strip()] or list(SCENARIOS)
    results: Dict[str, Any] = {}
    for sid in ids:
        name, fn = SCENARIOS[sid]
        print(f"\n=== [{sid}] {name} ===")
        t0 = time.time()
        try:
            res = fn()
        except Exception as e:  # noqa: BLE001
            res = {"ok": False, "metrics": {}, "notes": [f"场景异常: {type(e).__name__}: {e}"]}
        res["name"] = name
        res["sec"] = round(time.time() - t0, 1)
        results[sid] = res
        print(f"{'PASS' if res['ok'] else 'FAIL'} ({res['sec']}s)")
        for n in res["notes"]:
            print(f"  - {n}")

    ok_n = sum(1 for r in results.values() if r["ok"])
    print(f"\n汇总: {ok_n}/{len(results)} 通过")

    if args.json:
        Path(args.json).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.md:
        lines = ["| 场景 | 结果 | 耗时 | 发现 |", "|---|---|---|---|"]
        for sid, r in results.items():
            notes = "；".join(r["notes"]) or "—"
            lines.append(f"| {sid} {r['name']} | {'PASS' if r['ok'] else 'FAIL'} | {r['sec']}s | {notes} |")
        Path(args.md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if ok_n == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
