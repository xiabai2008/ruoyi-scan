#!/usr/bin/env python
# D5 误报率测试：启动 10 个非若依靶场，扫描并断言假阳率 <5%
#
# 运行：python scripts/run_fp_test.py
#
# 判定逻辑：
#   - 指纹识别误判为 ruoyi → 假阳（False Positive）
#   - 即使误判为 ruoyi，POC CONFIRMED → 严重假阳
#   - 假阳率 = 假阳靶场数 / 总靶场数
#   - 目标：假阳率 <5%（10 个靶场最多 0 个假阳）
import os
import subprocess
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.logger import get_logger  # noqa: E402
from common.models import STATUS_CONFIRMED  # noqa: E402
from core.fingerprint import detect_cms  # noqa: E402
from core.router import Router  # noqa: E402
from core.session import SessionManager  # noqa: E402
from lab.fp_lab.server import TARGETS  # noqa: E402

logger = get_logger(__name__)


def start_lab(target_id, port):
    """启动一个误报靶场实例"""
    env = os.environ.copy()
    env["FP_TARGET"] = target_id
    env["FP_PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=os.path.join(PROJECT_ROOT, "lab", "fp_lab"),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def wait_port(port, timeout=10):
    """等待端口可达"""
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(("127.0.0.1", port))
            s.close()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def scan_target(target_url):
    """扫描单个目标，返回 (cms, version, confidence, confirmed_count)"""
    session = SessionManager(timeout=5)
    # 指纹识别
    fp_result = detect_cms(target_url, session)
    cms = fp_result.cms
    version = fp_result.version
    confidence = fp_result.confidence

    # 如果误判为 ruoyi，跑 POC 看是否 CONFIRMED
    confirmed_count = 0
    if cms == "ruoyi":
        plugins = Router().resolve(fp_result)
        for cls in plugins:
            try:
                plugin = cls()
                result = plugin.verify(target_url, SessionManager(timeout=5))
                if result.status == STATUS_CONFIRMED:
                    confirmed_count += 1
            except Exception:
                logger.debug("插件执行异常", exc_info=True)
    return cms, version, confidence, confirmed_count


def main():
    print("=" * 70)
    print("D5 误报率测试：10 个非若依靶场")
    print("=" * 70)

    # 启动 10 个靶场（端口 8501-8510）
    procs = []
    port_base = 8501
    targets = list(TARGETS.items())
    for i, (target_id, desc) in enumerate(targets):
        port = port_base + i
        proc = start_lab(target_id, port)
        procs.append(proc)
        if not wait_port(port, timeout=10):
            print(f"[!] 启动失败: {target_id} port={port}")
        else:
            print(f"[+] 启动: {target_id:<22} port={port}  ({desc})")

    print()
    print("-" * 70)
    print(f"{'靶场':<22} {'指纹':<12} {'置信度':<8} {'CONFIRMED':<10} {'判定':<10}")
    print("-" * 70)

    false_positives = 0
    results = []
    for i, (target_id, desc) in enumerate(targets):
        port = port_base + i
        target_url = f"http://127.0.0.1:{port}/"
        try:
            cms, version, confidence, confirmed = scan_target(target_url)
        except Exception as e:
            cms, confidence, confirmed = "error", 0.0, 0
            print(f"[!] 扫描异常 {target_id}: {e}")

        is_fp = cms == "ruoyi"
        if is_fp:
            false_positives += 1
        verdict = "假阳" if is_fp else "正确"
        results.append((target_id, desc, cms, confidence, confirmed, is_fp))
        print(f"{target_id:<22} {cms:<12} {confidence:<8.2f} {confirmed:<10} {verdict:<10}")

    # 清理靶场进程
    for proc in procs:
        proc.terminate()
    for proc in procs:
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

    print("-" * 70)
    total = len(targets)
    fp_rate = false_positives / total * 100
    print(f"总计: {total} 个靶场，假阳 {false_positives} 个，假阳率 {fp_rate:.1f}%")
    print(f"目标: 假阳率 <5%（≤{int(total * 0.05)} 个假阳）")
    if fp_rate < 5:
        print("结果: PASS ✅")
        return 0
    else:
        print("结果: FAIL ❌")
        return 1


if __name__ == "__main__":
    sys.exit(main())
