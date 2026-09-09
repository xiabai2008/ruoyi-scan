# G3 AI 闭环 v2：生成即验证（签名靶场三态验证流水线）
#
# 定位（ROADMAP G3）：AI 生成的 POC 必须先在签名靶场跑出预期三态才允许入库。
# 多数「AI 生成 POC」项目止步于语法检查；本项目 lab 体系天然是验证器——
# vuln 模式必须 CONFIRMED（命中签名）、safe 模式绝不 CONFIRMED（误报红线）。
#
# 验证语义（三态纪律在 AI 环节的延伸）：
#   pass        vuln 模式 CONFIRMED 且 safe 模式非 CONFIRMED —— 允许入库
#   fail        safe 模式误报 CONFIRMED（红线）—— 拒绝入库
#   unverified  vuln 模式未命中（签名靶场未覆盖该漏洞签名）—— 隔离目录待人工复核
#
# 入库纪律：
#   pass       → plugins/{category}/（正式目录）
#   unverified → plugins/_quarantine/（隔离目录，loader 跳过 _ 前缀目录，人工确认后移入）
#   fail       → 不落盘插件，仅输出验证报告
#
# 用法：
#   python main.py --ai "检测若依任意文件读取" --ai-validate
#   python main.py --ai-validate plugins/ruoyi/xxx.py   # 对已有插件独立验证
import importlib.util
import os
import sys
from typing import Any, Dict, List, Optional

from common.logger import get_logger

logger = get_logger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_UNVERIFIED = "unverified"


class _LabHandle:
    """进程内签名靶场句柄（vuln/safe 分时切换，MODE 为 lab.server 模块全局量）"""

    def __init__(self, port: int):
        from werkzeug.serving import make_server

        import lab.server as lab_mod

        self._lab = lab_mod
        self.server = make_server("127.0.0.1", port, lab_mod.app, threaded=True)
        # port=0 时由系统分配随机端口，必须从 socket 取回实际端口
        self.port = self.server.socket.getsockname()[1]
        import threading

        self._t = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._t.start()
        self._wait_healthy()

    def _wait_healthy(self, timeout: float = 5.0) -> bool:
        import time as _time
        import urllib.request

        deadline = _time.time() + timeout
        while _time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=2) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                _time.sleep(0.1)
        return False

    def set_mode(self, mode: str) -> None:
        self._lab.MODE = mode

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def load_plugin_classes(filepath: str) -> List[type]:
    """动态加载插件文件中的 PluginBase 子类（AI 生成插件的落盘前验证）"""
    from plugins.base import PluginBase

    mod_name = "ai_generated_" + os.path.splitext(os.path.basename(filepath))[0]
    spec = importlib.util.spec_from_file_location(mod_name, filepath)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载插件文件: {filepath}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)

    classes = []
    for attr in dir(module):
        obj = getattr(module, attr)
        if (
            isinstance(obj, type)
            and issubclass(obj, PluginBase)
            and obj is not PluginBase
            and obj.__module__ == mod_name
        ):
            classes.append(obj)
    return classes


def _run_plugin_on_lab(plugin_cls: type, target: str) -> Optional[Any]:
    """在当前 lab 模式下执行插件 verify；返回 ScanResult（异常返回 None）"""
    from core.session import SessionManager

    try:
        inst = plugin_cls()
        session = SessionManager(timeout=5)
        return inst.verify(target, session)
    except Exception as e:
        logger.debug("插件在靶场执行异常: %s", e, exc_info=True)
        return None


def validate_ai_plugin(filepath: str, port: int = 0) -> Dict[str, Any]:
    """对 AI 生成插件执行签名靶场三态验证

    Args:
        filepath: 插件 .py 文件路径
        port: lab 端口（0=自动选择）

    Returns:
        {
            'verdict': 'pass' | 'fail' | 'unverified',
            'plugin': 插件名,
            'vuln_status': vuln 模式判定（CONFIRMED/SAFE/UNKNOWN/ERROR）,
            'safe_status': safe 模式判定,
            'reasons': [结论说明],
        }
    """
    from common.models import STATUS_CONFIRMED

    classes = load_plugin_classes(filepath)
    if not classes:
        return {
            "verdict": VERDICT_UNVERIFIED,
            "plugin": os.path.basename(filepath),
            "vuln_status": "ERROR",
            "safe_status": "ERROR",
            "reasons": ["文件中未发现 PluginBase 子类"],
        }
    plugin_cls = classes[0]

    lab = _LabHandle(port=port)
    reasons: List[str] = []
    try:
        # 1. vuln 模式：期望 CONFIRMED（存在性验证命中签名）
        lab.set_mode("vuln")
        vuln_res = _run_plugin_on_lab(plugin_cls, f"http://127.0.0.1:{lab.port}/")
        vuln_status = getattr(vuln_res, "status", "ERROR")
        # 2. safe 模式：绝不 CONFIRMED（误报红线）
        lab.set_mode("safe")
        safe_res = _run_plugin_on_lab(plugin_cls, f"http://127.0.0.1:{lab.port}/")
        safe_status = getattr(safe_res, "status", "ERROR")
    finally:
        lab.close()

    if vuln_status == STATUS_CONFIRMED and safe_status != STATUS_CONFIRMED:
        verdict = VERDICT_PASS
        reasons.append(f"vuln 模式 CONFIRMED、safe 模式 {safe_status}：签名靶场三态验证通过")
    elif safe_status == STATUS_CONFIRMED:
        verdict = VERDICT_FAIL
        reasons.append("红线：safe 模式（已修复靶场）误报 CONFIRMED——拒绝入库")
    else:
        verdict = VERDICT_UNVERIFIED
        reasons.append(f"vuln 模式判定 {vuln_status}（签名靶场未覆盖该漏洞签名）——转入隔离目录，需人工复核")

    return {
        "verdict": verdict,
        "plugin": getattr(plugin_cls, "name", plugin_cls.__name__),
        "vuln_status": vuln_status,
        "safe_status": safe_status,
        "reasons": reasons,
    }


def decide_install_path(filepath: str, category: str, verdict: str) -> Optional[str]:
    """按验证结论决定插件落盘位置（入库纪律）

    Returns:
        目标路径；fail（误报红线）返回 None（不落盘）
    """
    from lib.plugin_sdk import _to_filename

    filename = _to_filename(os.path.splitext(os.path.basename(filepath))[0]) + ".py"
    if verdict == VERDICT_PASS:
        return os.path.join(PROJECT_ROOT, "plugins", category, filename)
    if verdict == VERDICT_UNVERIFIED:
        return os.path.join(PROJECT_ROOT, "plugins", "_quarantine", filename)
    return None  # fail：不落盘


def run_ai_validate_mode(args) -> int:
    """--ai-validate <plugin.py> 模式入口：对已有插件独立验证"""
    from lib.colors import GREEN, RED, RESET, YELLOW

    filepath = args.ai_validate
    if not os.path.isfile(filepath):
        print(f"{RED}[!]插件文件不存在: {filepath}{RESET}")
        return 1
    print(f"{YELLOW}[*]签名靶场三态验证中: {filepath}{RESET}")
    report = validate_ai_plugin(filepath)
    print(f"[*]插件: {report['plugin']}")
    print(f"[*]vuln 模式判定: {report['vuln_status']} / safe 模式判定: {report['safe_status']}")
    for r in report["reasons"]:
        print(f"    - {r}")
    if report["verdict"] == VERDICT_PASS:
        print(f"{GREEN}[✓]验证通过（pass）{RESET}")
        return 0
    if report["verdict"] == VERDICT_FAIL:
        print(f"{RED}[✗]验证失败（fail）——误报红线，拒绝入库{RESET}")
        return 1
    print(f"{YELLOW}[?]未能验证（unverified）——建议人工复核{RESET}")
    return 2


def validate_generated_source(name: str, category: str, source: str, max_retries: int = 3) -> Dict[str, Any]:
    """生成即验证闭环：把 LLM 源码写入临时文件 → 靶场三态验证 → 返回结论与目标路径

    供 run_ai_generate_mode 接入：pass 落正式目录 / unverified 落隔离目录 / fail 不落盘。
    """
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="ai_plugin_validate_")
    from lib.plugin_sdk import _to_filename

    tmp_path = os.path.join(tmpdir, _to_filename(name) + ".py")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(source)

    report = validate_ai_plugin(tmp_path)
    report["generated"] = True
    target_path = decide_install_path(tmp_path, category, report["verdict"])
    report["install_path"] = target_path

    if target_path:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(source)
    return report
