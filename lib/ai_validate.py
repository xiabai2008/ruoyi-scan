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
import hashlib
import importlib.util
import os
import sys
import threading
from typing import Any, Dict, List, Optional

from common.logger import get_logger
from lib.reporter import emit

logger = get_logger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_UNVERIFIED = "unverified"

# MODE 是 lab.server 的进程级全局量，并发验证会互相翻转 vuln/safe 模式导致判定不可复现；
# 用模块级锁串行化「切换模式 + 执行插件」段（不改变 lab 本身的接口）
_LAB_MODE_LOCK = threading.Lock()


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
        if not self._wait_healthy():
            # 靶场未就绪：释放资源并显式失败，避免对未就绪靶场跑出伪三态判定
            self.close()
            raise RuntimeError("签名靶场未在超时时间内就绪（端口 %d）" % self.port)

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

    # 模块名取绝对路径哈希：不同目录的同名插件不再共享 sys.modules 键而互相覆盖
    digest = hashlib.md5(os.path.abspath(filepath).encode("utf-8")).hexdigest()[:12]
    mod_name = "ai_generated_" + digest
    spec = importlib.util.spec_from_file_location(mod_name, filepath)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载插件文件: {filepath}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        # 加载完即移出 sys.modules：避免反复验证累积模块，
        # 类对象仍持有模块全局字典引用，不影响后续实例化/执行
        sys.modules.pop(mod_name, None)

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

    session = None
    try:
        inst = plugin_cls()
        session = SessionManager(timeout=5)
        return inst.verify(target, session)
    except Exception as e:
        # 执行异常（插件自身 bug/导入失败/网络错误）不可与「未命中」混同：
        # 提升到 warning 暴露问题，调用方按 ERROR 状态转入 unverified 人工复核
        logger.warning("插件在靶场执行异常: %s", e, exc_info=True)
        return None
    finally:
        # 旧实现缺陷：成功/异常均不关闭 session，每次验证（vuln+safe 两模式）泄漏 2 个连接。
        # finally 保证任何路径都释放连接（参考 core/auth_chain.py 的正确写法）。
        if session is not None:
            session.close()


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

    try:
        lab = _LabHandle(port=port)
    except RuntimeError as e:
        # 靶场启动失败：不做三态判定，按 unverified 隔离处理并给出原因
        return {
            "verdict": VERDICT_UNVERIFIED,
            "plugin": getattr(plugin_cls, "name", plugin_cls.__name__),
            "vuln_status": "ERROR",
            "safe_status": "ERROR",
            "reasons": ["签名靶场启动失败: %s" % e],
        }

    reasons: List[str] = []
    try:
        # MODE 是 lab 模块全局量：并发验证会互相翻转模式，整段持锁保证三态结论可复现
        with _LAB_MODE_LOCK:
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
        emit(f"{RED}[!]插件文件不存在: {filepath}{RESET}")
        return 1
    emit(f"{YELLOW}[*]签名靶场三态验证中: {filepath}{RESET}")
    report = validate_ai_plugin(filepath)
    emit(f"[*]插件: {report['plugin']}")
    emit(f"[*]vuln 模式判定: {report['vuln_status']} / safe 模式判定: {report['safe_status']}")
    for r in report["reasons"]:
        emit(f"    - {r}")
    if report["verdict"] == VERDICT_PASS:
        emit(f"{GREEN}[✓]验证通过（pass）{RESET}")
        return 0
    if report["verdict"] == VERDICT_FAIL:
        emit(f"{RED}[✗]验证失败（fail）——误报红线，拒绝入库{RESET}")
        return 1
    emit(f"{YELLOW}[?]未能验证（unverified）——建议人工复核{RESET}")
    return 2


def validate_generated_source(name: str, category: str, source: str) -> Dict[str, Any]:
    """生成即验证闭环：把 LLM 源码写入临时文件 → 靶场三态验证 → 返回结论与目标路径

    供 run_ai_generate_mode 接入：pass 落正式目录 / unverified 落隔离目录 / fail 不落盘。
    """
    import tempfile

    from lib.plugin_sdk import _to_filename

    # TemporaryDirectory 上下文管理器保证任何 return/异常路径都清理临时目录
    with tempfile.TemporaryDirectory(prefix="ai_plugin_validate_") as tmpdir:
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
