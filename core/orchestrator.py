"""扫描编排：预检 → 侦察 → 指纹 → 能力 → 插件 → 报告。

层：编排层（core）｜上游：cli/api｜下游：engine/session/plugins
先读：docs/CONCEPTS.md#12-报告管线
"""

# D9.1 扫描编排器：从 main.py run_mode 抽取，CLI 与 API 共用
#
# 设计目标：
#   1. 封装 detect_cms → detect_waf → load_plugins → engine.run → report 全流程
#   2. 同步接口（CLI 用 run_sync）+ 异步接口（API 用 submit/_run）
#   3. 事件回调机制：on_event(event_type, payload)，CLI 打印彩色输出，API 推送 WS
#   4. CLI 行为零变化：run_mode 内部调用 orchestrator，传入打印回调
#
# 架构约束（红线）：
#   - core/engine.py 零修改（通过 on_result 回调）
#   - core/router.py 零修改
#   - common/models.py / plugins/base.py 零修改（新增能力走回调与组合）
#   - ThreadPoolExecutor 使用 daemon 线程（避免测试/进程退出时后台线程阻塞）
from __future__ import annotations

import threading
import time
import uuid
import weakref
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures.thread import _worker
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, FingerprintResult, ScanResult, UnknownReason
from config import settings
from core.engine import ScanEngine
from core.fingerprint import detect_cms, detect_waf
from core.fingerprint_cache import FingerprintCache
from core.http import normalize_scan_target, normalize_target, preflight
from core.loader import load_plugins
from core.report import ReportBuilder
from core.router import Router
from core.session import RequestCounter, SessionManager


class _DaemonThreadPoolExecutor(ThreadPoolExecutor):
    """daemon 线程池：线程标记为 daemon 且不注册到全局 _threads_queues。

    标准 ThreadPoolExecutor 的线程会注册到 concurrent.futures.thread._threads_queues，
    _python_exit atexit 处理器会 join 所有注册的线程——即使它们是 daemon。
    本子类跳过 _threads_queues 注册，使 daemon 线程在进程退出时被自动终止，
    避免 API 测试中后台扫描线程阻止 pytest 退出（CI 挂起根因）。
    """

    def _adjust_thread_count(self) -> None:
        """重写线程创建：daemon 线程且不注册 _threads_queues（规避 atexit join 挂起）"""
        if self._idle_semaphore.acquire(timeout=0):
            return

        # weakref 回调只绑定队列（同标准库写法），绝不能捕获 self：
        # 捕获 self 会让回调强引用 executor，weakref 失去意义——executor 无法被
        # 回收，唤醒 worker 的 None 哨兵永远不会投递（线程泄漏到进程退出）。
        def _weakref_cb(_: Any, q: Any = self._work_queue) -> None:
            q.put(None)

        num_threads = len(self._threads)
        if num_threads < self._max_workers:
            thread_name = "%s_%d" % (self._thread_name_prefix or self, num_threads)
            t = threading.Thread(
                name=thread_name,
                target=_worker,
                args=(
                    weakref.ref(self, _weakref_cb),
                    self._work_queue,
                    self._initializer,
                    self._initargs,
                ),
                daemon=True,
            )
            t.start()
            self._threads.add(t)  # type: ignore[attr-defined]
            # 不注册到 _threads_queues，避免 _python_exit atexit handler join daemon 线程


logger = get_logger(__name__)


# 弱证据判定阈值：置信度不超过这个值时，认为「cms 只是猜的」，不该排他加载插件包。
#
# 背景（2026-11-01 盲测 v2 发现）：`spring` 的 root_json_keys 特征
# （根路径返回 {"timestamp","status","error","path"}）被算作**强特征**，
# 单独命中就给 0.5 置信度。但「返回 Spring Boot 默认错误 JSON」只说明这是个
# Spring 应用 —— 它完全可能同时也是若依/Jeecg。
#
# 后果实测（C4-4 / C4-5）：
#   GET / → {"timestamp","status","error","path"}  → cms=spring (0.5)
#   → 只加载 plugins.spring（26 个插件）
#   → plugins.jeecgboot / plugins.ruoyi **整包不加载**
#   → freemarker_ssti / ruoyi_gen_rce 根本没被调用 → 0 CONFIRMED
# 而靶场真的存在 SSTI（手工验证 ${7*7} → 49）。
#
# 一个错误的指纹判定屏蔽掉整个插件包的漏洞面，比单个插件判定不准严重得多。
_WEAK_FINGERPRINT_CONFIDENCE = 0.5

# 弱证据时额外补加载的包：凡是「Spring 生态上的应用」都该一起跑。
# 顺序即优先级，去重按类对象。
_EXPANDED_PACKAGES = ("plugins.ruoyi", "plugins.spring", "plugins.jeecgboot")


def _load_plugins_from(packages: tuple[str, ...] | list[str]) -> Tuple[List[type], List[Dict[str, Any]]]:
    """从给定包列表加载插件，按类对象去重。

    Args:
        packages: 包名列表（如 "plugins.ruoyi"）
    Returns:
        (插件类列表, 每个包的加载明细)；明细含 package/count，失败时含 error。
    """
    plugins: List[type] = []
    loaded: List[Dict[str, Any]] = []
    seen: set[type] = set()
    for package in packages:
        try:
            bundle = load_plugins(package)
        except Exception as e:
            logger.warning("插件包 %s 加载失败：%s", package, e, exc_info=True)
            loaded.append({"package": package, "count": 0, "error": str(e)})
            continue
        added = 0
        for cls in bundle:
            if cls in seen:
                continue
            seen.add(cls)
            plugins.append(cls)
            added += 1
        loaded.append({"package": package, "count": added})
    return plugins, loaded


def _load_fallback_plugins() -> Tuple[List[type], List[Dict[str, Any]]]:
    """cms 未识别时的回退插件包：ruoyi + spring，按类对象去重。

    F7-1：旧实现只加载 plugins.ruoyi。C2-2（Spring4Shell）cms 为空，
    报告里没有任何 Spring 插件结果——真实 Spring MVC 站点没有 /actuator
    强特征时永远轮不到 plugins.spring。这里补回退覆盖面，但不猜 CMS：
    两个包都加载，让插件自己给出 SAFE/UNKNOWN/CONFIRMED。

    plugins.spring 加载失败只 warning，不影响 ruoyi；去重避免同一个类
    被两个包同时导出时重复执行。

    Returns:
        (插件类列表, 每个包的加载明细)；明细含 package/count，失败时含 error。
    """
    return _load_plugins_from(("plugins.ruoyi", "plugins.spring"))


def _is_weak_fingerprint(fp_result: Any) -> bool:
    """判断指纹结论是否只是「弱证据猜出来的」，此时不该排他。

    条件：cms 非空，但置信度不超过阈值（只有弱特征命中，没有真正的标志性证据）。
    cms 为空的情况已由 _load_fallback_plugins 覆盖，不在此列。
    """
    cms = getattr(fp_result, "cms", "") or ""
    if not cms:
        return False
    try:
        conf = float(getattr(fp_result, "confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return False
    return conf <= _WEAK_FINGERPRINT_CONFIDENCE


def downgrade_auth_required_results(results: List[ScanResult], auth_status: str, auth_required_names: set[str]) -> int:
    """把「需高权会话」插件的 CONFIRMED/SAFE 统一降级为 UNKNOWN（单一入口）。

    为什么需要：auth_status != ok 时，这些插件看到的只是登录墙/401，既不能证明
    漏洞存在，也不能证明不存在。把 SAFE 留在报告里等于宣称「已确认安全」，是
    比漏报更危险的假安全感。低权对照插件不在此列（它们自己解析显式
    --surface-account，缺凭证时已返回 UNKNOWN）。

    Args:
        results: 待处理的结果列表（原地修改）
        auth_status: ok / failed / not_attempted
        auth_required_names: 标记了 requires_auth=True 的插件名集合

    Returns:
        被降级的条数
    """
    if auth_status == "ok" or not auth_required_names:
        return 0
    count = 0
    for r in results:
        if r.name in auth_required_names and r.status in (STATUS_CONFIRMED, STATUS_SAFE):
            r.evidence = (
                f"未取得高权会话（auth_status={auth_status}），需登录的结论降级为 UNKNOWN。原证据：{r.evidence}"
            )
            r.status = STATUS_UNKNOWN
            r.unknown_reason = UnknownReason.NO_SESSION.value
            count += 1
    return count


# extra 布尔标记 → 原因码。标记由产生点在写 status 时同步写入（不是事后猜文本）。
_EXTRA_REASON_MAP = (
    ("auth_wall", UnknownReason.AUTH_WALL.value),
    ("no_evidence", UnknownReason.NO_EVIDENCE.value),
    ("blocked", UnknownReason.BLOCKED.value),
    ("denied", UnknownReason.DENIED.value),
    ("unreachable", UnknownReason.UNREACHABLE.value),
)


def fill_unknown_reasons(results: List[ScanResult]) -> Tuple[int, int]:
    """给所有 UNKNOWN 结果补齐 `unknown_reason`（v1.7 WP-1 单一收口点）。

    设计纪律（v1.6 复盘教训）：
      - 只填空值，不覆盖产生点已经写入的精确原因（插件可显式传 unknown_reason）；
      - 优先读 `extra` 里的结构化布尔标记；
      - 仅对历史/第三方插件返回的**固定证据前缀**走受控白名单
        （lib/unknown_reasons.py），不按目标响应文本猜；
      - 仍无法归类的显式写 `unclassified`，保证「可计数」，目标 <5%。

    Returns:
        (本次补齐条数, 仍为 unclassified 的条数)
    """
    filled = 0
    unclassified = 0
    for r in results:
        if getattr(r, "status", "") != STATUS_UNKNOWN:
            continue
        if getattr(r, "unknown_reason", ""):
            continue
        extra = getattr(r, "extra", None) or {}
        reason = ""
        if isinstance(extra, dict):
            for key, code in _EXTRA_REASON_MAP:
                if extra.get(key):
                    reason = code
                    break
        if not reason:
            # 兼容桥：历史/第三方插件直接构造 UNKNOWN 时没有原因码。只匹配
            # 本仓库代码生成的固定证据前缀（见 lib/unknown_reasons.py），
            # 不按目标响应文本猜；匹配不到就如实记 unclassified。
            from lib.unknown_reasons import classify_legacy_unknown

            reason = classify_legacy_unknown(str(getattr(r, "evidence", "") or ""))
        if not reason:
            reason = UnknownReason.UNCLASSIFIED.value
            unclassified += 1
        r.unknown_reason = reason
        filled += 1
    return filled, unclassified


# === 数据模型 ===


@dataclass
class ScanRequest:
    """扫描请求（跨 CLI/API 通用）

    封装一次扫描的全部输入参数，CLI 与 API 构造相同的 ScanRequest，
    由 ScanOrchestrator 统一执行。
    """

    target: str  # 目标 URL
    mode: str = "u"  # 扫描模式 u/m/p/l（综合/目录/漏洞/爆破）
    cms: str = ""  # 手动指定 CMS（空=自动指纹识别）
    threads: int = 1  # 并发线程数
    rate: int = 0  # 限速（每秒请求数，0=不限）
    # 限速作用域：request=逐 HTTP 请求（默认，真实 QPS）；plugin=逐插件启动（v1.7.1 旧行为）
    rate_scope: str = "request"
    proxy: str = ""  # 代理地址（单代理）
    # D13：代理池。非空时优先于 proxy，由 SessionManager 逐请求轮换；
    # 文件格式：每行一个代理 URL，# 开头为注释（与 lib/proxy_pool.ProxyPool.from_file 一致）
    proxy_file: str = ""
    proxy_strategy: str = "round-robin"  # round-robin / random / least-fail
    timeout: int = 10  # 超时秒数
    debug: bool = False  # 调试模式
    report_dir: str = ""  # 报告输出目录（空=不生成报告）
    report_format: str = "all"  # 报告格式
    no_dedup: bool = False  # 关闭去重
    pass_level: str = "top100"  # 口令字典级别（安全默认：完整字典需显式 --pass-level full）
    portscan: bool = False  # 端口扫描
    ports: str = ""  # 自定义端口
    bypass_waf: str = "auto"  # WAF 绕过模式 auto/on/off
    # 可选：指定插件列表（None=按 CMS 路由加载全部）
    plugins: Optional[List[str]] = None
    # D14：主动信息收集
    crawl: bool = False  # 是否启用主动爬虫
    crawl_depth: int = 2  # 爬虫深度
    crawl_max_pages: int = 50  # 爬虫最大页面数
    subdomain: bool = False  # 是否启用子域名枚举
    js_extract: bool = False  # 是否启用 JS 端点提取
    # D26：认证扫描增强（CLI args.auth / args.auth_file / args.auth_login 解析后传入）
    auth: Optional[Dict[str, Any]] = None  # {"cookies": {...}, "headers": {...}, "type": "..."}
    # 显式低权账号（--surface-account user:pass，可多次；越权对照的唯一来源）
    surface_account: Optional[List[str]] = None
    # v1.5.6 WP1：显式指定的 API 前缀（--base-path 可多次）。优先级高于自动探测——
    # 现场运维知道真实 context-path 时不该再赌探测，也不该因为探测逻辑判据不匹配就漏扫。
    base_paths: Optional[List[str]] = None
    # 主扫描（admin）认证状态：ok / failed / not_attempted（报告元信息与「需会话插件」统一降级用）
    auth_status: str = "not_attempted"
    # --auth-surface 的独立会话状态：ok / failed / not_attempted（与主扫描分开记录）
    surface_auth_status: str = "not_attempted"
    # D19：扫描模板名称（quick / deep / compliance / dengbao）
    template: str = ""
    # P0：外部插件路径列表（--plugin-path 可多次指定）
    plugin_paths: Optional[List[str]] = None
    # E2：组件版本检测（--components 启用；默认关闭，向后兼容）
    components: bool = False
    # OAST 带外验证（--oast 启用）：编排器启动本地 HTTP/TCP 回调监听，
    # 插件通过 session.oast_client 取 interaction。host 是目标可达地址，
    # bind 是本机监听地址（远程目标场景常为 0.0.0.0）；port=0 自动分配。
    oast: bool = False
    oast_host: str = "127.0.0.1"
    oast_bind: str = ""
    oast_port: int = 0
    # Log4j TCP 回调端口：0=每次探测临时端口；远程目标需固定端口并放行
    oast_tcp_port: int = 0
    oast_timeout: float = 8.0
    # E4：nuclei YAML 模板（--nuclei 可多次指定路径/目录）
    nuclei_paths: Optional[List[str]] = None
    nuclei_tags: Optional[List[str]] = None
    nuclei_severity: Optional[List[str]] = None
    nuclei_exclude_tags: Optional[List[str]] = None
    # 单目标时间预算（秒）：0=不限制。慢站/限速站点上用于避免「看起来卡死」
    time_budget: float = 0.0
    # 方案 A：对抗型传输层（--adversarial-transport 启用；默认关闭，向后兼容）
    # 开启后 WAF 绕过编排器会把 L5 引擎策略（Scrapling 指纹/隐身浏览器）作为
    # 兜底追加到尝试序列，用于突破 Cloudflare Turnstile/Interstitial 等 JS 挑战。
    # 需安装额外依赖：pip install 'ruoyi-scan[adversarial]'
    adversarial_transport: bool = False
    # F8：Spring4Shell 真实利用（--exploit；默认关闭，仅回环/内网目标允许）
    exploit: bool = False
    # 时序盲注开关：默认关闭。一轮约 20-25s，只有显式开启才执行 SqlBlindTimePlugin
    time_based: bool = False

    def __post_init__(self) -> None:
        """API/嵌入式调用可能直接传 auth 但不设 auth_status：有凭据即视为 ok。"""
        if self.auth_status == "not_attempted" and self.auth:
            if self.auth.get("cookies") or self.auth.get("headers"):
                self.auth_status = "ok"


def build_proxy_pool(req: "ScanRequest") -> Optional[Any]:
    """按 `--proxy-file` 构造代理池；未配置/文件为空时返回 None（回退固定代理）。

    单列出来是为了可测：代理池曾在 D13 只实现了库、从未被主流程构造，
    CLI 的 --proxy-file 因此只起"跳过预检"的作用（v1.8 修）。
    """
    if not getattr(req, "proxy_file", ""):
        return None
    from lib.proxy_pool import ProxyPool

    pool = ProxyPool.from_file(req.proxy_file, strategy=getattr(req, "proxy_strategy", "") or "round-robin")
    if pool.total_count() == 0:
        logger.warning("代理池文件为空或不可读，回退固定代理: %s", req.proxy_file)
        return None
    logger.debug("代理池已启用: %d 个代理, 策略=%s", pool.total_count(), req.proxy_strategy)
    return pool


@dataclass
class ScanTask:
    """扫描任务句柄（API 模式用）

    记录任务状态、结果、计时信息，供 TaskRegistry 管理。
    """

    task_id: str
    request: ScanRequest
    status: str = "pending"  # pending/running/done/failed
    results: List[ScanResult] = field(default_factory=list)
    fingerprint: Optional[FingerprintResult] = None
    waf_info: Dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    finished_at: float = 0.0
    duration: float = 0.0
    request_count: int = 0
    # 插件级成本归因：[{plugin, duration_ms, requests}, ...]
    plugin_metrics: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""
    report_paths: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转为可序列化字典（API 响应用）"""
        return {
            "task_id": self.task_id,
            "status": self.status,
            "target": self.request.target,
            "mode": self.request.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "request_count": self.request_count,
            "plugin_metrics": self.plugin_metrics,
            "result_count": len(self.results),
            "confirmed_count": sum(1 for r in self.results if r.status == STATUS_CONFIRMED),
            "safe_count": sum(1 for r in self.results if r.status == STATUS_SAFE),
            "unknown_count": sum(1 for r in self.results if r.status == STATUS_UNKNOWN),
            "error": self.error,
            "fingerprint": {
                "cms": self.fingerprint.cms if self.fingerprint else "",
                "variant": getattr(self.fingerprint, "variant", "") if self.fingerprint else "",
                "confidence": self.fingerprint.confidence if self.fingerprint else 0,
                "matched": self.fingerprint.matched if self.fingerprint else [],
            }
            if self.fingerprint
            else None,
            "waf": self.waf_info or None,
            "report_paths": self.report_paths,
        }


# 事件回调类型：on_event(event_type: str, payload: Any)
# CLI 模式：payload 含预格式化的彩色文本，直接 print
# API 模式：payload 为原始数据，推送到 WS
EventHandler = Callable[[str, Any], None]


class TaskCancelled(Exception):
    """任务被用户取消（协作式：执行线程在检查点抛出，保留已收集结果）"""


class TargetUnreachable(Exception):
    """扫描前预检失败（目标不可达 / HTTP 层无响应）"""


class ScanOrchestrator:
    """扫描编排器：封装完整扫描流程，CLI 与 API 共用

    流程：
        1. 会话创建（SessionManager）
        2. 端口扫描（可选）
        3. 指纹识别（detect_cms）
        4. WAF 探测（detect_waf）+ 绕过协调器构建
        5. 插件加载 + 路由（Router）
        6. 引擎执行（ScanEngine.run，含 WAF 绕过钩子）
        7. 报告生成（ReportBuilder）

    两种调用方式：
        - run_sync(req, on_event): 同步执行，返回 results 列表（CLI 用）
        - submit(req): 异步提交，返回 task_id（API 用，需配合 TaskRegistry）
    """

    def __init__(self, registry: Optional[Any] = None) -> None:
        """初始化编排器

        Args:
            registry: TaskRegistry 实例（API 模式用，None 则 CLI 模式）
        """
        self.registry = registry
        self._pool: Optional[Any] = None  # 懒加载线程池（API 模式，_DaemonThreadPoolExecutor）
        self._pool_lock = threading.Lock()
        # 协作式取消：每个任务一个 Event，执行线程在阶段边界/插件入口检查
        self._cancel_events: Dict[str, threading.Event] = {}
        self._cancel_lock = threading.Lock()
        # 最近一次 run_sync 的实际请求数：session 在 _run 内部已关闭，调用方拿不到
        # session.request_count，报告里只能写 0。此处留一个只读快照供 CLI 出报告用。
        self.last_request_count: int = 0
        # 最近一次扫描的插件级耗时/请求数（报告与性能基线用）
        self.last_plugin_metrics: List[Dict[str, Any]] = []
        # 最近一次 run_sync 的全站拦截探测结果（CLI 出报告时写进 summary）
        self.last_block_info: Dict[str, Any] = {"blocked": False}
        # 最近一次 run_sync 的登录墙探测结果（报告与 CLI 提示用）
        self.last_auth_wall: Dict[str, Any] = {"wall": False}
        # 最近一次 WAF 探测结果（报告 summary 用；R12/R13 曾因缺字段无法解释拦截）
        self.last_waf_info: Dict[str, Any] = {"waf": "", "display": "", "bypass_hint": ""}

    def run_sync(self, req: ScanRequest, on_event: Optional[EventHandler] = None) -> List[ScanResult]:
        """同步执行扫描（CLI 模式）

        Args:
            req: 扫描请求
            on_event: 事件回调（None 则无事件输出）

        Returns:
            扫描结果列表（实际请求数见 self.last_request_count）
        """
        task = ScanTask(
            task_id=uuid.uuid4().hex[:12],
            request=req,
            started_at=time.time(),
        )
        results = self._run(task, on_event)
        self.last_request_count = task.request_count
        self.last_plugin_metrics = list(task.plugin_metrics)
        return results

    def submit(self, req: ScanRequest) -> str:
        """异步提交扫描任务（API 模式），返回 task_id

        内部通过 ThreadPoolExecutor 异步执行，调用方通过 registry 查询状态。

        Args:
            req: 扫描请求

        Returns:
            task_id
        """
        task_id = uuid.uuid4().hex[:12]
        task = ScanTask(
            task_id=task_id,
            request=req,
            started_at=time.time(),
        )
        with self._cancel_lock:
            self._cancel_events[task_id] = threading.Event()
        if self.registry:
            self.registry.register(task_id, task.to_dict())
            self.registry.notify(task_id, "status", {"status": "pending", "task_id": task_id})

        # 提交到线程池
        # 注意：on_event 传 None —— 事件推送统一走 _run 内部 _emit 的 registry.notify 通道，
        # 若再传 _api_event_handler 会造成每个事件被推送两次（历史/WS 全部翻倍）。
        try:
            with self._pool_lock:
                if self._pool is None:
                    self._pool = _DaemonThreadPoolExecutor(max_workers=4, thread_name_prefix="scan")
                self._pool.submit(self._run_task, task)
        except Exception as e:
            # 提交失败（如并发 shutdown 后线程池已关闭：RuntimeError: cannot schedule
            # new futures after shutdown）不能只抛给调用方——注册表条目会永久停留在
            # pending 且无错误信息。这里兜底置为 failed 并通知 registry。
            logger.exception("任务提交线程池失败: %s", task_id)
            task.status = "failed"
            task.error = str(e)
            task.finished_at = time.time()
            task.duration = task.finished_at - task.started_at
            if self.registry:
                self.registry.update_task_dict(task_id, task.to_dict())
                self.registry.notify(task_id, "status", {"status": "failed", "task_id": task_id})
            self._forget_cancel(task_id)
        return task_id

    def _run_task(self, task: ScanTask) -> None:
        """线程池入口：执行扫描并在结束后清理取消标志"""
        try:
            self._run(task, None)
        finally:
            self._forget_cancel(task.task_id)

    def _forget_cancel(self, task_id: str) -> None:
        with self._cancel_lock:
            self._cancel_events.pop(task_id, None)

    def cancel(self, task_id: str) -> bool:
        """请求取消任务（协作式）

        - 置 Event：执行线程在阶段边界/每个插件入口检查，停止启动新插件；
        - 立即把 registry 状态置为 cancelled 并落盘，UI 不必等线程退出；
        - 返回 False 表示任务不在执行队列中（已完成/不存在）。
        正在执行的单个插件无法被强杀（requests 不支持中断），最多等一个 HTTP 超时。
        """
        with self._cancel_lock:
            ev = self._cancel_events.get(task_id)
        if ev is None:
            return False
        ev.set()
        if self.registry:
            self.registry.mark_status(task_id, "cancelled")
            self.registry.notify(task_id, "status", {"status": "cancelled", "task_id": task_id})
        return True

    def _cancelled(self, task_id: str) -> bool:
        with self._cancel_lock:
            ev = self._cancel_events.get(task_id)
        return ev is not None and ev.is_set()

    def _raise_if_cancelled(self, task_id: str) -> None:
        if self._cancelled(task_id):
            raise TaskCancelled

    def is_task_active(self, task_id: str) -> bool:
        """任务是否仍在执行队列中（调度器防堆积用）"""
        with self._cancel_lock:
            return task_id in self._cancel_events

    def _run(self, task: ScanTask, on_event: Optional[EventHandler] = None) -> List[ScanResult]:
        """实际扫描逻辑（同步，从 main.py run_mode 抽取）

        Args:
            task: 扫描任务句柄
            on_event: 事件回调

        Returns:
            扫描结果列表
        """
        req = task.request
        # 执行层再校验一次：API 已有 Pydantic 校验，CLI/调度路径也要拦住畸形目标，
        # 否则 requests 只会抛 InvalidSchema，最终被插件吞成 UNKNOWN
        target = normalize_target(normalize_scan_target(req.target))
        # 提前初始化结果列表：异常路径也要能返回失败前已收集的部分结果，
        # 而不是静默丢弃（task.results 在失败时可能尚未赋值）
        all_results: List[ScanResult] = []
        # 全站拦截探测结果：SAFE 降级与报告摘要都要用；异常路径保持未拦截
        block_info: Dict[str, Any] = {"blocked": False}
        # 登录墙探测结果（应用认证要求），异常路径保持无墙
        auth_wall: Dict[str, Any] = {"wall": False, "reason": ""}

        def _emit(event_type: str, payload: Any) -> None:
            """发送事件（同时调用回调 + 通知 registry）"""
            if on_event is not None:
                try:
                    on_event(event_type, payload)
                except Exception:
                    logger.debug("事件回调执行失败", exc_info=True)
            if self.registry:
                # 为 registry 补充 task_id
                if isinstance(payload, dict) and "task_id" not in payload:
                    payload = {**payload, "task_id": task.task_id}
                elif not isinstance(payload, dict):
                    payload = {"task_id": task.task_id, "data": payload}
                # 先同步 task_dict 再广播：状态事件会立即把 record.status 改为新状态，
                # 若 task_dict 后写，GET /api/scan 可能短暂看到「status=failed 但 error 为空」。
                # error 事件同样要落 task_dict（否则异常原因只在事件流里）。
                if event_type in ("status", "error", "fingerprint", "waf", "complete"):
                    self.registry.update_task_dict(task.task_id, task.to_dict())
                self.registry.notify(task.task_id, event_type, payload)

        # 资源泄漏防护（#3）：session 在 try 块内创建，旧实现只在正常路径 (:651)
        # 调用 session.close()；一旦其后的任意步骤抛异常走 except 直接 return，session
        # 永不关闭，连接池与 keep-alive socket 泄漏。这里提前置 None，由 finally 统一关闭
        # （finally 在本方法唯一出口处执行，覆盖正常返回与异常返回两条路径）。
        session: Optional[SessionManager] = None
        # OAST 回调服务器生命周期与 session 同层：启动失败不阻断扫描，
        # 只是不加载 requires_oast 插件；成功则 finally 统一停止。
        oast_client: Optional[Any] = None
        # 扫描级共享请求计数器；创建失败/目标不可达时可能保持 None
        request_counter: Optional[RequestCounter] = None

        try:
            # 任务可能在排队期间就被取消：先检查，避免先广播 running 再 cancelled
            self._raise_if_cancelled(task.task_id)
            task.status = "running"
            _emit("status", {"status": "running", "task_id": task.task_id})
            self._raise_if_cancelled(task.task_id)

            # 0. 可达性预检：目标不可达时立即给出可读原因，而不是 0/0 干等
            # 配了代理时跳过直连探测（经代理可达的目标会被误判为不可达，与 CLI 语义一致）
            if not req.proxy:
                ok, stage, reason = preflight(target, timeout=min(float(req.timeout), 8.0))
                _emit(
                    "preflight",
                    {
                        "ok": ok,
                        "stage": stage,
                        "reason": reason,
                        "target": target,
                        "task_id": task.task_id,
                    },
                )
                if not ok:
                    raise TargetUnreachable(reason)

            self._raise_if_cancelled(task.task_id)

            # 一次扫描共用一个桶：主会话 + recon 临时会话都挂同一个 limiter，
            # 否则两个会话各自建桶 → 实际 QPS 翻倍。
            from lib.rate_limit import TokenBucket

            limiter: Optional[TokenBucket] = (
                TokenBucket(req.rate) if (req.rate > 0 and req.rate_scope == "request") else None
            )
            # D13：--proxy-file 配置了代理池时逐请求轮换；未配置则沿用固定代理。
            # 在侦察之前构造，主会话与 recon 临时会话共享同一个池（健康度统计不分裂）。
            proxy_pool = build_proxy_pool(req)
            if proxy_pool is not None:
                _emit(
                    "status",
                    {
                        "message": f"代理池已启用：{proxy_pool.total_count()} 个代理（{req.proxy_strategy}）",
                        "task_id": task.task_id,
                    },
                )

            # 扫描级共享请求计数：recon / 主会话 / 匿名会话 / 隔离登录会话共用，
            # 否则报告 request_count 只统计主会话（R11 实测少 88 条）。
            request_counter = RequestCounter()

            # 1. 端口扫描（可选）
            self._stage_portscan(req, target, _emit, task.task_id)

            # D14：主动信息收集（爬虫 + 子域名 + JS 提取）
            recon_info = self._stage_recon(req, target, _emit, task.task_id, limiter, proxy_pool, request_counter)

            # 2. 会话 + 引擎（攻击面注入 / 认证注入 / 字典 / 低权账号）
            session, engine = self._stage_session(
                req, task.task_id, _emit, limiter, proxy_pool, recon_info, request_counter
            )

            # 2.9 扫描级 OAST 回调监听（仅在 --oast 时启动）
            oast_client = self._stage_oast(req, _emit, task.task_id)
            if oast_client is not None:
                session.oast_client = oast_client

            # 3.5-3.6 全站拦截 + 登录墙探测
            block_info, auth_wall = self._stage_reachability(session, target, _emit, task.task_id)

            # 4. 指纹识别（routes: 是否按 cms/variant/version 过滤插件）
            router, fp_result, fp_cache, all_plugins = self._stage_fingerprint(req, target, session, _emit, task)

            # 5. 环境能力：WAF / 组件检测 / 绕过协调器 / API 前缀
            (
                waf_result,
                component_results,
                waf_bypass_coordinator,
                plugin_target,
            ) = self._stage_capabilities(req, target, session, fp_result, fp_cache, _emit, task)

            # 6. 插件加载 + 过滤 + 分组
            all_plugins, plugins_by_cat, categories = self._stage_load_plugins(
                req,
                fp_result,
                all_plugins,
                _emit,
                task.task_id,
                oast_enabled=oast_client is not None,
            )

            # 7. 引擎执行
            # （all_results 已在 try 外初始化：异常路径可返回已收集的部分结果）
            total_plugins = sum(len(plugins_by_cat.get(c, [])) for c in categories)
            done_count = [0]  # 闭包可变

            def _on_metric(metric: Dict[str, Any]) -> None:
                """引擎回调：保存插件耗时/请求数，同时推送事件供 API/性能工具消费。"""
                task.plugin_metrics.append(metric)
                _emit("plugin_metric", {**metric, "task_id": task.task_id})

            # 需要高权会话才能给出 CONFIRMED/SAFE 的插件名集合：auth_status != ok 时统一降级
            auth_required_names = {
                getattr(cls, "name", "") for cls in all_plugins if getattr(cls, "requires_auth", False)
            }

            def _on_result(res: ScanResult) -> None:
                """引擎结果回调：推送事件 + 计数"""
                all_results.append(res)
                done_count[0] += 1
                # 发完整结果（to_dict 含 fix/reproduce/cve/cvss/compliance），
                # 结果详情抽屉与持久化共用同一形状；task_id 由 _emit 补齐
                payload = res.to_dict() if hasattr(res, "to_dict") else {"name": getattr(res, "name", "")}
                payload = {**payload, "task_id": task.task_id}
                _emit("result", payload)
                # 每 25 条增量落盘：进程异常退出时也能保住大部分证据
                if len(all_results) % 25 == 0:
                    self._persist_results(task.task_id, all_results)
                percent = (done_count[0] / total_plugins * 100) if total_plugins > 0 else 0
                _emit(
                    "progress",
                    {
                        "done": done_count[0],
                        "total": total_plugins,
                        "percent": round(percent, 1),
                        "task_id": task.task_id,
                    },
                )

            for cat in categories:
                self._raise_if_cancelled(task.task_id)
                classes = plugins_by_cat.get(cat, [])
                if not classes:
                    continue
                _emit(
                    "category_start",
                    {
                        "category": cat,
                        "count": len(classes),
                        "task_id": task.task_id,
                    },
                )
                engine.run(
                    classes,
                    plugin_target,
                    session,
                    on_result=_on_result,
                    waf_bypass_coordinator=waf_bypass_coordinator,
                    should_stop=lambda: self._cancelled(task.task_id),
                    # F9：把不带前缀的站点根一并传下去。path_scope="root" 的插件
                    # （.git/.env/备份/IDE 残留）用它探测——这些文件部署在 web 根，
                    # 加了 API 前缀必然探不到（实测 R7 根路径 .git/HEAD 200，
                    # 探 /prod-api/.git/HEAD 得 502，最终错误判 SAFE）。
                    root_target=target,
                    on_metric=_on_metric,
                )

            task.results = all_results
            task.request_count = request_counter.value()
            # 7.1 三态降级 / 归属标注 / UNKNOWN 原因码
            self._stage_degrade(
                req,
                target,
                all_results,
                component_results,
                auth_wall,
                block_info,
                auth_required_names,
                _emit,
                task.task_id,
            )

            task.results = all_results
            # 三态降级全部完成后再落一次完整快照（增量落盘只覆盖到第 25n 条）
            self._persist_results(task.task_id, all_results)
            self._raise_if_cancelled(task.task_id)
            # session 关闭统一放到 finally（成功/失败路径共用，避免泄漏）

            # 8. 报告生成（可选；仅 API/嵌入式路径传 report_dir）
            self._stage_report(req, task, target, session, all_results, fp_result, router, block_info, _emit)

            # 9. 完成
            task.status = "done"
            task.finished_at = time.time()
            task.duration = task.finished_at - task.started_at
            _emit("status", {"status": "done", "task_id": task.task_id})
            _emit(
                "complete",
                {
                    "task_id": task.task_id,
                    "duration": task.duration,
                    "result_count": len(all_results),
                    "confirmed_count": sum(1 for r in all_results if r.status == STATUS_CONFIRMED),
                    "safe_count": sum(1 for r in all_results if r.status == STATUS_SAFE),
                    "unknown_count": sum(1 for r in all_results if r.status == STATUS_UNKNOWN),
                },
            )

            return all_results

        except TaskCancelled:
            # 用户取消：保留已收集结果，不再生成报告（半程报告会误导），
            # 状态以 cancelled 收尾；执行线程退出后释放线程池槽位
            task.status = "cancelled"
            task.finished_at = time.time()
            task.duration = task.finished_at - task.started_at
            task.results = task.results or all_results
            fill_unknown_reasons(task.results)
            self._persist_results(task.task_id, task.results)
            _emit("status", {"status": "cancelled", "task_id": task.task_id})
            return task.results

        except TargetUnreachable as e:
            # 预检失败：不给“0/0 无事件”让用户干等，直接失败并说明原因
            task.status = "failed"
            task.error = f"目标不可达：{e}"
            task.finished_at = time.time()
            task.duration = task.finished_at - task.started_at
            task.results = all_results
            fill_unknown_reasons(all_results)
            self._persist_results(task.task_id, all_results)
            _emit("error", {"error": task.error, "code": "unreachable", "task_id": task.task_id})
            _emit("status", {"status": "failed", "task_id": task.task_id})
            return all_results

        except Exception as e:
            # CLI 模式下 _emit 可能没有任何消费者（无 on_event 且无 registry），
            # 不落日志会让「扫描崩溃」与「扫描无发现」无法区分
            logger.exception("扫描任务执行异常: %s", task.task_id)
            task.status = "failed"
            task.error = str(e)
            task.finished_at = time.time()
            task.duration = task.finished_at - task.started_at
            # 保留失败前已收集的部分结果（引擎中途异常时 task.results 可能尚未赋值）
            task.results = task.results or all_results
            fill_unknown_reasons(task.results)
            self._persist_results(task.task_id, task.results)
            _emit(
                "error",
                {
                    "error": str(e),
                    "task_id": task.task_id,
                },
            )
            _emit("status", {"status": "failed", "task_id": task.task_id})
            return task.results

        finally:
            # 无论成功/失败都刷新真实请求数：失败路径也应收录已发生的流量
            if request_counter is not None:
                task.request_count = request_counter.value()
            # 无论成功/失败都关闭会话（含认证注入、指纹、WAF、插件执行等中途异常）；
            # 口令字典已改为扫描级注入（session.password_dict），无需恢复进程级全局
            if oast_client is not None:
                try:
                    oast_client.close()
                    if oast_client.server is not None:
                        oast_client.server.stop()
                except Exception:
                    logger.debug("OAST 服务器关闭失败", exc_info=True)
            if session is not None:
                try:
                    session.close()
                except Exception:
                    logger.debug("会话关闭失败", exc_info=True)

    def _stage_portscan(self, req: ScanRequest, target: str, emit: Callable[..., None], task_id: str) -> None:
        """步骤 1：可选端口扫描，只发事件（结果不进入插件流水线）。"""
        if not req.portscan:
            return
        from core.portscan import DEFAULT_PORTS, PortScanner

        host = self._host_of(target)
        ports = self._parse_ports(req.ports, DEFAULT_PORTS)
        scanner = PortScanner(timeout=req.timeout, threads=req.threads)
        port_results = scanner.scan(host, ports)
        emit(
            "portscan",
            {
                "host": host,
                "open_count": len(port_results),
                "total": len(ports),
                "ports": [{"port": p.port, "service": p.service, "banner": p.banner} for p in port_results],
                "task_id": task_id,
            },
        )

    def _stage_oast(self, req: ScanRequest, emit: Callable[..., None], task_id: str) -> Optional[Any]:
        """步骤 2.9：启用 --oast 时启动扫描级 OAST 回调监听（HTTP + 按需 TCP）。"""
        if not req.oast:
            return None
        from lib.oast import OASTClient, OASTServer

        host = req.oast_host or "127.0.0.1"
        bind = req.oast_bind or host
        server = OASTServer(bind, int(req.oast_port or 0))
        if not server.start():
            emit(
                "oast",
                {
                    "enabled": False,
                    "reason": "回调端口绑定失败（bind=%s:%s）" % (bind, req.oast_port),
                    "task_id": task_id,
                },
            )
            logger.warning("OAST 服务器启动失败，requires_oast 插件将被跳过（bind=%s:%s）", bind, req.oast_port)
            return None
        client = OASTClient(
            server=server,
            host=host,
            bind_host=bind,
            timeout=req.oast_timeout,
            tcp_port=req.oast_tcp_port,
        )
        emit(
            "oast",
            {
                "enabled": True,
                "host": host,
                "http_port": server.bound_port,
                "tcp_port": req.oast_tcp_port,
                "timeout": req.oast_timeout,
                "task_id": task_id,
            },
        )
        return client

    def _stage_recon(
        self,
        req: ScanRequest,
        target: str,
        emit: Callable[..., None],
        task_id: str,
        limiter: Optional[Any],
        proxy_pool: Optional[Any],
        request_counter: Optional[RequestCounter] = None,
    ) -> Dict[str, Any]:
        """步骤 1′：可选的主动信息收集（爬虫 / 子域名 / JS 端点），返回侦察结果。"""
        if not (req.crawl or req.subdomain or req.js_extract):
            return {}
        recon_info = self._run_recon(
            req,
            target,
            emit,
            task_id,
            limiter=limiter,
            proxy_pool=proxy_pool,
            request_counter=request_counter,
        )
        for key, event_type, payload_key in (
            ("subdomains", "subdomain", "subdomains"),
            ("crawled_urls", "crawl", "urls"),
            ("js_endpoints", "js_extract", "endpoints"),
        ):
            values = recon_info.get(key)
            if values:
                emit(
                    "recon",
                    {
                        "type": event_type,
                        payload_key: values,
                        "count": len(values),
                        "task_id": task_id,
                    },
                )
        return recon_info

    def _stage_session(
        self,
        req: ScanRequest,
        task_id: str,
        emit: Callable[..., None],
        limiter: Optional[Any],
        proxy_pool: Optional[Any],
        recon_info: Dict[str, Any],
        request_counter: Optional[RequestCounter] = None,
    ) -> Tuple[SessionManager, ScanEngine]:
        """步骤 2–3.1：建会话/引擎，注入攻击面、认证、字典与低权账号。"""
        # 2. 会话创建
        # 连接池尺寸必须与线程数挂钩（性能 P0）：旧实现不传 pool_size，session.py 里
        # _pool = max(pool_size or settings.THREADS or 10, 10)，而 settings.THREADS=1
        # 且从不被 --threads 写回 → 连接池恒为 10（pool_maxsize=20）。--threads 50 时
        # 引擎开 50 线程但池只有 20，30 个线程每次请求都新建 TCP 连接，keep-alive
        # 复用率崩掉。这里显式把 pool_size 设为线程数，使池与并发匹配。
        session = SessionManager(
            proxy=req.proxy or None,
            proxy_pool=proxy_pool,
            debug=req.debug,
            timeout=req.timeout,
            pool_size=req.threads,
            rate=req.rate,
            rate_scope=req.rate_scope,
            limiter=limiter,
            request_counter=request_counter,
        )
        try:
            # F8：插件通过 session.exploit 读取真实利用开关，不直接依赖 CLI
            session.exploit = req.exploit
            # D14 回流：把侦察到的攻击面写入扫描级共享对象，供 consumes_surface
            # 插件消费。未启用 --crawl/--js-extract（或清单为空）时保持 None——
            # 引擎据此把消费方的 CONFIRMED/SAFE 降级为 UNKNOWN。
            inv = recon_info.get("surface") if recon_info else None
            if inv is not None and inv.endpoints:
                session.surface = inv
                emit(
                    "surface",
                    {
                        "endpoints": len(inv.endpoints),
                        "pages": len(inv.pages),
                        "js_endpoints": len(inv.js_endpoints),
                        "truncated": inv.truncated,
                        "task_id": task_id,
                    },
                )
            self._raise_if_cancelled(task_id)
            engine = ScanEngine(
                threads=req.threads,
                # request 作用域由会话层限速，引擎必须传 0，避免双重限速把 QPS 压成 1/N
                rate=0 if req.rate_scope == "request" else req.rate,
                deadline=(time.monotonic() + req.time_budget) if req.time_budget > 0 else None,
            )
            # 时序盲注插件在花 20 秒之前要先问预算：把引擎的截止点交给会话，
            # 插件用 getattr(session, "deadline", None) 读取（哑对象 session 不会炸）
            session.deadline = engine.deadline

            # D26：认证扫描增强（将 auth 配置注入 session）
            if req.auth:
                from lib.auth_inject import apply_auth_to_session

                apply_auth_to_session(session, req.auth)
                auth_summary = []
                if req.auth.get("cookies"):
                    auth_summary.append(f"{len(req.auth['cookies'])} 个 Cookie")
                if req.auth.get("headers"):
                    auth_summary.append(f"{len(req.auth['headers'])} 个自定义头")
                emit(
                    "auth",
                    {
                        "summary": " + ".join(auth_summary),
                        "cookies": len(req.auth.get("cookies", {})),
                        "headers": len(req.auth.get("headers", {})),
                        "task_id": task_id,
                    },
                )

            # 本次扫描是否真正拿到了高权会话：供 file_upload 的「登录后上传」维度判断。
            session.authenticated = req.auth_status == "ok"

            # 3. 口令字典分级：只解析本次扫描的字典路径并注入当前 session，不改写进程级
            # settings.PASSWORD_DICT——API 并发扫描下不同 pass_level 的任务会互相覆盖字典
            # （爆破类插件优先读取 session.password_dict，回退进程级默认值）
            selected_password_dict = settings.PASSWORD_DICT
            if req.pass_level != "full" and req.pass_level in settings.PASSWORD_DICT_BY_LEVEL:
                selected_password_dict = settings.PASSWORD_DICT_BY_LEVEL[req.pass_level]
            session.password_dict = selected_password_dict

            # 3.1 显式低权账号：只挂在本次扫描的会话上（不写进程级 settings），
            # 供越权对照插件读取；未提供时插件必须返回 UNKNOWN。
            if req.surface_account:
                from core.lowpriv import parse_account

                for item in req.surface_account:
                    parsed = parse_account(item)
                    if parsed:
                        session.surface_account = parsed
                        break

            return session, engine
        except BaseException:
            try:
                session.close()
            except Exception:
                logger.debug("会话初始化失败后关闭失败", exc_info=True)
            raise

    def _stage_reachability(
        self, session: SessionManager, target: str, emit: Callable[..., None], task_id: str
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """步骤 3.5-3.6：识别全站拦截与登录墙，供后续 SAFE 降级使用。"""
        # 3.5 全站拦截探测（WAF / 网关 / 认证墙）
        # 站点被统一拒绝时，每个插件拿到的都是同一个 403，按插件自身逻辑会落到
        # 「没命中 = 不存在」，报告会写出「N 项确认不存在」——比漏报更危险的假安全感。
        # 这里先识别拦截状态，插件跑完后再把 SAFE 统一降级为 UNKNOWN。
        from lib.reachability import detect_blocked

        block_info = detect_blocked(session, target)
        self.last_block_info = block_info
        if block_info["blocked"]:
            emit("blocked", dict(block_info, task_id=task_id))

        # 3.6 登录墙探测（应用自身认证要求，与 WAF 拦截不同）
        # 真实 RuoYi 未认证访问受保护接口是 302 -> /login（跟随后 200 登录页），
        # 不是 401。插件只看到 200 登录页就会把「没测到」写成 SAFE。
        from lib.reachability import detect_auth_wall

        auth_wall = detect_auth_wall(session, target)
        self.last_auth_wall = auth_wall
        if auth_wall["wall"]:
            emit("auth_wall", dict(auth_wall, task_id=task_id))

        return block_info, auth_wall

    def _stage_fingerprint(
        self, req: ScanRequest, target: str, session: SessionManager, emit: Callable[..., None], task: ScanTask
    ) -> Tuple[Any, Any, Optional[Any], List[type]]:
        """步骤 4：指纹识别（手动 --cms 优先），返回路由器与候选插件。"""
        # 4. 指纹识别
        # 性能（P1-C）：自建 FingerprintCache 交给 detect_cms，事后复用给 detect_waf，
        # 使根路径响应在两者间共享（旧实现 detect_waf 会对根路径重发一次请求，
        # 单目标至少 3 次根路径请求）。req.cms 手动指定时无 detect_cms，缓存不建。
        router = Router()
        fp_cache: Optional[FingerprintCache] = None
        if req.cms:
            fp_result = FingerprintResult(cms=req.cms, version="", confidence=1.0, matched=["manual"])
            all_plugins = router.resolve_by_name(req.cms)
        else:
            fp_cache = FingerprintCache(session)
            fp_result = detect_cms(target, session, cache=fp_cache)
            # 自定义 context-path 兜底（D1 实测 /portal）：根路径 302 到
            # /portal/auth/signin，页面已品牌化，拿不到 RuoYi 关键字/favicon。
            # 只在 cms 为空时探测一次前缀，再用 {target}/{context}/ 重新指纹。
            # /prod-api、/admin-api 等前后端分离前缀不重复套一层（那由 basepath
            # 阶段处理），避免把 /prod-api 再拼成 /prod-api/。
            if not fp_result.cms:
                try:
                    from core.basepath import detect_api_base

                    api_base = detect_api_base(target, session)
                    proxy_prefixes = ("/prod-api", "/admin-api", "/jeecg-boot", "/api", "/nacos", "/gateway")
                    if api_base and not any(api_base == p or api_base.startswith(p + "/") for p in proxy_prefixes):
                        ctx_target = target.rstrip("/") + api_base + "/"
                        ctx_fp = detect_cms(ctx_target, session)
                        if ctx_fp.cms:
                            ctx_fp.matched.append("context:%s" % api_base)
                            fp_result = ctx_fp
                except Exception:
                    logger.debug("context-path 指纹兜底失败", exc_info=True)
            all_plugins = router.resolve(fp_result)

        task.fingerprint = fp_result
        emit(
            "fingerprint",
            {
                "cms": fp_result.cms,
                "version": fp_result.version,
                "variant": getattr(fp_result, "variant", ""),
                "confidence": fp_result.confidence,
                "matched": fp_result.matched,
                "task_id": task.task_id,
            },
        )

        return router, fp_result, fp_cache, all_plugins

    def _stage_capabilities(
        self,
        req: ScanRequest,
        target: str,
        session: SessionManager,
        fp_result: Any,
        fp_cache: Optional[Any],
        emit: Callable[..., None],
        task: ScanTask,
    ) -> Tuple[Dict[str, Any], List[Any], Optional[Any], str]:
        """步骤 5-5.5：WAF/组件/绕过协调器/API 前缀，返回探测结果与插件基准 target。"""
        # 5. WAF 探测 + 绕过协调器
        # 传入 fp_cache 复用 detect_cms 已缓存的根响应（未命中才发请求，向后兼容）
        waf_result = detect_waf(target, session, cache=fp_cache)
        task.waf_info = waf_result
        self.last_waf_info = waf_result
        emit(
            "waf",
            {
                "waf": waf_result.get("waf", ""),
                "display": waf_result.get("display", ""),
                "bypass_hint": waf_result.get("bypass_hint", ""),
                "task_id": task.task_id,
            },
        )

        # E2：组件版本检测（--components 启用）
        component_results = []
        if req.components:
            from lib.component_detect import ComponentDetector

            try:
                detector = ComponentDetector(oast_client=getattr(session, "oast_client", None))
                component_results = detector.detect_all(target, session, ruoyi_version=fp_result.version)
                for cr in component_results:
                    emit(
                        "component",
                        {
                            "component": cr.component,
                            "status": cr.status,
                            "cve": cr.cve,
                            "detected_version": cr.detected_version,
                            "evidence": cr.evidence,
                            "task_id": task.task_id,
                        },
                    )
            except Exception as e:
                logger.debug("组件检测失败", exc_info=True)
                emit("component", {"error": str(e), "task_id": task.task_id})

        # --oast 但未开 --components 时，仍单独跑 Log4j JNDI（带外确认的独立类别）；
        # 开了 --components 时 ComponentDetector 已包含 Log4j，避免重复。
        if getattr(session, "oast_client", None) is not None and not req.components:
            from lib.component_detect import detect_log4j

            try:
                log4j_result = detect_log4j(target, session, session.oast_client)
                component_results.append(log4j_result)
                emit(
                    "component",
                    {
                        "component": log4j_result.component,
                        "status": log4j_result.status,
                        "cve": log4j_result.cve,
                        "evidence": log4j_result.evidence,
                        "task_id": task.task_id,
                    },
                )
            except Exception as e:
                logger.debug("Log4j OAST 探测失败", exc_info=True)
                emit("component", {"error": str(e), "task_id": task.task_id})

        waf_bypass_coordinator = self._build_waf_bypass(req, waf_result, target, session)

        # WAF 绕过状态事件（CLI 打印绕过模式信息）
        bypass_mode = req.bypass_waf or "auto"
        if waf_bypass_coordinator:
            emit(
                "waf_bypass",
                {
                    "mode": bypass_mode,
                    "enabled": True,
                    "origin_ip": getattr(waf_bypass_coordinator, "origin_ip", ""),
                    "task_id": task.task_id,
                },
            )

        # 5.5 API 前缀探测（前后端分离部署）
        # 分离版标准 nginx 只反代 /prod-api/，根路径下所有后端路径都会落到 SPA 的
        # index.html（200 HTML）→ 按根路径拼 URL 的插件拿不到后端真实响应，
        # 该报的 Druid/Actuator/默认口令/定时任务全部落空 = 系统性漏报。
        # 实测 2026-10-29 R7（严格只反代 /prod-api/）：除宿主级 Redis 外无任何命中。
        # 根路径已直连后端（单机版）时 detect_api_base 返回空串，行为不变。
        # v1.5.6 WP1：候选表写死 → 自定义 context-path（如二开的 /portal）永远识别不出。
        # 现改为：显式 --base-path 优先 → 被动提取（Set-Cookie/Location/JS baseURL）
        # → 写死候选兜底。抽出的前缀仍要过「真图片/真 JSON」判据才采纳，判定不放松。
        plugin_target = target
        api_base = ""
        try:
            from core.basepath import detect_api_base

            api_base = detect_api_base(target, session, extra_hints=req.base_paths)
        except Exception:
            logger.debug("API 前缀探测失败", exc_info=True)
        if api_base:
            # JeecgBoot 的插件路径自带 /jeecg-boot context-path，helper 会避免双前缀
            from core.basepath import plugin_target_for

            plugin_target = plugin_target_for(target, api_base)
            emit(
                "basepath",
                {"base": api_base, "plugin_target": plugin_target, "task_id": task.task_id},
            )

        # 5.6 低成本登录页探测：只对会执行 brute 的模式做；供引擎跳过无意义的
        # 口令字典（R11 无登录页仍跑 6×1053 Druid 字典 = 6318 请求）。
        # 探测失败（None）时保持旧行为（brute 继续跑），不因探测故障漏掉默认口令。
        session.login_page_available = None  # type: ignore[attr-defined]
        if req.mode in ("u", "l"):
            try:
                from lib.reachability import detect_login_page

                login_probe = detect_login_page(session, target, plugin_target)
                session.login_page_available = login_probe.get("available")
                emit(
                    "login_page",
                    {
                        "available": login_probe.get("available"),
                        "url": login_probe.get("url", ""),
                        "status": login_probe.get("status", 0),
                        "reason": login_probe.get("reason", ""),
                        "task_id": task.task_id,
                    },
                )
            except Exception:
                logger.debug("登录页探测失败，brute 插件保持执行", exc_info=True)

        return waf_result, component_results, waf_bypass_coordinator, plugin_target

    def _stage_load_plugins(
        self,
        req: ScanRequest,
        fp_result: Any,
        all_plugins: List[type],
        emit: Callable[..., None],
        task_id: str,
        oast_enabled: bool = True,
    ) -> Tuple[List[type], Dict[str, List[type]], List[str]]:
        """步骤 6：加载候选插件 → 过滤 → 按 category 分组。

        requires_oast 插件在未启用 --oast（或回调端口启动失败）时不加载：
        否则每个目标都会产出一条"未启用 OAST"的 UNKNOWN，污染报告。
        """
        all_plugins = self._load_plugin_candidates(req, fp_result, all_plugins, emit, task_id)
        if not oast_enabled:
            oast_plugins = [cls for cls in all_plugins if getattr(cls, "requires_oast", False)]
            if oast_plugins:
                all_plugins = [cls for cls in all_plugins if not getattr(cls, "requires_oast", False)]
                emit(
                    "oast_disabled",
                    {
                        "skipped_plugins": [getattr(cls, "name", "") for cls in oast_plugins],
                        "count": len(oast_plugins),
                        "task_id": task_id,
                    },
                )
        return self._filter_and_group_plugins(req, all_plugins, emit, task_id)

    def _stage_degrade(
        self,
        req: ScanRequest,
        target: str,
        all_results: List[ScanResult],
        component_results: List[Any],
        auth_wall: Dict[str, Any],
        block_info: Dict[str, Any],
        auth_required_names: set,
        emit: Callable[..., None],
        task_id: str,
    ) -> None:
        """步骤 7.1：组件并入、SAFE→UNKNOWN 降级、归属标注、原因码补齐。"""
        # E2：组件检测结果并入任务结果（报告统计口径：vuln 类 CONFIRMED 计入）
        from lib.component_detect import to_scan_result

        for cr in component_results:
            all_results.append(to_scan_result(cr))
        # SAFE → UNKNOWN：全站拦截时没有任何一条「确认不存在」成立（三态铁律）
        from lib.attribution import annotate as annotate_attribution
        from lib.reachability import (
            downgrade_auth_wall_safe,
            downgrade_evidence_less_safe,
            downgrade_safe_results,
            upgrade_denied_safe_to_unknown,
        )

        # 单接口被拒（401/403/429）：只有该接口没测到，不是"漏洞不存在"
        denied = upgrade_denied_safe_to_unknown(all_results)
        if denied:
            emit("denied_downgrade", {"count": denied, "task_id": task_id})

        # SAFE 必须带证据：空证据的 SAFE 没有可复核性，不能宣称"确认不存在"
        no_evidence = downgrade_evidence_less_safe(all_results)
        if no_evidence:
            emit("evidence_downgrade", {"count": no_evidence, "task_id": task_id})

        # 登录墙：拿到 200 登录页的 SAFE 同样是"没测到"，降级为 UNKNOWN
        wall_downgraded = downgrade_auth_wall_safe(all_results, auth_wall)
        if wall_downgraded:
            emit(
                "auth_wall_downgrade",
                {
                    "count": wall_downgraded,
                    "reason": auth_wall.get("reason", ""),
                    "task_id": task_id,
                },
            )

        downgraded = downgrade_safe_results(all_results, block_info)
        if downgraded:
            emit(
                "blocked_downgrade",
                {
                    "count": downgraded,
                    "status": block_info.get("status", 0),
                    "reason": block_info.get("reason", ""),
                    "task_id": task_id,
                },
            )

        # 归属标注：中间件插件探的是「目标主机的另一个端口」，发现的资产属于
        # 这台主机而不是这个站点。不标注的话，批量扫描时同一个宿主 Redis 会在
        # N 份站点报告里各报一次（2026-11-02 实测：R1 单机版根本不带 Redis，
        # 却因宿主 C4-1 的 16379 无认证而报「R1 存在 Redis 未授权」）。
        # 只标注不降级：端口确实无认证，归属是另一个正交维度。
        attribution_stats = annotate_attribution(all_results, target)
        if attribution_stats["host_level"]:
            emit(
                "attribution",
                {
                    "host_level": attribution_stats["host_level"],
                    "site_level": attribution_stats["site_level"],
                    "task_id": task_id,
                },
            )

        # 认证纪律：auth_status != ok 时，需会话插件的 CONFIRMED/SAFE 一律降级为 UNKNOWN。
        # 这不是「降低误报」，而是把「没拿到会话」如实表达出来；低权对照插件不在此列
        # （它们自己解析显式 --surface-account，缺凭证时已返回 UNKNOWN）。
        auth_downgraded = downgrade_auth_required_results(all_results, req.auth_status, auth_required_names)
        if auth_downgraded:
            emit(
                "auth_downgrade",
                {
                    "count": auth_downgraded,
                    "auth_status": req.auth_status,
                    "task_id": task_id,
                },
            )

        # v1.7 WP-1：三态降级全部完成后统一补齐 UNKNOWN 原因码（只填空值）。
        # 必须在报告生成与落盘之前：缺少原因码的 UNKNOWN 对用户不可解释。
        _filled, _unclassified = fill_unknown_reasons(all_results)
        if _unclassified:
            logger.debug("UNKNOWN 原因码仍为 unclassified：%d 条", _unclassified)

    def _stage_report(
        self,
        req: ScanRequest,
        task: ScanTask,
        target: str,
        session: SessionManager,
        all_results: List[ScanResult],
        fp_result: Any,
        router: Any,
        block_info: Dict[str, Any],
        emit: Callable[..., None],
    ) -> None:
        """步骤 8：按 report_dir 生成报告（CLI 不走此路径）。"""
        # 8. 报告生成（可选）
        if req.report_dir:
            # E3：版本对照矩阵（检测版本 vs 各插件适用性）——与 CLI 共用同一实现，
            # 避免两处逻辑漂移（CLI 传 report_dir="" 自行出报告，走 cli/runner.py 的补算）
            from core.ruoyi_versions import build_version_matrix

            # 用「未按版本过滤」的候选集——否则 applicable 恒为真，对照表失去意义
            version_matrix = build_version_matrix(fp_result.version, router.candidates(fp_result))
            summary = {
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(task.started_at)),
                "duration": time.time() - task.started_at,
                "request_count": session.request_count,
                "mode": req.mode,
                "fingerprint": {
                    "cms": fp_result.cms,
                    "variant": getattr(fp_result, "variant", ""),
                    "version": fp_result.version,
                    "confidence": fp_result.confidence,
                    "matched": fp_result.matched,
                },
                "version_matrix": version_matrix,
                "blocked": block_info,
                "auth_status": {
                    "admin": req.auth_status,
                    "surface": req.surface_auth_status,
                },
            }
            builder = ReportBuilder(results=all_results, target=target, summary=summary, dedup=not req.no_dedup)
            formats = self._parse_formats(req.report_format)
            paths = builder.render_all(req.report_dir, formats=formats, stem=task.task_id)
            task.report_paths = paths
            emit(
                "report",
                {
                    "paths": paths,
                    "task_id": task.task_id,
                },
            )

    def _load_plugin_candidates(
        self,
        req: ScanRequest,
        fp_result: Any,
        all_plugins: List[type],
        emit: Callable[..., None],
        task_id: str,
    ) -> List[type]:
        """按五条来源加载插件（路由包 + 扩展来源）。"""
        all_plugins = self._load_routed_plugins(req, fp_result, all_plugins, emit, task_id)
        return self._load_extension_plugins(req, all_plugins, emit, task_id)

    def _filter_and_group_plugins(
        self, req: ScanRequest, all_plugins: List[type], emit: Callable[..., None], task_id: str
    ) -> Tuple[List[type], Dict[str, List[type]], List[str]]:
        """按 --plugins/--template/--time-based 过滤，并按 category 分组。"""
        # 指定插件过滤（API 可指定插件子集）
        if req.plugins:
            all_plugins = [cls for cls in all_plugins if getattr(cls, "name", "") in req.plugins]

        # D19：扫描模板过滤插件
        template_obj = None
        if req.template:
            from lib.scan_profiles import filter_plugins, get_template

            template_obj = get_template(req.template)
            if template_obj:
                before_count = len(all_plugins)
                all_plugins = filter_plugins(all_plugins, template_obj)
                after_count = len(all_plugins)
                emit(
                    "template",
                    {
                        "name": template_obj.display_name,
                        "before": before_count,
                        "after": after_count,
                        "task_id": task_id,
                    },
                )

        # 时序盲注默认不执行：一轮 20-25s，只有 --time-based 显式开启才保留。
        # 按模块路径过滤（name 是中文文案，改一个字就失效）。
        if not req.time_based:
            all_plugins = [cls for cls in all_plugins if not getattr(cls, "__module__", "").endswith("sql_blind_time")]

        # 按 category 分组（对应 MODE_CATEGORIES）
        mode_categories = {
            "u": ["recon", "vuln", "brute"],
            "m": ["recon"],
            "p": ["vuln"],
            "l": ["brute"],
        }
        plugins_by_cat: Dict[str, List[type]] = {}
        for cls in all_plugins:
            cat = getattr(cls, "category", "")
            plugins_by_cat.setdefault(cat, []).append(cls)

        categories = mode_categories.get(req.mode, ["vuln"])
        return all_plugins, plugins_by_cat, categories

    def _load_routed_plugins(
        self,
        req: ScanRequest,
        fp_result: Any,
        all_plugins: List[type],
        emit: Callable[..., None],
        task_id: str,
    ) -> List[type]:
        """步骤 6a：按指纹路由加载专项包（含弱证据扩展）。"""
        # 6. 插件加载 + 路由
        #
        # 三层策略：
        #   a) cms 未识别      → 回退 ruoyi + spring（F7-1）
        #   b) cms 弱证据命中  → 在原包基础上补加载 ruoyi + spring + jeecgboot
        #   c) cms 强证据命中  → 只加载该 CMS 的包（正常路径）
        #
        # b 是为了修「弱指纹排他导致整包漏扫」（2026-11-01 盲测 v2 发现）：
        # 根路径返回 Spring Boot 默认错误 JSON 就把 cms 判成 spring，
        # 于是一整类 CMS 的专项插件全不跑。C4-4/C4-5 实测 0 CONFIRMED 即此因。
        if not all_plugins:
            all_plugins, fallback_packages = _load_fallback_plugins()
            emit(
                "plugin_fallback",
                {
                    "plugin": fp_result.cms or req.cms or "auto",
                    "reason": "未匹配专用插件包，回退加载默认 ruoyi + spring 包",
                    "packages": fallback_packages,
                    "total_count": len(all_plugins),
                    "task_id": task_id,
                },
            )
        elif _is_weak_fingerprint(fp_result):
            # 弱证据：保留原判定的包，再补上其它可能同时成立的包。
            # 不丢弃原包 —— 用户看到 cms=spring 时仍应看到 spring 插件结果。
            base_cms = getattr(fp_result, "cms", "") or ""
            merged_packages = [f"plugins.{base_cms}"]
            for pkg in _EXPANDED_PACKAGES:
                if pkg not in merged_packages:
                    merged_packages.append(pkg)
            expanded, expand_detail = _load_plugins_from(tuple(merged_packages))
            if expanded:
                all_plugins = expanded
                emit(
                    "plugin_fallback",
                    {
                        "plugin": base_cms,
                        "reason": (
                            f"指纹为弱证据（{base_cms} 置信度 "
                            f"{getattr(fp_result, 'confidence', 0):.2f} ≤ {_WEAK_FINGERPRINT_CONFIDENCE}），"
                            "补加载 ruoyi/spring/jeecgboot，避免整包漏扫"
                        ),
                        "packages": expand_detail,
                        "total_count": len(all_plugins),
                        "task_id": task_id,
                    },
                )

        return all_plugins

    def _load_extension_plugins(
        self, req: ScanRequest, all_plugins: List[type], emit: Callable[..., None], task_id: str
    ) -> List[type]:
        """步骤 6b：通用/外部/用户/entry_points/nuclei 来源。"""
        # 通用漏洞检测包
        # ⚠ 旧实现只记 debug（生产默认 WARNING 级不可见）：plugins.common 加载失败时
        # 用户只看到「已加载 N 个插件」，少掉的十几个通用 POC 无从得知 → 升为 warning。
        try:
            common_plugins = load_plugins("plugins.common")
            all_plugins = all_plugins + common_plugins
            emit(
                "plugins_loaded",
                {"common_count": len(common_plugins), "total_count": len(all_plugins), "task_id": task_id},
            )
        except Exception as e:
            logger.warning("通用插件包 plugins.common 加载失败：%s", e, exc_info=True)

        # P0: 外部插件加载（--plugin-path）
        if req.plugin_paths:
            from core.loader import load_external_plugins

            external_plugins = load_external_plugins(req.plugin_paths)
            if external_plugins:
                all_plugins = all_plugins + external_plugins
                emit(
                    "plugins_loaded",
                    {
                        "external_count": len(external_plugins),
                        "total_count": len(all_plugins),
                        "task_id": task_id,
                    },
                )

        # E5: 用户安装目录插件（~/.ruoyi-scan/plugins/，--plugin-update 安装）
        try:
            from lib.plugin_repo import load_user_installed_plugins

            user_plugins = load_user_installed_plugins()
            if user_plugins:
                all_plugins = all_plugins + user_plugins
                emit(
                    "plugins_loaded",
                    {
                        "user_plugin_count": len(user_plugins),
                        "total_count": len(all_plugins),
                        "task_id": task_id,
                    },
                )
        except Exception as e:
            # 用户安装插件（~/.ruoyi-scan/plugins/）加载失败升为 warning：用户装完插件
            # 却看不到 POC，唯一线索就是这条日志，debug 级不可见。
            logger.warning("用户安装插件目录加载失败（~/.ruoyi-scan/plugins/）：%s", e, exc_info=True)

        # P1: entry_points 注册的第三方插件（pip install 自动发现）
        try:
            from core.loader import load_entry_point_plugins

            ep_plugins = load_entry_point_plugins()
            if ep_plugins:
                all_plugins = all_plugins + ep_plugins
                emit(
                    "plugins_loaded",
                    {
                        "entry_point_count": len(ep_plugins),
                        "total_count": len(all_plugins),
                        "task_id": task_id,
                    },
                )
        except Exception as e:
            # entry_points 注册的第三方插件加载失败升为 warning（pip 安装的插件包
            # 依赖/入口配置错误时用户需可见，否则静默少了整批插件）。
            logger.warning("entry_points 第三方插件加载失败：%s", e, exc_info=True)

        # E4: nuclei YAML 模板（--nuclei）
        if req.nuclei_paths:
            from lib.nuclei_loader import load_nuclei_templates

            try:
                nuclei_plugins = load_nuclei_templates(
                    req.nuclei_paths,
                    tags=req.nuclei_tags,
                    severities=req.nuclei_severity,
                    exclude_tags=req.nuclei_exclude_tags,
                )
                if nuclei_plugins:
                    all_plugins = all_plugins + nuclei_plugins
                    emit(
                        "plugins_loaded",
                        {
                            "nuclei_count": len(nuclei_plugins),
                            "total_count": len(all_plugins),
                            "task_id": task_id,
                        },
                    )
            except Exception as e:
                # nuclei 模板加载失败升为 warning 并带上路径：用户指定了 --nuclei 却
                # 一个模板没跑时，需能从日志看出是路径/模板语法问题。事件仍照发。
                logger.warning("nuclei 模板加载失败（路径=%s）：%s", req.nuclei_paths, e, exc_info=True)
                emit("nuclei_error", {"error": str(e), "task_id": task_id})

        return all_plugins

    def _build_waf_bypass(
        self, req: ScanRequest, waf_result: Dict[str, Any], target: str, session: SessionManager
    ) -> Optional[Any]:
        """构建 WAF 绕过协调器（从 main.py 抽取）"""
        bypass_mode = req.bypass_waf or "auto"
        waf_type = waf_result.get("waf", "")

        # 方案 A：对抗型传输层兜底。仅在用户显式开启时启用；启用前确认 Scrapling 已安装，
        # 否则降级为常规绕过并告警（避免静默产生永远失败的无效尝试）。
        engine_fallback = bool(getattr(req, "adversarial_transport", False))
        scrapling_version = ""
        if engine_fallback:
            try:
                import scrapling  # noqa: F401

                scrapling_version = getattr(scrapling, "__version__", "?")
            except ImportError:
                logger.warning(
                    "已请求 --adversarial-transport 但未安装 Scrapling，本次降级为常规绕过"
                    "（安装：pip install 'ruoyi-scan[adversarial]'）"
                )
                engine_fallback = False

        # 仅在确实会构建协调器的模式下打印「已启用」：--bypass-waf off 时下方两个分支
        # 都会被跳过（返回 None），提前提示会造成误导
        if engine_fallback and bypass_mode in ("auto", "on"):
            logger.info("对抗型传输层已启用（Scrapling %s），JS 挑战型 WAF 将追加引擎级兜底", scrapling_version)

        if waf_type and bypass_mode in ("auto", "on"):
            from lib.origin_finder import OriginIPFinder
            from lib.waf_bypass import BypassStatsTracker, WafBypassCoordinator

            stats_tracker = BypassStatsTracker()
            origin_ip = ""
            try:
                from urllib.parse import urlparse

                domain = urlparse(target).hostname or ""
                if domain:
                    finder = OriginIPFinder(timeout=5)
                    ips = finder.find_origin_ip(domain, session)
                    if ips:
                        origin_ip = ips[0]
            except Exception:
                logger.debug("源站 IP 探测失败", exc_info=True)
            return WafBypassCoordinator(
                waf_type=waf_type,
                origin_ip=origin_ip,
                stats_tracker=stats_tracker,
                enable_engine_fallback=engine_fallback,
            )

        # 未识别出 WAF 但用户强制 on：仍构建协调器（对误报/新型 WAF 保留绕过尝试）
        if not waf_type and bypass_mode == "on":
            from lib.waf_bypass import BypassStatsTracker, WafBypassCoordinator

            stats_tracker = BypassStatsTracker()
            return WafBypassCoordinator(
                waf_type="", stats_tracker=stats_tracker, enable_engine_fallback=engine_fallback
            )

        return None

    def _run_recon(
        self,
        req: ScanRequest,
        target: str,
        _emit: Callable[..., None],
        task_id: str,
        limiter: Optional[Any] = None,
        proxy_pool: Optional[Any] = None,
        request_counter: Optional[RequestCounter] = None,
    ) -> Dict[str, Any]:
        """D14：执行主动信息收集（爬虫 + 子域名 + JS 提取）

        Args:
            limiter: 本次扫描共享的请求限速桶（request 作用域下由 orchestrator 创建）。
                临时会话挂同一个桶，保证侦察流量与主扫描合计不超过 --rate。

        Returns:
            {
                'crawled_urls': [...],     # 爬虫抓取的所有 URL
                'subdomains': [...],       # 发现的子域名
                'js_endpoints': [...],     # JS 中提取的端点
            }
        """
        result: Dict[str, Any] = {
            "crawled_urls": [],
            "subdomains": [],
            "js_endpoints": [],
            "surface": None,  # 攻击面清单（SurfaceInventory），仅在爬虫/JS 分支成功后填充
        }

        # 子域名枚举（独立于爬虫，仅依赖域名）
        if req.subdomain:
            try:
                from lib.subdomain import SubdomainEnumerator

                domain = self._host_of(target)
                if domain:
                    _emit(
                        "recon_start",
                        {
                            "type": "subdomain",
                            "domain": domain,
                            "task_id": task_id,
                        },
                    )
                    enum = SubdomainEnumerator(verify_dns=False)
                    subs = enum.enumerate(domain)
                    result["subdomains"] = subs
            except Exception as e:
                _emit(
                    "recon_error",
                    {
                        "type": "subdomain",
                        "error": str(e),
                        "task_id": task_id,
                    },
                )

        # 主动爬虫 + JS 端点提取
        if req.crawl or req.js_extract:
            recon_session: Optional[SessionManager] = None
            try:
                from lib.crawler import Crawler
                from lib.js_extractor import JSExtractor

                # 创建临时 session（避免与主 session 状态污染）
                # 同样显式传 pool_size 与线程数匹配（#4）：爬虫/JS 提取的并发也依赖连接池复用。
                recon_session = SessionManager(
                    proxy=req.proxy or None,
                    proxy_pool=proxy_pool,
                    debug=req.debug,
                    timeout=req.timeout,
                    pool_size=req.threads,
                    rate=req.rate,
                    rate_scope=req.rate_scope,
                    limiter=limiter,
                    request_counter=request_counter,
                )

                _emit(
                    "recon_start",
                    {
                        "type": "crawl",
                        "target": target,
                        "max_depth": req.crawl_depth,
                        "max_pages": req.crawl_max_pages,
                        "task_id": task_id,
                    },
                )

                # 爬取（如果仅需要 JS 提取，也需先爬取收集 JS URL）
                crawler = Crawler(
                    max_depth=req.crawl_depth,
                    max_pages=req.crawl_max_pages,
                    same_host_only=True,
                    include_static=False,
                )
                # 同时收集 JS URL（即使 include_static=False，cralwer 内部会特殊处理 .js）
                crawl_result = crawler.crawl_with_js_urls(target, recon_session)
                result["crawled_urls"] = crawl_result["all"]

                # JS 端点提取
                if req.js_extract and crawl_result["js"]:
                    _emit(
                        "recon_start",
                        {
                            "type": "js_extract",
                            "js_count": len(crawl_result["js"]),
                            "task_id": task_id,
                        },
                    )
                    extractor = JSExtractor()
                    endpoints = extractor.extract_from_urls(crawl_result["js"], session=recon_session)
                    # 仅保留端点 URL（去重）
                    seen = set()
                    endpoint_urls = []
                    for ep in endpoints:
                        if ep.url not in seen:
                            seen.add(ep.url)
                            endpoint_urls.append(ep.url)
                    result["js_endpoints"] = endpoint_urls

                # D14 回流：把爬到的页面与 JS 端点固化为扫描级清单。
                # 必须放在 result["js_endpoints"] 赋值之后，否则清单会缺 JS 端点。
                from lib.surface_inventory import SurfaceInventory

                inv = SurfaceInventory(pages=crawl_result["pages"])
                for u in crawl_result["pages"]:
                    inv.add(u, "crawl")
                for u in result["js_endpoints"]:
                    inv.add(u, "js")
                result["surface"] = inv

            except Exception as e:
                _emit(
                    "recon_error",
                    {
                        "type": "crawl",
                        "error": str(e),
                        "task_id": task_id,
                    },
                )
            finally:
                # 爬虫/JS 提取中途异常也要关闭临时会话，否则连接池泄漏
                if recon_session is not None:
                    try:
                        recon_session.close()
                    except Exception:
                        logger.debug("recon 会话关闭失败", exc_info=True)

        return result

    def _host_of(self, url: str) -> str:
        """从 URL 提取主机名"""
        from urllib.parse import urlparse

        return urlparse(url).hostname or ""

    def _parse_ports(self, ports_str: str, default: List[int]) -> List[int]:
        """解析端口字符串"""
        if not ports_str:
            return default
        return [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]

    def _parse_formats(self, fmt_str: Optional[str] = None) -> Union[str, List[str], None]:
        """解析报告格式字符串"""
        if not fmt_str:
            return None
        fmt_str = fmt_str.strip().lower()
        if fmt_str == "all":
            return "all"
        valid = {"html", "json", "csv", "pdf", "docx", "xlsx"}
        parts = [f.strip() for f in fmt_str.split(",") if f.strip()]
        parts = [p for p in parts if p in valid]
        return parts or None

    def _persist_results(self, task_id: str, results: List[ScanResult]) -> None:
        """把结果明细落盘（失败仅记录 debug，不阻断扫描）

        事件表有 500 条上限，长任务的结果会被截断；findings 表按 seq 保序
        存完整快照，重启后 /api/scan/{id}/results 与报告重建都从这里取。
        """
        storage = getattr(self.registry, "storage", None) if self.registry else None
        if storage is None:
            return
        try:
            # 采纳 main 的写法：只接受 to_dict()，不再用 vars() 兜底。
            # vars() 是安全加固时去掉的 —— 它会把任意对象的 __dict__ 整体落盘，
            # 结果对象换成别的类型时可能写入非预期字段。results 的契约就是 ScanResult。
            rows = [r.to_dict() for r in results]
            storage.save_results(task_id, rows)
        except Exception:
            logger.debug("结果明细落盘失败 task=%s", task_id, exc_info=True)

    def shutdown(self) -> None:
        """关闭线程池（API 模式停服 / 测试清理时调用）

        策略：
          1. cancel_futures=True 取消尚未开始的任务
          2. join 运行中线程（5s 超时）——在 mock 仍生效的 TestClient 退出阶段，
             后台线程应快速完成（空插件列表）；超时则放弃等待，由 daemon 标志兜底
        """
        with self._pool_lock:
            pool = self._pool
            self._pool = None
        if pool:
            pool.shutdown(wait=False, cancel_futures=True)
            for t in list(pool._threads):
                t.join(timeout=5)
