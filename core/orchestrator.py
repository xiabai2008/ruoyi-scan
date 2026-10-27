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
#   - core/models.py 零修改
#   - ThreadPoolExecutor 使用 daemon 线程（避免测试/进程退出时后台线程阻塞）
import threading
import time
import uuid
import weakref
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures.thread import _worker
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, FingerprintResult, ScanResult
from config import settings
from core.cache import FingerprintCache
from core.engine import ScanEngine
from core.fingerprint import detect_cms, detect_waf
from core.http import normalize_target
from core.loader import load_plugins
from core.report import ReportBuilder
from core.router import Router
from core.session import SessionManager


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
    proxy: str = ""  # 代理地址
    timeout: int = 10  # 超时秒数
    debug: bool = False  # 调试模式
    report_dir: str = ""  # 报告输出目录（空=不生成报告）
    report_format: str = "all"  # 报告格式
    no_dedup: bool = False  # 关闭去重
    pass_level: str = "full"  # 口令字典级别
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
    # 注：auth 字段在扫描请求参数区已声明过（历史遗留重复声明），功能不受影响，
    # dataclass 重复字段以最后一次声明为准，此处仅为 D26 语义补充说明
    # D26：认证扫描增强（CLI args.auth / args.auth_file / args.auth_login 解析后传入）
    auth: Optional[Dict[str, Any]] = None  # {"cookies": {...}, "headers": {...}, "type": "..."}
    # D19：扫描模板名称（quick / deep / compliance / dengbao）
    template: str = ""
    # P0：外部插件路径列表（--plugin-path 可多次指定）
    plugin_paths: Optional[List[str]] = None
    # E2：组件版本检测（--components 启用；默认关闭，向后兼容）
    components: bool = False
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
        # 最近一次 run_sync 的实际请求数：session 在 _run 内部已关闭，调用方拿不到
        # session.request_count，报告里只能写 0。此处留一个只读快照供 CLI 出报告用。
        self.last_request_count: int = 0
        # 最近一次 run_sync 的全站拦截探测结果（CLI 出报告时写进 summary）
        self.last_block_info: Dict[str, Any] = {"blocked": False}
        # 最近一次 run_sync 的登录墙探测结果（报告与 CLI 提示用）
        self.last_auth_wall: Dict[str, Any] = {"wall": False}

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
                self._pool.submit(self._run, task, None)
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
        return task_id

    def _run(self, task: ScanTask, on_event: Optional[EventHandler] = None) -> List[ScanResult]:
        """实际扫描逻辑（同步，从 main.py run_mode 抽取）

        Args:
            task: 扫描任务句柄
            on_event: 事件回调

        Returns:
            扫描结果列表
        """
        req = task.request
        target = normalize_target(req.target)
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
                self.registry.notify(task.task_id, event_type, payload)
                # 状态变更时同步 task_dict 到 registry（供 GET /api/scan 查询）
                if event_type in ("status", "fingerprint", "waf", "complete"):
                    self.registry.update_task_dict(task.task_id, task.to_dict())

        # 资源泄漏防护（#3）：session 在 try 块内创建，旧实现只在正常路径 (:651)
        # 调用 session.close()；一旦其后的任意步骤抛异常走 except 直接 return，session
        # 永不关闭，连接池与 keep-alive socket 泄漏。这里提前置 None，由 finally 统一关闭
        # （finally 在本方法唯一出口处执行，覆盖正常返回与异常返回两条路径）。
        session: Optional[SessionManager] = None

        try:
            task.status = "running"
            _emit("status", {"status": "running", "task_id": task.task_id})

            # 1. 端口扫描（可选）
            if req.portscan:
                from core.portscan import DEFAULT_PORTS, PortScanner

                host = self._host_of(target)
                ports = self._parse_ports(req.ports, DEFAULT_PORTS)
                scanner = PortScanner(timeout=req.timeout, threads=req.threads)
                port_results = scanner.scan(host, ports)
                _emit(
                    "portscan",
                    {
                        "host": host,
                        "open_count": len(port_results),
                        "total": len(ports),
                        "ports": [{"port": p.port, "service": p.service, "banner": p.banner} for p in port_results],
                        "task_id": task.task_id,
                    },
                )

            # D14：主动信息收集（爬虫 + 子域名 + JS 提取）
            if req.crawl or req.subdomain or req.js_extract:
                recon_info = self._run_recon(req, target, _emit, task.task_id)
                if recon_info.get("subdomains"):
                    _emit(
                        "recon",
                        {
                            "type": "subdomain",
                            "subdomains": recon_info["subdomains"],
                            "count": len(recon_info["subdomains"]),
                            "task_id": task.task_id,
                        },
                    )
                if recon_info.get("crawled_urls"):
                    _emit(
                        "recon",
                        {
                            "type": "crawl",
                            "urls": recon_info["crawled_urls"],
                            "count": len(recon_info["crawled_urls"]),
                            "task_id": task.task_id,
                        },
                    )
                if recon_info.get("js_endpoints"):
                    _emit(
                        "recon",
                        {
                            "type": "js_extract",
                            "endpoints": recon_info["js_endpoints"],
                            "count": len(recon_info["js_endpoints"]),
                            "task_id": task.task_id,
                        },
                    )

            # 2. 会话创建
            # 连接池尺寸必须与线程数挂钩（性能 P0）：旧实现不传 pool_size，session.py 里
            # _pool = max(pool_size or settings.THREADS or 10, 10)，而 settings.THREADS=1
            # 且从不被 --threads 写回 → 连接池恒为 10（pool_maxsize=20）。--threads 50 时
            # 引擎开 50 线程但池只有 20，30 个线程每次请求都新建 TCP 连接，keep-alive
            # 复用率崩掉。这里显式把 pool_size 设为线程数，使池与并发匹配。
            session = SessionManager(
                proxy=req.proxy or None,
                debug=req.debug,
                timeout=req.timeout,
                pool_size=req.threads,
            )
            engine = ScanEngine(
                threads=req.threads,
                rate=req.rate,
                deadline=(time.monotonic() + req.time_budget) if req.time_budget > 0 else None,
            )

            # D26：认证扫描增强（将 auth 配置注入 session）
            if req.auth:
                from lib.auth_scan import apply_auth_to_session

                apply_auth_to_session(session, req.auth)
                auth_summary = []
                if req.auth.get("cookies"):
                    auth_summary.append(f"{len(req.auth['cookies'])} 个 Cookie")
                if req.auth.get("headers"):
                    auth_summary.append(f"{len(req.auth['headers'])} 个自定义头")
                _emit(
                    "auth",
                    {
                        "summary": " + ".join(auth_summary),
                        "cookies": len(req.auth.get("cookies", {})),
                        "headers": len(req.auth.get("headers", {})),
                        "task_id": task.task_id,
                    },
                )

            # 3. 口令字典分级：只解析本次扫描的字典路径并注入当前 session，不改写进程级
            # settings.PASSWORD_DICT——API 并发扫描下不同 pass_level 的任务会互相覆盖字典
            # （爆破类插件优先读取 session.password_dict，回退进程级默认值）
            selected_password_dict = settings.PASSWORD_DICT
            if req.pass_level != "full" and req.pass_level in settings.PASSWORD_DICT_BY_LEVEL:
                selected_password_dict = settings.PASSWORD_DICT_BY_LEVEL[req.pass_level]
            session.password_dict = selected_password_dict

            # 3.5 全站拦截探测（WAF / 网关 / 认证墙）
            # 站点被统一拒绝时，每个插件拿到的都是同一个 403，按插件自身逻辑会落到
            # 「没命中 = 不存在」，报告会写出「N 项确认不存在」——比漏报更危险的假安全感。
            # 这里先识别拦截状态，插件跑完后再把 SAFE 统一降级为 UNKNOWN。
            from lib.reachability import detect_blocked

            block_info = detect_blocked(session, target)
            self.last_block_info = block_info
            if block_info["blocked"]:
                _emit("blocked", dict(block_info, task_id=task.task_id))

            # 3.6 登录墙探测（应用自身认证要求，与 WAF 拦截不同）
            # 真实 RuoYi 未认证访问受保护接口是 302 -> /login（跟随后 200 登录页），
            # 不是 401。插件只看到 200 登录页就会把「没测到」写成 SAFE。
            from lib.reachability import detect_auth_wall

            auth_wall = detect_auth_wall(session, target)
            self.last_auth_wall = auth_wall
            if auth_wall["wall"]:
                _emit("auth_wall", dict(auth_wall, task_id=task.task_id))

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
                all_plugins = router.resolve(fp_result)

            task.fingerprint = fp_result
            _emit(
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

            # 5. WAF 探测 + 绕过协调器
            # 传入 fp_cache 复用 detect_cms 已缓存的根响应（未命中才发请求，向后兼容）
            waf_result = detect_waf(target, session, cache=fp_cache)
            task.waf_info = waf_result
            _emit(
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
                from lib.component_detect import ComponentDetector, to_scan_result

                try:
                    detector = ComponentDetector()
                    component_results = detector.detect_all(target, session, ruoyi_version=fp_result.version)
                    for cr in component_results:
                        _emit(
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
                    _emit("component", {"error": str(e), "task_id": task.task_id})

            waf_bypass_coordinator = self._build_waf_bypass(req, waf_result, target, session)

            # WAF 绕过状态事件（CLI 打印绕过模式信息）
            bypass_mode = req.bypass_waf or "auto"
            if waf_bypass_coordinator:
                _emit(
                    "waf_bypass",
                    {
                        "mode": bypass_mode,
                        "enabled": True,
                        "origin_ip": getattr(waf_bypass_coordinator, "origin_ip", ""),
                        "task_id": task.task_id,
                    },
                )

            # 6. 插件加载 + 路由
            if not all_plugins:
                all_plugins = load_plugins("plugins.ruoyi")
                _emit(
                    "plugin_fallback",
                    {"task_id": task.task_id},
                )

            # 通用漏洞检测包
            # ⚠ 旧实现只记 debug（生产默认 WARNING 级不可见）：plugins.common 加载失败时
            # 用户只看到「已加载 N 个插件」，少掉的十几个通用 POC 无从得知 → 升为 warning。
            try:
                common_plugins = load_plugins("plugins.common")
                all_plugins = all_plugins + common_plugins
                _emit(
                    "plugins_loaded",
                    {"common_count": len(common_plugins), "total_count": len(all_plugins), "task_id": task.task_id},
                )
            except Exception as e:
                logger.warning("通用插件包 plugins.common 加载失败：%s", e, exc_info=True)

            # P0: 外部插件加载（--plugin-path）
            if req.plugin_paths:
                from core.loader import load_external_plugins

                external_plugins = load_external_plugins(req.plugin_paths)
                if external_plugins:
                    all_plugins = all_plugins + external_plugins
                    _emit(
                        "plugins_loaded",
                        {
                            "external_count": len(external_plugins),
                            "total_count": len(all_plugins),
                            "task_id": task.task_id,
                        },
                    )

            # E5: 用户安装目录插件（~/.ruoyi-scan/plugins/，--plugin-update 安装）
            try:
                from lib.plugin_repo import load_user_installed_plugins

                user_plugins = load_user_installed_plugins()
                if user_plugins:
                    all_plugins = all_plugins + user_plugins
                    _emit(
                        "plugins_loaded",
                        {
                            "user_plugin_count": len(user_plugins),
                            "total_count": len(all_plugins),
                            "task_id": task.task_id,
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
                    _emit(
                        "plugins_loaded",
                        {
                            "entry_point_count": len(ep_plugins),
                            "total_count": len(all_plugins),
                            "task_id": task.task_id,
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
                        _emit(
                            "plugins_loaded",
                            {
                                "nuclei_count": len(nuclei_plugins),
                                "total_count": len(all_plugins),
                                "task_id": task.task_id,
                            },
                        )
                except Exception as e:
                    # nuclei 模板加载失败升为 warning 并带上路径：用户指定了 --nuclei 却
                    # 一个模板没跑时，需能从日志看出是路径/模板语法问题。事件仍照发。
                    logger.warning("nuclei 模板加载失败（路径=%s）：%s", req.nuclei_paths, e, exc_info=True)
                    _emit("nuclei_error", {"error": str(e), "task_id": task.task_id})

            # 指定插件过滤（API 可指定插件子集）
            if req.plugins:
                all_plugins = [cls for cls in all_plugins if getattr(cls, "name", "") in req.plugins]

            # D19：扫描模板过滤插件
            template_obj = None
            if req.template:
                from lib.scan_templates import filter_plugins, get_template

                template_obj = get_template(req.template)
                if template_obj:
                    before_count = len(all_plugins)
                    all_plugins = filter_plugins(all_plugins, template_obj)
                    after_count = len(all_plugins)
                    _emit(
                        "template",
                        {
                            "name": template_obj.display_name,
                            "before": before_count,
                            "after": after_count,
                            "task_id": task.task_id,
                        },
                    )

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

            # 7. 引擎执行
            # （all_results 已在 try 外初始化：异常路径可返回已收集的部分结果）
            categories = mode_categories.get(req.mode, ["vuln"])
            total_plugins = sum(len(plugins_by_cat.get(c, [])) for c in categories)
            done_count = [0]  # 闭包可变

            def _on_result(res: ScanResult) -> None:
                """引擎结果回调：推送事件 + 计数"""
                all_results.append(res)
                done_count[0] += 1
                _emit(
                    "result",
                    {
                        "name": res.name,
                        "status": res.status,
                        "severity": res.severity,
                        "url": res.url,
                        "evidence": res.evidence,
                        "extra": res.extra if isinstance(res.extra, dict) else {},
                        "task_id": task.task_id,
                    },
                )
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
                    classes, target, session, on_result=_on_result, waf_bypass_coordinator=waf_bypass_coordinator
                )

            task.results = all_results
            task.request_count = session.request_count
            # E2：组件检测结果并入任务结果（报告统计口径：vuln 类 CONFIRMED 计入）
            for cr in component_results:
                all_results.append(to_scan_result(cr))
            # SAFE → UNKNOWN：全站拦截时没有任何一条「确认不存在」成立（三态铁律）
            from lib.reachability import (
                downgrade_auth_wall_safe,
                downgrade_safe_results,
                upgrade_denied_safe_to_unknown,
            )

            # 单接口被拒（401/403/429）：只有该接口没测到，不是"漏洞不存在"
            denied = upgrade_denied_safe_to_unknown(all_results)
            if denied:
                _emit("denied_downgrade", {"count": denied, "task_id": task.task_id})

            # 登录墙：拿到 200 登录页的 SAFE 同样是"没测到"，降级为 UNKNOWN
            wall_downgraded = downgrade_auth_wall_safe(all_results, auth_wall)
            if wall_downgraded:
                _emit(
                    "auth_wall_downgrade",
                    {
                        "count": wall_downgraded,
                        "reason": auth_wall.get("reason", ""),
                        "task_id": task.task_id,
                    },
                )

            downgraded = downgrade_safe_results(all_results, block_info)
            if downgraded:
                _emit(
                    "blocked_downgrade",
                    {
                        "count": downgraded,
                        "status": block_info.get("status", 0),
                        "reason": block_info.get("reason", ""),
                        "task_id": task.task_id,
                    },
                )
            task.results = all_results
            # session 关闭统一放到 finally（成功/失败路径共用，避免泄漏）

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
                }
                builder = ReportBuilder(results=all_results, target=target, summary=summary, dedup=not req.no_dedup)
                formats = self._parse_formats(req.report_format)
                paths = builder.render_all(req.report_dir, formats=formats)
                task.report_paths = paths
                _emit(
                    "report",
                    {
                        "paths": paths,
                        "task_id": task.task_id,
                    },
                )

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
            # 无论成功/失败都关闭会话（含认证注入、指纹、WAF、插件执行等中途异常）；
            # 口令字典已改为扫描级注入（session.password_dict），无需恢复进程级全局
            if session is not None:
                try:
                    session.close()
                except Exception:
                    logger.debug("会话关闭失败", exc_info=True)

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

    def _run_recon(self, req: ScanRequest, target: str, _emit: Callable[..., None], task_id: str) -> Dict[str, Any]:
        """D14：执行主动信息收集（爬虫 + 子域名 + JS 提取）

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
                    debug=req.debug,
                    timeout=req.timeout,
                    pool_size=req.threads,
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
