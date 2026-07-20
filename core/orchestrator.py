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
#   - ThreadPoolExecutor 保持不变
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from config import settings
from core.engine import ScanEngine
from core.fingerprint import detect_cms, detect_waf
from core.loader import load_plugins
from core.models import STATUS_CONFIRMED, FingerprintResult, ScanResult
from core.report import ReportBuilder
from core.router import Router
from core.session import SessionManager
from lib.http import normalize_target

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
    # 可选：认证信息（登录链）
    auth: Optional[dict] = None
    # D14：主动信息收集
    crawl: bool = False  # 是否启用主动爬虫
    crawl_depth: int = 2  # 爬虫深度
    crawl_max_pages: int = 50  # 爬虫最大页面数
    subdomain: bool = False  # 是否启用子域名枚举
    js_extract: bool = False  # 是否启用 JS 端点提取


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

    def to_dict(self) -> dict:
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
            "error": self.error,
            "fingerprint": {
                "cms": self.fingerprint.cms if self.fingerprint else "",
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

    def __init__(self, registry=None):
        """初始化编排器

        Args:
            registry: TaskRegistry 实例（API 模式用，None 则 CLI 模式）
        """
        self.registry = registry
        self._pool = None  # 懒加载线程池（API 模式）
        self._pool_lock = threading.Lock()

    def run_sync(self, req: ScanRequest, on_event: EventHandler = None) -> List[ScanResult]:
        """同步执行扫描（CLI 模式）

        Args:
            req: 扫描请求
            on_event: 事件回调（None 则无事件输出）

        Returns:
            扫描结果列表
        """
        task = ScanTask(
            task_id=uuid.uuid4().hex[:12],
            request=req,
            started_at=time.time(),
        )
        return self._run(task, on_event)

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
        with self._pool_lock:
            if self._pool is None:
                self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scan")
        self._pool.submit(self._run, task, self._api_event_handler)
        return task_id

    def _api_event_handler(self, event_type: str, payload: Any):
        """API 模式事件回调：推送到 registry（线程安全）"""
        if self.registry:
            task_id = getattr(payload, "task_id", None) if hasattr(payload, "task_id") else None
            # _run 内部会传入带 task_id 的事件
            if isinstance(payload, dict) and "task_id" in payload:
                task_id = payload["task_id"]
            if task_id:
                self.registry.notify(task_id, event_type, payload)

    def _run(self, task: ScanTask, on_event: EventHandler = None) -> List[ScanResult]:
        """实际扫描逻辑（同步，从 main.py run_mode 抽取）

        Args:
            task: 扫描任务句柄
            on_event: 事件回调

        Returns:
            扫描结果列表
        """
        req = task.request
        target = normalize_target(req.target)

        def _emit(event_type: str, payload: Any):
            """发送事件（同时调用回调 + 通知 registry）"""
            if on_event:
                try:
                    on_event(event_type, payload)
                except Exception:
                    pass
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
            session = SessionManager(
                proxy=req.proxy or None,
                debug=req.debug,
                timeout=req.timeout,
            )
            engine = ScanEngine(threads=req.threads, rate=req.rate)

            # 3. 口令字典分级
            if req.pass_level != "full" and req.pass_level in settings.PASSWORD_DICT_BY_LEVEL:
                settings.PASSWORD_DICT = settings.PASSWORD_DICT_BY_LEVEL[req.pass_level]

            # 4. 指纹识别
            router = Router()
            if req.cms:
                fp_result = FingerprintResult(cms=req.cms, version="", confidence=1.0, matched=["manual"])
            else:
                fp_result = detect_cms(target, session)

            task.fingerprint = fp_result
            _emit(
                "fingerprint",
                {
                    "cms": fp_result.cms,
                    "version": fp_result.version,
                    "confidence": fp_result.confidence,
                    "matched": fp_result.matched,
                    "task_id": task.task_id,
                },
            )

            all_plugins = router.resolve(fp_result)

            # 5. WAF 探测 + 绕过协调器
            waf_result = detect_waf(target, session)
            task.waf_info = waf_result
            _emit(
                "waf",
                {
                    "waf": waf_result.get("waf", ""),
                    "display": waf_result.get("display", ""),
                    "task_id": task.task_id,
                },
            )

            waf_bypass_coordinator = self._build_waf_bypass(req, waf_result, target, session)

            # 6. 插件加载 + 路由
            if not all_plugins:
                all_plugins = load_plugins("plugins.ruoyi")

            # 通用漏洞检测包
            try:
                common_plugins = load_plugins("plugins.common")
                all_plugins = all_plugins + common_plugins
            except Exception:
                pass

            # 指定插件过滤（API 可指定插件子集）
            if req.plugins:
                all_plugins = [cls for cls in all_plugins if getattr(cls, "name", "") in req.plugins]

            # 按 category 分组（对应 MODE_CATEGORIES）
            mode_categories = {
                "u": ["recon", "vuln", "brute"],
                "m": ["recon"],
                "p": ["vuln"],
                "l": ["brute"],
            }
            plugins_by_cat = {}
            for cls in all_plugins:
                cat = getattr(cls, "category", "")
                plugins_by_cat.setdefault(cat, []).append(cls)

            # 7. 引擎执行
            all_results = []
            categories = mode_categories.get(req.mode, ["vuln"])
            total_plugins = sum(len(plugins_by_cat.get(c, [])) for c in categories)
            done_count = [0]  # 闭包可变

            def _on_result(res: ScanResult):
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
            session.close()

            # 8. 报告生成（可选）
            if req.report_dir:
                summary = {
                    "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(task.started_at)),
                    "duration": time.time() - task.started_at,
                    "request_count": session.request_count,
                    "mode": req.mode,
                    "fingerprint": {
                        "cms": fp_result.cms,
                        "confidence": fp_result.confidence,
                        "matched": fp_result.matched,
                    },
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
                },
            )

            return all_results

        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            task.finished_at = time.time()
            task.duration = task.finished_at - task.started_at
            _emit(
                "error",
                {
                    "error": str(e),
                    "task_id": task.task_id,
                },
            )
            _emit("status", {"status": "failed", "task_id": task.task_id})
            return task.results

    def _build_waf_bypass(self, req: ScanRequest, waf_result: dict, target: str, session: SessionManager):
        """构建 WAF 绕过协调器（从 main.py 抽取）"""
        bypass_mode = req.bypass_waf or "auto"
        waf_type = waf_result.get("waf", "")

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
                pass
            return WafBypassCoordinator(waf_type=waf_type, origin_ip=origin_ip, stats_tracker=stats_tracker)

        if not waf_type and bypass_mode == "on":
            from lib.waf_bypass import BypassStatsTracker, WafBypassCoordinator

            stats_tracker = BypassStatsTracker()
            return WafBypassCoordinator(waf_type="", stats_tracker=stats_tracker)

        return None

    def _run_recon(self, req: ScanRequest, target: str, _emit, task_id: str) -> dict:
        """D14：执行主动信息收集（爬虫 + 子域名 + JS 提取）

        Returns:
            {
                'crawled_urls': [...],     # 爬虫抓取的所有 URL
                'subdomains': [...],       # 发现的子域名
                'js_endpoints': [...],     # JS 中提取的端点
            }
        """
        result = {
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
            try:
                from lib.crawler import Crawler
                from lib.js_extractor import JSExtractor

                # 创建临时 session（避免与主 session 状态污染）
                recon_session = SessionManager(
                    proxy=req.proxy or None,
                    debug=req.debug,
                    timeout=req.timeout,
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

                recon_session.close()
            except Exception as e:
                _emit(
                    "recon_error",
                    {
                        "type": "crawl",
                        "error": str(e),
                        "task_id": task_id,
                    },
                )

        return result

    def _host_of(self, url: str) -> str:
        """从 URL 提取主机名"""
        from urllib.parse import urlparse

        return urlparse(url).hostname or ""

    def _parse_ports(self, ports_str: str, default: list) -> list:
        """解析端口字符串"""
        if not ports_str:
            return default
        return [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]

    def _parse_formats(self, fmt_str: str):
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

    def shutdown(self):
        """关闭线程池（API 模式停服时调用）"""
        with self._pool_lock:
            if self._pool:
                self._pool.shutdown(wait=False)
                self._pool = None
