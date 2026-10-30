# E9：定时扫描调度器（--schedule）
#
# 设计：
#   1. cron 5 段式（如 "*/5 * * * *"）→ APScheduler CronTrigger（可选依赖）
#   2. 简单间隔（如 "every:300" 秒）→ threading.Timer 自调度（零依赖降级路径）
#   3. 任务落库（core.storage.schedules 表），服务重启自动恢复
#   4. 触发执行：调用 orchestrator.submit 异步扫描（不阻塞调度线程）
import re
import threading
import time
import uuid
from typing import Any, Dict, List

from common.logger import get_logger
from core.http import normalize_scan_target

logger = get_logger(__name__)

# 连续失败阈值：目标不可达时，避免每个 cron 周期都白起一次扫描（测评中每 5 分钟
# 自动触发一次、任务越堆越多）。达到阈值后暂停调度，等用户处理或点击恢复。
MAX_CONSECUTIVE_FAILURES = 3

CRON_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$")
INTERVAL_RE = re.compile(r"^every:(\d+)$")


def parse_schedule_expr(expr: str) -> Dict[str, Any]:
    """解析调度表达式

    Args:
        expr: '*/5 * * * *'（cron 5 段）或 'every:300'（秒）

    Returns:
        {'type': 'cron'|'interval', 'expr': ..., 'seconds': N}

    Raises:
        ValueError: 表达式格式非法
    """
    expr = (expr or "").strip()
    if not expr:
        raise ValueError("调度表达式为空")
    if INTERVAL_RE.match(expr):
        return {"type": "interval", "expr": expr, "seconds": int(INTERVAL_RE.match(expr).group(1))}
    if CRON_RE.match(expr):
        return {"type": "cron", "expr": expr, "seconds": 0}
    raise ValueError("调度表达式格式非法（支持 cron 5 段式 或 every:<秒>）")


class ScanScheduler:
    """定时扫描调度器

    用法：
        scheduler = ScanScheduler(orchestrator, storage)
        scheduler.add_job('*/5 * * * *', 'http://target/')
        scheduler.start()
        scheduler.shutdown()
    """

    def __init__(self, orchestrator=None, storage=None, on_trigger=None):
        """初始化调度器

        Args:
            orchestrator: ScanOrchestrator 实例（触发扫描用，None 则用 on_trigger 回调）
            storage: Storage 实例（持久化，None 则不落库）
            on_trigger: 触发回调 on_trigger(target, mode, payload)（替代 orchestrator）
        """
        self.orchestrator = orchestrator
        self.storage = storage
        self.on_trigger = on_trigger
        self._jobs: Dict[str, Dict[str, Any]] = {}  # job_id -> job info
        self._timers: Dict[str, threading.Timer] = {}  # job_id -> Timer（interval 模式）
        self._apscheduler = None  # APScheduler BackgroundScheduler（cron 模式，可选）
        self._lock = threading.Lock()
        self._running = False

    # ── 内部：APScheduler（cron 支持，可选依赖）──

    def _ensure_apscheduler(self):
        """初始化 APScheduler BackgroundScheduler（不可用时返回 None）"""
        if self._apscheduler is not None:
            return self._apscheduler
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
        except ImportError:
            return None
        try:
            self._apscheduler = BackgroundScheduler(timezone="Asia/Shanghai")
            self._apscheduler.start()
        except Exception as e:
            logger.debug("APScheduler 启动失败，降级 interval 模式: %s", e)
            self._apscheduler = None
        return self._apscheduler

    # ── 任务管理 ──

    def add_job(
        self, cron_expr: str, target: str, mode: str = "u", payload: Dict[str, Any] = None, job_id: str = ""
    ) -> str:
        """添加定时扫描任务

        Args:
            cron_expr: '*/5 * * * *' 或 'every:300'
            target: 扫描目标
            mode: 扫描模式 u/m/p/l
            payload: 附加参数（如报告目录）
            job_id: 任务 ID（缺省自动生成）

        Returns:
            job_id
        """
        parsed = parse_schedule_expr(cron_expr)
        # 目标与扫描入口共用校验（缺协议补 http://、仅 http/https、端口合法）
        target = normalize_scan_target(target)
        # job_id 用 UUID：旧实现把 cron 拼进 id，`*/30` 会生成含 `/` 的
        # `job_*/30_...`，REST 路径无法匹配 → 默认预设的调度删不掉（测评 P1-12）。
        # 自定义 id 也过滤成 URL 安全字符，避免把 `/`、`:` 带进路径参数。
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", job_id or "")
        job_id = safe_id or f"job_{uuid.uuid4().hex[:12]}"
        job = {
            "cron": cron_expr,
            "target": target,
            "mode": mode,
            "payload": payload or {},
            "parsed": parsed,
            "degraded": False,
            "effective_cron": cron_expr,
            "warning": "",
            "paused": False,
            "paused_reason": "",
            "last_task_id": "",
            "last_run_at": 0.0,
            "last_status": "",
            "consecutive_failures": 0,
            "counted_task_id": "",
        }
        with self._lock:
            self._jobs[job_id] = job
        if self.storage:
            try:
                self.storage.save_schedule(job_id, cron_expr, target, mode, payload)
            except Exception as e:
                logger.debug("定时任务落库失败: %s", e)
        if self._running:
            self._schedule_job(job_id, job)
            # _schedule_job 在锁外执行：期间可能已被并发 remove_job/shutdown 撤销，
            # 复查后清理刚注册的触发器，避免已删除任务仍触发一次与 timer 泄漏
            with self._lock:
                alive = self._running and job_id in self._jobs
            if not alive:
                self._unschedule_job(job_id)
        return job_id

    def remove_job(self, job_id: str) -> bool:
        """删除定时任务（内存 + 持久化），返回是否真的删除了记录

        旧实现只从内存 pop，内存里没有（如历史 job_id 含 `/` 无法通过 REST
        匹配而残留）就直接 return，数据库行永远删不掉。现在无论内存是否存在
        都尝试删库，并如实返回结果，供 API 决定 200/404。
        """
        with self._lock:
            job = self._jobs.pop(job_id, None)
        self._unschedule_job(job_id)
        removed_db = False
        if self.storage:
            try:
                existed = self.storage.get_schedule(job_id) is not None
                self.storage.delete_schedule(job_id)
                removed_db = existed
            except Exception as e:
                logger.warning("删除持久化定时任务失败 %s: %s", job_id, e)
        return job is not None or removed_db

    def resume_job(self, job_id: str) -> bool:
        """恢复被连续失败自动暂停的任务"""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            job["paused"] = False
            job["paused_reason"] = ""
            job["consecutive_failures"] = 0
            snapshot = dict(job)
        self._persist_state(job_id, snapshot)
        return True

    @property
    def cron_supported(self) -> bool:
        """当前构建是否支持 cron（APScheduler 可导入并启动成功）"""
        return self._ensure_apscheduler() is not None

    def _unschedule_job(self, job_id: str):
        """取消任务已注册的 timer / APScheduler 触发器（幂等，失败仅记录不抛出）"""
        timer = self._timers.pop(job_id, None)
        if timer:
            timer.cancel()
        if self._apscheduler is not None:
            try:
                # cron 注册时以 job_id 作为 APScheduler 任务 id；任务不存在属预期
                self._apscheduler.remove_job(job_id)
            except Exception as e:
                logger.debug("移除 APScheduler 任务失败 %s: %s", job_id, e)

    def list_jobs(self) -> List[Dict[str, Any]]:
        """列出任务（含降级/暂停/上次执行状态，供 UI 显式展示）"""
        with self._lock:
            return [
                {
                    "job_id": jid,
                    "cron": job["cron"],
                    "target": job["target"],
                    "mode": job["mode"],
                    "payload": job["payload"],
                    "degraded": bool(job.get("degraded")),
                    "effective_cron": job.get("effective_cron") or job["cron"],
                    "warning": job.get("warning", ""),
                    "paused": bool(job.get("paused")),
                    "paused_reason": job.get("paused_reason", ""),
                    "last_task_id": job.get("last_task_id", ""),
                    "last_run_at": job.get("last_run_at", 0.0),
                    "last_status": job.get("last_status", ""),
                    "consecutive_failures": job.get("consecutive_failures", 0),
                }
                for jid, job in self._jobs.items()
            ]

    # ── 调度执行 ──

    def start(self):
        """启动调度器（恢复 storage 中的任务 + 调度所有任务）"""
        if self._running:
            return
        self._running = True
        # 恢复持久化任务
        if self.storage:
            try:
                schedules = self.storage.list_schedules()
            except Exception as e:
                logger.debug("读取持久化定时任务失败: %s", e)
                schedules = []
            for rec in schedules:
                # 单条记录损坏（cron 非法/字段缺失）只跳过该条，不阻断其余任务恢复
                try:
                    jid = rec["job_id"]
                    # 内存中已有的任务（启动前手动添加）不重复恢复，以内存为准
                    if jid in self._jobs:
                        continue
                    payload = rec.get("payload") or {}
                    state = payload.get("_state") if isinstance(payload.get("_state"), dict) else {}
                    self._jobs[jid] = {
                        "cron": rec["cron"],
                        "target": rec["target"],
                        "mode": rec["mode"],
                        "payload": payload,
                        "parsed": parse_schedule_expr(rec["cron"]),
                        "degraded": False,
                        "effective_cron": rec["cron"],
                        "warning": "",
                        "paused": bool(state.get("paused", False)),
                        "paused_reason": str(state.get("paused_reason", "")),
                        "last_task_id": str(state.get("last_task_id", "")),
                        "last_run_at": float(state.get("last_run_at", 0.0) or 0.0),
                        "last_status": str(state.get("last_status", "")),
                        "consecutive_failures": int(state.get("consecutive_failures", 0) or 0),
                        "counted_task_id": str(state.get("counted_task_id", "")),
                    }
                except Exception as e:
                    logger.debug("跳过无法恢复的定时任务 %s: %s", rec, e)
        with self._lock:
            job_ids = list(self._jobs.keys())
        for jid in job_ids:
            # 旧实现缺陷：锁外 self._jobs[jid] 直接解引用，并发 remove_job 会把该 jid 删掉
            # 触发 KeyError。改为 get + None 跳过（check-then-act 竞态修复）。
            job = self._jobs.get(jid)
            if job is None:
                continue
            self._schedule_job(jid, job)

    def shutdown(self):
        """停止调度器"""
        self._running = False
        with self._lock:
            timers = list(self._timers.values())
            self._timers.clear()
        for t in timers:
            t.cancel()
        if self._apscheduler is not None:
            try:
                self._apscheduler.shutdown(wait=False)
            except Exception:
                pass
            self._apscheduler = None

    def _schedule_job(self, job_id: str, job: Dict[str, Any]):
        """按类型调度单个任务"""
        parsed = job["parsed"]
        if parsed["type"] == "interval":
            self._schedule_interval(job_id, job, parsed["seconds"])
        else:
            self._schedule_cron(job_id, job, parsed["expr"])

    def _schedule_interval(self, job_id: str, job: Dict[str, Any], seconds: int):
        """interval 模式：threading.Timer 自调度（零依赖）"""
        # 强制最小间隔 5 秒，防止误配的高频触发打爆目标
        seconds = max(seconds, 5)  # 最小 5 秒，防误配

        def _tick():
            if not self._running:
                return
            try:
                self._trigger(job_id, job)
            except Exception as e:
                logger.debug("定时触发失败: %s", e)
            finally:
                # 自调度下一轮
                with self._lock:
                    if self._running and job_id in self._jobs:
                        timer = threading.Timer(seconds, _tick)
                        timer.daemon = True
                        timer.start()
                        self._timers[job_id] = timer

        # 同一 job_id 重复注册（add_job 复用 id / cron 降级重入）时先取消旧 timer，
        # 否则旧的自调度链失去引用仍按旧节奏触发，造成重复执行
        with self._lock:
            # 并发 remove_job/shutdown 可能已撤销任务：不再为已撤销任务启动新 timer
            if job_id not in self._jobs:
                return
            old_timer = self._timers.get(job_id)
            if old_timer is not None:
                old_timer.cancel()
            timer = threading.Timer(seconds, _tick)
            timer.daemon = True
            self._timers[job_id] = timer
        timer.start()

    def _schedule_cron(self, job_id: str, job: Dict[str, Any], cron_expr: str):
        """cron 模式：APScheduler（可选依赖，缺失降级 interval 300 秒并告警）"""
        sched = self._ensure_apscheduler()
        if sched is None:
            logger.warning("APScheduler 未安装，cron 任务 %s 降级为每 5 分钟间隔", job_id)
            job["parsed"] = {"type": "interval", "expr": "every:300", "seconds": 300}
            # 降级必须对用户可见：旧实现只在引擎日志留一行 warning，
            # UI 里仍显示 */30，实际每 5 分钟扫一次（测评 P1-8）。
            job["degraded"] = True
            job["effective_cron"] = "every:300"
            job["warning"] = "当前构建未包含 APScheduler：cron 已降级为每 5 分钟执行"
            self._schedule_interval(job_id, job, 300)
            return
        try:
            from apscheduler.triggers.cron import CronTrigger

            # 显式传入与 BackgroundScheduler 一致的时区，避免触发时间落到宿主机本地时区
            trigger = CronTrigger.from_crontab(cron_expr, timezone="Asia/Shanghai")
            aps_job = sched.add_job(
                lambda: self._trigger(job_id, job),
                trigger=trigger,
                id=job_id,
                replace_existing=True,
            )
            job["aps_job_id"] = aps_job.id
        except Exception as e:
            logger.warning("cron 任务注册失败 %s: %s，降级 interval 300 秒", cron_expr, e)
            job["parsed"] = {"type": "interval", "expr": "every:300", "seconds": 300}
            job["degraded"] = True
            job["effective_cron"] = "every:300"
            job["warning"] = f"cron 注册失败（{e}），已降级为每 5 分钟执行"
            self._schedule_interval(job_id, job, 300)

    def _persist_state(self, job_id: str, job: Dict[str, Any]) -> None:
        """把暂停/上次执行状态并入 payload 的 `_state` 落库

        schedules 表没有独立的 state 列，复用 payload JSON 可避免破坏性迁移；
        `_state` 是保留键，调度参数读取方（_trigger）只取已知字段，不受影响。
        """
        if not self.storage:
            return
        state = {
            "paused": bool(job.get("paused")),
            "paused_reason": job.get("paused_reason", ""),
            "last_task_id": job.get("last_task_id", ""),
            "last_run_at": job.get("last_run_at", 0.0),
            "last_status": job.get("last_status", ""),
            "consecutive_failures": job.get("consecutive_failures", 0),
            "counted_task_id": job.get("counted_task_id", ""),
        }
        payload = {**(job.get("payload") or {}), "_state": state}
        with self._lock:
            # 任务可能在触发/持久化之间被删除：不能把已删除的调度重新写回数据库
            if job_id not in self._jobs:
                return
            job["payload"] = payload
        try:
            self.storage.save_schedule(job_id, job["cron"], job["target"], job["mode"], payload)
        except Exception as e:
            logger.debug("定时任务状态落库失败 %s: %s", job_id, e)

    def _refresh_state(self, job_id: str, job: Dict[str, Any]) -> None:
        """在触发前结算上一轮任务结果（用于连续失败自动暂停）"""
        orch = self.orchestrator
        registry = getattr(orch, "registry", None) if orch is not None else None
        prev = job.get("last_task_id") or ""
        if not prev or prev == job.get("counted_task_id") or registry is None:
            return
        record = registry.get(prev)
        if record is None:
            return
        job["last_status"] = record.status
        if record.status not in ("done", "failed", "cancelled", "interrupted"):
            return
        job["counted_task_id"] = prev
        error = (record.task_dict or {}).get("error", "")
        if record.status == "failed" and "目标不可达" in str(error):
            job["consecutive_failures"] = int(job.get("consecutive_failures", 0)) + 1
        else:
            job["consecutive_failures"] = 0
        if job["consecutive_failures"] >= MAX_CONSECUTIVE_FAILURES:
            job["paused"] = True
            job["paused_reason"] = f"连续 {job['consecutive_failures']} 次目标不可达，已自动暂停"
            logger.warning("定时任务 %s 连续失败 %s 次，已暂停", job_id, job["consecutive_failures"])
        self._persist_state(job_id, job)

    def _trigger(self, job_id: str, job: Dict[str, Any]):
        """触发执行：orchestrator.submit 或 on_trigger 回调"""
        with self._lock:
            # 定时器可能在 remove_job 之后仍触发一次：已删除的调度不再执行
            if job_id not in self._jobs:
                return
        if job.get("paused"):
            return
        # 先结算上一轮：失败次数、暂停状态
        self._refresh_state(job_id, job)
        if job.get("paused"):
            return

        target = job["target"]
        mode = job["mode"]
        payload = job.get("payload") or {}
        orch = self.orchestrator

        # 防堆积：上一轮仍 pending/running 时跳过本轮（旧实现每 5 分钟无脑起新任务，
        # 4 个 worker 被占满后，新扫描 0/0 卡死）
        last_task_id = job.get("last_task_id") or ""
        is_active = getattr(orch, "is_task_active", None) if orch is not None else None
        if last_task_id and callable(is_active) and is_active(last_task_id):
            logger.info("定时任务 %s 上一轮仍在执行（%s），跳过本轮", job_id, last_task_id)
            self._persist_state(job_id, job)
            return

        logger.info("定时任务触发: %s → %s (%s)", job_id, target, mode)
        if self.on_trigger:
            self.on_trigger(target, mode, payload)
            job["last_run_at"] = time.time()
            self._persist_state(job_id, job)
            return
        if orch is not None:
            from core.orchestrator import ScanRequest

            req = ScanRequest(
                target=target,
                mode=mode,
                report_dir=payload.get("report_dir", ""),
                report_format=payload.get("report_format", "all"),
                threads=int(payload.get("threads", 1)),
            )
            task_id = orch.submit(req)
            job["last_task_id"] = task_id or ""
            job["last_run_at"] = time.time()
            job["last_status"] = "pending"
            self._persist_state(job_id, job)
