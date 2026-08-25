# E9：定时扫描调度器（--schedule）
#
# 设计：
#   1. cron 5 段式（如 "*/5 * * * *"）→ APScheduler CronTrigger（可选依赖）
#   2. 简单间隔（如 "every:300" 秒）→ threading.Timer 自调度（零依赖降级路径）
#   3. 任务落库（core.storage.schedules 表），服务重启自动恢复
#   4. 触发执行：调用 orchestrator.submit 异步扫描（不阻塞调度线程）
import re
import threading
from typing import Any, Dict, List

from common.logger import get_logger

logger = get_logger(__name__)

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
        # 自动生成稳定 job_id：cron 表达式中的空白/冒号转下划线，目标截断防 ID 过长
        job_id = job_id or (
            "job_" + re.sub(r"[\s:]", "_", cron_expr) + "_" + target.replace("://", "_").replace("/", "_")[:24]
        )
        job = {
            "cron": cron_expr,
            "target": target,
            "mode": mode,
            "payload": payload or {},
            "parsed": parsed,
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
        return job_id

    def remove_job(self, job_id: str):
        """删除定时任务"""
        with self._lock:
            job = self._jobs.pop(job_id, None)
        if job is None:
            return
        # 停止 timer
        timer = self._timers.pop(job_id, None)
        if timer:
            timer.cancel()
        # APScheduler job
        if self._apscheduler is not None and job.get("aps_job_id"):
            try:
                self._apscheduler.remove_job(job["aps_job_id"])
            except Exception:
                pass
        if self.storage:
            try:
                self.storage.delete_schedule(job_id)
            except Exception:
                pass

    def list_jobs(self) -> List[Dict[str, Any]]:
        """列出任务"""
        with self._lock:
            return [
                {
                    "job_id": jid,
                    "cron": job["cron"],
                    "target": job["target"],
                    "mode": job["mode"],
                    "payload": job["payload"],
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
                for rec in self.storage.list_schedules():
                    jid = rec["job_id"]
                    # 内存中已有的任务（启动前手动添加）不重复恢复，以内存为准
                    if jid in self._jobs:
                        continue
                    self._jobs[jid] = {
                        "cron": rec["cron"],
                        "target": rec["target"],
                        "mode": rec["mode"],
                        "payload": rec.get("payload") or {},
                        "parsed": parse_schedule_expr(rec["cron"]),
                    }
            except Exception as e:
                logger.debug("恢复定时任务失败: %s", e)
        with self._lock:
            job_ids = list(self._jobs.keys())
        for jid in job_ids:
            self._schedule_job(jid, self._jobs[jid])

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

        timer = threading.Timer(seconds, _tick)
        timer.daemon = True
        with self._lock:
            self._timers[job_id] = timer
        timer.start()

    def _schedule_cron(self, job_id: str, job: Dict[str, Any], cron_expr: str):
        """cron 模式：APScheduler（可选依赖，缺失降级 interval 300 秒并告警）"""
        sched = self._ensure_apscheduler()
        if sched is None:
            logger.warning("APScheduler 未安装，cron 任务 %s 降级为每 5 分钟间隔", job_id)
            job["parsed"] = {"type": "interval", "expr": "every:300", "seconds": 300}
            self._schedule_interval(job_id, job, 300)
            return
        try:
            from apscheduler.triggers.cron import CronTrigger

            trigger = CronTrigger.from_crontab(cron_expr)
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
            self._schedule_interval(job_id, job, 300)

    def _trigger(self, job_id: str, job: Dict[str, Any]):
        """触发执行：orchestrator.submit 或 on_trigger 回调"""
        target = job["target"]
        mode = job["mode"]
        payload = job.get("payload") or {}
        logger.info("定时任务触发: %s → %s (%s)", job_id, target, mode)
        if self.on_trigger:
            self.on_trigger(target, mode, payload)
            return
        if self.orchestrator is not None:
            from core.orchestrator import ScanRequest

            req = ScanRequest(
                target=target,
                mode=mode,
                report_dir=payload.get("report_dir", ""),
                report_format=payload.get("report_format", "all"),
                threads=int(payload.get("threads", 1)),
            )
            self.orchestrator.submit(req)
