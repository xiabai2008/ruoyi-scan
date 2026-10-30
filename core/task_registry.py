# D9 TaskRegistry：任务状态管理 + WebSocket 推送桥
#
# 工作线程通过 notify() 推送事件（线程安全），
# WS handler 通过 subscribe() 订阅任务事件（在 asyncio loop 中）。
#
# 跨线程推送核心：asyncio.run_coroutine_threadsafe(queue.put(event), main_loop)
import asyncio
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from common.logger import get_logger

logger = get_logger(__name__)

# 任务终态：到达后不会再有新事件，WS 补播完即可关闭连接
TERMINAL_STATUSES = ("done", "failed", "cancelled", "interrupted")


def _canonical_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """把持久化事件归一化为 WS/前端契约形状 {type,data,task_id,timestamp}

    SQLite events 表存的是 event_type/payload，而 notify() 推送与前端消费的是
    type/data。恢复时若不转换，WS 补播会发出 event_type/payload → 前端
    `e.type` 为 undefined，终端显示 "undefined:"，结果接口也读不到 result 事件。
    幂等：已是 {type,data} 形状的直接返回。
    """
    if "type" in raw and "data" in raw:
        return raw
    payload = raw.get("payload")
    return {
        "type": raw.get("event_type", ""),
        "data": payload if isinstance(payload, dict) else {"data": payload},
        "task_id": raw.get("task_id", ""),
        "timestamp": raw.get("timestamp", 0.0),
    }


@dataclass
class TaskRecord:
    """任务记录（TaskRegistry 内部用）"""

    task_id: str
    status: str = "pending"  # pending/running/done/failed
    created_at: float = field(default_factory=time.time)
    events: List[Dict[str, Any]] = field(default_factory=list)  # 历史事件（供后加入的订阅者补播）
    task_dict: Dict[str, Any] = field(default_factory=dict)  # ScanTask.to_dict() 的快照


class TaskRegistry:
    """任务注册表 + WebSocket 推送桥

    线程模型：
        - 工作线程（ThreadPoolExecutor）调用 notify() → run_coroutine_threadsafe → asyncio loop
        - WS handler（asyncio loop）调用 subscribe() → asyncio.Queue.get()

    事件缓冲：
        - 每个任务维护 events 历史列表
        - 新订阅者连接时补播历史事件（避免漏看）
        - 任务完成后保留事件 1 小时（可配置）
    """

    def __init__(
        self, max_events_per_task: int = 500, retention_seconds: int = 3600, storage: Optional[Any] = None
    ) -> None:
        """初始化注册表

        Args:
            max_events_per_task: 每个任务最大事件缓冲数（防止内存泄漏）
            retention_seconds: 已完成任务保留时长（秒）
            storage: Storage 实例（D11 持久化，None 则不落盘）
        """
        self._tasks: Dict[str, TaskRecord] = {}
        self._subscribers: Dict[str, Set["asyncio.Queue[Dict[str, Any]]"]] = defaultdict(set)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lock = threading.Lock()  # 保护 _tasks 和 _subscribers
        self.max_events_per_task = max_events_per_task
        self.retention_seconds = retention_seconds
        self.storage = storage  # D11：SQLite 持久层

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """绑定主事件循环（在 FastAPI startup 中调用）"""
        self._loop = loop

    def unbind_loop(self) -> None:
        """解绑事件循环（在 FastAPI shutdown 中调用）"""
        self._loop = None

    def register(self, task_id: str, task_dict: Optional[Dict[str, Any]] = None) -> None:
        """注册新任务"""
        td = task_dict or {}
        with self._lock:
            self._tasks[task_id] = TaskRecord(
                task_id=task_id,
                status="pending",
                task_dict=td,
            )
        # D11：落盘
        if self.storage:
            try:
                self.storage.save_task(task_id, td)
            except Exception:
                logger.debug("任务状态落盘失败", exc_info=True)

    def update_task_dict(self, task_id: str, task_dict: Dict[str, Any]) -> None:
        """更新任务快照"""
        with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].task_dict = task_dict
        # D11：落盘
        if self.storage:
            try:
                self.storage.save_task(task_id, task_dict)
            except Exception:
                logger.debug("任务快照落盘失败", exc_info=True)

    def get(self, task_id: str) -> Optional[TaskRecord]:
        """获取任务记录（返回内部对象引用，调用方只读，勿修改 events/task_dict）"""
        with self._lock:
            return self._tasks.get(task_id)

    def list(self) -> List[TaskRecord]:
        """列出所有任务（返回内部对象引用，调用方只读，勿修改 events/task_dict）"""
        with self._lock:
            return list(self._tasks.values())

    def notify(self, task_id: str, event_type: str, payload: Any) -> None:
        """工作线程调用：推送事件到所有订阅者

        通过 run_coroutine_threadsafe 跨线程安全投递到 asyncio loop。
        """
        event = {
            "type": event_type,
            "data": payload,
            "task_id": task_id,
            "timestamp": time.time(),
        }

        # 记录到历史事件缓冲
        with self._lock:
            record = self._tasks.get(task_id)
            if record is not None:
                record.events.append(event)
                # 限制缓冲大小
                if len(record.events) > self.max_events_per_task:
                    record.events = record.events[-self.max_events_per_task :]
                # 更新状态
                # 事件语义约定："status" 事件以 payload.status 为准；"error" 事件直接置为 failed
                if event_type == "status" and isinstance(payload, dict):
                    record.status = payload.get("status", record.status)
                elif event_type == "error":
                    record.status = "failed"

            # 订阅者与任务是否已注册无关：subscribe() 并不要求先 register()，
            # 若未注册就取空集合，会导致已订阅队列永远收不到事件（事件却已落盘，成为不可达数据）
            subscribers = list(self._subscribers.get(task_id, set()))

        # D11：事件落盘
        if self.storage:
            try:
                self.storage.save_event(task_id, event_type, payload)
            except Exception:
                logger.debug("事件落盘失败", exc_info=True)

        # 跨线程投递到 asyncio loop
        if self._loop and subscribers:
            for queue in subscribers:
                try:
                    asyncio.run_coroutine_threadsafe(queue.put(event), self._loop)
                except Exception:
                    logger.debug("事件投递到 asyncio loop 失败（loop 可能已关闭）", exc_info=True)

    async def subscribe(self, task_id: str) -> "asyncio.Queue[Dict[str, Any]]":
        """WS handler 调用：订阅任务事件

        返回 asyncio.Queue，handler 通过 await queue.get() 等待事件。
        队列只承载订阅之后的新事件；历史事件由订阅方另行调用 get_history() 补播。
        ⚠ get_history() 与 subscribe() 非原子，两步之间的事件会同时在历史与队列中
        出现（重复）；需要补播历史时请改用 subscribe_with_history()。
        """
        queue: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue()
        with self._lock:
            self._subscribers[task_id].add(queue)
        return queue

    async def subscribe_with_history(
        self, task_id: str
    ) -> Tuple["asyncio.Queue[Dict[str, Any]]", List[Dict[str, Any]]]:
        """原子订阅：同一把锁内注册新事件队列并取历史快照

        订阅方先补播返回的 history，再从 queue 取新事件即可既不重复也不丢失：
        历史快照与订阅在同一临界区完成，之后的事件只会进入队列。

        Returns:
            (queue, history)：新事件队列 + 订阅时刻的历史事件快照
        """
        queue: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue()
        with self._lock:
            self._subscribers[task_id].add(queue)
            record = self._tasks.get(task_id)
            history = list(record.events) if record else []
        return queue, history

    def unsubscribe(self, task_id: str, queue: "asyncio.Queue[Dict[str, Any]]") -> None:
        """WS handler 断开时调用：取消订阅（集合清空后删除 key，避免空集合长期累积）"""
        with self._lock:
            subscribers = self._subscribers.get(task_id)
            if subscribers is None:
                return
            subscribers.discard(queue)
            if not subscribers:
                del self._subscribers[task_id]

    def get_history(self, task_id: str) -> List[Dict[str, Any]]:
        """获取任务历史事件（供新订阅者补播）"""
        with self._lock:
            record = self._tasks.get(task_id)
            return list(record.events) if record else []

    def cleanup_expired(self) -> List[str]:
        """清理过期任务（超过 retention_seconds 的已完成任务）

        保留期以「完成时间」为准（task_dict.finished_at，缺失时回退 created_at）：
        按创建时间计算会把刚结束的长任务立即清理掉。
        """
        now = time.time()
        expired = []
        with self._lock:
            for task_id, record in list(self._tasks.items()):
                if record.status in TERMINAL_STATUSES:
                    finished_at = record.task_dict.get("finished_at") or record.created_at
                    if now - finished_at > self.retention_seconds:
                        expired.append(task_id)
            for task_id in expired:
                del self._tasks[task_id]
        return expired

    def task_count(self) -> int:
        """当前任务数"""
        with self._lock:
            return len(self._tasks)

    def mark_status(self, task_id: str, status: str, error: str = "") -> None:
        """更新并持久化任务状态（不广播事件）

        取消/重启归一化等“非执行线程”路径使用：旧实现只改 record.status，
        task_dict 与 SQLite 仍是旧状态，导致 GET /api/scan 仍显示 running，
        重启后又把已取消任务恢复成 running。
        """
        with self._lock:
            record = self._tasks.get(task_id)
            if record is None:
                return
            record.status = status
            td = dict(record.task_dict or {})
            td["status"] = status
            if error:
                td["error"] = error
            record.task_dict = td
            task_dict = dict(td)
        if self.storage:
            try:
                self.storage.save_task(task_id, task_dict)
            except Exception:
                logger.debug("任务状态落盘失败", exc_info=True)

    # === D11：SQLite 持久化恢复 ===

    def restore_from_storage(self, storage: Any) -> None:
        """从 SQLite 恢复历史任务到内存

        在 FastAPI startup 中调用，确保进程重启后历史任务可查询。
        """
        # 只恢复最近 100 条（list_tasks 按创建时间倒序），避免启动时全量载入拖慢初始化
        try:
            tasks = storage.list_tasks(limit=100)
            for td in tasks:
                task_id = td.get("task_id", "")
                if not task_id:
                    continue
                # 历史任务状态以持久化字段为准；缺失时按 pending 恢复，
                # 不臆断为 done（否则未完成任务在重启后被静默标记为已完成）
                status = td.get("status") or "pending"
                # 引擎重启后，pending/running 任务已经没有执行线程：保持 running 会让
                # UI 永远显示“进行中”，且取消接口也无法真正结束它。归一化为 interrupted，
                # 并立即回写，避免下次重启重复显示为旧状态。
                if status in ("pending", "running"):
                    status = "interrupted"
                    td = {
                        **td,
                        "status": status,
                        "error": "引擎重启，任务已中断（结果可能不完整）",
                    }
                    try:
                        storage.save_task(task_id, td)
                    except Exception:
                        logger.debug("中断状态回写失败", exc_info=True)
                # 恢复事件历史：统一成 {type,data} 契约（P0-1 根因），
                # 并只取最近 max_events_per_task 条
                raw_events = storage.get_events(task_id, limit=self.max_events_per_task, canonical=True)
                events = [_canonical_event(e) for e in raw_events]
                with self._lock:
                    self._tasks[task_id] = TaskRecord(
                        task_id=task_id,
                        status=status,
                        # created_at 优先取自身持久化字段：TTL 清理按 created_at 计算，
                        # 借用 started_at（或 time.time()）会失真
                        created_at=td.get("created_at") or td.get("started_at") or time.time(),
                        events=events[-self.max_events_per_task :],
                        task_dict=td,
                    )
        except Exception:
            logger.debug("任务状态恢复失败，不阻断启动", exc_info=True)
