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
from typing import Dict, List, Optional, Set

from common.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TaskRecord:
    """任务记录（TaskRegistry 内部用）"""

    task_id: str
    status: str = "pending"  # pending/running/done/failed
    created_at: float = field(default_factory=time.time)
    events: List[dict] = field(default_factory=list)  # 历史事件（供后加入的订阅者补播）
    task_dict: dict = field(default_factory=dict)  # ScanTask.to_dict() 的快照


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

    def __init__(self, max_events_per_task: int = 500, retention_seconds: int = 3600, storage=None):
        """初始化注册表

        Args:
            max_events_per_task: 每个任务最大事件缓冲数（防止内存泄漏）
            retention_seconds: 已完成任务保留时长（秒）
            storage: Storage 实例（D11 持久化，None 则不落盘）
        """
        self._tasks: Dict[str, TaskRecord] = {}
        self._subscribers: Dict[str, Set[asyncio.Queue]] = defaultdict(set)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lock = threading.Lock()  # 保护 _tasks 和 _subscribers
        self.max_events_per_task = max_events_per_task
        self.retention_seconds = retention_seconds
        self.storage = storage  # D11：SQLite 持久层

    def bind_loop(self, loop: asyncio.AbstractEventLoop):
        """绑定主事件循环（在 FastAPI startup 中调用）"""
        self._loop = loop

    def unbind_loop(self):
        """解绑事件循环（在 FastAPI shutdown 中调用）"""
        self._loop = None

    def register(self, task_id: str, task_dict: dict = None):
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

    def update_task_dict(self, task_id: str, task_dict: dict):
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
        """获取任务记录"""
        with self._lock:
            return self._tasks.get(task_id)

    def list(self) -> List[TaskRecord]:
        """列出所有任务"""
        with self._lock:
            return list(self._tasks.values())

    def notify(self, task_id: str, event_type: str, payload: any):
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
            if task_id in self._tasks:
                self._tasks[task_id].events.append(event)
                # 限制缓冲大小
                if len(self._tasks[task_id].events) > self.max_events_per_task:
                    self._tasks[task_id].events = self._tasks[task_id].events[-self.max_events_per_task :]
                # 更新状态
                if event_type == "status" and isinstance(payload, dict):
                    self._tasks[task_id].status = payload.get("status", self._tasks[task_id].status)
                elif event_type == "error":
                    self._tasks[task_id].status = "failed"

                subscribers = list(self._subscribers.get(task_id, set()))
            else:
                subscribers = []

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

    async def subscribe(self, task_id: str) -> asyncio.Queue:
        """WS handler 调用：订阅任务事件

        返回 asyncio.Queue，handler 通过 await queue.get() 等待事件。
        """
        queue = asyncio.Queue()
        with self._lock:
            self._subscribers[task_id].add(queue)
        return queue

    def unsubscribe(self, task_id: str, queue: asyncio.Queue):
        """WS handler 断开时调用：取消订阅"""
        with self._lock:
            self._subscribers[task_id].discard(queue)

    def get_history(self, task_id: str) -> List[dict]:
        """获取任务历史事件（供新订阅者补播）"""
        with self._lock:
            record = self._tasks.get(task_id)
            return list(record.events) if record else []

    def cleanup_expired(self):
        """清理过期任务（超过 retention_seconds 的已完成任务）"""
        now = time.time()
        expired = []
        with self._lock:
            for task_id, record in list(self._tasks.items()):
                if record.status in ("done", "failed"):
                    if now - record.created_at > self.retention_seconds:
                        expired.append(task_id)
            for task_id in expired:
                del self._tasks[task_id]
        return expired

    def task_count(self) -> int:
        """当前任务数"""
        with self._lock:
            return len(self._tasks)

    # === D11：SQLite 持久化恢复 ===

    def restore_from_storage(self, storage):
        """从 SQLite 恢复历史任务到内存

        在 FastAPI startup 中调用，确保进程重启后历史任务可查询。
        """
        try:
            tasks = storage.list_tasks(limit=100)
            for td in tasks:
                task_id = td.get("task_id", "")
                if not task_id:
                    continue
                status = td.get("status", "done")
                # 恢复事件历史
                events = storage.get_events(task_id, limit=self.max_events_per_task)
                with self._lock:
                    self._tasks[task_id] = TaskRecord(
                        task_id=task_id,
                        status=status,
                        created_at=td.get("started_at", time.time()),
                        events=events,
                        task_dict=td,
                    )
        except Exception:
            logger.debug("任务状态恢复失败，不阻断启动", exc_info=True)
