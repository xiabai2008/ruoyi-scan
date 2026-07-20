# D11 SQLite 持久层：任务历史 + 事件落盘
#
# 设计目标：
#   1. 标准库 sqlite3，零新增依赖
#   2. WAL 模式，读写不互斥
#   3. TaskRegistry 启动时从 SQLite 恢复历史任务
#   4. notify() 同步写盘（轻量，不阻塞主流程）
#
# 表结构：
#   tasks(task_id, status, target, task_dict_json, created_at, finished_at)
#   events(task_id, event_type, payload_json, timestamp)
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

# 默认数据库路径
DEFAULT_DB_PATH = os.path.join("data", "tasks.db")


class Storage:
    """SQLite 持久层（线程安全）

    用法：
        storage = Storage('data/tasks.db')
        storage.save_task(task_id, task_dict)
        storage.save_event(task_id, event_type, payload)
        tasks = storage.list_tasks(limit=50)
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        # 确保目录存在
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        # 初始化表结构
        self._init_db()

    def _init_db(self):
        """初始化表结构 + WAL 模式"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tasks (
                        task_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL DEFAULT 'pending',
                        target TEXT,
                        task_dict TEXT,
                        created_at REAL,
                        finished_at REAL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        task_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        payload TEXT,
                        timestamp REAL,
                        FOREIGN KEY (task_id) REFERENCES tasks(task_id)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_task ON events(task_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
                conn.commit()
            finally:
                conn.close()

    def save_task(self, task_id: str, task_dict: Dict[str, Any]):
        """保存或更新任务（upsert）"""
        status = task_dict.get("status", "pending")
        target = task_dict.get("target", "")
        created_at = task_dict.get("started_at", time.time())
        finished_at = task_dict.get("finished_at")
        task_json = json.dumps(task_dict, ensure_ascii=False)

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    """
                    INSERT INTO tasks (task_id, status, target, task_dict, created_at, finished_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(task_id) DO UPDATE SET
                        status=excluded.status,
                        task_dict=excluded.task_dict,
                        finished_at=excluded.finished_at
                """,
                    (task_id, status, target, task_json, created_at, finished_at),
                )
                conn.commit()
            finally:
                conn.close()

    def save_event(self, task_id: str, event_type: str, payload: Any):
        """保存事件"""
        payload_json = json.dumps(payload, ensure_ascii=False) if payload else "{}"
        ts = time.time()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    """
                    INSERT INTO events (task_id, event_type, payload, timestamp)
                    VALUES (?, ?, ?, ?)
                """,
                    (task_id, event_type, payload_json, ts),
                )
                conn.commit()
            finally:
                conn.close()

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """查询单个任务"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
                if row:
                    return json.loads(row["task_dict"]) if row["task_dict"] else {}
                return None
            finally:
                conn.close()

    def list_tasks(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """列出任务（按创建时间倒序）"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
                ).fetchall()
                return [json.loads(r["task_dict"]) for r in rows if r["task_dict"]]
            finally:
                conn.close()

    def get_events(self, task_id: str, limit: int = 500) -> List[Dict[str, Any]]:
        """查询任务的事件历史"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM events WHERE task_id = ? ORDER BY timestamp ASC LIMIT ?", (task_id, limit)
                ).fetchall()
                return [
                    {
                        "task_id": r["task_id"],
                        "event_type": r["event_type"],
                        "payload": json.loads(r["payload"]) if r["payload"] else {},
                        "timestamp": r["timestamp"],
                    }
                    for r in rows
                ]
            finally:
                conn.close()

    def delete_task(self, task_id: str):
        """删除任务 + 其事件"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("DELETE FROM events WHERE task_id = ?", (task_id,))
                conn.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
                conn.commit()
            finally:
                conn.close()

    def cleanup_expired(self, max_age_seconds: int = 86400):
        """清理过期任务（默认 24 小时）"""
        cutoff = time.time() - max_age_seconds
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                # 删除旧任务的事件
                conn.execute(
                    """
                    DELETE FROM events WHERE task_id IN (
                        SELECT task_id FROM tasks WHERE created_at < ? AND status IN ('done', 'failed')
                    )
                """,
                    (cutoff,),
                )
                conn.execute('DELETE FROM tasks WHERE created_at < ? AND status IN ("done", "failed")', (cutoff,))
                conn.commit()
            finally:
                conn.close()

    def count_tasks(self) -> int:
        """任务总数"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                row = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()
                return row[0] if row else 0
            finally:
                conn.close()
