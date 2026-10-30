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

    def _connect(self) -> sqlite3.Connection:
        """创建连接（统一入口）：SQLite 默认不启用外键，且 PRAGMA 是连接级设置，
        必须在每个连接上打开，否则 events.task_id 的外键约束形同虚设"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        """初始化表结构 + WAL 模式"""
        with self._lock:
            conn = self._connect()
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
                # D11：扫描结果明细落盘。
                # 事件表只保留每任务 max_events_per_task 条（默认 500），长任务的
                # result 事件会被截断；且只有计数没有明细时，重启后结果页只能显示 0。
                # 结果按 seq 保序存整份 ScanResult.to_dict()，与报告/详情共用同一形状。
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        task_id TEXT NOT NULL,
                        seq INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (task_id, seq),
                        FOREIGN KEY (task_id) REFERENCES tasks(task_id)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id)")
                # E9：定时扫描任务表
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS schedules (
                        job_id TEXT PRIMARY KEY,
                        cron TEXT NOT NULL,
                        target TEXT NOT NULL,
                        mode TEXT NOT NULL DEFAULT 'u',
                        payload TEXT,
                        created_at REAL
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    def save_task(self, task_id: str, task_dict: Dict[str, Any]) -> None:
        """保存或更新任务（upsert）"""
        status = task_dict.get("status", "pending")
        target = task_dict.get("target", "")
        # 任务字典中的 started_at 对应表的 created_at 列（记录首次创建时间）
        created_at = task_dict.get("started_at", time.time())
        finished_at = task_dict.get("finished_at")
        task_json = json.dumps(task_dict, ensure_ascii=False)

        with self._lock:
            conn = self._connect()
            try:
                # 冲突时仅更新可变字段（状态/快照/结束时间），target 与 created_at 保持首次写入值
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

    def save_event(self, task_id: str, event_type: str, payload: Any) -> None:
        """保存事件"""
        # 显式 None 判断：0/False/[]/'' 都是合法 payload，不能被当作空值丢成 {}；
        # 真正缺省（None）仍存 {}，保持读取端 get_events 的默认形状
        payload_json = json.dumps(payload, ensure_ascii=False) if payload is not None else "{}"
        ts = time.time()
        with self._lock:
            conn = self._connect()
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
            conn = self._connect()
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
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
                ).fetchall()
                return [json.loads(r["task_dict"]) for r in rows if r["task_dict"]]
            finally:
                conn.close()

    def get_events(self, task_id: str, limit: int = 500, canonical: bool = False) -> List[Dict[str, Any]]:
        """查询任务的事件历史

        Args:
            task_id: 任务 ID
            limit: 最多返回条数（取**最后** limit 条，再按时间正序返回）
            canonical: True 时返回 WS/前端契约形状 {type,data,task_id,timestamp}；
                False（默认）保留历史形状 {event_type,payload}，兼容既有调用与测试。

        为什么取最后 N 条：旧实现 ORDER BY timestamp ASC LIMIT N 取的是最早 N 条，
        长任务的最新事件（含终态/结果）会被截掉；而补播最需要的是最近现场。
        """
        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                # 子查询按时间倒序取最近 N 条，外层再正序，保证回放顺序正确
                rows = conn.execute(
                    """
                    SELECT * FROM (
                        SELECT * FROM events WHERE task_id = ?
                        ORDER BY timestamp DESC, id DESC LIMIT ?
                    ) ORDER BY timestamp ASC, id ASC
                """,
                    (task_id, limit),
                ).fetchall()
                out: List[Dict[str, Any]] = []
                for r in rows:
                    payload = json.loads(r["payload"]) if r["payload"] else {}
                    if canonical:
                        # payload 正常是 dict（notify 已把非 dict 包成 {"data": ...}）；
                        # 极端脏数据仍保证 data 是 dict，前端不必再做类型判断
                        out.append(
                            {
                                "type": r["event_type"],
                                "data": payload if isinstance(payload, dict) else {"data": payload},
                                "task_id": r["task_id"],
                                "timestamp": r["timestamp"],
                            }
                        )
                    else:
                        out.append(
                            {
                                "task_id": r["task_id"],
                                "event_type": r["event_type"],
                                "payload": payload,
                                "timestamp": r["timestamp"],
                            }
                        )
                return out
            finally:
                conn.close()

    # ── D11：扫描结果明细持久化 ──

    def save_results(self, task_id: str, results: List[Dict[str, Any]]) -> None:
        """全量保存任务结果明细（先删后插，单事务）"""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM findings WHERE task_id = ?", (task_id,))
                conn.executemany(
                    "INSERT INTO findings (task_id, seq, payload) VALUES (?, ?, ?)",
                    [
                        (task_id, i, json.dumps(r, ensure_ascii=False, default=str))
                        for i, r in enumerate(results)
                    ],
                )
                conn.commit()
            finally:
                conn.close()

    def get_results(self, task_id: str) -> List[Dict[str, Any]]:
        """按 seq 读取任务结果明细（文件不存在/未落盘时返回空列表）"""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT payload FROM findings WHERE task_id = ? ORDER BY seq ASC", (task_id,)
                ).fetchall()
                out: List[Dict[str, Any]] = []
                for (payload,) in rows:
                    try:
                        item = json.loads(payload) if payload else {}
                    except (TypeError, ValueError):
                        continue
                    if isinstance(item, dict):
                        out.append(item)
                return out
            finally:
                conn.close()

    def delete_task(self, task_id: str) -> None:
        """删除任务 + 其事件"""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM events WHERE task_id = ?", (task_id,))
                conn.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
                conn.commit()
            finally:
                conn.close()

    def cleanup_expired(self, max_age_seconds: int = 86400) -> None:
        """清理过期任务（默认 24 小时）

        保留期以「完成时间」为准（finished_at，缺失/未落盘时回退 created_at）：
        长任务可能创建很久后才结束，按 created_at 清理会把它刚完成就删除，
        而更早完成的旧任务却留在库里。0.0 是未完成的哨兵值，与 NULL 一样回退。
        """
        cutoff = time.time() - max_age_seconds
        with self._lock:
            conn = self._connect()
            try:
                # 删除旧任务的事件（保留期判定与 tasks 表保持完全一致）
                conn.execute(
                    """
                    DELETE FROM events WHERE task_id IN (
                        SELECT task_id FROM tasks
                        WHERE COALESCE(NULLIF(finished_at, 0), created_at) < ?
                          AND status IN ('done', 'failed', 'cancelled', 'interrupted')
                    )
                """,
                    (cutoff,),
                )
                # 只清理已结束任务：进行中/待执行任务即使超龄也不删除，避免丢失半程状态
                conn.execute(
                    """
                    DELETE FROM tasks
                    WHERE COALESCE(NULLIF(finished_at, 0), created_at) < ?
                      AND status IN ('done', 'failed', 'cancelled', 'interrupted')
                """,
                    (cutoff,),
                )
                conn.commit()
            finally:
                conn.close()

    def count_tasks(self) -> int:
        """任务总数"""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()
                return row[0] if row else 0
            finally:
                conn.close()

    # ── E9：定时扫描任务 ──

    def save_schedule(
        self, job_id: str, cron: str, target: str, mode: str = "u", payload: Optional[Dict[str, Any]] = None
    ) -> None:
        """保存/更新定时扫描任务（upsert）"""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO schedules (job_id, cron, target, mode, payload, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(job_id) DO UPDATE SET
                        cron=excluded.cron, target=excluded.target,
                        mode=excluded.mode, payload=excluded.payload
                """,
                    (job_id, cron, target, mode, json.dumps(payload or {}, ensure_ascii=False), time.time()),
                )
                conn.commit()
            finally:
                conn.close()

    def list_schedules(self) -> List[Dict[str, Any]]:
        """列出全部定时扫描任务"""
        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM schedules ORDER BY created_at ASC").fetchall()
                return [
                    {
                        "job_id": r["job_id"],
                        "cron": r["cron"],
                        "target": r["target"],
                        "mode": r["mode"],
                        "payload": json.loads(r["payload"]) if r["payload"] else {},
                        "created_at": r["created_at"],
                    }
                    for r in rows
                ]
            finally:
                conn.close()

    def get_schedule(self, job_id: str) -> Optional[Dict[str, Any]]:
        """查询单个定时任务"""
        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM schedules WHERE job_id = ?", (job_id,)).fetchone()
                if row:
                    return {
                        "job_id": row["job_id"],
                        "cron": row["cron"],
                        "target": row["target"],
                        "mode": row["mode"],
                        "payload": json.loads(row["payload"]) if row["payload"] else {},
                        "created_at": row["created_at"],
                    }
                return None
            finally:
                conn.close()

    def delete_schedule(self, job_id: str) -> None:
        """删除定时任务"""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM schedules WHERE job_id = ?", (job_id,))
                conn.commit()
            finally:
                conn.close()
