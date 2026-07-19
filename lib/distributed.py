# D36：分布式任务队列
#
# 提供分布式扫描任务队列，支持多节点并行扫描、任务分发、结果聚合。
# 使用 Redis 作为消息中间件（轻量级实现，不强制依赖 Celery）。
#
# 设计原则：
#   1. 基于 Redis list 实现简单的 FIFO 任务队列（LPUSH/BRPOP）
#   2. 无 Celery 依赖，降低部署复杂度
#   3. 支持 Master-Worker 架构：Master 分发任务，Worker 执行扫描
#   4. 结果聚合到 Redis，Master 汇总生成报告
#
# 架构：
#   Master 节点                     Worker 节点（可多个）
#   ┌─────────┐   Redis    ┌──────────────────┐
#   │ 分发任务 │ ────────→ │ BRPOP scan:tasks  │
#   │ 聚合结果 │ ←──────── │ 执行扫描 + LPUSH  │
#   └─────────┘            └──────────────────┘
#
# 使用方式：
#   # Master 模式：分发任务
#   python main.py --distributed master --redis redis://127.0.0.1:6379 \
#     -f targets.txt
#
#   # Worker 模式：执行扫描
#   python main.py --distributed worker --redis redis://127.0.0.1:6379
#
#   # 独立模式：本机分发 + 执行（无需 Redis）
#   python main.py --distributed standalone -f targets.txt
import datetime
import json
import os
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple


# ============================================================
# Redis 连接（延迟导入，避免未安装时报错）
# ============================================================

def get_redis_client(redis_url: str = 'redis://127.0.0.1:6379'):
    """获取 Redis 客户端

    Args:
        redis_url: Redis 连接 URL

    Returns:
        redis.Redis 实例

    Raises:
        ImportError: 未安装 redis 库
        ConnectionError: Redis 连接失败
    """
    try:
        import redis
    except ImportError:
        raise ImportError('分布式模式需要安装 redis：pip install redis')

    client = redis.from_url(redis_url, decode_responses=True)
    try:
        client.ping()
    except redis.ConnectionError:
        raise ConnectionError(f'无法连接 Redis: {redis_url}')
    return client


# ============================================================
# 任务模型
# ============================================================

class ScanTask:
    """扫描任务"""

    def __init__(self, task_id: str = '', target: str = '',
                 mode: str = 'full', config: Dict = None,
                 priority: int = 0):
        self.task_id = task_id or uuid.uuid4().hex[:12]
        self.target = target
        self.mode = mode  # full/vuln/dir/brute
        self.config = config or {}
        self.priority = priority
        self.created_at = datetime.datetime.now().isoformat()
        self.status = 'pending'  # pending/running/completed/failed

    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'target': self.target,
            'mode': self.mode,
            'config': self.config,
            'priority': self.priority,
            'created_at': self.created_at,
            'status': self.status,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'ScanTask':
        task = cls(
            task_id=d.get('task_id', ''),
            target=d.get('target', ''),
            mode=d.get('mode', 'full'),
            config=d.get('config', {}),
            priority=d.get('priority', 0),
        )
        task.created_at = d.get('created_at', '')
        task.status = d.get('status', 'pending')
        return task

    @classmethod
    def from_json(cls, json_str: str) -> 'ScanTask':
        return cls.from_dict(json.loads(json_str))


class TaskResult:
    """任务结果"""

    def __init__(self, task_id: str = '', worker_id: str = '',
                 results: List[Dict] = None, error: str = '',
                 duration: float = 0.0):
        self.task_id = task_id
        self.worker_id = worker_id
        self.results = results or []
        self.error = error
        self.duration = duration
        self.completed_at = datetime.datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'worker_id': self.worker_id,
            'results': self.results,
            'error': self.error,
            'duration': round(self.duration, 3),
            'completed_at': self.completed_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'TaskResult':
        r = cls(
            task_id=d.get('task_id', ''),
            worker_id=d.get('worker_id', ''),
            results=d.get('results', []),
            error=d.get('error', ''),
            duration=d.get('duration', 0.0),
        )
        r.completed_at = d.get('completed_at', '')
        return r


# ============================================================
# 分布式任务队列（Redis 实现）
# ============================================================

TASK_QUEUE_KEY = 'ruoyi_scan:tasks'
RESULT_QUEUE_KEY = 'ruoyi_scan:results'
TASK_STATUS_KEY = 'ruoyi_scan:status'  # Hash: task_id → status
WORKER_HEARTBEAT_KEY = 'ruoyi_scan:workers'  # Hash: worker_id → last_heartbeat


class DistributedTaskQueue:
    """分布式任务队列

    基于 Redis list 实现的轻量级任务队列。
    """

    def __init__(self, redis_url: str = 'redis://127.0.0.1:6379'):
        """
        Args:
            redis_url: Redis 连接 URL

        Raises:
            ImportError: 未安装 redis
            ConnectionError: Redis 连接失败
        """
        self.redis = get_redis_client(redis_url)
        self.redis_url = redis_url

    def push_task(self, task: ScanTask) -> str:
        """推送任务到队列

        Args:
            task: 扫描任务

        Returns:
            task_id
        """
        # 记录任务状态
        self.redis.hset(TASK_STATUS_KEY, task.task_id, 'pending')
        # LPUSH 到队列头部
        self.redis.lpush(TASK_QUEUE_KEY, task.to_json())
        return task.task_id

    def push_tasks_batch(self, tasks: List[ScanTask]) -> List[str]:
        """批量推送任务

        Args:
            tasks: 任务列表

        Returns:
            task_id 列表
        """
        pipe = self.redis.pipeline()
        task_ids = []
        for task in tasks:
            pipe.hset(TASK_STATUS_KEY, task.task_id, 'pending')
            pipe.lpush(TASK_QUEUE_KEY, task.to_json())
            task_ids.append(task.task_id)
        pipe.execute()
        return task_ids

    def pop_task(self, timeout: int = 30) -> Optional[ScanTask]:
        """从队列获取任务（阻塞式）

        Args:
            timeout: 阻塞超时秒数（0 表示永久阻塞）

        Returns:
            ScanTask 或 None（超时）
        """
        # BRPOP 从队列尾部获取（FIFO）
        result = self.redis.brpop(TASK_QUEUE_KEY, timeout=timeout)
        if result is None:
            return None
        _, task_json = result
        task = ScanTask.from_json(task_json)
        # 更新状态为 running
        self.redis.hset(TASK_STATUS_KEY, task.task_id, 'running')
        return task

    def push_result(self, result: TaskResult) -> None:
        """推送任务结果

        Args:
            result: 任务结果
        """
        self.redis.lpush(RESULT_QUEUE_KEY, result.to_json())
        status = 'failed' if result.error else 'completed'
        self.redis.hset(TASK_STATUS_KEY, result.task_id, status)

    def pop_result(self, timeout: int = 0) -> Optional[TaskResult]:
        """获取任务结果

        Args:
            timeout: 阻塞超时秒数

        Returns:
            TaskResult 或 None
        """
        result = self.redis.brpop(RESULT_QUEUE_KEY, timeout=timeout)
        if result is None:
            return None
        _, result_json = result
        return TaskResult.from_dict(json.loads(result_json))

    def get_task_status(self, task_id: str) -> str:
        """获取任务状态"""
        return self.redis.hget(TASK_STATUS_KEY, task_id) or 'unknown'

    def get_all_status(self) -> Dict[str, str]:
        """获取所有任务状态"""
        return self.redis.hgetall(TASK_STATUS_KEY)

    def get_queue_size(self) -> int:
        """获取待处理任务数"""
        return self.redis.llen(TASK_QUEUE_KEY)

    def get_result_count(self) -> int:
        """获取结果数"""
        return self.redis.llen(RESULT_QUEUE_KEY)

    def register_worker(self, worker_id: str) -> None:
        """注册 Worker"""
        self.redis.hset(WORKER_HEARTBEAT_KEY, worker_id,
                         datetime.datetime.now().isoformat())

    def heartbeat(self, worker_id: str) -> None:
        """Worker 心跳"""
        self.redis.hset(WORKER_HEARTBEAT_KEY, worker_id,
                         datetime.datetime.now().isoformat())

    def get_active_workers(self, max_age: int = 60) -> List[str]:
        """获取活跃 Worker

        Args:
            max_age: 最大心跳间隔秒数

        Returns:
            Worker ID 列表
        """
        all_workers = self.redis.hgetall(WORKER_HEARTBEAT_KEY)
        now = datetime.datetime.now()
        active = []
        for wid, heartbeat in all_workers.items():
            try:
                hb_time = datetime.datetime.fromisoformat(heartbeat)
                if (now - hb_time).total_seconds() < max_age:
                    active.append(wid)
            except (ValueError, TypeError):
                continue
        return active

    def clear_all(self) -> None:
        """清空所有队列和状态"""
        self.redis.delete(TASK_QUEUE_KEY, RESULT_QUEUE_KEY,
                          TASK_STATUS_KEY, WORKER_HEARTBEAT_KEY)

    def get_stats(self) -> Dict[str, Any]:
        """获取队列统计"""
        status = self.get_all_status()
        return {
            'queue_size': self.get_queue_size(),
            'result_count': self.get_result_count(),
            'total_tasks': len(status),
            'pending': sum(1 for s in status.values() if s == 'pending'),
            'running': sum(1 for s in status.values() if s == 'running'),
            'completed': sum(1 for s in status.values() if s == 'completed'),
            'failed': sum(1 for s in status.values() if s == 'failed'),
            'active_workers': len(self.get_active_workers()),
        }


# ============================================================
# Master 节点
# ============================================================

class MasterNode:
    """Master 节点：分发任务 + 聚合结果

    工作流：
    1. 从目标列表创建任务
    2. 推送任务到 Redis 队列
    3. 等待所有任务完成（轮询结果队列）
    4. 聚合结果生成最终报告
    """

    def __init__(self, redis_url: str = 'redis://127.0.0.1:6379'):
        self.queue = DistributedTaskQueue(redis_url)

    def distribute_tasks(self, targets: List[str], mode: str = 'full',
                         config: Dict = None) -> List[str]:
        """分发扫描任务

        Args:
            targets: 目标 URL 列表
            mode: 扫描模式
            config: 扫描配置

        Returns:
            task_id 列表
        """
        tasks = [
            ScanTask(target=t, mode=mode, config=config or {})
            for t in targets
        ]
        return self.queue.push_tasks_batch(tasks)

    def collect_results(self, expected_count: int,
                        timeout: float = 300,
                        progress_callback: Optional[Callable] = None) -> List[TaskResult]:
        """收集任务结果

        Args:
            expected_count: 预期结果数
            timeout: 最大等待时间秒数
            progress_callback: 进度回调 fn(completed, total)

        Returns:
            TaskResult 列表
        """
        results = []
        deadline = time.time() + timeout

        while len(results) < expected_count and time.time() < deadline:
            remaining = expected_count - len(results)
            # 非阻塞获取（1 秒超时）
            result = self.queue.pop_result(timeout=1)
            if result:
                results.append(result)
                if progress_callback:
                    progress_callback(len(results), expected_count)
            else:
                # 检查是否还有未完成任务
                stats = self.queue.get_stats()
                if stats['queue_size'] == 0 and stats['running'] == 0:
                    # 队列空且无运行中任务，可能 Worker 宕机
                    break

        return results

    def aggregate_results(self, results: List[TaskResult]) -> Dict[str, Any]:
        """聚合所有结果

        Args:
            results: TaskResult 列表

        Returns:
            聚合报告字典
        """
        all_vulns = []
        failed_tasks = []
        total_duration = 0.0

        for r in results:
            if r.error:
                failed_tasks.append({
                    'task_id': r.task_id,
                    'error': r.error,
                })
            else:
                all_vulns.extend(r.results)
            total_duration += r.duration

        # 按严重度统计
        severity_count = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        for v in all_vulns:
            sev = v.get('severity', 'low')
            if sev in severity_count:
                severity_count[sev] += 1
            severity_count['total'] += 1

        return {
            'total_tasks': len(results),
            'successful': len(results) - len(failed_tasks),
            'failed': len(failed_tasks),
            'total_vulns': len(all_vulns),
            'severity_distribution': severity_count,
            'all_vulns': all_vulns,
            'failed_tasks': failed_tasks,
            'total_duration': round(total_duration, 3),
            'aggregated_at': datetime.datetime.now().isoformat(),
        }


# ============================================================
# Worker 节点
# ============================================================

class WorkerNode:
    """Worker 节点：从队列获取任务 + 执行扫描 + 推送结果

    工作流：
    1. 从 Redis 队列 BRPOP 获取任务
    2. 执行扫描（调用 scan_fn）
    3. 将结果 LPUSH 到结果队列
    4. 循环直到收到停止信号
    """

    def __init__(self, redis_url: str = 'redis://127.0.0.1:6379',
                 worker_id: str = ''):
        self.queue = DistributedTaskQueue(redis_url)
        self.worker_id = worker_id or f'worker-{uuid.uuid4().hex[:8]}'
        self._running = False
        self._stats = {
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_duration': 0.0,
        }

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def run(self, scan_fn: Callable[[ScanTask], List[Dict]],
            poll_interval: int = 5,
            max_tasks: int = 0,
            heartbeat_interval: int = 30) -> None:
        """运行 Worker 循环

        Args:
            scan_fn: 扫描函数 fn(task) → results_list
            poll_interval: 轮询间隔秒数
            max_tasks: 最大处理任务数（0 表示无限）
            heartbeat_interval: 心跳间隔秒数
        """
        self._running = True
        self.queue.register_worker(self.worker_id)

        last_heartbeat = time.time()
        processed = 0

        print(f'[*]Worker {self.worker_id} 已启动，等待任务...')

        while self._running:
            # 心跳
            if time.time() - last_heartbeat > heartbeat_interval:
                self.queue.heartbeat(self.worker_id)
                last_heartbeat = time.time()

            # 获取任务
            task = self.queue.pop_task(timeout=poll_interval)
            if task is None:
                continue

            print(f'[*]收到任务: {task.task_id} → {task.target}')

            # 执行扫描
            start = time.time()
            try:
                results = scan_fn(task)
                duration = time.time() - start

                result = TaskResult(
                    task_id=task.task_id,
                    worker_id=self.worker_id,
                    results=results or [],
                    duration=duration,
                )
                self.queue.push_result(result)
                self._stats['tasks_completed'] += 1
                self._stats['total_duration'] += duration
                print(f'[+]任务完成: {task.task_id}（{len(results or [])} 个结果，{duration:.2f}s）')

            except Exception as e:
                duration = time.time() - start
                result = TaskResult(
                    task_id=task.task_id,
                    worker_id=self.worker_id,
                    error=str(e),
                    duration=duration,
                )
                self.queue.push_result(result)
                self._stats['tasks_failed'] += 1
                print(f'[!]任务失败: {task.task_id} - {e}')

            processed += 1
            if max_tasks > 0 and processed >= max_tasks:
                print(f'[*]已处理 {processed} 个任务，Worker 退出')
                break

        print(f'[*]Worker {self.worker_id} 已停止')
        print(f'    完成: {self._stats["tasks_completed"]} 失败: {self._stats["tasks_failed"]}')

    def stop(self) -> None:
        """停止 Worker"""
        self._running = False


# ============================================================
# 独立模式（无需 Redis，本机多线程）
# ============================================================

class StandaloneDistributor:
    """独立模式：本机多线程分发任务（无需 Redis）

    适用于单机多核场景，使用线程池替代 Redis 队列。
    """

    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers

    def distribute_and_collect(self, targets: List[str],
                               scan_fn: Callable[[str], List[Dict]],
                               progress_callback: Optional[Callable] = None) -> List[Dict]:
        """分发任务并收集结果

        Args:
            targets: 目标列表
            scan_fn: 扫描函数 fn(target) → results
            progress_callback: 进度回调

        Returns:
            所有结果（扁平化）
        """
        import concurrent.futures

        all_results = []
        total = len(targets)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(scan_fn, t): t for t in targets
            }

            completed = 0
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results = future.result()
                    if results:
                        all_results.extend(results)
                except Exception:
                    pass
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, target)

        return all_results


# ============================================================
# 模式入口
# ============================================================

def run_distributed_master_mode(args, targets: List[str],
                                scan_config: Dict = None) -> int:
    """分布式 Master 模式入口

    Args:
        args: CLI 参数
        targets: 目标列表
        scan_config: 扫描配置

    Returns:
        0 表示成功
    """
    redis_url = getattr(args, 'redis_url', None) or 'redis://127.0.0.1:6379'
    mode = getattr(args, 'u', None) and 'full' or 'full'

    try:
        master = MasterNode(redis_url)
    except ImportError as e:
        print(f'[!]{e}')
        return 1
    except ConnectionError as e:
        print(f'[!]{e}')
        return 1

    print(f'[*]Master 节点启动，分发 {len(targets)} 个任务...')
    task_ids = master.distribute_tasks(targets, mode=mode, config=scan_config or {})
    print(f'[+]已分发 {len(task_ids)} 个任务')

    # 等待结果
    print(f'[*]等待 Worker 处理...')
    results = master.collect_results(
        expected_count=len(task_ids),
        timeout=getattr(args, 'distributed_timeout', 600),
        progress_callback=lambda c, t: print(f'[*]进度: {c}/{t} 完成')
    )

    # 聚合结果
    report = master.aggregate_results(results)
    print(f'\n[+]扫描完成:')
    print(f'    总任务: {report["total_tasks"]}')
    print(f'    成功: {report["successful"]}')
    print(f'    失败: {report["failed"]}')
    print(f'    总漏洞: {report["total_vulns"]}')
    print(f'    高危: {report["severity_distribution"]["high"]}')
    print(f'    中危: {report["severity_distribution"]["medium"]}')
    print(f'    低危: {report["severity_distribution"]["low"]}')

    # 保存报告
    report_path = os.path.join('reports', 'distributed_report.json')
    os.makedirs('reports', exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f'[+]聚合报告已保存: {report_path}')

    return 0


def run_distributed_worker_mode(args, scan_fn: Callable[[ScanTask], List[Dict]]) -> int:
    """分布式 Worker 模式入口

    Args:
        args: CLI 参数
        scan_fn: 扫描函数

    Returns:
        0 表示成功
    """
    redis_url = getattr(args, 'redis_url', None) or 'redis://127.0.0.1:6379'

    try:
        worker = WorkerNode(redis_url=redis_url)
    except ImportError as e:
        print(f'[!]{e}')
        return 1
    except ConnectionError as e:
        print(f'[!]{e}')
        return 1

    max_tasks = getattr(args, 'worker_max_tasks', 0) or 0

    try:
        worker.run(scan_fn, max_tasks=max_tasks)
    except KeyboardInterrupt:
        print('\n[*]停止 Worker...')
        worker.stop()

    return 0


def run_distributed_standalone_mode(targets: List[str],
                                    scan_fn: Callable[[str], List[Dict]],
                                    max_workers: int = 10,
                                    progress_callback: Optional[Callable] = None) -> List[Dict]:
    """独立模式入口（本机多线程，无需 Redis）

    Args:
        targets: 目标列表
        scan_fn: 扫描函数
        max_workers: 最大并发数
        progress_callback: 进度回调

    Returns:
        所有扫描结果
    """
    distributor = StandaloneDistributor(max_workers=max_workers)
    return distributor.distribute_and_collect(targets, scan_fn, progress_callback)
