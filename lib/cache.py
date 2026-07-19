# D37：结果缓存
#
# 避免对相同目标的重复扫描，基于目标 URL + 插件配置生成缓存键，
# 使用 SQLite 持久化存储扫描结果，支持 TTL 过期和缓存命中率统计。
#
# 设计原则：
#   1. 透明缓存：--cache 开启后自动缓存，无需修改插件
#   2. SQLite 持久化：无需额外依赖，跨进程共享
#   3. 细粒度缓存：按（目标 + 插件配置）缓存，指纹变更自动失效
#   4. 命中率统计：帮助评估缓存效果
#
# 使用方式：
#   python main.py -u http://target/ --cache              # 启用缓存
#   python main.py -u http://target/ --cache --cache-ttl 3600  # 自定义 TTL
#   python main.py --cache-stats                          # 查看缓存统计
#   python main.py --cache-clear                          # 清除缓存
import datetime
import hashlib
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# 缓存键生成
# ============================================================

def generate_cache_key(target: str, plugin_config: Dict = None,
                       scan_mode: str = '') -> str:
    """生成缓存键

    基于目标 URL + 插件配置 + 扫描模式生成 SHA256 哈希

    Args:
        target: 目标 URL
        plugin_config: 插件配置（如模板、认证等）
        scan_mode: 扫描模式

    Returns:
        16 位十六进制缓存键
    """
    # 标准化目标 URL（去除尾部斜杠、小写化域名）
    normalized_target = target.rstrip('/').lower()

    # 序列化配置
    config_str = json.dumps(plugin_config or {}, sort_keys=True, ensure_ascii=False)

    # 组合生成哈希
    combined = f'{normalized_target}|{scan_mode}|{config_str}'
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()[:16]


def generate_plugin_cache_key(target: str, plugin_name: str,
                               plugin_config: Dict = None) -> str:
    """生成单个插件的缓存键

    Args:
        target: 目标 URL
        plugin_name: 插件名称
        plugin_config: 插件配置

    Returns:
        16 位十六进制缓存键
    """
    normalized_target = target.rstrip('/').lower()
    config_str = json.dumps(plugin_config or {}, sort_keys=True, ensure_ascii=False)
    combined = f'{normalized_target}|{plugin_name}|{config_str}'
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()[:16]


# ============================================================
# SQLite 缓存存储
# ============================================================

class CacheStorage:
    """SQLite 缓存存储

    表结构：
        cache_entries (
            cache_key TEXT PRIMARY KEY,   -- 缓存键
            target TEXT,                  -- 目标 URL
            plugin_name TEXT,             -- 插件名称（可选）
            result_json TEXT,             -- 结果 JSON
            created_at TEXT,              -- 创建时间 ISO
            expires_at TEXT,              -- 过期时间 ISO
            hit_count INTEGER DEFAULT 0   -- 命中次数
        )
    """

    def __init__(self, db_path: str = 'data/scan_cache.db'):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """初始化数据库"""
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cache_entries (
                    cache_key TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    plugin_name TEXT,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    hit_count INTEGER DEFAULT 0
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_target ON cache_entries(target)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_expires ON cache_entries(expires_at)')
            conn.commit()
            conn.close()

    def get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """获取缓存

        Args:
            cache_key: 缓存键

        Returns:
            缓存的字典，或 None（不存在/已过期）
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                'SELECT * FROM cache_entries WHERE cache_key = ?',
                (cache_key,)
            )
            row = cursor.fetchone()

            if row is None:
                conn.close()
                return None

            # 检查过期
            expires_at = datetime.datetime.fromisoformat(row['expires_at'])
            if datetime.datetime.now() > expires_at:
                # 已过期，删除
                conn.execute('DELETE FROM cache_entries WHERE cache_key = ?', (cache_key,))
                conn.commit()
                conn.close()
                return None

            # 增加命中次数
            conn.execute(
                'UPDATE cache_entries SET hit_count = hit_count + 1 WHERE cache_key = ?',
                (cache_key,)
            )
            conn.commit()
            conn.close()

            return json.loads(row['result_json'])

    def set(self, cache_key: str, target: str, result: Dict[str, Any],
            ttl: int = 3600, plugin_name: str = '') -> None:
        """设置缓存

        Args:
            cache_key: 缓存键
            target: 目标 URL
            result: 结果字典
            ttl: 有效期秒数
            plugin_name: 插件名称（可选）
        """
        now = datetime.datetime.now()
        expires_at = now + datetime.timedelta(seconds=ttl)

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                INSERT OR REPLACE INTO cache_entries
                (cache_key, target, plugin_name, result_json, created_at, expires_at, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            ''', (
                cache_key, target, plugin_name,
                json.dumps(result, ensure_ascii=False),
                now.isoformat(), expires_at.isoformat()
            ))
            conn.commit()
            conn.close()

    def delete(self, cache_key: str) -> bool:
        """删除缓存

        Returns:
            True 表示删除成功
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                'DELETE FROM cache_entries WHERE cache_key = ?',
                (cache_key,)
            )
            conn.commit()
            deleted = cursor.rowcount > 0
            conn.close()
            return deleted

    def clear_all(self) -> int:
        """清除所有缓存

        Returns:
            清除的条目数
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute('SELECT COUNT(*) FROM cache_entries')
            count = cursor.fetchone()[0]
            conn.execute('DELETE FROM cache_entries')
            conn.commit()
            conn.close()
            return count

    def clear_expired(self) -> int:
        """清除过期缓存

        Returns:
            清除的条目数
        """
        now = datetime.datetime.now().isoformat()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                'DELETE FROM cache_entries WHERE expires_at < ?',
                (now,)
            )
            conn.commit()
            count = cursor.rowcount
            conn.close()
            return count

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row

            # 总条目数
            total = conn.execute('SELECT COUNT(*) FROM cache_entries').fetchone()[0]

            # 过期条目数
            now = datetime.datetime.now().isoformat()
            expired = conn.execute(
                'SELECT COUNT(*) FROM cache_entries WHERE expires_at < ?', (now,)
            ).fetchone()[0]

            # 总命中次数
            total_hits = conn.execute(
                'SELECT COALESCE(SUM(hit_count), 0) FROM cache_entries'
            ).fetchone()[0]

            # 高频命中（top 5）
            top = conn.execute(
                'SELECT target, hit_count FROM cache_entries '
                'ORDER BY hit_count DESC LIMIT 5'
            ).fetchall()

            # 按目标统计
            by_target = conn.execute(
                'SELECT target, COUNT(*) as cnt FROM cache_entries '
                'GROUP BY target ORDER BY cnt DESC LIMIT 10'
            ).fetchall()

            conn.close()

            return {
                'total_entries': total,
                'expired_entries': expired,
                'active_entries': total - expired,
                'total_hits': total_hits,
                'hit_rate': round(total_hits / total, 2) if total > 0 else 0,
                'top_hit': [dict(r) for r in top],
                'by_target': [dict(r) for r in by_target],
            }

    def get_by_target(self, target: str) -> List[Dict[str, Any]]:
        """获取指定目标的所有缓存

        Args:
            target: 目标 URL

        Returns:
            缓存条目列表
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                'SELECT * FROM cache_entries WHERE target = ? ORDER BY created_at DESC',
                (target,)
            )
            rows = cursor.fetchall()
            conn.close()
            return [dict(r) for r in rows]


# ============================================================
# 扫描结果缓存管理器
# ============================================================

class ScanCache:
    """扫描结果缓存管理器

    提供扫描结果的缓存查询和存储接口。

    使用方式：
        cache = ScanCache(ttl=3600)
        # 查询缓存
        cached = cache.get_scan_result('http://target/', scan_mode='full')
        if cached:
            # 使用缓存结果
            results = cached['results']
        else:
            # 执行扫描
            results = scan(target)
            # 存储到缓存
            cache.set_scan_result('http://target/', results, scan_mode='full')
    """

    def __init__(self, db_path: str = 'data/scan_cache.db', ttl: int = 3600):
        """
        Args:
            db_path: SQLite 数据库路径
            ttl: 默认缓存有效期秒数（默认 1 小时）
        """
        self.storage = CacheStorage(db_path)
        self.ttl = ttl
        self._hit_count = 0
        self._miss_count = 0

    @property
    def hit_count(self) -> int:
        return self._hit_count

    @property
    def miss_count(self) -> int:
        return self._miss_count

    @property
    def hit_rate(self) -> float:
        total = self._hit_count + self._miss_count
        return round(self._hit_count / total, 2) if total > 0 else 0

    def get_scan_result(self, target: str, scan_mode: str = '',
                        plugin_config: Dict = None) -> Optional[Dict[str, Any]]:
        """查询扫描结果缓存

        Args:
            target: 目标 URL
            scan_mode: 扫描模式
            plugin_config: 插件配置

        Returns:
            缓存的结果字典，或 None
        """
        cache_key = generate_cache_key(target, plugin_config, scan_mode)
        result = self.storage.get(cache_key)
        if result is not None:
            self._hit_count += 1
        else:
            self._miss_count += 1
        return result

    def set_scan_result(self, target: str, results: List[Dict[str, Any]],
                        scan_mode: str = '', plugin_config: Dict = None,
                        ttl: int = None) -> str:
        """存储扫描结果到缓存

        Args:
            target: 目标 URL
            results: 扫描结果列表
            scan_mode: 扫描模式
            plugin_config: 插件配置
            ttl: 有效期秒数（默认使用 self.ttl）

        Returns:
            cache_key
        """
        cache_key = generate_cache_key(target, plugin_config, scan_mode)
        cache_data = {
            'target': target,
            'scan_mode': scan_mode,
            'results': results,
            'cached_at': datetime.datetime.now().isoformat(),
        }
        self.storage.set(cache_key, target, cache_data, ttl or self.ttl)
        return cache_key

    def get_plugin_result(self, target: str, plugin_name: str,
                          plugin_config: Dict = None) -> Optional[Dict[str, Any]]:
        """查询单个插件的缓存结果

        Args:
            target: 目标 URL
            plugin_name: 插件名称
            plugin_config: 插件配置

        Returns:
            缓存结果，或 None
        """
        cache_key = generate_plugin_cache_key(target, plugin_name, plugin_config)
        return self.storage.get(cache_key)

    def set_plugin_result(self, target: str, plugin_name: str,
                          result: Dict[str, Any],
                          plugin_config: Dict = None,
                          ttl: int = None) -> str:
        """存储单个插件结果到缓存"""
        cache_key = generate_plugin_cache_key(target, plugin_name, plugin_config)
        cache_data = {
            'target': target,
            'plugin': plugin_name,
            'result': result,
            'cached_at': datetime.datetime.now().isoformat(),
        }
        self.storage.set(cache_key, target, cache_data, ttl or self.ttl,
                        plugin_name=plugin_name)
        return cache_key

    def invalidate_target(self, target: str) -> int:
        """失效指定目标的所有缓存

        Args:
            target: 目标 URL

        Returns:
            删除的条目数
        """
        entries = self.storage.get_by_target(target)
        count = 0
        for entry in entries:
            if self.storage.delete(entry['cache_key']):
                count += 1
        return count

    def clear_all(self) -> int:
        """清除所有缓存"""
        return self.storage.clear_all()

    def clear_expired(self) -> int:
        """清除过期缓存"""
        return self.storage.clear_expired()

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        stats = self.storage.get_stats()
        stats['session_hits'] = self._hit_count
        stats['session_misses'] = self._miss_count
        stats['session_hit_rate'] = self.hit_rate
        return stats


# ============================================================
# 缓存装饰器
# ============================================================

def cached_scan(cache: ScanCache, target_arg: str = 'target',
                plugin_name: str = '', ttl: int = None):
    """扫描函数缓存装饰器

    Args:
        cache: ScanCache 实例
        target_arg: 目标参数名
        plugin_name: 插件名称
        ttl: 缓存有效期

    Returns:
        装饰器函数

    使用方式：
        @cached_scan(cache, plugin_name='sqli_detector')
        def detect_sqli(target, session):
            # 扫描逻辑
            return result
    """
    def decorator(fn):
        def wrapper(*args, **kwargs):
            target = kwargs.get(target_arg) or (args[0] if args else '')
            if not target:
                return fn(*args, **kwargs)

            # 查询缓存
            cached = cache.get_plugin_result(target, plugin_name or fn.__name__)
            if cached is not None:
                return cached.get('result')

            # 执行扫描
            result = fn(*args, **kwargs)

            # 存储缓存
            if result is not None:
                cache.set_plugin_result(target, plugin_name or fn.__name__,
                                       result, ttl=ttl)
            return result
        return wrapper
    return decorator


# ============================================================
# 模式入口
# ============================================================

def run_cache_stats_mode(args) -> int:
    """缓存统计模式入口"""
    db_path = getattr(args, 'cache_db', None) or 'data/scan_cache.db'
    cache = ScanCache(db_path=db_path)
    stats = cache.get_stats()

    print('[*]缓存统计:')
    print(f'    数据库: {db_path}')
    print(f'    总条目: {stats["total_entries"]}')
    print(f'    活跃条目: {stats["active_entries"]}')
    print(f'    过期条目: {stats["expired_entries"]}')
    print(f'    总命中次数: {stats["total_hits"]}')
    print(f'    命中率: {stats["hit_rate"]}')

    if stats['top_hit']:
        print(f'\n[+]高频命中:')
        for item in stats['top_hit']:
            print(f'    {item["target"]} → {item["hit_count"]} 次')

    if stats['by_target']:
        print(f'\n[+]按目标统计:')
        for item in stats['by_target']:
            print(f'    {item["target"]} → {item["cnt"]} 条缓存')

    return 0


def run_cache_clear_mode(args) -> int:
    """缓存清除模式入口"""
    db_path = getattr(args, 'cache_db', None) or 'data/scan_cache.db'
    cache = ScanCache(db_path=db_path)

    # 先清除过期
    expired = cache.clear_expired()
    print(f'[+]已清除 {expired} 条过期缓存')

    # --cache-clear 清除全部
    if getattr(args, 'cache_clear_all', False):
        count = cache.clear_all()
        print(f'[+]已清除全部 {count} 条缓存')

    return 0
