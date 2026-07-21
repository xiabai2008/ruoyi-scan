"""性能基准测试（P2: pytest-benchmark 框架）

衡量关键路径性能，防止性能回归：
- SessionManager 连接池性能
- CacheStorage WAL 模式并发性能
- AsyncScanEngine 批量扫描性能
- PluginBase CVSS 评分计算性能

运行方式：
    python -m pytest tests/test_benchmark.py --benchmark-only -v
    python -m pytest tests/test_benchmark.py --benchmark-only --benchmark-compare

注意：CI 默认不运行基准测试（pytest-benchmark 仅在 dev 依赖中）。
CI 通过 --ignore tests/test_benchmark.py 跳过，或通过 pytest.ini 的 addopts 排除。
"""

import os
import sys

import pytest

# 确保项目根目录在 sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# 当 pytest-benchmark 未安装时跳过所有基准测试
# pytest-benchmark 注册 'benchmark' fixture，通过 _pytest.fixture 检测
try:
    import pytest_benchmark  # noqa: F401

    _HAS_BENCHMARK = True
except ImportError:
    _HAS_BENCHMARK = False

pytestmark = pytest.mark.skipif(
    not _HAS_BENCHMARK,
    reason="pytest-benchmark 未安装，跳过基准测试（pip install pytest-benchmark 启用）",
)


# ── SessionManager 连接池基准 ──────────────────────────


class TestSessionManagerBenchmark:
    """SessionManager 连接池 + 重试性能基准"""

    def test_session_creation(self, benchmark):
        """基准：SessionManager 创建（含 HTTPAdapter 配置）"""
        from core.session import SessionManager

        def create_session():
            return SessionManager(timeout=10)

        sm = benchmark(create_session)
        assert sm is not None
        assert sm.session is not None

    def test_session_pool_config(self, benchmark):
        """基准：连接池大小配置（threads=20 场景）"""
        from core.session import SessionManager

        def config_pool():
            return SessionManager(pool_size=20, max_retries=2)

        sm = benchmark(config_pool)
        adapter = sm.session.get_adapter("https://example.com")
        assert adapter._pool_maxsize == 40  # pool_size * 2


# ── CacheStorage WAL 并发性能基准 ──────────────────────


class TestCacheBenchmark:
    """CacheStorage WAL 模式性能基准"""

    @pytest.fixture
    def cache(self, tmp_path):
        from lib.cache import CacheStorage

        db_path = str(tmp_path / "bench_cache.db")
        c = CacheStorage(db_path)
        yield c
        c.close()

    def test_cache_set(self, benchmark, cache):
        """基准：缓存写入（WAL 模式）"""

        data = {"name": "SQL注入测试", "status": "CONFIRMED", "severity": "high"}

        def cache_set():
            cache.set("bench_key_001", "http://target.com/", data, ttl=3600, plugin_name="SQL注入-角色列表")

        benchmark(cache_set)

    def test_cache_get(self, benchmark, cache):
        """基准：缓存读取（WAL 模式，含命中计数）"""
        data = {"name": "SQL注入测试", "status": "CONFIRMED", "severity": "high"}
        cache.set("bench_get_key", "http://target.com/", data, ttl=3600)

        def cache_get():
            return cache.get("bench_get_key")

        result = benchmark(cache_get)
        assert result is not None
        assert result["status"] == "CONFIRMED"

    def test_cache_miss(self, benchmark, cache):
        """基准：缓存未命中（空查询）"""

        def cache_miss():
            return cache.get("nonexistent_key_12345")

        result = benchmark(cache_miss)
        assert result is None


# ── AsyncScanEngine 批量扫描基准 ────────────────────────


class TestAsyncEngineBenchmark:
    """AsyncScanEngine 批量并发性能基准"""

    def test_batch_concurrent(self, benchmark):
        """基准：4 目标并发扫描（模拟 IO）"""
        import time

        from lib.async_engine import scan_batch_targets

        def slow_scan(target):
            time.sleep(0.05)  # 模拟 50ms 网络请求
            return [{"target": target, "status": "CONFIRMED"}]

        targets = ["http://a.com/", "http://b.com/", "http://c.com/", "http://d.com/"]

        def run_batch():
            return scan_batch_targets(scan_fn=slow_scan, targets=targets, max_workers=4)

        results = benchmark(run_batch)
        assert len(results) == 4

    def test_batch_sequential_comparison(self, benchmark):
        """基准：4 目标顺序扫描（对照组）"""
        import time

        def slow_scan_sequential(targets):
            results = []
            for t in targets:
                time.sleep(0.05)
                results.append({"target": t, "status": "CONFIRMED"})
            return results

        targets = ["http://a.com/", "http://b.com/", "http://c.com/", "http://d.com/"]

        results = benchmark(slow_scan_sequential, targets)
        assert len(results) == 4


# ── CVSS 评分计算基准 ──────────────────────────────────


class TestCVSSBenchmark:
    """CVSS v3.1 评分计算性能基准"""

    def test_cvss_calculation(self, benchmark):
        """基准：CVSS v3.1 向量解析 + 评分计算"""
        from plugins.base import cvss_score

        # 典型 CVSS v3.1 向量（SQL 注入：高严重度）
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        score = benchmark(cvss_score, vector)
        assert 9.0 <= score <= 10.0  # Critical range

    def test_cvss_empty_vector(self, benchmark):
        """基准：空向量快速返回（零开销路径）"""
        from plugins.base import cvss_score

        score = benchmark(cvss_score, "")
        assert score == 0.0


# ── 插件加载基准 ───────────────────────────────────────


class TestPluginLoaderBenchmark:
    """插件加载性能基准"""

    def test_discover_packages(self, benchmark):
        """基准：插件包自动发现"""
        from core.loader import discover_plugin_packages

        packages = benchmark(discover_plugin_packages)
        assert len(packages) >= 3  # ruoyi + spring + common

    def test_load_all_plugins(self, benchmark):
        """基准：加载全部插件类"""
        from core.loader import discover_plugin_packages, load_plugins

        def load_all():
            all_plugins = []
            for pkg in discover_plugin_packages():
                all_plugins.extend(load_plugins(pkg))
            return all_plugins

        plugins = benchmark(load_all)
        assert len(plugins) >= 30  # 38 POC - some may be filtered
