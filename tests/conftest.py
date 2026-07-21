"""Pytest 共享 fixture（tests/conftest.py）

消除测试文件中的重复 setup 代码：
- sys.path 注入（替代 39 处 sys.path.insert）
- mock_router / mock_network（替代 3 文件重复 patch 块）
- app / client（替代 4 文件重复 TestClient 创建）
- storage / registry / mock_registry（替代重复实例化）
- make_scan_request / sample_scan_request（替代 22 处 ScanRequest 构造）
- tmp_report_dir / cache_db_path（统一临时目录风格）

注意：现有测试文件中的 sys.path.insert 和 fixture 定义不会立即删除，
新 fixture 供后续测试迁移使用，保证渐进式重构安全。
"""

import atexit
import os as _os
import sys as _sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# 确保项目根目录在 sys.path 中（替代各测试文件顶部的 sys.path.insert）
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, PROJECT_ROOT)


# ── 进程退出安全网 ──────────────────────────────────────────────

# concurrent.futures 在 import 时通过 atexit.register(_python_exit) 注册了
# atexit handler，它会 join 所有 ThreadPoolExecutor 线程——包括 ScanEngine
# 内部线程池的非 daemon 线程。当 mock fixture 失效后后台线程加载真实插件
# 并发起 HTTP 请求，join 无限等待导致 pytest 进程挂起（CI D9 超时根因）。
#
# 解决方案：在 _python_exit 之前注册我们的 atexit handler，用 os._exit 绕过
# 后续 atexit handler（包括 _python_exit）。atexit 按后注册先执行的顺序调用，
# 因此我们在 conftest import 时注册即可保证先于 _python_exit 执行。
_exit_code_holder = {"code": 0}


def pytest_sessionfinish(session, exitstatus):
    """记录最终 exitstatus，供 atexit handler 使用"""
    _exit_code_holder["code"] = exitstatus


def _force_exit_bypass_thread_join():
    """绕过 concurrent.futures._python_exit，强制进程退出"""
    _sys.stdout.flush()
    _sys.stderr.flush()
    _os._exit(_exit_code_holder["code"])


atexit.register(_force_exit_bypass_thread_join)


# ── P0: mock_router / mock_network ──────────────────────────────


@pytest.fixture
def mock_router():
    """Mock core.orchestrator.Router，避免真实插件加载

    resolve() 和 resolve_by_name() 返回空列表，
    适用于不依赖具体插件逻辑的 orchestrator / API 测试。
    """
    with patch("core.orchestrator.Router") as mock:
        mock.return_value.resolve.return_value = []
        mock.return_value.resolve_by_name.return_value = []
        yield mock


@pytest.fixture
def mock_network(mock_router):
    """完整 mock：Router + detect_cms + detect_waf + load_plugins

    适用于 API 集成测试（test_api_scan / test_api_ws）和
    orchestrator 的 submit/run_sync 测试，避免真实网络请求和插件加载。
    """
    with patch("core.orchestrator.detect_cms") as mock_cms, patch("core.orchestrator.detect_waf") as mock_waf, patch(
        "core.orchestrator.load_plugins"
    ) as mock_load:
        mock_cms.return_value = MagicMock(cms="", version="", confidence=0, matched=[])
        mock_waf.return_value = {"waf": "", "display": "", "bypass_hint": ""}
        mock_load.return_value = []
        yield {"router": mock_router, "cms": mock_cms, "waf": mock_waf, "load": mock_load}


# ── P0: app / client ────────────────────────────────────────────


@pytest.fixture
def app(tmp_path):
    """创建 FastAPI 应用（临时 SQLite 数据库）

    使用 tmp_path 自动清理，替代 tempfile.mkdtemp + shutil.rmtree 反模式。
    """
    from api.app import create_app

    db_path = str(tmp_path / "test_task.db")
    application = create_app(db_path=db_path)
    yield application


@pytest.fixture
def app_with_key(tmp_path):
    """创建带 API Key 鉴权的 FastAPI 应用"""
    from api.app import create_app

    db_path = str(tmp_path / "test_task_auth.db")
    application = create_app(api_key="test-secret-key", db_path=db_path)
    yield application


@pytest.fixture
def app_in_memory():
    """创建使用 :memory: SQLite 的 FastAPI 应用（无持久化）"""
    from api.app import create_app

    application = create_app(db_path=":memory:")
    yield application


@pytest.fixture
def client(app, mock_network):
    """FastAPI TestClient（自动管理 startup/shutdown）

    依赖 mock_network：确保 mock 在 client 之前 setup、之后 teardown，
    使 orchestrator.shutdown() 在 mock 仍生效时执行（避免后台线程脱离 mock 后
    加载真实插件并发起 HTTP 请求导致进程挂起）。
    """
    from starlette.testclient import TestClient

    with TestClient(app) as c:
        yield c


@pytest.fixture
def client_with_key(app_with_key):
    """带 API Key 鉴权的 TestClient"""
    from starlette.testclient import TestClient

    with TestClient(app_with_key) as c:
        yield c


# ── P1: storage / registry ──────────────────────────────────────


@pytest.fixture
def storage(tmp_path):
    """SQLite Storage 实例（临时数据库）"""
    from core.storage import Storage

    db_path = str(tmp_path / "test_storage.db")
    return Storage(db_path)


@pytest.fixture
def registry():
    """真实 TaskRegistry 实例（默认参数）"""
    from core.task_registry import TaskRegistry

    return TaskRegistry()


@pytest.fixture
def registry_factory():
    """TaskRegistry 工厂 fixture（支持自定义参数）

    用法：
        def test_xxx(registry_factory):
            reg = registry_factory(max_events_per_task=5, retention_seconds=0)
    """
    from core.task_registry import TaskRegistry

    def _create(**kwargs):
        return TaskRegistry(**kwargs)

    return _create


@pytest.fixture
def mock_registry():
    """MagicMock TaskRegistry（用于 orchestrator 异步提交测试）"""
    reg = MagicMock()
    return reg


@pytest.fixture
def orch(mock_registry, mock_router):
    """ScanOrchestrator 实例（带 mock registry + mock router）

    yield 后自动 shutdown，清理线程池。
    """
    from core.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator(registry=mock_registry)
    yield orchestrator
    try:
        orchestrator.shutdown()
    except Exception:
        pass


# ── P1: ScanRequest 工厂 ────────────────────────────────────────


@pytest.fixture
def make_scan_request():
    """ScanRequest 工厂 fixture（预设合理默认值）

    用法：
        def test_xxx(make_scan_request):
            req = make_scan_request(target='http://target:8080/', mode='p')
            req = make_scan_request(mode='u', threads=5)
    """
    from core.orchestrator import ScanRequest

    def _create(**kwargs):
        defaults = {
            "target": "http://example.com/",
            "mode": "p",
        }
        defaults.update(kwargs)
        return ScanRequest(**defaults)

    return _create


@pytest.fixture
def sample_scan_request(make_scan_request):
    """预构造的常用 ScanRequest（mode='p', target='http://example.com/'）"""
    return make_scan_request()


# ── P2: 临时目录辅助 ────────────────────────────────────────────


@pytest.fixture
def tmp_report_dir(tmp_path):
    """报告输出临时目录（替代 tempfile.TemporaryDirectory 反模式）"""
    report_dir = tmp_path / "reports"
    report_dir.mkdir(exist_ok=True)
    return report_dir


@pytest.fixture
def cache_db_path(tmp_path):
    """缓存数据库路径（供 CacheStorage / ScanCache 测试）"""
    return str(tmp_path / "cache.db")
