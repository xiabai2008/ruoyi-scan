# D9 FastAPI 应用工厂
#
# 创建 FastAPI 应用，注册路由、WebSocket、静态资源，
# 绑定 TaskRegistry 和 ScanOrchestrator 到 app.state。
# D11：新增 API Key 鉴权中间件 + CORS 收紧 + SQLite 持久化
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from core.task_registry import TaskRegistry
from core.orchestrator import ScanOrchestrator
from core.storage import Storage, DEFAULT_DB_PATH
from api.routes import scan, report, plugin, system
from api import metrics
from api.ws.handler import scan_ws
from api.auth import ApiKeyMiddleware, get_api_key_from_env


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期：startup 绑定 loop + 恢复历史，shutdown 清理资源"""
    import asyncio
    # Startup: 绑定 asyncio loop 到 registry（跨线程推送需要）
    loop = asyncio.get_running_loop()
    app.state.registry.bind_loop(loop)
    # D11：从 SQLite 恢复历史任务到内存
    if app.state.storage:
        app.state.registry.restore_from_storage(app.state.storage)
    yield
    # Shutdown: 清理资源
    app.state.registry.unbind_loop()
    app.state.orchestrator.shutdown()


def create_app(api_key: str = '', cors_origins: list = None,
               db_path: str = '') -> FastAPI:
    """创建 FastAPI 应用实例

    Args:
        api_key: API Key（空则从环境变量获取，仍空则仅允许本地访问）
        cors_origins: 允许的 CORS 源列表（None 默认仅 localhost）
        db_path: SQLite 路径（空则用默认 data/tasks.db）

    Returns:
        配置好的 FastAPI 应用
    """
    app = FastAPI(
        title='若依综合漏洞检测 API',
        description='Ruoyi-Scan Web API — 提交扫描任务、实时事件推送、报告下载',
        version='1.0.0',
        docs_url='/docs',
        redoc_url='/redoc',
        lifespan=lifespan,
    )

    # D11：CORS 收紧（默认仅 localhost，可配置）
    if cors_origins is None:
        cors_origins = ['http://localhost:3000', 'http://127.0.0.1:3000',
                        'http://localhost:8000', 'http://127.0.0.1:8000']
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=['GET', 'POST', 'DELETE'],
        allow_headers=['X-API-Key', 'Content-Type', 'Authorization'],
    )

    # D11：API Key 鉴权中间件
    key = api_key or get_api_key_from_env()
    app.add_middleware(ApiKeyMiddleware, api_key=key)

    # D11：SQLite 持久层
    storage = Storage(db_path or DEFAULT_DB_PATH)

    # 核心组件
    registry = TaskRegistry(storage=storage)
    orchestrator = ScanOrchestrator(registry=registry)

    # 挂载到 app.state（路由通过 Depends 访问）
    app.state.registry = registry
    app.state.orchestrator = orchestrator
    app.state.storage = storage
    app.state.api_key = key

    # 注册 REST 路由
    app.include_router(scan.router, prefix='/api')
    app.include_router(report.router, prefix='/api')
    app.include_router(plugin.router, prefix='/api')
    app.include_router(system.router, prefix='/api')
    # D16：Prometheus 指标端点
    app.include_router(metrics.router, prefix='/api')

    # 注册 WebSocket 路由
    app.add_api_websocket_route('/ws/scan/{task_id}', scan_ws, name='scan_ws')

    # 静态资源（Web 控制台）— 仅当 web/ 目录存在时挂载
    web_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'web')
    if os.path.isdir(web_dir):
        app.mount('/', StaticFiles(directory=web_dir, html=True), name='web')

    return app
