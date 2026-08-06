"""CLI submodule — Web API 服务"""

from __future__ import annotations

import os
from argparse import Namespace

from common.logger import get_logger
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW

logger = get_logger(__name__)


def run_serve_mode(args: Namespace) -> None:
    """Web API 服务模式（D9 + D11）：启动 FastAPI + WebSocket + Web 控制台"""
    print(f"{YELLOW}[*]启动 Web API 服务模式（D9 + D11）{RESET}")
    print(f"{YELLOW}[*]监听地址: {args.host}:{args.port}{RESET}")
    print(f"{YELLOW}[*]API 文档: http://{args.host}:{args.port}/docs{RESET}")
    print(f"{YELLOW}[*]Web 控制台: http://{args.host}:{args.port}/{RESET}")

    api_key = getattr(args, "api_key", None) or ""
    if not api_key:
        api_key = os.environ.get("RUOYI_SCAN_API_KEY", "")
    if api_key:
        print(f"{GREEN}[*]API 鉴权: 已启用（X-API-Key 头）{RESET}")
    else:
        print(f"{YELLOW}[*]API 鉴权: 未设置 API Key，仅允许 127.0.0.1 访问{RESET}")

    db_path = args.db_path or "data/tasks.db"
    print(f"{YELLOW}[*]任务持久化: {db_path}{RESET}")
    print(f"{SEPARATOR}")

    try:
        import uvicorn

        from api.app import create_app

        cors_origins = None
        if args.cors_origins:
            cors_origins = [o.strip() for o in args.cors_origins.split(",") if o.strip()]
        app = create_app(api_key=api_key, cors_origins=cors_origins, db_path=args.db_path or "")
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    except ImportError as e:
        print(f"{RED}[!]启动 API 服务需要 fastapi + uvicorn，请安装：pip install fastapi uvicorn[standard]{RESET}")
        print(f"{RED}[!]缺失模块: {e}{RESET}")
