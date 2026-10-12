"""CLI submodule — Web API 服务"""

from __future__ import annotations

import os
from argparse import Namespace

from common.logger import get_logger
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW
from lib.reporter import set_quiet

logger = get_logger(__name__)


def run_serve_mode(args: Namespace) -> None:
    """Web API 服务模式（D9 + D11）：启动 FastAPI + WebSocket + Web 控制台"""
    print(f"{YELLOW}[*]启动 Web API 服务模式（D9 + D11）{RESET}")
    print(f"{YELLOW}[*]监听地址: {args.host}:{args.port}{RESET}")
    print(f"{YELLOW}[*]API 文档: http://{args.host}:{args.port}/docs{RESET}")
    print(f"{YELLOW}[*]Web 控制台: http://{args.host}:{args.port}/{RESET}")

    # API Key 成链回退：命令行 --api-key 优先，环境变量兜底；均缺失则降级为仅本机可访问
    api_key = getattr(args, "api_key", None) or ""
    if not api_key:
        api_key = os.environ.get("RUOYI_SCAN_API_KEY", "")
    if api_key:
        print(f"{GREEN}[*]API 鉴权: 已启用（X-API-Key 头）{RESET}")
    else:
        print(f"{YELLOW}[*]API 鉴权: 未设置 API Key，仅允许 127.0.0.1 访问{RESET}")

    db_path = args.db_path or "data/tasks.db"
    print(f"{YELLOW}[*]任务持久化: {db_path}{RESET}")

    # E9：定时扫描（--schedule "cron" --schedule-target <url>）
    schedule_expr = getattr(args, "schedule", None) or ""
    schedule_target = getattr(args, "schedule_target", None) or ""
    # 定时扫描两个参数必须成对出现：半配置若继续启动，调度任务会被静默忽略
    # （create_app 仅在两者齐备时注册），用户以为在定时扫描实则从未生效，故直接失败
    if bool(schedule_expr) != bool(schedule_target):
        print(f"{RED}[!]定时扫描需同时指定 --schedule 与 --schedule-target{RESET}")
        return
    if schedule_expr and schedule_target:
        print(f"{YELLOW}[*]定时扫描: {schedule_expr} → {schedule_target}{RESET}")

    print(f"{SEPARATOR}")

    # 仅依赖导入错误在 try 内捕获：create_app 的其它启动错误与运行期错误
    # 各自带有真实语义，不应被误报为"缺少 fastapi + uvicorn"
    try:
        import uvicorn

        from api.app import create_app
    except ImportError as e:
        print(f"{RED}[!]启动 API 服务需要 fastapi + uvicorn，请安装：pip install fastapi uvicorn[standard]{RESET}")
        print(f"{RED}[!]缺失模块: {e}{RESET}")
        return

    # 服务模式默认静默：插件的进度输出改走 logging，不再直接写服务进程 stdout
    # （API 已通过 WebSocket 事件流向前端推送实时进度，stdout 属冗余噪音）。
    # 注意：静默是服务入口的职责，create_app 作为工厂不再改写全局 reporter 状态，
    # 避免库/测试调用 create_app 时被意外带入静默模式。
    set_quiet(True)
    # 未指定 --cors-origins 时保持 None，交由 create_app 应用默认 CORS 策略
    cors_origins = None
    if args.cors_origins:
        cors_origins = [o.strip() for o in args.cors_origins.split(",") if o.strip()]
    app = create_app(
        api_key=api_key,
        cors_origins=cors_origins,
        db_path=args.db_path or "",
        schedule_expr=schedule_expr or None,
        schedule_target=schedule_target or None,
    )
    # uvicorn.run 阻塞直至服务停止
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
