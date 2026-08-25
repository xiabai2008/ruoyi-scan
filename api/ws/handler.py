# D9 WebSocket 连接管理：订阅任务实时事件
#
# 第2周安全收口：
#   - BaseHTTPMiddleware 不拦截 WebSocket 请求，此处单独做与 REST 一致的鉴权
#   - 无 Key 模式：仅允许本地回环（127.0.0.1 / ::1 / localhost / testclient）
#   - 有 Key 模式：密钥经 Sec-WebSocket-Protocol 子协议头传递
#     （浏览器 WebSocket 无法设置自定义 Header，子协议是标准凭据通道；
#      禁止 ?api_key= URL 传输，避免密钥泄露到日志/Referer）
#   - 密钥比较一律使用 hmac.compare_digest（常量时间，防时序侧信道）
import asyncio
import hmac

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.auth import parse_api_keys
from core.task_registry import TaskRegistry

router = APIRouter()

# 心跳间隔（秒）：事件队列空闲时发送 ping 保持连接（测试可缩短验证）
HEARTBEAT_INTERVAL = 30.0

# WebSocket 子协议标识：握手时携带密钥
#   Sec-WebSocket-Protocol: ruoyi-scan-api-key, <api_key>
WS_SUBPROTOCOL = "ruoyi-scan-api-key"

# 无 Key 模式下允许访问的回环地址（与 api/auth.py 中间件保持一致）
_LOCAL_HOSTS = ("127.0.0.1", "::1", "localhost", "testclient")


def _ws_auth_error(websocket: WebSocket) -> str | None:
    """校验 WebSocket 连接凭据；返回 None 表示通过，否则返回拒绝原因

    策略与 ApiKeyMiddleware 一致：
        - api_key 未配置：仅允许本地回环
        - api_key 已配置：从 Sec-WebSocket-Protocol 子协议头取密钥，
          常量时间比较（不提前返回，防时序泄露），禁止 URL 查询参数传输
    """
    api_key = getattr(websocket.app.state, "api_key", "")
    if not api_key:
        client_host = websocket.client.host if websocket.client else ""
        if client_host in _LOCAL_HOSTS:
            return None
        return "API Key 未配置，仅允许本地访问"

    # 从子协议头提取密钥（跳过协议标识自身）
    provided_key = ""
    for part in websocket.headers.get("sec-websocket-protocol", "").split(","):
        part = part.strip()
        if part and part != WS_SUBPROTOCOL:
            provided_key = part
    if not provided_key:
        return "缺少 API Key（Sec-WebSocket-Protocol 子协议头）"

    key_scopes = parse_api_keys(api_key)
    if not key_scopes:
        return None if hmac.compare_digest(provided_key, api_key) else "无效的 API Key"
    # 常量时间遍历查找（不提前返回）
    for stored_key in key_scopes:
        if hmac.compare_digest(provided_key, stored_key):
            return None
    return "无效的 API Key"


async def scan_ws(websocket: WebSocket, task_id: str):
    """WebSocket 端点：订阅扫描任务实时事件

    客户端连接后：
        1. 鉴权（未通过则以 1008 拒绝连接）
        2. 补播历史事件（避免漏看已发生的事件）
        3. 实时推送新事件
        4. 任务完成后发送 complete 事件并保持连接（客户端可主动关闭）

    用法（有 Key 模式需携带子协议密钥）：
        const ws = new WebSocket(
            `ws://localhost:8000/ws/scan/${taskId}`,
            ['ruoyi-scan-api-key', apiKey],
        );
        ws.onmessage = (e) => console.log(JSON.parse(e.data))
    """
    # 鉴权：未通过则拒绝连接（1008 Policy Violation）
    auth_error = _ws_auth_error(websocket)
    if auth_error:
        await websocket.close(code=1008, reason=auth_error)
        return

    # 仅当客户端显式请求了子协议时才回选（否则不返回子协议）
    requested = {
        p.strip() for p in websocket.headers.get("sec-websocket-protocol", "").split(",") if p.strip()
    }
    subprotocol = WS_SUBPROTOCOL if WS_SUBPROTOCOL in requested else None
    await websocket.accept(subprotocol=subprotocol)

    # 从 app.state 获取 registry
    registry: TaskRegistry = websocket.app.state.registry
    record = registry.get(task_id)

    if record is None:
        await websocket.send_json(
            {
                "type": "error",
                "data": {"error": f"任务不存在: {task_id}"},
                "task_id": task_id,
            }
        )
        await websocket.close(code=1008, reason="任务不存在")
        return

    # 1. 补播历史事件
    history = registry.get_history(task_id)
    for event in history:
        await websocket.send_json(event)

    # 如果任务已完成，发送完历史后保持连接（客户端可主动关闭）
    if record.status in ("done", "failed", "cancelled"):
        await websocket.send_json(
            {
                "type": "connection_closed",
                "data": {"reason": f"任务已结束: {record.status}"},
                "task_id": task_id,
            }
        )
        await websocket.close(code=1000, reason="任务已结束")
        return

    # 2. 订阅新事件
    queue = await registry.subscribe(task_id)

    try:
        while True:
            # 等待新事件（带超时心跳）
            try:
                event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_INTERVAL)
                await websocket.send_json(event)

                # 任务完成事件后关闭连接
                if event.get("type") in ("complete", "error"):
                    # 给客户端一点时间接收，然后关闭
                    await asyncio.sleep(0.5)
                    await websocket.close(code=1000, reason="任务完成")
                    break

                # 与上方 complete/error 独立的一条关闭路径：终态 status 事件（兼容事件顺序差异）
                if event.get("type") == "status" and event.get("data", {}).get("status") in (
                    "done",
                    "failed",
                    "cancelled",
                ):
                    await asyncio.sleep(0.5)
                    await websocket.close(code=1000, reason="任务结束")
                    break

            except asyncio.TimeoutError:
                # 心跳：每 30 秒发送 ping 保持连接
                await websocket.send_json(
                    {
                        "type": "ping",
                        "data": {"ts": asyncio.get_event_loop().time()},
                        "task_id": task_id,
                    }
                )

    except WebSocketDisconnect:
        pass
    except Exception:
        # 连接异常关闭
        pass
    finally:
        registry.unsubscribe(task_id, queue)
