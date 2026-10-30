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

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.auth import _secure_equals, parse_api_keys
from common.logger import get_logger
from core.task_registry import TaskRegistry

logger = get_logger(__name__)

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
        return None if _secure_equals(provided_key, api_key) else "无效的 API Key"
    # 常量时间遍历查找（不提前返回，与 ApiKeyMiddleware._lookup_scope 一致）
    matched = False
    for stored_key in key_scopes:
        matched |= _secure_equals(provided_key, stored_key)
    return None if matched else "无效的 API Key"


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
    requested = {p.strip() for p in websocket.headers.get("sec-websocket-protocol", "").split(",") if p.strip()}
    subprotocol = WS_SUBPROTOCOL if WS_SUBPROTOCOL in requested else None
    await websocket.accept(subprotocol=subprotocol)

    # 从 app.state 获取 registry
    registry: TaskRegistry = websocket.app.state.registry

    # 任务不存在时直接拒绝：先于 subscribe，避免为随机 task_id 在订阅表中留下空条目
    if registry.get(task_id) is None:
        await websocket.send_json(
            {
                "type": "error",
                "data": {"error": f"任务不存在: {task_id}"},
                "task_id": task_id,
            }
        )
        await websocket.close(code=1008, reason="任务不存在")
        return

    # 1. 先订阅再补播：若先补播后订阅，两步之间由工作线程产生的事件只进历史不进队列，
    #    客户端会永久漏事件；先订阅保证窗口内事件一定进入队列，重复部分按对象身份去重
    #    （notify 写入历史与投递队列的是同一个 event 对象）。
    queue = await registry.subscribe(task_id)

    try:
        # 2. 先取任务快照，再补播历史：任务的终态事件与状态在同一次 notify 锁内写入，
        #    因此只要快照已是终态，终态事件必然包含在随后的历史快照中
        record = registry.get(task_id)
        if record is None:
            # 订阅窗口内任务被清理（保留期外），按不存在处理
            await websocket.send_json(
                {
                    "type": "error",
                    "data": {"error": f"任务不存在: {task_id}"},
                    "task_id": task_id,
                }
            )
            await websocket.close(code=1008, reason="任务不存在")
            return

        # 3. 补播历史事件
        history = registry.get_history(task_id)
        replayed = {id(event) for event in history}
        for event in history:
            await websocket.send_json(event)

        # 如果任务已完成，发送完历史后保持连接（客户端可主动关闭）
        if record.status in ("done", "failed", "cancelled", "interrupted"):
            await websocket.send_json(
                {
                    "type": "connection_closed",
                    "data": {"reason": f"任务已结束: {record.status}"},
                    "task_id": task_id,
                }
            )
            await websocket.close(code=1000, reason="任务已结束")
            return

        # 4. 实时推送新事件
        while True:
            # 等待新事件（带超时心跳）
            try:
                event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_INTERVAL)
            except asyncio.TimeoutError:
                # 心跳：每 30 秒发送 ping 保持连接
                await websocket.send_json(
                    {
                        "type": "ping",
                        "data": {"ts": asyncio.get_running_loop().time()},
                        "task_id": task_id,
                    }
                )
                continue

            # 订阅窗口内产生的事件既在补播历史中又在队列里，跳过重复投递
            if id(event) not in replayed:
                await websocket.send_json(event)

            # 任务完成事件后关闭连接（补播过的重复终态事件也要触发关闭，避免漏关）
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
                "interrupted",
            ):
                await asyncio.sleep(0.5)
                await websocket.close(code=1000, reason="任务结束")
                break

    except WebSocketDisconnect:
        pass
    except Exception:
        # 连接异常关闭：断连本身属常态，但序列化失败/registry 内部错误等
        # 意外异常需要日志留痕（debug 档可查），不再静默 pass
        logger.debug("WebSocket 会话异常终止 task_id=%s", task_id, exc_info=True)
    finally:
        registry.unsubscribe(task_id, queue)
