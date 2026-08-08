# D9 WebSocket 连接管理：订阅任务实时事件
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.task_registry import TaskRegistry

router = APIRouter()

# 心跳间隔（秒）：事件队列空闲时发送 ping 保持连接（测试可缩短验证）
HEARTBEAT_INTERVAL = 30.0


async def scan_ws(websocket: WebSocket, task_id: str):
    """WebSocket 端点：订阅扫描任务实时事件

    客户端连接后：
        1. 补播历史事件（避免漏看已发生的事件）
        2. 实时推送新事件
        3. 任务完成后发送 complete 事件并保持连接（客户端可主动关闭）

    用法：
        ws = new WebSocket('ws://localhost:8000/ws/scan/{task_id}')
        ws.onmessage = (e) => console.log(JSON.parse(e.data))
    """
    await websocket.accept()

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
