"""显式低权限账号解析（越权对照的唯一来源）。

设计约束：
- 不内置任何默认账号。账号只能来自 `--surface-account user:pass`（可多次）
  或 API 的 surface_account 字段。
- 未提供账号时，调用方必须把结果判为 UNKNOWN，不能判 SAFE。
- 凭据挂在每次扫描的 SessionManager 上（`session.surface_account`），
  不走进程级 settings，避免并发任务之间互相污染。
"""

from typing import Any, Optional, Tuple

Account = Tuple[str, str]


def parse_account(value: str) -> Optional[Account]:
    """解析 "user:pass"；格式不合法返回 None（不抛异常，避免单条脏配置中断扫描）。"""
    raw = str(value or "")
    user, sep, password = raw.partition(":")
    user = user.strip()
    if not sep or not user or not password:
        return None
    return user, password


def resolve_surface_account(session: Any) -> Optional[Account]:
    """从当前扫描会话读取显式低权账号；没有则返回 None。

    只认 SessionManager 上的 surface_account，不读 settings/env——
    默认值一旦存在，就会在真实客户环境里变成一个静默生效的假账号。
    """
    raw = getattr(session, "surface_account", None)
    if isinstance(raw, (tuple, list)) and len(raw) == 2:
        user, password = str(raw[0] or ""), str(raw[1] or "")
        if user and password:
            return user, password
    return None
