# 会话状态判定：如何确认一个 SessionManager 是否已经「带着凭据」。
#
# 为什么单独抽这个模块
# ====================
# 引擎里所有插件复用同一个 SessionManager。而有些插件（默认口令、Druid 爆破、
# 认证链）会在它上面**登录**，登录状态会一直保留给后续所有插件——这是项目记录过的
# 「认证状态泄漏」问题（v4.8.3 曾因此多出 6 个假 CONFIRMED）。
#
# 对「未授权访问」类插件（MinIO/Nacos/Swagger/Druid…）来说这是致命的：
# 它们的被测命题是「**不需要登录**就能访问」。如果探测时手上带着 admin 的 cookie，
# 拿到的 200 只能证明「登录后能访问」，不构成未授权漏洞。
#
# 一个真实会出事的场景：
#   客户把 Swagger 开了但配了认证 → 扫描器先跑「后台默认口令」拿到会话
#   → Swagger 插件复用该会话 → 200 + 真实页面 → 报「Swagger 未授权访问」
#   → 客户复核「我们明明加了认证」，报告可信度归零。
#
# 为什么不直接用 session.authenticated
# ====================================
# `SessionManager.authenticated` 只由 orchestrator 在扫描前按 `--auth-login` 的结果
# 显式设置，**不反映插件中途登录造成的泄漏**——默认口令插件跑完之后，
# 那个标志仍然是 False，但 cookie 已经在会话里了。
#
# 所以必须直接看凭据本身：cookie jar 非空 / 存在 Authorization 头。
# 这也是唯一可靠、不依赖调用顺序的判断方式。
from __future__ import annotations

from typing import Any

from common.logger import get_logger

logger = get_logger(__name__)


def session_has_credentials(session: Any) -> bool:
    """判断会话是否已经带有凭据（cookie 或 Authorization 头）。

    Args:
        session: SessionManager 实例（或任何有 `.session` 属性的包装对象）

    Returns:
        True 表示会话已有认证痕迹，用它做「未授权」判定会失真。
        拿不到内部会话时返回 False（保守：不因此阻断插件，只是不做隔离）。
    """
    inner = getattr(session, "session", None)  # SessionManager 内部的 requests.Session
    if inner is None:
        return False
    try:
        if len(list(inner.cookies)) > 0:
            return True
        headers = inner.headers or {}
        return any(str(k).lower() == "authorization" for k in headers)
    except Exception:
        logger.debug("会话凭据判定失败", exc_info=True)
        return False


def session_credential_summary(session: Any) -> str:
    """凭据摘要（写进证据用；**只报类型与数量，绝不回显凭据值**）。

    漏洞报告会外发，cookie 值等同于账号凭据，不能进 evidence。
    """
    inner = getattr(session, "session", None)
    if inner is None:
        return "无内部会话"
    try:
        n = len(list(inner.cookies))
        has_auth = any(str(k).lower() == "authorization" for k in (inner.headers or {}))
    except Exception:
        return "无法读取"
    parts = []
    if n:
        parts.append(f"{n} 个 cookie")
    if has_auth:
        parts.append("Authorization 头")
    return "、".join(parts) if parts else "无凭据"
