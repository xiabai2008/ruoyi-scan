# 全站拦截探测：识别 WAF / 网关 / 认证墙导致的「全站统一拒绝」
#
# 为什么需要它
# ============
# 三态判定承诺「网络异常、WAF 拦截、验证码阻断 → UNKNOWN，绝不冒充 SAFE」。
# 但站点被 WAF 全站拦截时，每个插件拿到的都是一致的 403，按插件自身的判定逻辑
# 会落到「没命中 = 不存在」分支，于是一份报告可能写着「22 项确认不存在」——
# 而真实情况是「一项都没测到」。这是比漏报更危险的方向（假安全感）。
#
# 本模块在插件执行前做一次基线探测：
#   - 随机不存在路径（站点应返回 404）
#   - 站点根路径
# 若随机路径返回 401/403/406/429/5xx（而非 404），说明拦截发生在路由之前，
# 此时把全部 SAFE 结果降级为 UNKNOWN，并在 evidence 里写清原因。
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List

from common.logger import get_logger
from common.models import STATUS_SAFE, STATUS_UNKNOWN

logger = get_logger(__name__)

# 这些状态码说明「请求没被正常处理」，而不是「资源不存在」
_BLOCK_STATUS = frozenset({401, 403, 406, 407, 429, 500, 502, 503, 504})


def _probe(session: Any, url: str) -> Dict[str, Any]:
    """发起一次探测，返回状态码/Server 头/是否异常。"""
    info: Dict[str, Any] = {"url": url, "status": 0, "server": "", "error": ""}
    try:
        resp = session.get(url)
        info["status"] = int(getattr(resp, "status_code", 0) or 0)
        headers = getattr(resp, "headers", {}) or {}
        info["server"] = str(headers.get("Server", ""))[:60]
    except Exception as e:  # 网络异常本身不构成"拦截"，交给插件判 UNKNOWN
        info["error"] = f"{type(e).__name__}: {e}"[:200]
    return info


def detect_blocked(session: Any, target: str) -> Dict[str, Any]:
    """探测目标是否被全站拦截。

    Args:
        session: 已配置的 HTTP 会话（需提供 get(url)）
        target: 已归一化的目标根 URL

    Returns:
        {
          "blocked": bool,      # 是否判定为全站拦截
          "status": int,        # 随机路径的状态码
          "root_status": int,   # 根路径状态码
          "server": str,        # Server 头（常见 WAF 会改写）
          "probe_path": str,    # 探测路径
          "reason": str,        # 人类可读原因
        }
    """
    token = uuid.uuid4().hex
    path = f"/__ruoyi_scan_block_probe_{token}"
    probe = _probe(session, target.rstrip("/") + path)
    root = _probe(session, target)
    status = probe["status"]

    blocked = False
    reason = ""
    if status in _BLOCK_STATUS:
        blocked = True
        reason = f"随机路径返回 {status}（正常站点应为 404），疑似 WAF/网关在路由前拦截"
    elif probe["error"] and root["status"] in _BLOCK_STATUS:
        blocked = True
        reason = f"随机路径请求失败、根路径返回 {root['status']}，疑似全站拦截"
    elif status == 200 and root["status"] in _BLOCK_STATUS:
        # 兜底路由把所有路径都回 200，但根路径是拒绝态
        blocked = True
        reason = f"根路径返回 {root['status']}，疑似网关拒绝"

    info = {
        "blocked": blocked,
        "status": status,
        "root_status": root["status"],
        "server": probe["server"] or root["server"],
        "probe_path": path,
        "reason": reason,
    }
    if blocked:
        logger.warning("目标疑似全站拦截：%s（probe=%s root=%s）", reason, status, root["status"])
    return info


def downgrade_safe_results(results: List[Any], block: Dict[str, Any]) -> int:
    """把 SAFE 结果降级为 UNKNOWN（全站拦截时 SAFE 不成立）。

    CONFIRMED 保留：即便有 WAF，拿到回显证据就仍是确认存在。
    返回被降级的条数。
    """
    if not block or not block.get("blocked"):
        return 0
    note = f"目标疑似被拦截（{block.get('reason', '')}），本次未取得有效响应"
    n = 0
    for r in results:
        if getattr(r, "status", "") != STATUS_SAFE:
            continue
        r.status = STATUS_UNKNOWN
        old = getattr(r, "evidence", "") or ""
        r.evidence = f"{note}；原证据：{old}" if old else note
        extra = dict(getattr(r, "extra", None) or {})
        extra["blocked"] = True
        extra["blocked_status"] = block.get("status")
        r.extra = extra
        n += 1
    if n:
        logger.warning("全站拦截：%d 条 SAFE 已降级为 UNKNOWN", n)
    return n


# 响应里出现这些字样 = 请求被拒绝（未认证/无权限/限流），而不是"漏洞不存在"。
# 用正则而非裸数字：证据里常有 "长度=1403" / URL 路径含 403 之类，裸匹配会误伤。
_DENY_RE = re.compile(
    r"(?:状态码|status|code|HTTP)[^\dA-Za-z]{0,4}(401|403|429)\b"
    r"|Unauthorized|Forbidden|Too Many Requests|认证失败|未登录|无权限|没有权限",
    re.IGNORECASE,
)


def upgrade_denied_safe_to_unknown(results: List[Any]) -> int:
    """把「因 401/403/429 被判成 SAFE」的结果改成 UNKNOWN。

    背景：只有全站拦截才会触发 detect_blocked；但真实站点更常见的是**单个接口**
    要求登录——插件拿到 `{"code":401,"msg":"认证失败"}` 后按"没有命中特征"判定
    SAFE，等于把"没测到"写成"确认不存在"。审计实测：行为级靶场上
    POST型报错注入（role/dept）与任意文件上传在 401 响应下均被判 SAFE。

    这里做统一兜底：SAFE 且证据里出现拒绝类标记 → UNKNOWN，并标注原因。
    CONFIRMED / 已是 UNKNOWN 的结果不受影响。
    """
    n = 0
    for r in results:
        if getattr(r, "status", "") != STATUS_SAFE:
            continue
        ev = str(getattr(r, "evidence", "") or "")
        m = _DENY_RE.search(ev)
        if not m:
            continue
        hit = m.group(1) or m.group(0)
        r.status = STATUS_UNKNOWN
        r.evidence = f"响应被拒绝（{hit}，无法判定是否存在）；原证据：{ev}" if ev else f"响应被拒绝（{hit}）"
        extra = dict(getattr(r, "extra", None) or {})
        extra["denied"] = True
        r.extra = extra
        n += 1
    if n:
        logger.warning("响应被拒绝（401/403/429）：%d 条 SAFE 已改为 UNKNOWN", n)
    return n
