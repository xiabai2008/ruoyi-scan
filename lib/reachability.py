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

    # 判定要区分「WAF 在路由前拦截」与「站点正常限流/偶发 5xx」：
    # 随机路径 429/5xx 且根路径正常，是限流或应用错误，不是全站拦截（对抗审计实测误报）。
    blocked = False
    reason = ""
    if status in (401, 403, 406):
        blocked = True
        reason = f"随机路径返回 {status}（正常站点应为 404），疑似 WAF/网关在路由前拦截"
    elif status in (429, 500, 502, 503, 504) and root["status"] in _BLOCK_STATUS:
        # 根路径也是拒绝/错误态，才说明整站都进不去
        blocked = True
        reason = f"随机路径返回 {status} 且根路径 {root['status']}，疑似全站拦截"
    elif status == 200 and root["status"] in (401, 403, 406, 429):
        # 兜底路由把所有路径都回 200，但根路径是拒绝态
        blocked = True
        reason = f"根路径返回 {root['status']}，疑似网关拒绝"
    elif probe["error"] and root["status"] in (401, 403, 406):
        blocked = True
        reason = f"随机路径请求失败、根路径返回 {root['status']}，疑似全站拦截"

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


# 通用「登录墙」探测端点：RuoYi 的 /system/role/list 需要登录，未认证时
# 会 302 到 /login（或返回 200 登录页）。真实 4.7.8 栈上这是最常见形态。
_AUTH_WALL_PROBE_PATH = "/system/role/list"


def detect_auth_wall(session: Any, target: str) -> Dict[str, Any]:
    """探测目标是否存在「登录墙」（未认证时受保护接口统一跳登录页）。

    与 detect_blocked 的区别：blocked 是 WAF/网关拒绝，这里是应用自身的认证要求。
    真实 RuoYi（Shiro）默认对受保护接口返回 302 -> /login，跟随后是 200 登录页；
    插件若只看「没命中漏洞特征」就会写出 SAFE，把「没登录」误报成「确认不存在」。
    """
    url = target.rstrip("/") + _AUTH_WALL_PROBE_PATH
    info: Dict[str, Any] = {"wall": False, "reason": "", "status": 0}
    try:
        try:
            resp = session.get(url, allow_redirects=True)
        except TypeError:
            # 会话替身/自定义会话可能不接受 allow_redirects
            resp = session.get(url)
    except Exception as e:  # 网络异常不等于登录墙，交给插件判 UNKNOWN
        info["reason"] = f"探测异常: {type(e).__name__}: {e}"[:160]
        return info
    status = int(getattr(resp, "status_code", 0) or 0)
    info["status"] = status
    final_url = str(getattr(resp, "url", "") or "")
    wall = login_wall_reason(resp)
    if wall or "/login" in final_url.lower():
        info["wall"] = True
        info["reason"] = wall or "受保护接口被重定向到登录页"
        logger.warning("目标存在登录墙：%s（探测 %s）", info["reason"], _AUTH_WALL_PROBE_PATH)
    return info


# SAFE 证据里明确出现 4xx：端点不存在/被拒绝，登录墙不改变该结论（保持 SAFE）
_ABSENT_EVIDENCE_RE = re.compile(r"状态码\s*=\s*4\d\d|HTTP\s*4\d\d|\b(401|403|404)\b", re.IGNORECASE)


def _unlock_hint(cap: Dict[str, Any]) -> str:
    """按插件能力给出「怎么才能测到」的具体建议。

    为什么需要（v1.6 A2 配套）：降级后的证据原本统一是「需登录后才能判定」，
    读者只知道「测不了」，不知道下一步该做什么。而这三类插件的解法完全不同，
    给错建议比不给更糟——比如让未授权类插件「加 --auth-login 重扫」，
    重扫出来的 CONFIRMED 恰恰是假的（登录后可访问 ≠ 未授权访问）。
    """
    if cap.get("requires_auth"):
        return "——需 --auth-login 提供高权账号后重扫"
    # 未授权类：登录后重扫**不能**解决问题，反而会引入假阳性。
    # 判定依据有两条：显式声明了 anonymous_probe，或 vuln_type 就是 unauth/info_leak
    # （部分插件走 socket 直连不经过 HTTP 会话，没法用 anonymous_probe 语义表达，
    #   但它们的被测命题仍然是「未授权可达」，同样不能靠登录解锁）。
    if cap.get("anonymous_probe") or cap.get("vuln_type") in ("unauth", "info_leak"):
        return "——本项判定的是「未登录能否访问」，登录后重扫得到的结论无效；应从目标网络侧确认该端点是否真的要求认证"
    if cap.get("path_scope") == "root":
        return "——可加 --auth-login 后重扫（登录后放行才能探测 web 根下的静态文件）"
    return "——可加 --auth-login 后重扫"


def downgrade_auth_wall_safe(results: List[Any], wall: Dict[str, Any]) -> int:
    """存在登录墙时，把「没有 4xx 证据」的 SAFE 降级为 UNKNOWN。

    登录墙下插件拿到的往往是 200 登录页：既没命中漏洞特征，也没拿到 404，
    此时的 SAFE 是「没测到」而不是「确认不存在」。明确 404/401/403 的 SAFE 保留
    （后者本应已被 upgrade_denied 降级）。CONFIRMED/已是 UNKNOWN 不受影响。
    """
    if not wall or not wall.get("wall"):
        return 0
    base_note = f"目标存在登录墙（{wall.get('reason', '')}），需登录后才能判定"
    n = 0
    for r in results:
        if getattr(r, "status", "") != STATUS_SAFE:
            continue
        ev = str(getattr(r, "evidence", "") or "")
        if _ABSENT_EVIDENCE_RE.search(ev):
            continue
        r.status = STATUS_UNKNOWN
        extra = dict(getattr(r, "extra", None) or {})
        # 能力元信息由 PluginBase.enrich() 写入；缺失时退化到通用提示
        cap = extra.get("plugin_capability") or {}
        note = base_note + _unlock_hint(cap if isinstance(cap, dict) else {})
        r.evidence = f"{note}；原证据：{ev}" if ev else note
        extra["auth_wall"] = True
        r.extra = extra
        n += 1
    if n:
        logger.warning("登录墙：%d 条 SAFE 已降级为 UNKNOWN", n)
    return n


def downgrade_evidence_less_safe(results: List[Any]) -> int:
    """把「SAFE 但没有任何判定证据」的结果降级为 UNKNOWN。

    三态纪律里 SAFE = 测过了、排除；如果插件连证据都没给出，读者无从判断
    「端点不存在」「已修复」「请求根本没发出去」中的哪一种，此时 SAFE 是假安全感。
    对抗审计实测：MinIO / RocketMQ 等中间件插件在目标无该服务时返回 SAFE + 空证据。
    """
    n = 0
    for r in results:
        if getattr(r, "status", "") != STATUS_SAFE:
            continue
        if str(getattr(r, "evidence", "") or "").strip():
            continue
        r.status = STATUS_UNKNOWN
        r.evidence = "SAFE 缺少判定证据（插件未说明为何确认不存在），已降级为无法判定"
        extra = dict(getattr(r, "extra", None) or {})
        extra["no_evidence"] = True
        r.extra = extra
        n += 1
    if n:
        logger.warning("缺少证据的 SAFE：%d 条已降级为 UNKNOWN", n)
    return n


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


# 响应里出现这些显式状态码 = 请求被拒绝（未认证/无权限/限流），而不是"漏洞不存在"。
# 只认「状态码/status/code/HTTP + 401/403/429」和明确的「认证失败」。
# 不再匹配裸词 Forbidden/Unauthorized/无权限/没有权限：它们会误伤
# 「响应未含 Forbidden 关键字」「未检测到 Unauthorized」，以及
# 「没有权限访问用户数据」——后者恰恰是防护生效的正证据（对抗审计实测）。
# 「请求被拒绝」的识别。除了显式的 401/403/429，还要认 **JSON 信封形态**：
#   {"code":401,"msg":"账号未登录"} / {"success":false,"code":500,"message":"Token校验失败"}
#
# 为什么必须认（v1.6 WP-U1，2026-11-02 实测）：
#   - 芋道（yudao）的未授权响应是 `HTTP 200 + {"code":401}`——它的
#     AuthenticationEntryPoint 用 hutool 直接 writeJSON，**不设 HTTP status**。
#   - Jeecg 是 `HTTP 200 + {"success":false,"code":500,"message":"Token校验失败"}`。
#   - 旧正则要求 `code` 后紧跟 `[:=]`，`"code":401` 中间隔了个引号 → 认不出
#     → 插件判的 SAFE 不会被升级成 UNKNOWN → 「把没测到写成确认不存在」（B 类缺陷）。
#
# 实测旧正则表现（2026-11-02）：
#   {"code":401,...}  → False ❌     {"code": 401} → False ❌
#   状态码=401        → True  ✅     HTTP 401      → True  ✅
#
# ⚠ 只匹配 401/403/429，**绝不匹配 200**：芋道的业务成功码是 `code:0`（不是 200），
#   若依是 `code:200`，两者都是正常响应，命中就会把正常结果误降级。
# 两个必须处理的 JSON 细节（2026-11-02 实测踩过）：
#   ① JSON 的键名**自带引号**：`"code":401` —— 不只是 `code:401`。
#      正则必须在关键字**前后**都允许引号，否则 `"code":` 里多出的那个 `"` 会让匹配失败。
#   ② 状态码后面不能用 `\b`：`401"`、`401,`、`401}` 的边界行为与前面的可选引号组合会错位。
#      改用「后面不能再跟数字」的负向断言 `(?!\d)`，既精确又不受引号影响
#      （`4010` 不会被误认成 `401`）。
_DENY_RE = re.compile(
    r"[\"']?(?:状态码|status|code|HTTP)[\"']?\s*[:=]?\s*[\"']?\s*(401|403|429)(?!\d)"
    r"|认证失败|Token校验失败|token.*(?:失效|过期|无效)",
    re.IGNORECASE,
)
# 匹配点前出现这些词 = 否定式证据（"没出现拒绝"），不能据此降级
_NEGATIONS = ("未含", "未出现", "未检测到", "不含", "不存在", "没有出现")
# 请求根本没拿到有效响应：SAFE 结论不成立（网络异常 ≠ 确认不存在）
_UNREACHABLE_RE = re.compile(
    r"基线探测未取得响应|连接失败|无法连接|连接被拒绝|InvalidSchema|Max retries exceeded|timed out|Timeout",
    re.IGNORECASE,
)
# 登录页特征（真实 RuoYi 未认证访问受保护接口：302 -> /login -> 200 登录页）
_LOGIN_PAGE_MARKERS = ("/captcha/captchaImage", 'name="password"', "loginForm", "若依后台管理")


def login_wall_evidence(reason: str, what: str = "", unlock_hint: str = "") -> str:
    """构造「因登录墙无法判定」的证据文本（插件内部返回 UNKNOWN 时统一使用）。

    为什么要有这个助手：7 个插件（file_read / file_read_path / file_upload /
    job_rce / sql_inject_* / thymeleaf_ssti）各自手写证据文案，措辞已经漂移成
    「无法判定文件读取是否存在」「无法判定上传接口是否可写」等多种说法，
    且都没有告诉用户下一步该怎么做。

    与 downgrade_auth_wall_safe() 的关系：那条路径处理「插件判了 SAFE、由链路降级」；
    这里是「插件自己就判 UNKNOWN」，两条路径的**用户可见文案应当一致**。
    统一到本函数，避免改一处漏一处。

    Args:
        reason: login_wall_reason() 的返回值
        what: 被测对象（如「文件读取是否存在」），用于让证据读起来自然
        unlock_hint: 覆盖默认解锁提示（缺省用通用提示）

    Returns:
        形如「请求被登录墙拦截（…），无法判定 X——可加 --auth-login 后重扫」的证据串
    """
    subject = f"无法判定{what}" if what else "无法判定"
    tail = unlock_hint or "——可加 --auth-login 后重扫"
    return f"请求被登录墙拦截（{reason}），{subject}{tail}"


def login_wall_reason(resp: Any) -> str:
    """判断响应是否是「登录墙」（302→/login 或 200 登录页），返回原因或空串。

    真实若依（Shiro）未登录访问受保护接口时是 302 跳 /login（requests 默认跟随后
    拿到 200 登录页），不是 401。插件只看「没命中漏洞特征」就会写出 SAFE，
    等于把未测到写成确认不存在。命中登录墙时应返回 UNKNOWN。
    """
    status = int(getattr(resp, "status_code", 0) or 0)
    headers = getattr(resp, "headers", {}) or {}
    location = str(headers.get("Location", "") or "")
    if status in (301, 302, 303, 307, 308) and "login" in location.lower():
        return f"HTTP {status} 重定向到登录页"
    if status == 200:
        text = str(getattr(resp, "text", "") or "")[:4096]
        if ("若依" in text or "ruoyi" in text.lower()) and any(m in text for m in _LOGIN_PAGE_MARKERS):
            return "返回 200 登录页（会话未认证）"
    return ""


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
        hit = ""
        for m in _DENY_RE.finditer(ev):
            prefix = ev[max(0, m.start() - 12) : m.start()]
            if any(neg in prefix for neg in _NEGATIONS):
                continue
            hit = m.group(1) or m.group(0)
            break
        if hit:
            r.status = STATUS_UNKNOWN
            r.evidence = f"响应被拒绝（{hit}，无法判定是否存在）；原证据：{ev}" if ev else f"响应被拒绝（{hit}）"
            extra = dict(getattr(r, "extra", None) or {})
            extra["denied"] = True
            r.extra = extra
        elif _UNREACHABLE_RE.search(ev):
            # 网络异常 / 基线探测失败：没拿到响应就不能宣称"不存在"
            r.status = STATUS_UNKNOWN
            r.evidence = f"未取得有效响应（网络异常或基线失败），SAFE 不成立；原证据：{ev}"
            extra = dict(getattr(r, "extra", None) or {})
            extra["unreachable"] = True
            r.extra = extra
        else:
            continue
        n += 1
    if n:
        logger.warning("响应被拒绝（401/403/429）：%d 条 SAFE 已改为 UNKNOWN", n)
    return n
