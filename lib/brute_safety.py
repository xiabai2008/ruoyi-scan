"""Brute-force safety: lockout / rate-limit detection and attempt guard.

三态纪律同样适用于爆破：收到账号锁定/429/验证码要求时继续喷字典，
既可能把客户账号打锁定，也会把后续失败误读成"口令不存在"。
本模块只做**停止信号识别**，不参与"口令是否正确"的判定。
"""

from __future__ import annotations

from typing import Any, Tuple

# 强锁定信号：出现即停止（继续请求只会延长锁定）
_HARD_LOCK_KEYWORDS = (
    "账号已锁定",
    "账户已锁定",
    "用户已锁定",
    "account locked",
    "account is locked",
    "too many attempts",
    "too many failed",
    "尝试次数过多",
    "失败次数过多",
)
# 限流/软锁定信号：连续出现 N 次停止（单次可能是瞬时限流）
_SOFT_BLOCK_KEYWORDS = (
    "429",
    "too many requests",
    "请求过于频繁",
    "操作过于频繁",
    "请稍后再试",
    "retry-after",
)
# 验证码要求：继续爆破没有意义（必须人工/OCR，且通常意味风控已触发）
_CAPTCHA_KEYWORDS = (
    "验证码错误",
    "请输入验证码",
    "captcha required",
    "invalid captcha",
)

MAX_CONSECUTIVE_BLOCKS = 3


def classify_brute_block(resp: Any) -> Tuple[bool, str, bool]:
    """判断一次登录响应是否是"应停止爆破"的信号。

    Returns:
        (blocked, reason, hard)
        blocked=False 表示普通失败响应，可继续下一组口令；
        hard=True 表示硬锁定，应立即停止。
    """
    status = int(getattr(resp, "status_code", 0) or 0)
    headers = getattr(resp, "headers", {}) or {}
    body = str(getattr(resp, "text", "") or "")
    low = body.lower()

    if status == 423:
        return True, "HTTP 423 账号锁定", True
    if status == 429 or "retry-after" in {str(k).lower() for k in headers}:
        return True, f"HTTP {status or 0} 限流", False
    for keyword in _HARD_LOCK_KEYWORDS:
        if keyword in low:
            return True, f"响应包含锁定特征：{keyword}", True
    for keyword in _CAPTCHA_KEYWORDS:
        if keyword in low:
            return True, f"响应要求验证码：{keyword}", True
    for keyword in _SOFT_BLOCK_KEYWORDS:
        if keyword in low:
            return True, f"响应包含限流特征：{keyword}", False
    # JSON 业务码 429/423（部分系统 HTTP 200 + code）
    try:
        payload = resp.json()
        if isinstance(payload, dict):
            code = payload.get("code")
            if code in (423, "423"):
                return True, "业务码 423 账号锁定", True
            if code in (429, "429"):
                return True, "业务码 429 限流", False
    except Exception:
        pass
    return False, "", False


class BruteGuard:
    """记录爆破过程中的停止信号；插件每收到响应调用 observe()。

    设计目标：默认只停"确定会伤害目标"的信号，不因普通口令错误提前停，
    避免把"没跑完"伪装成"全部未命中"。
    """

    def __init__(self, max_consecutive_blocks: int = MAX_CONSECUTIVE_BLOCKS) -> None:
        self.max_consecutive_blocks = max(1, max_consecutive_blocks)
        self.consecutive_blocks = 0
        self.stop_reason = ""
        self.attempts = 0
        self.blocks = 0

    def observe(self, resp: Any) -> bool:
        """记录一次响应；返回 True 表示必须停止后续爆破。"""
        self.attempts += 1
        blocked, reason, hard = classify_brute_block(resp)
        if not blocked:
            self.consecutive_blocks = 0
            return False
        self.blocks += 1
        self.consecutive_blocks += 1
        if hard:
            self.stop_reason = f"检测到账号锁定/风控（{reason}），已停止爆破"
            return True
        if self.consecutive_blocks >= self.max_consecutive_blocks:
            self.stop_reason = f"连续 {self.consecutive_blocks} 次限流/风控（{reason}），已停止爆破"
            return True
        return False

    @property
    def stopped(self) -> bool:
        return bool(self.stop_reason)
