# lib/soft404.py — 软 404（catch-all 路由）基线探测
"""软 404 基线探测：判断「HTTP 200」能否作为「文件/路径存在」的证据。

为什么需要它
============
很多站点对**任意**路径都返回 HTTP 200 加一段固定内容：

  - SPA 前端（Vue/React）配 `try_files $uri /index.html` 的 nginx 兜底
  - 自定义错误页把 404 渲染成 200
  - CDN / 网关把上游错误统一改写为 200

在这类站点上，仅凭状态码判定存在性的插件会一次性误报几十个「泄露文件」。
实测（2026-09-16）：`backup_scan` 在一个完全正常的页面上报告了 65 个可访问备份文件。

正确做法是先探测一个**必然不存在**的随机路径，把它作为基线：

  - 基线也是 2xx + 有内容  → 站点存在兜底路由，状态码不可信，必须比对响应内容
  - 基线是 404/403 等      → 状态码可信，按原有逻辑判定即可

用法
====
    from lib.soft404 import Soft404Baseline

    baseline = Soft404Baseline.probe(target, session)
    ...
    if baseline.looks_like_real_file(resp):
        found.append(path)

注意：`looks_like_real_file()` 只回答「这个响应是否指向一个独立文件」，
不判断该文件是否敏感。敏感性与危害判断仍由插件负责。
"""

import hashlib
import uuid
from typing import Any, Optional

from core.http import join_url

# 单次基线探测的随机路径前缀，避免与真实目录命名冲突
_PROBE_PREFIX = "__ruoyi_scan_soft404_probe__"

# 计算内容摘要时只取前 N 字节：兜底页通常整页一致，取前缀足以判别，
# 同时避免大文件（如备份包）全量哈希带来的开销
_DIGEST_BYTES = 4096


def _digest(body: bytes) -> str:
    """计算响应体前 N 字节的 sha256 摘要"""
    return hashlib.sha256(body[:_DIGEST_BYTES]).hexdigest()


class Soft404Baseline:
    """软 404 基线：记录随机不存在路径的响应特征，用于判别兜底路由"""

    __slots__ = ("reachable", "status_code", "length", "digest", "probe_path")

    def __init__(
        self,
        reachable: bool = False,
        status_code: int = 0,
        length: int = 0,
        digest: str = "",
        probe_path: str = "",
    ) -> None:
        self.reachable = reachable  # 基线请求是否成功拿到响应
        self.status_code = status_code
        self.length = length
        self.digest = digest
        self.probe_path = probe_path

    @property
    def is_catch_all(self) -> bool:
        """站点是否存在兜底路由（随机不存在路径也返回 2xx 且有内容）"""
        return self.reachable and 200 <= self.status_code < 400 and self.length > 0

    def looks_like_real_file(self, resp: Optional[Any]) -> bool:
        """判断响应是否指向一个独立文件（而非兜底页）

        Args:
            resp: 待判定的响应对象（requests.Response 兼容，需有 status_code/content）

        Returns:
            True 表示可判定为独立文件；False 表示不存在或与兜底页无法区分
        """
        if resp is None:
            return False
        code = getattr(resp, "status_code", 0)
        if not (200 <= code < 400):
            return False
        body = getattr(resp, "content", None) or b""
        if not body:
            # 部分框架对未知路径统一返回空 200，无内容不足以证明文件存在
            return False
        if not self.is_catch_all:
            # 站点无兜底路由：状态码 2xx + 非空即视为真实文件
            return True
        # 站点有兜底路由：与基线页完全一致 → 判定为同一个兜底页，不是独立文件
        if len(body) == self.length and _digest(body) == self.digest:
            return False
        # 内容与兜底页不同 → 确有差异，保守放行（由插件继续做关键字校验）
        return True

    def describe(self) -> str:
        """人类可读的基线描述，供 evidence 说明使用"""
        if not self.reachable:
            return "基线探测未取得响应"
        if self.is_catch_all:
            return f"站点存在兜底路由（基线 {self.probe_path} 返回 {self.status_code} / {self.length} 字节），已启用内容比对"
        return f"基线 {self.probe_path} 返回 {self.status_code}，状态码可信"

    @classmethod
    def probe(cls, target: str, session: Any) -> "Soft404Baseline":
        """探测软 404 基线

        Args:
            target: 目标站点根 URL
            session: 已配置的 HTTP 会话（需提供 get(url)）

        Returns:
            Soft404Baseline 实例。请求异常时 reachable=False，
            此时 looks_like_real_file() 退化为纯状态码判定（与加固前行为一致），
            不会因基线探测失败而漏报。
        """
        token = uuid.uuid4().hex
        probe_path = f"/{_PROBE_PREFIX}_{token}/does-not-exist-{token}.txt"
        try:
            resp = session.get(join_url(target, probe_path))
        except Exception:
            return cls(reachable=False, probe_path=probe_path)
        body = getattr(resp, "content", None) or b""
        return cls(
            reachable=True,
            status_code=getattr(resp, "status_code", 0),
            length=len(body),
            digest=_digest(body) if body else "",
            probe_path=probe_path,
        )
