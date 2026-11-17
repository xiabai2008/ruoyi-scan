# D14 攻击面清单：爬虫与 JS 提取产物的扫描级共享对象
#
# 背景：--crawl / --js-extract 的产物此前只作为 recon 事件负载展示，没有任何插件
# 能消费它（插件入参只有 target/session）。本模块把「一次扫描发现了哪些入口」
# 固化成 SurfaceInventory，由 orchestrator 写入 session.surface，供攻击面盘点类
# 插件（plugins/common/surface_sweep.py）遍历。它只描述「发现了什么」，不做漏洞
# 结论——未认证可达性由消费方自行探测。
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

from lib.crawler import normalize_link

# 单个目标的端点上限：爬虫 max_pages 已封顶，这里再兜一层，避免 JS 提取出数千条
# 相对路径时把清单和后续探测无限放大。
DEFAULT_MAX_ENDPOINTS = 200


def _normalize(url: str) -> Optional[str]:
    """归一化待入清单的 URL

    复用 lib.crawler.normalize_link（相对转绝对 / 去 fragment / 仅保留 http(s)），
    再用 core.http.normalize_target 统一站点根的空路径形态，使 `http://t` 与
    `http://t/` 视为同一条。尾斜杠只补在「根 URL」上——对业务路径补斜杠会改变
    资源语义（/api/user 与 /api/user/ 在部分框架下不是同一路由）。
    """
    absolute = normalize_link("", url or "")
    if not absolute:
        return None
    parts = urlsplit(absolute)
    if not parts.path and not parts.query:
        # 延迟导入：normalize_target 仅在此一处需要，避免模块级 import 顺序耦合
        from core.http import normalize_target

        return normalize_target(absolute)
    return absolute


@dataclass
class SurfaceEndpoint:
    """清单中的单个入口"""

    url: str
    source: str  # "crawl" | "js"
    method_hint: str = "GET"


@dataclass
class SurfaceInventory:
    """一次扫描的攻击面清单（端点去重、带上限与截断标记）"""

    endpoints: List[SurfaceEndpoint] = field(default_factory=list)
    pages: List[str] = field(default_factory=list)
    js_endpoints: List[str] = field(default_factory=list)
    truncated: bool = False
    max_endpoints: int = DEFAULT_MAX_ENDPOINTS

    def __post_init__(self) -> None:
        # 去重键 = 归一化后的完整 URL（含 query）。单列为实例属性而非 dataclass
        # 字段：它只是索引，不应进入 to_dict() / repr。
        self._seen: Set[str] = set()
        for ep in self.endpoints:
            self._seen.add(ep.url)

    def add(self, url: str, source: str) -> bool:
        """加入一个端点

        Returns:
            True 表示本次新增；False 表示被拒绝（空/非 http(s)）、重复、或已超上限。
            超上限时会置 truncated=True，不做静默丢弃。
        """
        normalized = _normalize(url)
        if not normalized:
            return False
        if normalized in self._seen:
            return False
        if len(self.endpoints) >= self.max_endpoints:
            self.truncated = True
            return False
        self._seen.add(normalized)
        self.endpoints.append(SurfaceEndpoint(url=normalized, source=source))
        return True

    def to_dict(self) -> Dict[str, Any]:
        """转为可 JSON 序列化的字典（报告/事件负载用）"""
        return {
            "endpoints": [{"url": ep.url, "source": ep.source, "method_hint": ep.method_hint} for ep in self.endpoints],
            "pages": list(self.pages),
            "js_endpoints": list(self.js_endpoints),
            "truncated": self.truncated,
            "max_endpoints": self.max_endpoints,
        }
