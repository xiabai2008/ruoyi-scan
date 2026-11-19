"""RuoYi-Cloud 网关路由解析与“单机版路径 → Cloud 路由别名”。

为什么需要独立模块
==================
RuoYi-Cloud 把单机版的 controller 路径挂在网关别名下：
  /monitor/job/**  → /schedule/job/**
  /tool/gen/**     → /code/gen/**
  /system/**       → /system/**（同名，无需别名）
网关 actuator 的 /actuator/gateway/routes 同时暴露显式路由和 Nacos 服务发现
自动生成的路由（/ruoyi-gen/** 等），后者是另一套可用别名。

本模块只做两件事：
  1. 解析 routes JSON，生成可供插件/报告使用的 Cloud profile；
  2. 给单机版路径生成 Cloud 候选路径（静态别名 + 路由表发现别名）。

判定边界
========
解析成功不等于漏洞；只有插件确认 actuator 可匿名读取时才判 CONFIRMED。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.http import join_url

GATEWAY_ROUTES_PATH = "/actuator/gateway/routes"

# 单机版路径 → Cloud 网关外部路径（由 RuoYi-Cloud 官方 gateway 配置 + StripPrefix 推导）
# 注意顺序：更长、更具体的路径必须在前，避免 /monitor/job 抢占 /monitor/job-log。
CLOUD_PATH_ALIASES: Tuple[Tuple[str, str], ...] = (
    ("/monitor/job-log", "/schedule/job/log"),
    ("/monitor/job", "/schedule/job"),
    ("/tool/gen", "/code/gen"),
)

_PATH_RE = re.compile(r"Paths:\s*\[([^\]]+)\]")
_STRIP_RE = re.compile(r"StripPrefix parts = (\d+)")


@dataclass(frozen=True)
class CloudRoute:
    """一条已解析的网关路由（外部路径前缀 → 服务）。"""

    route_id: str
    path: str
    uri: str
    discovery: bool = False
    strip_prefix: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "route_id": self.route_id,
            "path": self.path,
            "uri": self.uri,
            "discovery": self.discovery,
            "strip_prefix": self.strip_prefix,
        }


def _path_prefix(pattern: str) -> str:
    """把 Paths: [/auth/**] 转成 /auth。"""
    pattern = (pattern or "").strip()
    if pattern.endswith("/**"):
        pattern = pattern[:-3]
    return pattern.rstrip("/") or "/"


def _extract_paths(predicate: str) -> List[str]:
    match = _PATH_RE.search(predicate or "")
    if not match:
        return []
    return [item.strip() for item in match.group(1).split(",") if item.strip()]


def _extract_strip_prefix(filters: Any) -> int:
    text = " ".join(str(item) for item in filters) if isinstance(filters, list) else str(filters or "")
    match = _STRIP_RE.search(text)
    return int(match.group(1)) if match else 0


def parse_gateway_routes(payload: Any) -> List[CloudRoute]:
    """解析 actuator /gateway/routes 的 JSON 列表。

    真实 Spring Cloud Gateway 响应是对象数组；对象中可能没有 route_definition，
    但一定有 route_id / uri / predicate（Spring Boot 4 + actuator 实测）。
    非列表、空列表、缺字段的条目一律跳过，避免把普通 JSON 误当路由表。
    """
    if not isinstance(payload, list):
        return []
    routes: List[CloudRoute] = []
    seen: set = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        route_id = str(item.get("route_id") or item.get("routeId") or "").strip()
        uri = str(item.get("uri") or "").strip()
        predicate = str(item.get("predicate") or item.get("predicateDefinition") or "")
        if not route_id or not uri:
            continue
        strip_prefix = _extract_strip_prefix(item.get("filters"))
        discovery = route_id.startswith("ReactiveCompositeDiscoveryClient_")
        for pattern in _extract_paths(predicate):
            path = _path_prefix(pattern)
            key = (route_id, path, uri)
            if key in seen:
                continue
            seen.add(key)
            routes.append(
                CloudRoute(
                    route_id=route_id,
                    path=path,
                    uri=uri,
                    discovery=discovery,
                    strip_prefix=strip_prefix,
                )
            )
    return routes


def build_cloud_profile(payload: Any) -> Optional[Dict[str, Any]]:
    """把 routes 响应转成可缓存到 session.cloud_profile 的概要。"""
    routes = parse_gateway_routes(payload)
    if not routes:
        return None
    services = sorted({route.uri.replace("lb://", "") for route in routes if route.uri})
    return {
        "routes": [route.to_dict() for route in routes],
        "prefixes": sorted({route.path for route in routes}),
        "services": services,
        "route_count": len(routes),
        "has_ruoyi_service": any("ruoyi" in route.uri.lower() or "ruoyi" in route.route_id.lower() for route in routes),
    }


def discover_cloud_profile(session: Any, target: str) -> Optional[Dict[str, Any]]:
    """GET 网关路由表并缓存到 session.cloud_profile；失败返回 None。

    只读一页；不创建/修改路由。调用方负责判定是否 CONFIRMED。
    """
    cached = getattr(session, "cloud_profile", None)
    if isinstance(cached, dict) and cached.get("routes"):
        return cached
    try:
        response = session.get(join_url(target, GATEWAY_ROUTES_PATH))
    except Exception:
        return None
    if getattr(response, "status_code", 0) != 200:
        return None
    try:
        payload = response.json()
    except Exception:
        return None
    profile = build_cloud_profile(payload)
    if profile:
        setattr(session, "cloud_profile", profile)
    return profile


def cloud_alias_paths(path: str) -> List[str]:
    """单机版路径 → Cloud 外部路径（静态别名，不含路由表发现别名）。"""
    path = "/" + (path or "").lstrip("/")
    for old, new in CLOUD_PATH_ALIASES:
        if path == old or path.startswith(old + "/"):
            return [new + path[len(old) :]]
    return []


def discovery_alias_paths(profile: Optional[Dict[str, Any]], path: str) -> List[str]:
    """从 /ruoyi-<service>/** 服务发现路由生成别名。

    例：/tool/gen 的内部路径是 /gen，服务发现前缀 /ruoyi-gen/** 会
    RewritePath 掉前缀，因此 /ruoyi-gen/gen 等价于 /code/gen。
    """
    if not profile:
        return []
    aliases: List[str] = []
    path = "/" + (path or "").lstrip("/")
    for old, new in CLOUD_PATH_ALIASES:
        if not (path == old or path.startswith(old + "/")):
            continue
        internal = new
        # 只处理 /code/gen、/schedule/job 这种「网关前缀 + controller 根」；
        # 内部 controller 路径取网关别名的最后一段（gen/job）。
        service_path = internal.rsplit("/", 1)[-1]
        service = "ruoyi-" + service_path
        for route in profile.get("routes", []):
            if not route.get("discovery"):
                continue
            route_path = str(route.get("path") or "")
            if route.get("uri", "").replace("lb://", "") != service and route_path != "/" + service:
                continue
            alias = route_path.rstrip("/") + "/" + service_path
            alias += path[len(old) :]
            aliases.append(alias)
    return aliases


def cloud_candidate_paths(path: str, profile: Optional[Dict[str, Any]] = None) -> List[str]:
    """返回单机路径 + 所有 Cloud 别名（去重，保持优先级）。"""
    candidates = ["/" + (path or "").lstrip("/")]
    for alias in cloud_alias_paths(path) + discovery_alias_paths(profile, path):
        if alias not in candidates:
            candidates.append(alias)
    return candidates
