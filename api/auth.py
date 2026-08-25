# D11 API 鉴权中间件：API Key 模式
# E9：权限分级（read/scan/admin）+ 多 Key
# 第2周安全收口：
#   - 密钥比较一律使用 hmac.compare_digest（常量时间，防时序侧信道攻击）
#   - 禁止通过 URL 查询参数（?api_key=）传输密钥（会泄露到日志/历史/Referer），仅接受 X-API-Key 头
#
# 设计：
#   1. 最简鉴权：X-API-Key 头
#   2. 多 Key 格式：--api-key "key1:read,key2:scan,key3:admin"
#      （单个 key 无 scope = admin，向后兼容）
#   3. 权限矩阵：
#      read  = 查询任务/报告下载
#      scan  = read + 发起/取消扫描
#      admin = scan + 插件管理 + 定时任务管理
#   4. 无外部依赖；未设置 Key 时默认仅允许 127.0.0.1（开发模式）
#   5. /docs /openapi.json /api/system/health 不需要鉴权
import hmac
import os

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# 不需要鉴权的路径前缀
# 注：/api/system/metrics 对外开放供 Prometheus 抓取，建议通过网络层（防火墙/Docker 网络）限制访问
PUBLIC_PATHS = (
    "/docs",
    "/openapi.json",
    "/redoc",
    "/api/system/health",
    "/api/system/metrics",
    "/favicon.ico",
)

# 权限分级（数值越大权限越高）
_SCOPE_LEVEL = {"read": 1, "scan": 2, "admin": 3}

# 路径 → 所需最小权限（admin 路径先匹配）
_ADMIN_PATHS = (
    "/api/plugin",  # 插件管理
    "/api/schedule",  # 定时任务管理（创建/删除）
)
_SCAN_PATHS = (
    ("POST", "/api/scan"),
    ("DELETE", "/api/scan"),
)


def _required_scope(method: str, path: str) -> str:
    """返回路径所需的最小权限（read 默认）"""
    if path.startswith(_ADMIN_PATHS):
        return "admin"
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "scan"
    return "read"


def _scope_of(key_entry: str) -> str:
    """解析 key 条目的 scope（'key' → admin；'key:read' → read）"""
    if ":" in key_entry:
        return key_entry.rsplit(":", 1)[-1].strip().lower()
    return "admin"


def parse_api_keys(api_key_str: str) -> dict:
    """解析 API Key 配置字符串为 {key: scope} 映射

    Args:
        api_key_str: 如 'key1:read,key2:scan,key3:admin' 或 'single-key'

    Returns:
        {key: scope} 字典（无效 scope 回落 admin）
    """
    result = {}
    if not api_key_str:
        return result
    for entry in api_key_str.split(","):
        entry = entry.strip()
        if not entry:
            continue
        scope = _scope_of(entry)
        if scope not in _SCOPE_LEVEL:
            scope = "admin"
        key = entry.rsplit(":", 1)[0] if ":" in entry else entry
        result[key.strip()] = scope
    return result


def get_api_key_from_env() -> str:
    """从环境变量获取 API Key"""
    return os.environ.get("RUOYI_SCAN_API_KEY", "")


def generate_api_key() -> str:
    """生成随机 API Key（32 位十六进制）"""
    import secrets

    return secrets.token_hex(16)


class ApiKeyMiddleware(BaseHTTPMiddleware):
    """API Key 鉴权中间件（E9：权限分级）

    规则：
        - api_key 未设置（空）：仅允许 127.0.0.1 / localhost（开发模式）
        - api_key 已设置：仅接受 X-API-Key 头校验（禁止 ?api_key= URL 传输）
        - 密钥比较使用 hmac.compare_digest（常量时间，防时序侧信道）
        - 权限不足返回 403（read 不能发起扫描等）
        - 公共路径（/docs, /api/system/health 等）免鉴权
    """

    def __init__(self, app, api_key: str = ""):
        """初始化中间件，并预解析多 Key 配置为 {key: scope} 权限表"""
        super().__init__(app)
        self.api_key = api_key
        self.key_scopes = parse_api_keys(api_key)

    def _lookup_scope(self, provided_key: str) -> str | None:
        """常量时间查找 provided_key 的 scope（遍历全部 key，不提前返回，防时序泄露）

        单 Key 模式：命中返回 "admin"；多 Key 模式：命中返回对应 scope。
        """
        if not self.key_scopes:
            if hmac.compare_digest(provided_key, self.api_key):
                return "admin"
            return None
        matched = None
        for stored_key, scope in self.key_scopes.items():
            if hmac.compare_digest(provided_key, stored_key):
                matched = scope
                # 不 break：即使已匹配也继续遍历，保持恒定时间
        return matched

    async def dispatch(self, request: Request, call_next):
        """鉴权主流程：公共路径放行 → 本地访问放行 → X-API-Key 校验 → 权限分级校验"""
        path = request.url.path

        # 1. 公共路径放行
        if path.startswith(PUBLIC_PATHS):
            return await call_next(request)

        # 2. 无 API Key 模式：仅允许本地访问
        if not self.api_key:
            client_host = request.client.host if request.client else ""
            if client_host in ("127.0.0.1", "::1", "localhost", "testclient"):
                return await call_next(request)
            return JSONResponse(
                status_code=401,
                content={"detail": "API Key 未配置，仅允许本地访问。启动时设置 --api-key 以开放远程访问。"},
            )

        # 3. 校验 Key（仅接受 X-API-Key 头；禁止 ?api_key= URL 传输）
        provided_key = request.headers.get("X-API-Key", "")
        if not provided_key:
            return JSONResponse(status_code=401, content={"detail": "缺少 API Key（X-API-Key 头）"})

        # 3.1 常量时间查找（单 Key / 多 Key 统一）
        scope = self._lookup_scope(provided_key)
        if scope is None:
            return JSONResponse(status_code=401, content={"detail": "无效的 API Key"})

        # 未知 scope 按数值 0 处理、未知路径所需权限按 read 兜底：整体 fail-closed
        # 3.2 权限分级校验
        required = _required_scope(request.method, path)
        if _SCOPE_LEVEL.get(scope, 0) < _SCOPE_LEVEL.get(required, 1):
            return JSONResponse(
                status_code=403,
                content={"detail": "权限不足：需要 %s 权限（当前 %s）" % (required, scope)},
            )
        return await call_next(request)
