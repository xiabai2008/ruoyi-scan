# D11 API 鉴权中间件：API Key 模式
#
# 设计：
#   1. 最简鉴权：X-API-Key 头
#   2. 无外部依赖（不用 python-jose/passlib，降低部署门槛）
#   3. 未设置 API Key 时默认仅允许 127.0.0.1（开发模式）
#   4. /docs /openapi.json /api/system/health 不需要鉴权（健康检查 + 文档）
import os
from typing import Optional

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# 不需要鉴权的路径前缀
# 注：/api/system/metrics 对外开放供 Prometheus 抓取，建议通过网络层（防火墙/Docker 网络）限制访问
PUBLIC_PATHS = (
    '/docs',
    '/openapi.json',
    '/redoc',
    '/api/system/health',
    '/api/system/metrics',
    '/favicon.ico',
)


class ApiKeyMiddleware(BaseHTTPMiddleware):
    """API Key 鉴权中间件

    规则：
        - 如果 api_key 未设置（空），仅允许 127.0.0.1 / localhost 访问（开发模式）
        - 如果 api_key 已设置，所有请求必须带 X-API-Key 头匹配
        - 公共路径（/docs, /api/system/health 等）免鉴权
    """

    def __init__(self, app, api_key: str = ''):
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # 1. 公共路径放行
        if path.startswith(PUBLIC_PATHS):
            return await call_next(request)

        # 2. 无 API Key 模式：仅允许本地访问
        if not self.api_key:
            client_host = request.client.host if request.client else ''
            # TestClient 的 host 可能是 testclient 或 reserved client
            if client_host in ('127.0.0.1', '::1', 'localhost', 'testclient'):
                return await call_next(request)
            # 非本地访问拒绝
            return JSONResponse(
                status_code=401,
                content={'detail': 'API Key 未配置，仅允许本地访问。启动时设置 --api-key 以开放远程访问。'}
            )

        # 3. 校验 X-API-Key 头
        provided_key = request.headers.get('X-API-Key', '')
        if provided_key == self.api_key:
            return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={'detail': '无效的 API Key（请在 X-API-Key 头中提供正确的密钥）'}
        )


def get_api_key_from_env() -> str:
    """从环境变量获取 API Key"""
    return os.environ.get('RUOYI_SCAN_API_KEY', '')


def generate_api_key() -> str:
    """生成随机 API Key（32 位十六进制）"""
    import secrets
    return secrets.token_hex(16)
