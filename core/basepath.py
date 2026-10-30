# API 前缀（base path）探测：前后端分离版只反代 /prod-api/ 时的探测基准修正
#
# 背景（2026-10-29 R7 靶场实测）：
#   RuoYi-Vue / RuoYi-Cloud 等分离版的标准 nginx 形态是**只反代 /prod-api/**：
#       location /          { root .../dist; try_files $uri $uri/ /index.html; }
#       location /prod-api/ { proxy_pass http://127.0.0.1:8080/; }
#   此时根路径下的 /druid/index.html、/swagger-ui.html、/actuator/env、
#   /system/user/list 全部命中 SPA 的 index.html（HTTP 200 HTML）。
#   所有「按根路径拼 URL」的插件都拿不到后端真实响应：
#     - 该命中的（Druid 控制台暴露、默认口令、定时任务…）全部落空 → 系统性漏报
#     - 目录扫描把同一个 index.html 当成海量「存在的路径」→ 噪声
#   实测 R7（严格只反代 /prod-api/）无会话扫描：除宿主级 Redis 外全部「不存在/无法判定」。
#
# 本模块探测若依后端**匿名可达**的特征接口来判断前缀，供编排器把插件探测基准
# 从 http://host/ 提升为 http://host/prod-api/。根路径本身已直连后端（单机版）
# 时返回空串，行为不变。
import json
from typing import Any

from common.logger import get_logger

logger = get_logger(__name__)

# 候选前缀：RuoYi-Vue 官方脚手架为 /prod-api/，其余为常见改法
CANDIDATES = ("/prod-api", "/dev-api", "/api")

# 验证码接口（用来确认「这个前缀确实通到若依后端」）
#   RuoYi-Vue（3.8.x/3.9.x）: /captchaImage  -> {"code":200,"captchaEnabled":...}
#   RuoYi-Cloud（3.6.x）    : /code           -> 网关 RouterFunction 返回同样结构
#   RuoYi-Vue-Plus（5.x）   : /auth/code      -> {"code":200,"data":{"captchaEnabled":...}}
# 实测（2026-10-29 R8 RuoYi-Cloud v3.6.8）：只探测 /captchaImage 时，
# /prod-api/captchaImage 在网关上是 404（Cloud 没有该端点），前缀探测失败 →
# 插件全部退回根路径 → 命中的只有 SPA 的 index.html → 整站系统性漏报（含
# /prod-api/actuator/env、/prod-api/v3/api-docs 这类真实暴露项）。
# 实测（2026-10-29 R9 RuoYi-Vue-Plus v5.6.2）：同理，Plus 的验证码端点是
# /auth/code，缺这一条时 base-path 探测失败 → R9 首扫只出 1 条 CONFIRMED，
# 而 /prod-api/v3/api-docs 实际返回 312KB 的 OpenAPI 文档。
CAPTCHA_PATHS = ("/captchaImage", "/code", "/auth/code")


def _looks_like_ruoyi_api(resp: Any) -> bool:
    """判断响应是否是若依验证码接口的 JSON（证明「这个前缀通到后端」）

    RuoYi-Vue: GET {base}/captchaImage ->
        {"msg":"操作成功","code":200,"captchaEnabled":true,"uuid":"...","img":"/9j/..."}
    验证码关闭时只有 {"msg":"操作成功","code":200,"captchaEnabled":false}，
    因此不能要求 img/uuid，认 captchaEnabled 即可；同时兼容仍带 img/uuid 的版本。
    """
    try:
        if getattr(resp, "status_code", 0) != 200:
            return False
        ctype = (resp.headers.get("Content-Type") or "").lower()
        text = resp.text or ""
        if "json" not in ctype and not text.lstrip().startswith("{"):
            return False
        data = json.loads(text)
        if not isinstance(data, dict):
            return False
        if "captchaEnabled" in data or ("code" in data and ("img" in data or "uuid" in data)):
            return True
        # RuoYi-Vue-Plus 5.x 把业务字段包在 data 里：
        #   {"code":200,"msg":"操作成功","data":{"captchaEnabled":false,"uuid":null,"img":null}}
        inner = data.get("data")
        if isinstance(inner, dict) and "captchaEnabled" in inner:
            return True
        return False
    except Exception:
        return False


def _probe_api_base(base: str, session: Any) -> bool:
    """在给定前缀下依次尝试各验证码接口，任一命中即说明该前缀通到若依后端"""
    for path in CAPTCHA_PATHS:
        try:
            if _looks_like_ruoyi_api(session.get(base + path)):
                return True
        except Exception:
            logger.debug("验证码接口探测失败: %s%s", base, path, exc_info=True)
    return False


def detect_api_base(target: str, session: Any) -> str:
    """探测需要在 target 后追加的 API 前缀

    Returns:
        ''（根路径已直连后端，或未识别出前缀）或 '/prod-api' 这类前缀（不带尾斜杠）
    """
    base = target.rstrip("/")
    if not base:
        return ""
    # 1) 根路径就能拿到后端验证码 JSON → 不需要前缀（单机版 / 根路径反代）
    if _probe_api_base(base, session):
        return ""
    # 2) 逐候选前缀探测
    for cand in CANDIDATES:
        if _probe_api_base(base + cand, session):
            return cand
    return ""
