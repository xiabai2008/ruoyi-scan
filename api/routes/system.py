# D9 系统路由：健康检查/版本/在线指纹探测
import sys
import time

from fastapi import APIRouter, HTTPException, Query

from api.models.schemas import FingerprintDTO, HealthDTO, VersionDTO
from config import settings
from core.fingerprint import detect_cms, detect_waf
from core.http import normalize_target
from core.session import SessionManager

router = APIRouter(tags=["系统"])

# 服务启动时间（模块加载时记录）
_START_TIME = time.time()


@router.get("/system/health", response_model=HealthDTO, summary="健康检查")
async def health_check():
    """健康检查端点"""
    return HealthDTO(
        status="ok",
        version=settings.VERSION,
        uptime=round(time.time() - _START_TIME, 1),
    )


@router.get("/system/version", response_model=VersionDTO, summary="版本信息")
async def version_info():
    """返回工具版本信息"""
    return VersionDTO(
        version=settings.VERSION,
        author=settings.AUTHOR,
        github=settings.GITHUB,
        python_version=sys.version.split()[0],
    )


@router.get("/system/fingerprint", response_model=FingerprintDTO, summary="在线指纹探测")
async def fingerprint_probe(target: str = Query(..., description="目标 URL")):
    """在线指纹探测（轻量，不入任务表）

    对目标执行 detect_cms + detect_waf，返回识别结果。
    """
    try:
        normalized = normalize_target(target)
        # 每次请求独立会话，探测完成后主动关闭，避免连接泄漏
        session = SessionManager(timeout=10)
        fp = detect_cms(normalized, session)
        waf = detect_waf(normalized, session)
        session.close()
        return FingerprintDTO(
            target=normalized,
            cms=fp.cms,
            version=fp.version,
            confidence=round(fp.confidence, 2),
            matched=fp.matched,
            waf=waf.get("waf", ""),
            waf_display=waf.get("display", ""),
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"指纹探测失败: {e}")
