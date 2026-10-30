# D9 系统路由：健康检查/版本/在线指纹探测
import sys
import time

from fastapi import APIRouter, HTTPException, Query

from api.models.schemas import FingerprintDTO, HealthDTO, VersionDTO
from config import settings
from core.fingerprint import detect_cms, detect_waf
from core.http import normalize_scan_target, preflight
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
def fingerprint_probe(
    target: str = Query(..., description="目标 URL"),
    timeout: int = Query(8, ge=1, le=30, description="单次探测超时（秒）"),
):
    """在线指纹探测（轻量，不入任务表）

    对目标执行 detect_cms + detect_waf，返回识别结果。

    使用同步 def（而非 async def）：SessionManager/detect_cms/detect_waf 均为阻塞式
    网络 IO，FastAPI 会将同步端点放入线程池执行，避免阻塞事件循环。

    timeout 显式暴露：旧实现固定 10 秒，遇到黑洞目标时一次探测可挂 40 秒以上，
    前端按钮长期“探测中…”。前端按 8 秒 × 2 探测留出可取消的窗口。
    """
    session = None
    # 归一化在 try 之外：仅为字符串处理，若未来引入校验失败，不应被下文笼统伪装成
    # 502「上游探测失败」（编程错误应自然暴露为 500）
    try:
        normalized = normalize_scan_target(target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    try:
        # 每次请求独立会话，探测完成后主动关闭，避免连接泄漏
        session = SessionManager(timeout=timeout)
        fp = detect_cms(normalized, session)
        waf = detect_waf(normalized, session)
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
        # from e：保留原始异常链，便于日志追溯真实失败原因
        raise HTTPException(status_code=502, detail=f"指纹探测失败: {e}") from e
    finally:
        # 探测异常（网络错误/超时/解析失败）时同样关闭会话，避免连接池泄漏
        if session is not None:
            session.close()


@router.get("/system/probe", summary="目标可达性预检")
def probe_target(
    target: str = Query(..., description="目标 URL"),
    timeout: int = Query(5, ge=1, le=15, description="探测超时（秒）"),
):
    """扫描前预检：TCP 可连 + HTTP 有响应

    供新建扫描弹窗的“检查连通性”和定时任务创建前调用。不可达也返回 HTTP 200
    （ok=false + reason），便于前端直接展示原因，而不是把业务失败伪装成 5xx。
    与 CLI/orchestrator 共用 core.http.preflight，避免三处判定漂移。
    """
    try:
        normalized = normalize_scan_target(target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    started = time.time()
    ok, stage, reason = preflight(normalized, timeout=float(timeout))
    return {
        "target": normalized,
        "ok": ok,
        "stage": stage,
        "reason": reason,
        "elapsed_ms": round((time.time() - started) * 1000),
    }
