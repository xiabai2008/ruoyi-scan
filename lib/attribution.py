# 归属判定：区分「站点自身的漏洞」与「宿主/共享基础设施的暴露」
#
# 为什么需要它
# ============
# 中间件类插件（Redis/MinIO/RocketMQ）探的是**目标主机的独立端口**，不是站点
# 的 URL 路径。这在真实客户现场是有意义的（同一台机器上跑着 Redis），但在
# 多站点共用的宿主机上会产出「拓扑归属假阳性」：
#
#   实测（2026-11-02，本机靶场）：C4-1 把 Redis 放在 16379（未授权），
#   扫描 **R1（RuoYi 4.5.1 单机版，本身完全不依赖 Redis）** 时，
#   Redis 插件照常连 127.0.0.1:16379 并报 CONFIRMED。
#   报告读者会以为「R1 这个站点有 Redis 未授权漏洞」——而 R1 根本没有 Redis。
#
# 这既不是扫描器判定错（那个端口确实开着、确实无认证），也不是靶场造错（漏洞
# 确实存在）。错的是**归属**：发现的资产属于「127.0.0.1 这台主机」，不属于
# 「R1 这个站点」。报告必须把这两件事分开，否则批量扫描时同一个宿主漏洞会在
# N 份站点报告里重复出现 N 次，把交付物变成噪声。
#
# 判定口径（不做端口指纹猜谜，只看「探测坐标的坐标轴」）
# ==============================================================
# - 站点级（site）：探测 URL 与目标同源（同 host、同端口或跟随 base-path 前缀）
# - 宿主级（host）：探的是目标主机的**另一个端口**——发现的资产无法证明属于该站点
#
# 只标注、不降级：CONFIRMED 就是 CONFIRMED（端口确实无认证），
# 但要在 extra.attribution / 报告与终端输出里写清「这是 hosts 级发现」。
# 三态纪律针对「测没测到」，归属是另一个正交维度，两者不能互相冒充。
from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlsplit

from common.logger import get_logger

logger = get_logger(__name__)

# 归属级别
SCOPE_SITE = "site"  # 站点自身资产（与目标同源/同端口/同 base-path）
SCOPE_HOST = "host"  # 宿主级资产（目标主机的其它端口，无法证明归属该站点）

# extra 里的键名：结果、报告、API 都按它读取
ATTR_KEY = "attribution"


def _port_of(scheme: str, port: Any) -> int:
    """补齐默认端口，便于同源比较（http→80 / https→443）"""
    if port:
        return int(port)
    return 443 if (scheme or "").lower() == "https" else 80


def classify(target: str, result_url: str) -> Dict[str, Any]:
    """判定一条结果相对目标的归属级别。

    Args:
        target: 本次扫描的目标（已归一化，可能带 base-path）
        result_url: 结果里的 url 字段。可能是 http(s) URL，也可能是
            `host:port` 形式（Redis 这类 socket 插件就是这么写的）。

    Returns:
        {"scope": "site"|"host", "reason": str, "probe": str}
        - scope=site：无法判定/同源，按站点资产处理（默认，保持历史行为）
        - scope=host：明确是另一个端口，标注为宿主级
    """
    probe = (result_url or "").strip()
    if not probe:
        # 没有探测坐标就无法谈归属：按站点级处理（不无中生有地降级）
        return {"scope": SCOPE_SITE, "reason": "结果未给出探测地址", "probe": ""}

    try:
        tgt = urlsplit(target if "://" in target else "http://" + target)
        tgt_host = (tgt.hostname or "").lower()
        tgt_port = _port_of(tgt.scheme, tgt.port)

        if "://" in probe:
            res = urlsplit(probe)
            res_host = (res.hostname or "").lower()
            res_port = _port_of(res.scheme, res.port)
        else:
            # `host:port` 形态（socket 插件）：scheme 未知，按目标的 scheme 补
            res = urlsplit("//" + probe.split("/")[0])
            res_host = (res.hostname or "").lower()
            res_port = int(res.port) if res.port else tgt_port
    except Exception:
        logger.debug("归属判定解析失败: target=%s url=%s", target, probe, exc_info=True)
        return {"scope": SCOPE_SITE, "reason": "探测地址无法解析，按站点级处理", "probe": probe}

    if not res_host:
        return {"scope": SCOPE_SITE, "reason": "探测地址缺少主机名", "probe": probe}

    # 不同主机：不是「宿主级」而是「完全不同的资产」（子域名/CDN 回源等其他情况），
    # 同样不能算作该站点的漏洞归属——但也不该冒充成「同一主机的服务端口」。
    if tgt_host and res_host != tgt_host:
        return {
            "scope": SCOPE_HOST,
            "reason": f"探测地址主机（{res_host}）与目标主机（{tgt_host}）不同，不能归属该站点",
            "probe": probe,
        }

    if res_port != tgt_port:
        return {
            "scope": SCOPE_HOST,
            "reason": f"探测的是本机另一个端口（{res_port}，站点为 {tgt_port}），属宿主级资产",
            "probe": probe,
        }

    return {"scope": SCOPE_SITE, "reason": "与目标同源同端口", "probe": probe}


def annotate(results: Any, target: str) -> Dict[str, int]:
    """给结果集打上归属标记（原地修改 extra），返回统计。

    只标注 CONFIRMED：SAFE/UNKNOWN 不进报告漏洞表，「这条 SAFE 是宿主级的」
    对读者没有意义，反而会让 extra 噪声化。

    Returns:
        {"host_level": n, "site_level": n}
    """
    stats = {"host_level": 0, "site_level": 0}
    for r in results or []:
        if getattr(r, "status", "") != "CONFIRMED":
            continue
        info = classify(target, getattr(r, "url", "") or "")
        extra = dict(getattr(r, "extra", None) or {})
        extra[ATTR_KEY] = info
        r.extra = extra
        if info["scope"] == SCOPE_HOST:
            stats["host_level"] += 1
        else:
            stats["site_level"] += 1
    if stats["host_level"]:
        logger.info("归属：%d 条确认为宿主级资产（不属于站点自身）", stats["host_level"])
    return stats


def scope_of(result: Any) -> str:
    """读取结果上的归属级别；未标注的一律视为站点级（向后兼容历史产物）"""
    extra = getattr(result, "extra", None) or {}
    if not isinstance(extra, dict):
        return SCOPE_SITE
    info = extra.get(ATTR_KEY) or {}
    if isinstance(info, dict) and info.get("scope") == SCOPE_HOST:
        return SCOPE_HOST
    return SCOPE_SITE
