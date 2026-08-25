# 若依版本指纹库（D2 阶段）
#
# 功能：从目标响应中提取若依版本号，供 POC 版本适配使用。
#
# 版本指纹来源（按可靠性排序）：
#   1. /login 页面 HTML 中的版本号（如 "4.7.8"，出现于 footer 和 JS 变量）
#   2. 静态资源 URL 参数 ?v=4.7（仅主次版本，粗粒度）
#   3. /actuator/info JSON（若依微服务版可能暴露）
#
# 版本范围语义：
#   '>=4.2,<4.6'  表示 4.2 ≤ version < 4.6
#   '>=4.7'       表示 4.7 及以上
#   '<=4.5'       表示 4.5 及以下
#   ''            空串表示全版本适用（默认）
import re

from common.logger import get_logger

logger = get_logger(__name__)

# 若依版本指纹正则（匹配 X.Y.Z 格式，X/Y/Z 为数字）
# 真实若依 /login 页面含 "4.7.8" 两次（footer + JS 变量）
# 主版本限定 4/5：避免误命中页面中其他形如 x.y.z 的无关版本号（JS 库、构建号等）
VERSION_PATTERN = re.compile(r"\b(4|5)\.(\d+)\.(\d+)\b")


def extract_version(text):
    """从响应文本中提取若依版本号

    Args:
        text: 响应文本（/login 页面 HTML 或其他含版本号的响应）

    Returns:
        str: 版本号字符串（如 '4.7.8'），未找到返回 ''
    """
    if not text:
        return ""
    m = VERSION_PATTERN.search(text)
    if m:
        return "%s.%s.%s" % (m.group(1), m.group(2), m.group(3))
    return ""


def detect_version(target, session):
    """探测目标若依版本号

    按可靠性顺序尝试多个指纹来源：
    1. GET /login 页面 HTML（最可靠，含完整版本号）
    2. GET 根路径 HTML（footer 版本号）
    3. GET /actuator/info（微服务版）

    Args:
        target: 目标 URL
        session: SessionManager 实例

    Returns:
        str: 版本号字符串（如 '4.7.8'），未识别返回 ''
    """
    from core.http import join_url

    # 1. /login 页面（最可靠）
    try:
        resp = session.get(join_url(target, "/login"))
        text = resp.text or ""
        version = extract_version(text)
        if version:
            return version
    except Exception:
        logger.debug("探测 /login 页面版本失败", exc_info=True)

    # 2. 根路径 HTML（footer 或静态资源 ?v=4.7）
    try:
        resp = session.get(target)
        text = resp.text or ""
        # 先找完整版本号 X.Y.Z
        version = extract_version(text)
        if version:
            return version
        # 再找粗粒度版本号 ?v=4.7（静态资源参数）
        m = re.search(r"[?&]v=(4\.\d+)", text)
        if m:
            # 补全 patch 版本为 0（如 4.7 → 4.7.0）
            return m.group(1) + ".0"
    except Exception:
        logger.debug("探测根路径页面版本失败", exc_info=True)

    # 3. /actuator/info（微服务版）
    try:
        resp = session.get(join_url(target, "/actuator/info"))
        text = resp.text or ""
        version = extract_version(text)
        if version:
            return version
    except Exception:
        logger.debug("探测 /actuator/info 版本失败", exc_info=True)

    return ""


def parse_version(version_str):
    """将版本号字符串解析为可比较的 3-tuple

    Args:
        version_str: 版本号字符串（如 '4.7.8' 或 '4.7'）

    Returns:
        tuple: (major, minor, patch)，如 (4, 7, 8)；解析失败返回 (0, 0, 0)
        注：始终返回 3 元素元组，不足部分补 0（如 '4.7' → (4, 7, 0)）
    """
    if not version_str:
        return (0, 0, 0)
    parts = version_str.split(".")
    try:
        nums = [int(p) for p in parts[:3]]
    except (ValueError, TypeError):
        return (0, 0, 0)
    # 补零到 3 元素（'4.7' → [4, 7] → [4, 7, 0]）
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


def version_in_range(version, range_spec):
    """判断版本是否在指定范围内

    Args:
        version: 版本号字符串（如 '4.7.8'）
        range_spec: 范围表达式（如 '>=4.2,<4.6' 或 '>=4.7' 或 ''）

    Returns:
        bool: True 表示版本在范围内（或 range_spec 为空表示全版本适用）
    """
    if not range_spec:
        return True  # 空范围表示全版本适用
    if not version:
        return True  # 版本未识别时不过滤（保守策略：跑 POC）

    v = parse_version(version)

    # 解析范围表达式（逗号分隔的多个条件）
    conditions = range_spec.split(",")
    # 逗号分隔的多个条件为 AND 关系：任一条件不满足即整体不适用（如 ">=4.2,<4.6"）
    for cond in conditions:
        cond = cond.strip()
        if not cond:
            continue
        # 匹配 >=X.Y.Z, <=X.Y.Z, >X.Y.Z, <X.Y.Z
        m = re.match(r"(>=|<=|>|<)(\d+(?:\.\d+)*)", cond)
        if not m:
            continue
        op = m.group(1)
        bound = parse_version(m.group(2))
        if op == ">=" and not (v >= bound):
            return False
        if op == "<=" and not (v <= bound):
            return False
        if op == ">" and not (v > bound):
            return False
        if op == "<" and not (v < bound):
            return False
    return True


# 若依版本与漏洞对照表（供参考，实际 affected_versions 标注在各 POC 类属性）
# 数据来源：若依官方 release notes + CVE 数据库 + 社区实践
#
# 关键版本节点：
#   4.2.0  - params[dataScope] SQL 注入存在
#   4.6.0  - 修复 params[dataScope] SQL 注入；加强 /common/upload 扩展名校验
#   4.7.0  - 收紧 /monitor/job/edit 白名单；修复路径穿越
#   4.7.8  - 最新稳定版（本靶场使用）
#   5.x    - RuoYi-Vue（前后端分离，JWT 鉴权，接口前缀 /prod-api/）
RUOYI_VERSION_MILESTONES = {
    "4.2.0": "params[dataScope] SQL 注入存在；/common/upload 扩展名校验弱",
    "4.6.0": "修复 params[dataScope] SQL 注入；加强 /common/upload 扩展名校验",
    "4.7.0": "收紧 /monitor/job/edit 白名单；修复路径穿越",
    "4.7.8": "当前最新单机稳定版（本靶场使用）",
    "5.0.0": "RuoYi-Vue 前后端分离，JWT 鉴权，接口前缀 /prod-api/",
    # P0：RuoYi-Cloud 微服务版里程碑
    "Cloud-2.x": "RuoYi-Cloud 微服务版，Nacos + Gateway + Sentinel，Spring Boot 2.x",
}

# RuoYi-Cloud 特征路径（用于 detect_version 识别 Cloud 版）
RUOYI_CLOUD_PATHS = [
    "/nacos/",  # Nacos 控制台
    "/gateway/",  # Spring Gateway
    "/auth/login",  # Cloud 版 Gateway 统一登录
]
