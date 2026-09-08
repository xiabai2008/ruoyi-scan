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


def detect_version(target, session, variant=""):
    """探测目标若依版本号（G1：支持变体感知的指纹来源优先级）

    按可靠性顺序尝试多个指纹来源：
    1. 指定 variant 时优先探测该变体的特征来源（RUOYI_VARIANT_INFO.version_sources）
    2. GET /login 页面 HTML（最可靠，含完整版本号）
    3. GET 根路径 HTML（footer 版本号）
    4. GET /actuator/info（微服务版）

    Args:
        target: 目标 URL
        session: SessionManager 实例
        variant: 变体标识（可选，如 'ruoyi-plus'，影响探测顺序）

    Returns:
        str: 版本号字符串（如 '4.7.8'），未识别返回 ''
    """
    from core.http import join_url

    def _probe(url):
        """单 URL 探测，返回提取到的版本号或 ''"""
        try:
            resp = session.get(url)
            version = extract_version(resp.text or "")
            if not version:
                # 粗粒度 ?v=4.7 静态资源参数
                m = re.search(r"[?&]v=(4\.\d+)", resp.text or "")
                if m:
                    return m.group(1) + ".0"
            return version
        except Exception:
            logger.debug("探测版本失败: %s", url, exc_info=True)
            return ""

    # 0. 变体特征来源优先（如 plus 的 /actuator/info、cloud 的 /nacos/）
    for source in get_variant_info(variant).get("version_sources", []):
        if source in ("/login", "/"):  # 与通用路径重合的来源留给下方统一探测
            continue
        version = _probe(join_url(target, source))
        if version:
            return version

    # 1. /login 页面（最可靠）
    version = _probe(join_url(target, "/login"))
    if version:
        return version

    # 2. 根路径 HTML（footer 或静态资源 ?v=4.7）
    version = _probe(target)
    if version:
        return version

    # 3. /actuator/info（微服务版）
    version = _probe(join_url(target, "/actuator/info"))
    if version:
        return version

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
    # G1：变体分支里程碑（版本号语义参考官方 release notes）
    "Vue3-3.8.x": "RuoYi-Vue3 前端（vite + element-plus），接口与 RuoYi-Vue 共用 /prod-api/",
    "Plus-4.x": "RuoYi-Vue-Plus 4.x：Spring Boot 2.7 + Sa-Token + MyBatis-Plus",
    "Plus-5.x": "RuoYi-Vue-Plus 5.x：JDK17 + Spring Boot 3 + Sa-Token（接口路径与 4.x 基本兼容）",
}

# G1：若依变体元数据（fingerprint_features.py 负责识别变体标识，此处提供
# 接口前缀/鉴权方式/版本指纹来源等差异信息，供 POC 过滤与版本探测参考）
RUOYI_VARIANT_INFO = {
    "ruoyi": {
        "name": "RuoYi 单体版（前后端一体）",
        "auth": "Session + Shiro",
        "api_prefixes": [""],
        "version_sources": ["/login", "/"],
        "notes": "服务端模板渲染，接口与页面同域（如 /system/user/list 直接可达）",
    },
    "ruoyi-vue": {
        "name": "RuoYi-Vue（前后端分离）",
        "auth": "JWT Token",
        "api_prefixes": ["/prod-api"],
        "version_sources": ["/login", "/"],
        "notes": "后端接口统一挂 /prod-api 前缀，前端静态页不含后端版本号（版本多见于 /actuator/info）",
    },
    "ruoyi-vue3": {
        "name": "RuoYi-Vue3",
        "auth": "JWT Token",
        "api_prefixes": ["/prod-api"],
        "version_sources": ["/login", "/actuator/info"],
        "notes": "vite 构建（静态资源 index-* 哈希命名），接口与 RuoYi-Vue 一致",
    },
    "ruoyi-app": {
        "name": "RuoYi-App（uni-app 移动端）",
        "auth": "JWT Token",
        "api_prefixes": ["/prod-api"],
        "version_sources": ["/actuator/info"],
        "notes": "复用 RuoYi-Vue 后端接口，登录接口 /login（移动端 clientId 差异不影响 POC 路径）",
    },
    "ruoyi-plus": {
        "name": "RuoYi-Vue-Plus",
        "auth": "Sa-Token",
        "api_prefixes": ["/prod-api"],
        "version_sources": ["/login", "/actuator/info"],
        "notes": "登录 /auth/login（Sa-Token 风格），定时任务/监控端点路径与原版有差异（plus_job_unauth 专项覆盖）",
    },
    "ruoyi-cloud": {
        "name": "RuoYi-Cloud 微服务版",
        "auth": "Gateway 统一鉴权（JWT）",
        "api_prefixes": ["/prod-api", "/auth", "/system", "/gen"],
        "version_sources": ["/actuator/info", "/nacos/"],
        "notes": "Nacos + Gateway + Sentinel 三件套暴露面（ruoyi_cloud_nacos / nacos_unauth 专项覆盖）",
    },
    "ruoyi-cloud-plus": {
        "name": "RuoYi-Cloud-Plus",
        "auth": "Sa-Token + Gateway",
        "api_prefixes": ["/auth", "/system", "/resource"],
        "version_sources": ["/actuator/info"],
        "notes": "Spring Cloud 2022 + Nacos 2.x，微服务组件暴露面与 Cloud 版类似",
    },
}


def get_variant_info(variant):
    """获取变体元数据

    Args:
        variant: 变体标识（如 'ruoyi-plus'，由 fingerprint.detect_variant 识别）

    Returns:
        dict: {'name', 'auth', 'api_prefixes', 'version_sources', 'notes'}，未知变体返回 {}
    """
    return RUOYI_VARIANT_INFO.get(variant, {})


def get_variant_api_prefixes(variant):
    """获取变体的 API 路径前缀列表（POC 路径适配用）

    Args:
        variant: 变体标识

    Returns:
        list: 前缀列表（如 ['/prod-api']），未知变体返回 ['']（裸路径）
    """
    return RUOYI_VARIANT_INFO.get(variant, {}).get("api_prefixes", [""])


# RuoYi-Cloud 特征路径（用于 detect_version 识别 Cloud 版）
RUOYI_CLOUD_PATHS = [
    "/nacos/",  # Nacos 控制台
    "/gateway/",  # Spring Gateway
    "/auth/login",  # Cloud 版 Gateway 统一登录
]
