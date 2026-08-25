# E2：组件版本检测引擎（fastjson / Spring Boot / Shiro / Nacos / Log4j）
#
# 设计目标：若依的真实风险 90% 来自依赖组件，官方修复方式就是升级组件。
# 本模块对目标做非破坏性探测，识别组件存在性与版本，与 data/component_cve_map.json
# 比对输出命中 CVE / 修复版本，转换 ScanResult(category='component') 进入统一报告管线。
#
# 判定三态（与全局一致）：
#   CONFIRMED  组件存在且版本命中 CVE 区间（带 CVE）
#   SAFE       组件存在但版本不在 CVE 区间（或组件确认不存在）
#   UNKNOWN    网络异常 / 组件存在但版本无法识别（如 Shiro 无版本泄漏）
# 安全红线：仅做存在性探测，不落地破坏性 payload；Log4j JNDI 探测需显式启用 OAST。
import json
import os
import re
from typing import Dict, List

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ComponentVersionResult, ScanResult
from core.http import join_url

logger = get_logger(__name__)

# 组件 CVE 映射数据（data/component_cve_map.json，版本区间语义与 ruoyi_versions.py 一致）
_CVE_MAP: Dict[str, list] = {}
_CVE_MAP_LOADED = False


def _load_cve_map() -> Dict[str, list]:
    """加载组件 CVE 映射数据（懒加载，失败时返回空表不阻断）"""
    global _CVE_MAP, _CVE_MAP_LOADED
    if _CVE_MAP_LOADED:
        return _CVE_MAP
    _CVE_MAP_LOADED = True
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "component_cve_map.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            _CVE_MAP = json.load(f)
    except Exception:
        logger.debug("组件 CVE 映射加载失败", exc_info=True)
    return _CVE_MAP


def match_cve(component: str, version: str) -> dict:
    """版本比对 CVE 映射表

    Args:
        component: 组件名（fastjson/spring-boot/shiro/nacos/log4j）
        version: 已识别版本（'' = 未识别）

    Returns:
        dict: {'cve': ..., 'fix': ..., 'cvss': ..., 'note': ...} 或空 dict
        版本未识别 → 空（由调用方判 UNKNOWN）
    """
    if not version:
        return {}
    from core.ruoyi_versions import version_in_range

    for item in _load_cve_map().get(component, []):
        rng = item.get("range", "")
        if rng == "*":
            continue  # 兜底提示项（range='*'）仅在无 CVE 命中时由调用方作为 note 使用
        if version_in_range(version, rng):
            return item
    return {}


def fallback_note(component: str) -> str:
    """返回组件兜底提示（range='*' 条目），无则空串"""
    for item in _load_cve_map().get(component, []):
        if item.get("range") == "*":
            return item.get("note", "")
    return ""


# ── 若依版本 → 组件版本推断表（近似值，evidence 中注明"由若依版本推断"）──
# 数据来源：若依官方 pom.xml 历史依赖（fastjson/spring-boot 随版本升级）
RUOYI_COMPONENT_MAP = {
    "4.2": {"fastjson": "1.2.60", "spring-boot": "2.1.1"},
    "4.6": {"fastjson": "1.2.78", "spring-boot": "2.5.9"},
    "4.7": {"fastjson": "1.2.80", "spring-boot": "2.5.15"},
    "5": {"fastjson": "2.0.25", "spring-boot": "2.5.15"},
}


def _infer_from_ruoyi_version(component: str, ruoyi_version: str) -> str:
    """由若依版本推断组件版本（近似值，仅作参考）"""
    if not ruoyi_version:
        return ""
    for prefix, mapping in RUOYI_COMPONENT_MAP.items():
        # 若依 3.x 分支组件依赖与 5.x 一致，前缀特判补全推断覆盖
        if ruoyi_version.startswith(prefix) or (prefix == "5" and ruoyi_version.startswith("3.")):
            return mapping.get(component, "")
    return ""


# ── 各组件探测器 ──


def detect_fastjson(target: str, session, ruoyi_version: str = "") -> ComponentVersionResult:
    """fastjson 探测：错误页关键字 + 若依版本推断（零侵入）"""
    url = ""
    evidence = ""
    # 1. 关键字探测（错误页/响应泄漏 com.alibaba.fastjson 类名）
    try:
        for probe_path in ["/prod-api/", "/login", "/"]:
            u = join_url(target, probe_path)
            resp = session.get(u)
            text = (resp.text or "") + str(resp.headers)
            # and not url：只保留首个命中路径，避免后续探测覆盖已得证据
            if "fastjson" in text.lower() and not url:
                url = u
                evidence = "响应泄漏 fastjson 关键字"
                break
    except Exception:
        return ComponentVersionResult(component="fastjson", status=STATUS_UNKNOWN, evidence="网络异常")
    if url:
        # fastjson 存在但版本未泄漏 → 尝试若依版本推断
        inferred = _infer_from_ruoyi_version("fastjson", ruoyi_version)
        if inferred:
            m = match_cve("fastjson", inferred)
            if m:
                return ComponentVersionResult(
                    component="fastjson",
                    detected_version=inferred,
                    status=STATUS_CONFIRMED,
                    cve=m.get("cve", ""),
                    fix_version=m.get("fix", ""),
                    evidence="%s（由若依版本推断）" % evidence,
                    url=url,
                    cvss_score=float(m.get("cvss", 0)),
                )
            return ComponentVersionResult(
                component="fastjson",
                detected_version=inferred,
                status=STATUS_SAFE,
                evidence="%s，版本 %s 不在已知 CVE 区间" % (evidence, inferred),
                url=url,
            )
        return ComponentVersionResult(
            component="fastjson",
            status=STATUS_UNKNOWN,
            evidence="%s，版本无法识别（建议人工确认 pom.xml）" % evidence,
            url=url,
        # 语义：无论有无兜底提示，fix_version 都是假值（None/""），to_scan_result 不会输出修复建议
            fix_version=fallback_note("fastjson") and None,
        )
    # 2. 若依版本推断（无关键字泄漏时）
    inferred = _infer_from_ruoyi_version("fastjson", ruoyi_version)
    if inferred:
        m = match_cve("fastjson", inferred)
        if m:
            return ComponentVersionResult(
                component="fastjson",
                detected_version=inferred,
                status=STATUS_CONFIRMED,
                cve=m.get("cve", ""),
                fix_version=m.get("fix", ""),
                evidence="由若依版本 %s 推断" % ruoyi_version,
                cvss_score=float(m.get("cvss", 0)),
            )
        return ComponentVersionResult(
            component="fastjson",
            detected_version=inferred,
            status=STATUS_SAFE,
            evidence="由若依版本推断，版本 %s 不在已知 CVE 区间" % inferred,
        )
    # 3. 无法判定（fastjson 为后端库，无特征时无法确认不存在）
    return ComponentVersionResult(
        component="fastjson",
        status=STATUS_UNKNOWN,
        evidence="未探测到 fastjson 特征且无法推断版本（默认 UNKNOWN，不判 SAFE）",
    )


_SPRING_VERSION_PATTERNS = [
    re.compile(r'"spring-boot"\s*:\s*"([\d.]+)"'),
    re.compile(r"Spring Boot[^\d]{0,10}([\d.]+)"),
    re.compile(r'"version"\s*:\s*"([\d.]+)"'),
]


def _extract_spring_version(text: str) -> str:
    """从响应文本提取 Spring Boot 版本号"""
    if not text:
        return ""
    for pat in _SPRING_VERSION_PATTERNS:
        m = pat.search(text)
        if m and re.match(r"^\d+\.\d+", m.group(1)):
            return m.group(1)
    return ""


def detect_spring_boot(target: str, session, ruoyi_version: str = "") -> ComponentVersionResult:
    """Spring Boot 探测：/actuator + Whitelabel 错误页 + 错误 JSON 特征"""
    url = ""
    version = ""
    evidence = ""
    try:
        # 1. /actuator（强信号）
        resp = session.get(join_url(target, "/actuator"))
        if resp.status_code == 200:
            url = join_url(target, "/actuator")
            evidence = "/actuator 返回 200"
            version = _extract_spring_version(resp.text or "")
            if not version:
                try:
                    info = session.get(join_url(target, "/actuator/info"))
                    version = _extract_spring_version(info.text or "")
                except Exception:
                    pass
            if version:
                evidence += "，版本 %s" % version
        else:
            # 2. 根路径 Whitelabel / 错误 JSON 特征
            resp = session.get(target)
            text = resp.text or ""
            if "Whitelabel Error Page" in text:
                url = target
                evidence = "Whitelabel Error Page"
            elif '"timestamp"' in text and '"status"' in text and '"error"' in text:
                url = target
                evidence = "Spring Boot 默认错误 JSON"
            else:
                # 3. 触发 404 错误页（非破坏性）
                # 请求不存在的路径触发框架错误页，让 Spring 特征暴露出来（非破坏性）
                resp404 = session.get(join_url(target, "/nonexistent-e2e-probe-404"))
                text404 = resp404.text or ""
                if "Whitelabel Error Page" in text404:
                    url = join_url(target, "/nonexistent-e2e-probe-404")
                    evidence = "404 触发 Whitelabel Error Page"
                else:
                    return ComponentVersionResult(
                        component="spring-boot", status=STATUS_UNKNOWN, evidence="未探测到 Spring Boot 特征"
                    )
            version = _extract_spring_version(text)
    except Exception:
        return ComponentVersionResult(component="spring-boot", status=STATUS_UNKNOWN, evidence="网络异常")

    # 版本未识别时尝试若依推断
    if not version:
        version = _infer_from_ruoyi_version("spring-boot", ruoyi_version)
        if version:
            evidence += "（由若依版本推断）"
    if version:
        m = match_cve("spring-boot", version)
        if m:
            return ComponentVersionResult(
                component="spring-boot",
                detected_version=version,
                status=STATUS_CONFIRMED,
                cve=m.get("cve", ""),
                fix_version=m.get("fix", ""),
                evidence=evidence,
                url=url,
                cvss_score=float(m.get("cvss", 0)),
            )
        return ComponentVersionResult(
            component="spring-boot",
            detected_version=version,
            status=STATUS_SAFE,
            evidence="%s，版本 %s 不在已知 CVE 区间" % (evidence, version),
            url=url,
        )
    return ComponentVersionResult(
        component="spring-boot",
        status=STATUS_UNKNOWN,
        evidence="%s，版本无法识别" % evidence,
        url=url,
        fix_version=fallback_note("spring-boot") and None,
    )


def detect_shiro(target: str, session, ruoyi_version: str = "") -> ComponentVersionResult:
    """Shiro 探测：rememberMe=deleteMe Cookie 特征（复用 shiro_rememberme 探测逻辑）

    Shiro 无版本泄漏点 → 组件存在但版本 UNKNOWN；默认密钥风险提示（需人工复核）。
    """
    url = join_url(target, "/login")
    try:
        # 携带 rememberMe 值触发 Shiro 特征（Set-Cookie: rememberMe=deleteMe）
        resp = session.get(url, headers={"Cookie": "rememberMe=test"})
        set_cookie = resp.headers.get("Set-Cookie", "")
        if "rememberMe=deleteMe" in set_cookie or "rememberMe=deleteMe" in str(resp.headers):
            return ComponentVersionResult(
                component="shiro",
                status=STATUS_UNKNOWN,
                url=url,
                evidence="检测到 Shiro rememberMe 特征（rememberMe=deleteMe），版本无法从响应识别",
                fix_version="1.13.0+",
            )
        return ComponentVersionResult(component="shiro", status=STATUS_SAFE, url=url, evidence="未检测到 Shiro 特征")
    except Exception as e:
        return ComponentVersionResult(component="shiro", status=STATUS_UNKNOWN, evidence="网络异常: %s" % e)


_NACOS_VERSION_PATTERNS = [
    re.compile(r'"version"\s*:\s*"([\d.]+)"'),
    re.compile(r"Nacos[^\d]{0,6}([\d.]+)"),
]


def detect_nacos(target: str, session, ruoyi_version: str = "") -> ComponentVersionResult:
    """Nacos 探测：/nacos/ 控制台 + /nacos/v1/console/server/state 版本接口"""
    try:
        # 1. /nacos/v1/console/server/state（新版有版本 JSON）
        state_url = join_url(target, "/nacos/v1/console/server/state")
        resp = session.get(state_url)
        text = resp.text or ""
        if resp.status_code == 200 and "Nacos" in text:
            version = ""
            for pat in _NACOS_VERSION_PATTERNS:
                m = pat.search(text)
                if m:
                    version = m.group(1)
                    break
            if version:
                m = match_cve("nacos", version)
                if m:
                    return ComponentVersionResult(
                        component="nacos",
                        detected_version=version,
                        status=STATUS_CONFIRMED,
                        cve=m.get("cve", ""),
                        fix_version=m.get("fix", ""),
                        url=state_url,
                        evidence="Nacos %s" % version,
                        cvss_score=float(m.get("cvss", 0)),
                    )
                return ComponentVersionResult(
                    component="nacos",
                    detected_version=version,
                    status=STATUS_SAFE,
                    url=state_url,
                    evidence="Nacos %s 不在已知 CVE 区间" % version,
                )
            return ComponentVersionResult(
                component="nacos",
                status=STATUS_UNKNOWN,
                url=state_url,
                evidence="Nacos 存在但版本无法识别",
                fix_version=fallback_note("nacos") and None,
            )
        # 2. /nacos/ 控制台页面
        console_url = join_url(target, "/nacos/")
        resp2 = session.get(console_url)
        text2 = resp2.text or ""
        if resp2.status_code == 200 and "Nacos" in text2:
            version = ""
            for pat in _NACOS_VERSION_PATTERNS:
                m = pat.search(text2)
                if m:
                    version = m.group(1)
                    break
            return ComponentVersionResult(
                component="nacos",
                detected_version=version,
                status=STATUS_UNKNOWN if not version else STATUS_SAFE,
                url=console_url,
                evidence="Nacos 控制台存在%s" % ("，版本 %s" % version if version else "，版本无法识别"),
                fix_version=fallback_note("nacos") and None,
            )
        return ComponentVersionResult(component="nacos", status=STATUS_SAFE, evidence="未检测到 Nacos")
    except Exception as e:
        return ComponentVersionResult(component="nacos", status=STATUS_UNKNOWN, evidence="网络异常: %s" % e)


def detect_log4j(target: str, session, oast_client=None) -> ComponentVersionResult:
    """Log4j 探测：需 OAST 带外回调确认（非破坏性，不自动 CONFIRMED）

    未启用 OAST 时返回 UNKNOWN + 提示（Log4j 为库级组件，无响应特征可探测存在性）。
    """
    if oast_client is None:
        return ComponentVersionResult(
            component="log4j",
            status=STATUS_UNKNOWN,
            evidence="需 --oast 启用带外检测（JNDI 回调），当前未探测",
        )
    try:
        payload_url = oast_client.get_payload("log4j")
        # 将 ${jndi:ldap://<callback>} payload 注入一个无害参数触发日志（非破坏性）
        url = join_url(target, "/prod-api/system/user/list") + "?pageNum=${jndi:ldap://%s}" % payload_url
        session.get(url)
        if oast_client.wait_callback(interaction_id=payload_url, timeout=8):
            return ComponentVersionResult(
                component="log4j",
                status=STATUS_UNKNOWN,
                url=url,
                evidence="OAST 回调命中：疑似存在 Log4j JNDI 注入（需人工复核，不自动确认）",
                cve="CVE-2021-44228",
                fix_version="2.17.1+",
                cvss_score=10.0,
            )
        return ComponentVersionResult(component="log4j", status=STATUS_UNKNOWN, evidence="OAST 未收到回调")
    except Exception as e:
        return ComponentVersionResult(component="log4j", status=STATUS_UNKNOWN, evidence="探测异常: %s" % e)


# 探测器注册表（保持执行顺序）
DETECTORS = {
    "fastjson": detect_fastjson,
    "spring-boot": detect_spring_boot,
    "shiro": detect_shiro,
    "nacos": detect_nacos,
    "log4j": detect_log4j,
}


class ComponentDetector:
    """组件检测聚合器：对目标执行全部探测器，输出 ComponentVersionResult 列表"""

    def __init__(self, oast_client=None):
        """初始化聚合器

        Args:
            oast_client: 可选 OAST 客户端（lib/oast.OASTClient），用于 Log4j 探测
        """
        self.oast_client = oast_client

    def detect_all(self, target: str, session, ruoyi_version: str = "") -> List[ComponentVersionResult]:
        """探测全部组件

        Args:
            target: 目标 URL（已归一化）
            session: SessionManager 实例
            ruoyi_version: 已识别的若依版本（用于组件版本推断，可选）

        Returns:
            ComponentVersionResult 列表（每个组件一个结果）
        """
        results = []
        for name, detector in DETECTORS.items():
            try:
                if name == "log4j":
                    res = detector(target, session, self.oast_client)
                else:
                    res = detector(target, session, ruoyi_version)
                results.append(res)
            except Exception as e:
                logger.debug("组件探测 %s 失败", name, exc_info=True)
                results.append(
                    ComponentVersionResult(component=name, status=STATUS_UNKNOWN, evidence="探测异常: %s" % e)
                )
        return results


def to_scan_result(res: ComponentVersionResult) -> ScanResult:
    """将组件检测结果转换为统一 ScanResult（category='component' 进入报告管线）

    Args:
        res: 组件检测结果

    Returns:
        ScanResult（kind=vuln 仅当 CONFIRMED；severity 按 CVSS 映射）
    """
    from common.models import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM

    # CVSS → 严重度映射（与 SARIF level 映射一致：9+→high，4+→medium）
    if res.cvss_score >= 9.0:
        severity = SEVERITY_HIGH
    elif res.cvss_score >= 4.0:
        severity = SEVERITY_MEDIUM
    else:
        severity = SEVERITY_LOW

    fix = ""
    if res.fix_version:
        fix = "升级 %s 至 %s" % (res.component, res.fix_version)
    evidence = "组件: %s | 版本: %s | %s" % (
        res.component,
        res.detected_version or "未知",
        res.evidence,
    )
    if res.cve:
        evidence += " | 命中: %s" % res.cve
    return ScanResult(
        kind="vuln" if res.status == STATUS_CONFIRMED else "info",
        name="组件风险: %s" % res.component,
        severity=severity,
        status=res.status,
        url=res.url,
        evidence=evidence,
        fix=fix,
        cve=res.cve,
        cvss_score=res.cvss_score,
        compliance=res.compliance,
        extra={"component": res.component, "detected_version": res.detected_version},
    )
