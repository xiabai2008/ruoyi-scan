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
from typing import Any, Dict, List, Optional

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


# ── G1：数据驱动的通用组件探测器（Java 生态常见中间件/控制台，15 项）──
#
# 通用探测语义（与手写探测器一致的三态纪律）：
#   存在性判定：status_signal（指定状态码）/ body_signals（响应体子串）/ header_signals（响应头子串）
#   版本提取：version_headers（头值正则，优先）→ version_patterns（响应体正则）
#   CONFIRMED  存在 + 版本命中 CVE 区间
#   SAFE       存在但版本不在区间，或全部探测路径未命中特征（探测点层面可证不存在）
#   UNKNOWN    存在但版本未泄漏（fallback_note 提示人工复核）/ 网络异常
#
# CVE 数据在 data/component_cve_map.json 中按组件名同步维护；
# 版本区间不确定的组件只配 range='*' 兜底提示，不编造 CVE 精度。
_COMPONENT_SPECS: Dict[str, dict] = {
    "druid": {
        "label": "Alibaba Druid 监控台",
        "paths": ["/druid/index.html", "/druid/login.html"],
        "body_signals": ["Druid", "druid"],
        "version_patterns": [r"Druid\s+(?:Version\s*:?\s*)?v?([\d.]+)"],
    },
    "xxl-job": {
        "label": "XXL-JOB 调度中心",
        "paths": ["/xxl-job-admin/"],
        "body_signals": ["XXL-JOB", "xxl-job"],
        "version_patterns": [r"version['\"]?\s*[:=]\s*['\"]?([\d.]+)"],
    },
    "solr": {
        "label": "Apache Solr",
        "paths": ["/solr/admin/info/system", "/solr/"],
        "body_signals": ["lucene", "solr"],
        "version_patterns": [r'"solr-spec-version"\s*:\s*"([\d.]+)"', r'"solr_impl_version"\s*:\s*"([\d.]+)"'],
    },
    "rabbitmq": {
        "label": "RabbitMQ 管理控制台",
        "paths": ["/api/overview"],
        "body_signals": ["rabbitmq_version", "RabbitMQ"],
        "version_patterns": [r'"rabbitmq_version"\s*:\s*"([\d.]+)"', r'"management_version"\s*:\s*"([\d.]+)"'],
    },
    "elasticsearch": {
        "label": "Elasticsearch",
        "paths": ["/"],
        "body_signals": ["cluster_name", "You Know, for Search"],
        "version_patterns": [r'"version"\s*:\s*\{[^}]*"number"\s*:\s*"([\d.]+)"'],
    },
    "kibana": {
        "label": "Kibana",
        "paths": ["/api/status", "/app/kibana"],
        # /api/status 的 JSON 不含 "kibana" 字样，用 '"version"' 兜底信号
        "body_signals": ["kibana", "Kibana", '"version"'],
        "version_patterns": [r'"number"\s*:\s*"([\d.]+)"', r'"version"\s*:\s*"([\d.]+)"'],
    },
    "tomcat": {
        "label": "Apache Tomcat",
        "paths": ["/", "/nonexistent-e2e-probe-404"],
        "header_signals": {"Server": ["Apache-Coyote", "Apache Tomcat", "Tomcat/"]},
        "body_signals": ["Apache Tomcat/"],
        "version_headers": [("Server", r"Tomcat/([\d.]+)")],
        "version_patterns": [r"Apache Tomcat/([\d.]+)"],
    },
    "jetty": {
        "label": "Jetty",
        "paths": ["/", "/nonexistent-e2e-probe-404"],
        "header_signals": {"Server": ["Jetty"]},
        "version_headers": [("Server", r"Jetty\(([\d.]+)")],
    },
    "shenyu": {
        "label": "Apache ShenYu 网关管理台",
        "paths": ["/shenyu/", "/"],
        "body_signals": ["ShenYu", "shenyu"],
        "version_patterns": [r'"version"\s*:\s*"([\d.]+)"'],
    },
    "jenkins": {
        "label": "Jenkins CI",
        "paths": ["/login", "/"],
        # X-Jenkins 头存在即命中，且头值就是完整版本号
        "header_signals": {"X-Jenkins": None},
        "version_headers": [("X-Jenkins", r"([\d.]+)")],
    },
    "eureka": {
        "label": "Eureka 注册中心",
        "paths": ["/eureka/apps"],
        "body_signals": ["<applications", "application"],
        "version_patterns": [],
    },
    "minio": {
        "label": "MinIO 对象存储",
        # /minio/health/live 健康探测 200 即存在（无 body）
        "paths": ["/minio/health/live", "/minio/"],
        "status_signal": 200,
        "body_signals": ["MinIO", "minio"],
        "version_patterns": [],
    },
    "grafana": {
        "label": "Grafana",
        "paths": ["/api/health", "/login"],
        "body_signals": ["database", "Grafana"],
        "version_patterns": [r'"version"\s*:\s*"([\d.]+)"'],
    },
    "sentinel": {
        "label": "Sentinel 控制台",
        "paths": ["/", "/auth/login"],
        "body_signals": ["sentinel", "Sentinel"],
        "version_patterns": [],
    },
    "consul": {
        "label": "Consul",
        "paths": ["/v1/agent/self", "/ui/"],
        "body_signals": ["Config", "Consul"],
        "version_patterns": [r'"Version"\s*:\s*"([\d.]+)"', r'"version"\s*:\s*"([\d.]+)"'],
    },
}


def _detect_by_spec(name: str, spec: dict, target: str, session) -> ComponentVersionResult:
    """按探测规格执行单个组件探测（数据驱动通用探测器）

    Args:
        name: 组件名（与 component_cve_map.json 的 key 一致）
        spec: 探测规格（paths / signals / version patterns）
        target: 目标 URL
        session: SessionManager 实例

    Returns:
        ComponentVersionResult（三态语义与手写探测器一致）
    """
    label = spec.get("label", name)
    note = fallback_note(name)
    for path in spec.get("paths") or ["/"]:
        url = join_url(target, path)
        try:
            resp = session.get(url)
        except Exception as e:
            return ComponentVersionResult(component=name, status=STATUS_UNKNOWN, evidence="网络异常: %s" % e)
        text = resp.text or ""
        hit = False
        evidence = ""
        # 1. 状态码信号（如 MinIO 健康探测 200）
        status_signal = spec.get("status_signal")
        if status_signal is not None and resp.status_code == status_signal:
            hit = True
            evidence = "%s 探测点返回 %d" % (label, resp.status_code)
        # 2. 响应体信号
        if not hit:
            for sig in spec.get("body_signals", []):
                if sig and sig in text:
                    hit = True
                    evidence = "响应含 %s 特征" % label
                    break
        # 3. 响应头信号
        if not hit:
            for hname, subs in spec.get("header_signals", {}).items():
                hval = resp.headers.get(hname, "") if hasattr(resp, "headers") else ""
                if hval and (subs is None or any(s in hval for s in subs)):
                    hit = True
                    evidence = "%s 响应头 %s: %s" % (label, hname, hval)
                    break
        if not hit:
            continue
        # 版本提取：响应头正则优先，其次响应体
        version = ""
        for hname, vpat in spec.get("version_headers", []):
            hval = resp.headers.get(hname, "") if hasattr(resp, "headers") else ""
            if hval:
                m = re.search(vpat, hval)
                if m and re.match(r"^\d+\.\d+", m.group(1)):
                    version = m.group(1)
                    break
        if not version:
            for pat in spec.get("version_patterns", []):
                m = re.search(pat, text)
                if m and re.match(r"^\d+\.\d+", m.group(1)):
                    version = m.group(1)
                    break
        if version:
            m = match_cve(name, version)
            if m:
                note_hit = m.get("note", "")
                return ComponentVersionResult(
                    component=name,
                    detected_version=version,
                    status=STATUS_CONFIRMED,
                    cve=m.get("cve", ""),
                    fix_version=m.get("fix", ""),
                    url=url,
                    evidence="%s，版本 %s%s" % (evidence, version, "（%s）" % note_hit if note_hit else ""),
                    cvss_score=float(m.get("cvss", 0)),
                )
            return ComponentVersionResult(
                component=name,
                detected_version=version,
                status=STATUS_SAFE,
                url=url,
                evidence="%s，版本 %s 不在已知 CVE 区间" % (evidence, version),
            )
        # 存在但版本未泄漏 → UNKNOWN + 兜底提示（不判 SAFE）
        return ComponentVersionResult(
            component=name,
            status=STATUS_UNKNOWN,
            url=url,
            evidence="%s，版本无法识别%s" % (evidence, "（%s）" % note if note else ""),
        )
    # 全部探测路径未命中 → 探测点层面可证不存在（与 shiro/nacos 判定惯例一致）
    return ComponentVersionResult(component=name, status=STATUS_SAFE, evidence="未检测到 %s 特征" % label)


def _make_spec_detector(name: str, spec: dict):
    """为规格表生成探测器函数（签名与手写探测器一致，ruoyi_version 参数忽略）"""

    def detector(target: str, session, ruoyi_version: str = "") -> ComponentVersionResult:
        return _detect_by_spec(name, spec, target, session)

    detector.__name__ = "detect_%s" % name.replace("-", "_")
    detector.__doc__ = "%s 数据驱动探测（G1 通用组件探测器）" % spec.get("label", name)
    return detector


# 注册通用探测器（DETECTORS 顺序即 detect_all 输出顺序），
# 并按手写探测器命名惯例（'-'→'_'）导出模块级名字（detect_druid / detect_xxl_job ...）
for _name, _spec in _COMPONENT_SPECS.items():
    _det = _make_spec_detector(_name, _spec)
    DETECTORS[_name] = _det
    globals()["detect_%s" % _name.replace("-", "_")] = _det


class ComponentDetector:
    """组件检测聚合器：对目标执行全部探测器，输出 ComponentVersionResult 列表"""

    def __init__(self, oast_client: Optional[Any] = None) -> None:
        """初始化聚合器

        Args:
            oast_client: 可选 OAST 客户端（lib/oast.OASTClient），用于 Log4j 探测
        """
        self.oast_client = oast_client

    def detect_all(self, target: str, session: Any, ruoyi_version: str = "") -> List[ComponentVersionResult]:
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
