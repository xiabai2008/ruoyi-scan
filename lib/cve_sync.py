# D32：CVE/NVD 自动同步
#
# 从公开漏洞库自动同步 CVE 信息，更新插件库的 cve/cvss_vector/compliance 字段，
# 保持漏洞知识库常新。
#
# 数据源：
#   1. NVD REST API（https://services.nvd.nist.gov/rest/json/cves/2.0）— 主源
#   2. GHSA REST API（https://api.github.com/advisories）— G1 新增回退源：
#      NVD 未收录/查询失败时按 CVE 编号查 GitHub Advisory Database，
#      国内网络环境下 GHSA 可达性常优于 NVD
#   3. 本地缓存（避免重复请求，24h TTL）
#
# 使用方式：
#   # 同步所有插件的 CVE 信息
#   python main.py --cve-sync
#
#   # 同步指定 CVE
#   python main.py --cve-sync --cve-id CVE-2024-1234
#
#   # 从 NVD 查询单个 CVE
#   python main.py --cve-lookup CVE-2024-1234
#
# GHSA 提速（可选）：环境变量 RUOYI_SCAN_GHSA_TOKEN=<GitHub PAT>（60/h → 5000/h）
import datetime
import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from common.logger import get_logger

logger = get_logger(__name__)

# ============================================================
# 常量
# ============================================================

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_API_BASE = "https://api.github.com/advisories"
GHSA_TOKEN_ENV = "RUOYI_SCAN_GHSA_TOKEN"  # 可选 GitHub PAT，提升速率限制
CNVD_BASE = "https://www.cnvd.org.cn/flaw"  # G1：CNVD 漏洞库（无官方 API，网页抓取 best-effort）
OFFLINE_CVE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cve_offline.json")
_OFFLINE_CACHE: Optional[Dict[str, Dict[str, Any]]] = None
CACHE_DIR = "data/cve_cache"
CACHE_TTL_HOURS = 24  # 缓存有效期 24 小时


# ============================================================
# CVE 信息数据模型
# ============================================================


class CVEInfo:
    """CVE 信息"""

    def __init__(
        self,
        cve_id: str,
        description: str = "",
        cvss_vector: str = "",
        cvss_score: float = 0.0,
        severity: str = "",
        published: str = "",
        last_modified: str = "",
        references: List[str] = None,
        cwe: List[str] = None,
        source: str = "nvd",
    ):
        """初始化 CVE 信息对象

        Args:
            cve_id: CVE 编号
            description: 漏洞描述
            cvss_vector: CVSS 向量字符串
            cvss_score: CVSS 基础评分
            severity: 严重度（LOW/MEDIUM/HIGH/CRITICAL）
            published: 发布时间
            last_modified: 最后修改时间
            references: 参考链接列表
            cwe: CWE 编号列表
            source: 数据源标识（nvd/ghsa，仅展示用）
        """
        self.cve_id = cve_id
        self.description = description
        self.cvss_vector = cvss_vector
        self.cvss_score = cvss_score
        self.severity = severity  # LOW/MEDIUM/HIGH/CRITICAL
        self.published = published
        self.last_modified = last_modified
        self.references = references or []
        self.cwe = cwe or []
        self.source = source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "published": self.published,
            "last_modified": self.last_modified,
            "references": self.references,
            "cwe": self.cwe,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CVEInfo":
        return cls(
            cve_id=d.get("cve_id", ""),
            description=d.get("description", ""),
            cvss_vector=d.get("cvss_vector", ""),
            cvss_score=d.get("cvss_score", 0.0),
            severity=d.get("severity", ""),
            published=d.get("published", ""),
            last_modified=d.get("last_modified", ""),
            references=d.get("references", []),
            cwe=d.get("cwe", []),
            source=d.get("source", "nvd"),
        )

    def to_compliance_tag(self) -> str:
        """根据 CWE 生成合规映射标签"""
        # CWE → OWASP Top 10 映射
        cwe_owasp = {
            "CWE-79": "A03:2021",  # XSS
            "CWE-89": "A03:2021",  # SQL注入
            "CWE-78": "A03:2021",  # OS命令注入
            "CWE-73": "A03:2021",  # 外部控制文件名/路径
            "CWE-22": "A01:2021",  # 路径遍历
            "CWE-352": "A01:2021",  # CSRF
            "CWE-287": "A07:2021",  # 认证错误
            "CWE-306": "A01:2021",  # 关键功能缺失认证
            "CWE-862": "A01:2021",  # 授权缺失
            "CWE-863": "A01:2021",  # 不正确授权
            "CWE-502": "A08:2021",  # 反序列化
            "CWE-918": "A10:2021",  # SSRF
            "CWE-434": "A04:2021",  # 任意文件上传
            "CWE-1336": "A04:2021",  # 不安全设计
            "CWE-98": "A03:2021",  # 文件包含
            "CWE-94": "A03:2021",  # 代码注入
            "CWE-1236": "A03:2021",  # SSTI
        }

        # CWE → 等保 2.0 映射
        cwe_dengbao = {
            "CWE-79": "8.1.3",
            "CWE-89": "8.1.3",
            "CWE-78": "8.1.3",
            "CWE-22": "8.1.4",
            "CWE-352": "8.1.4",
            "CWE-287": "8.1.4",
            "CWE-306": "8.1.4",
            "CWE-862": "8.1.4",
            "CWE-863": "8.1.4",
            "CWE-502": "8.1.3",
            "CWE-918": "8.1.3",
            "CWE-434": "8.1.4",
            "CWE-98": "8.1.3",
            "CWE-94": "8.1.3",
            "CWE-1236": "8.1.3",
        }

        tags = []
        for cwe in self.cwe:
            owasp = cwe_owasp.get(cwe)
            dengbao = cwe_dengbao.get(cwe)
            if owasp and dengbao:
                tags.append(f"OWASP:{owasp};等保2.0:{dengbao}")
                break

        # 全部 CWE 未命中映射时给默认标签（A06），保证总有合规输出
        if not tags:
            tags.append("OWASP:A06:2021;等保2.0:8.1.3")

        return tags[0]

    def to_severity_lower(self) -> str:
        """NVD 严重度转小写"""
        # NVD 缺严重度时默认 medium，下游排序/过滤不受空值影响
        return self.severity.lower() if self.severity else "medium"


# ============================================================
# 缓存管理
# ============================================================


def get_cache_path(cve_id: str) -> str:
    """获取 CVE 缓存文件路径"""
    safe_id = cve_id.replace("-", "_")
    return os.path.join(CACHE_DIR, f"{safe_id}.json")


def load_from_cache(cve_id: str) -> Optional[CVEInfo]:
    """从缓存加载 CVE 信息

    Returns:
        CVEInfo 或 None（缓存不存在或过期）
    """
    path = get_cache_path(cve_id)
    if not os.path.exists(path):
        return None

    # 检查缓存有效期
    mtime = os.path.getmtime(path)
    age_hours = (datetime.datetime.now().timestamp() - mtime) / 3600
    if age_hours > CACHE_TTL_HOURS:
        return None

    try:
        with open(path, encoding="utf-8") as f:
            return CVEInfo.from_dict(json.load(f))
    except (json.JSONDecodeError, OSError):
        return None


def save_to_cache(cve: CVEInfo) -> None:
    """保存 CVE 信息到缓存"""
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = get_cache_path(cve.cve_id)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cve.to_dict(), f, ensure_ascii=False, indent=2)
    except OSError:
        logger.debug("保存 CVE 信息到缓存失败", exc_info=True)


def clear_cache() -> int:
    """清除所有缓存

    Returns:
        清除的文件数
    """
    count = 0
    if not os.path.exists(CACHE_DIR):
        return 0
    for f in os.listdir(CACHE_DIR):
        if f.endswith(".json"):
            try:
                os.remove(os.path.join(CACHE_DIR, f))
                count += 1
            except OSError:
                logger.debug("清除缓存文件失败", exc_info=True)
    return count


# ============================================================
# NVD API 查询
# ============================================================


def query_nvd_api(cve_id: str, timeout: int = 10, api_key: str = None) -> Optional[CVEInfo]:
    """从 NVD REST API 查询单个 CVE

    Args:
        cve_id: CVE 编号（如 CVE-2024-1234）
        timeout: 请求超时秒数
        api_key: NVD API Key（可选，提升速率限制）

    Returns:
        CVEInfo 或 None
    """
    url = f"{NVD_API_BASE}?cveId={urllib.parse.quote(cve_id)}"
    headers = {"User-Agent": "Ruoyi-Scan/2.0"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

    return parse_nvd_response(data)


def parse_nvd_response(data: Dict[str, Any]) -> Optional[CVEInfo]:
    """解析 NVD API 响应

    Args:
        data: NVD API JSON 响应

    Returns:
        CVEInfo 或 None
    """
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    cve_data = vulnerabilities[0].get("cve", {})

    # CVE ID
    cve_id = cve_data.get("id", "")

    # 描述（取英文描述）
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # CVSS v3.1 评分
    cvss_vector = ""
    cvss_score = 0.0
    severity = ""
    metrics = cve_data.get("metrics", {})
    # 优先 v3.1 评分，旧记录可能只有 v3.0/v2 指标，依次回退
    cvss_data = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if cvss_data:
        first = cvss_data[0]
        cvss = first.get("cvssData", {})
        cvss_vector = cvss.get("vectorString", "")
        cvss_score = cvss.get("baseScore", 0.0)
        severity = first.get("baseSeverity", "") or cvss.get("baseSeverity", "")

    # 发布/修改时间
    published = cve_data.get("published", "")
    last_modified = cve_data.get("lastModified", "")

    # 参考链接
    references = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")]

    # CWE
    cwe = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_id = desc.get("value", "")
            # 去重 + 剔除 NVD 无信息占位 CWE（NVD-CWE-noinfo）
            if cwe_id and cwe_id not in cwe and cwe_id != "NVD-CWE-noinfo":
                cwe.append(cwe_id)

    return CVEInfo(
        cve_id=cve_id,
        description=description,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        severity=severity,
        published=published,
        last_modified=last_modified,
        references=references,
        cwe=cwe,
    )


# ============================================================
# GHSA API 查询（G1：NVD 回退补充源）
# ============================================================

# GHSA severity 枚举（low/moderate/high/critical）→ NVD 词汇（LOW/MEDIUM/HIGH/CRITICAL）
_GHSA_SEVERITY_MAP = {"low": "LOW", "moderate": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}


def query_ghsa(cve_id: str, timeout: int = 10, token: str = None) -> Optional[CVEInfo]:
    """从 GitHub Advisory Database（GHSA）按 CVE 编号查询

    Args:
        cve_id: CVE 编号（如 CVE-2024-1234）
        timeout: 请求超时秒数
        token: GitHub PAT（可选；缺省读环境变量 RUOYI_SCAN_GHSA_TOKEN）

    Returns:
        CVEInfo（source='ghsa'）或 None
    """
    if token is None:
        token = os.environ.get(GHSA_TOKEN_ENV) or None
    url = f"{GHSA_API_BASE}?cve_id={urllib.parse.quote(cve_id)}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Ruoyi-Scan/2.0",
    }
    if token:
        headers["Authorization"] = "Bearer %s" % token
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    # 按 cve_id 过滤返回列表（API 可能返回同编号相关的多条 advisory）
    if not isinstance(data, list):
        return None
    for advisory in data:
        if isinstance(advisory, dict) and advisory.get("cve_id", "").upper() == cve_id.upper():
            return parse_ghsa_response(advisory)
    return None


def parse_ghsa_response(advisory: Dict[str, Any]) -> Optional[CVEInfo]:
    """解析 GHSA advisory JSON → CVEInfo

    Args:
        advisory: GHSA REST API 单条 advisory（https://docs.github.com/en/rest/security-advisories）

    Returns:
        CVEInfo（source='ghsa'）或 None（缺 cve_id）
    """
    cve_id = advisory.get("cve_id", "")
    if not cve_id:
        return None

    # 描述：优先完整 description，回退 summary
    description = advisory.get("description", "") or advisory.get("summary", "")

    # CVSS（GHSA cvss 对象含 score/vector_string）
    cvss = advisory.get("cvss", {}) or {}
    try:
        cvss_score = float(cvss.get("score") or 0.0)
    except (TypeError, ValueError):
        cvss_score = 0.0
    cvss_vector = cvss.get("vector_string", "") or ""

    severity = _GHSA_SEVERITY_MAP.get((advisory.get("severity") or "").lower(), "")

    references = [r.get("url", "") for r in advisory.get("references", []) if r.get("url")]

    # GHSA 的 cwes 字段为 CWE 编号列表（如 ["CWE-79"]），元素可能是字符串或含 cwe_id 的对象
    cwe = []
    for item in advisory.get("cwes", []) or []:
        cwe_id = item if isinstance(item, str) else item.get("cwe_id", "")
        if cwe_id and cwe_id not in cwe:
            cwe.append(cwe_id)

    return CVEInfo(
        cve_id=cve_id,
        description=description,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        severity=severity,
        published=advisory.get("published_at", ""),
        last_modified=advisory.get("updated_at", ""),
        references=references,
        cwe=cwe,
        source="ghsa",
    )


# ============================================================
# 高层接口
# ============================================================


# ============================================================
# 离线 CVE 库 + CNVD 源（G1）
# ============================================================


def _load_offline() -> Dict[str, Dict[str, Any]]:
    """加载离线 CVE 库（data/cve_offline.json，随包分发），按 id/别名建索引

    Returns:
        {编号大写: 条目}；文件缺失/损坏返回 {}（离线兜底静默降级）
    """
    global _OFFLINE_CACHE
    if _OFFLINE_CACHE is not None:
        return _OFFLINE_CACHE
    index: Dict[str, Dict[str, Any]] = {}
    try:
        with open(OFFLINE_CVE_PATH, encoding="utf-8") as f:
            doc = json.load(f)
        for entry in doc.get("entries", []):
            ids = [entry.get("id", "")] + list(entry.get("aliases", []))
            for iid in ids:
                if iid:
                    index[iid.upper()] = entry
    except (OSError, json.JSONDecodeError):
        logger.debug("离线 CVE 库加载失败（%s）", OFFLINE_CVE_PATH, exc_info=True)
    _OFFLINE_CACHE = index
    return index


def lookup_offline(cve_id: str) -> Optional[CVEInfo]:
    """从离线库按 CVE/CNVD 编号查询（内网兜底，零网络依赖）

    Returns:
        CVEInfo（source='offline'）或 None
    """
    entry = _load_offline().get(cve_id.upper())
    if not entry:
        return None
    return CVEInfo(
        cve_id=entry.get("id", cve_id),
        description=entry.get("description", ""),
        cvss_score=float(entry.get("cvss", 0.0)),
        severity=entry.get("severity", ""),
        references=[],
        cwe=[],
        source="offline",
    )


def search_offline(component: str = "") -> List[CVEInfo]:
    """按组件列出离线库条目（--cve-offline 内网排查用）

    Args:
        component: 组件名（空 = 全部）

    Returns:
        CVEInfo 列表（source='offline'，按 CVSS 降序）
    """
    seen = set()
    results: List[CVEInfo] = []
    for entry in _load_offline().values():
        if component and entry.get("component", "") != component:
            continue
        info = lookup_offline(entry.get("id", ""))
        if info and info.cve_id not in seen:
            seen.add(info.cve_id)
            results.append(info)
    return sorted(results, key=lambda x: -x.cvss_score)


def query_cnvd(keyword: str, timeout: int = 10) -> Optional[CVEInfo]:
    """从 CNVD（国家信息安全漏洞共享平台）查询漏洞信息

    注意：CNVD 无官方公开 REST API，本实现基于官网漏洞列表页抓取（best-effort），
    反爬/网络不可达时静默返回 None（不阻断查询链）。

    Args:
        keyword: CVE/CNVD 编号或关键字
        timeout: 请求超时秒数

    Returns:
        CVEInfo（source='cnvd'）或 None
    """
    url = f"{CNVD_BASE}/list?keyword={urllib.parse.quote(keyword)}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ruoyi-Scan/1.3",
        "Accept": "text/html",
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    return parse_cnvd_response(html, keyword=keyword)


def parse_cnvd_response(html: str, keyword: str = "") -> Optional[CVEInfo]:
    """解析 CNVD 列表页 HTML → CVEInfo（best-effort，页面改版时静默失败）

    Returns:
        CVEInfo（source='cnvd'）或 None（未解析到结果）
    """
    # 列表页第一条结果的 CNVD 编号（/flaw/show/CNVD-YYYY-XXXXX）
    m = re.search(r"/flaw/show/(CNVD-\d{4}-\d+)", html)
    if not m:
        return None
    cnvd_id = m.group(1)
    description = ""
    if keyword.upper() in html.upper():
        # 尽力提取结果行附近的标题文本（页面结构无稳定 id/class，正则兜底）
        idx = html.upper().find(keyword.upper())
        snippet = re.sub(r"<[^>]+>", " ", html[idx : idx + 400])
        description = re.sub(r"\s+", " ", snippet).strip()
    return CVEInfo(
        cve_id=cnvd_id,
        description=description[:300],
        source="cnvd",
    )


def lookup_cve(cve_id: str, use_cache: bool = True, api_key: str = None) -> Optional[CVEInfo]:
    """查询单个 CVE（缓存优先，NVD 主源 + GHSA 回退）

    Args:
        cve_id: CVE 编号
        use_cache: 是否使用缓存
        api_key: NVD API Key

    Returns:
        CVEInfo 或 None
    """
    # 缓存优先
    if use_cache:
        cached = load_from_cache(cve_id)
        if cached:
            return cached

    # 查询 NVD API（主源）
    cve = query_nvd_api(cve_id, api_key=api_key)

    # G1：NVD 未命中/不可达时逐级回退：
    #   GHSA（国内可达性好）→ CNVD（无官方 API，网页抓取 best-effort）→ 离线库（内网兜底）
    if cve is None:
        cve = query_ghsa(cve_id)
    if cve is None:
        cve = query_cnvd(cve_id)
    if cve is None:
        cve = lookup_offline(cve_id)

    if cve:
        save_to_cache(cve)

    return cve


def batch_lookup_cves(cve_ids: List[str], use_cache: bool = True, api_key: str = None) -> Dict[str, Optional[CVEInfo]]:
    """批量查询 CVE

    Args:
        cve_ids: CVE ID 列表
        use_cache: 是否使用缓存
        api_key: NVD API Key

    Returns:
        {cve_id: CVEInfo or None}
    """
    results = {}
    for cve_id in cve_ids:
        results[cve_id] = lookup_cve(cve_id, use_cache=use_cache, api_key=api_key)
    return results


# ============================================================
# 插件 CVE 信息更新
# ============================================================


def extract_cve_ids_from_plugins() -> List[Tuple[str, str]]:
    """从所有插件中提取 CVE 编号

    Returns:
        [(plugin_module, cve_id), ...]
    """
    import importlib
    import pkgutil

    from core.loader import discover_plugin_packages
    from plugins.base import PluginBase

    results = []
    for pkg_name in discover_plugin_packages():
        try:
            pkg = importlib.import_module(pkg_name)
            for _, name, is_pkg in pkgutil.iter_modules(pkg.__path__):
                if is_pkg or name.startswith("_"):
                    continue
                mn = f"{pkg_name}.{name}"
                try:
                    m = importlib.import_module(mn)
                    for an in dir(m):
                        a = getattr(m, an)
                        if (
                            isinstance(a, type)
                            and issubclass(a, PluginBase)
                            and a is not PluginBase
                            and a.__module__ == mn
                        ):
                            cve = getattr(a, "cve", "")
                            if cve and cve != "N/A":
                                results.append((mn, cve))
                except Exception:
                    continue
        except Exception:
            continue

    return results


def build_cve_update_report(
    plugins_cves: List[Tuple[str, str]], cve_infos: Dict[str, Optional[CVEInfo]]
) -> Dict[str, Any]:
    """构建 CVE 更新报告

    Args:
        plugins_cves: [(plugin_module, cve_id), ...]
        cve_infos: {cve_id: CVEInfo or None}

    Returns:
        报告字典
    """
    report = {
        "total_plugins": len(plugins_cves),
        "total_cves": len(cve_infos),
        "updated": 0,
        "not_found": 0,
        "details": [],
    }

    for plugin_module, cve_id in plugins_cves:
        info = cve_infos.get(cve_id)
        if info:
            report["updated"] += 1
            report["details"].append(
                {
                    "plugin": plugin_module,
                    "cve_id": cve_id,
                    "cvss_score": info.cvss_score,
                    "severity": info.severity,
                    "cvss_vector": info.cvss_vector,
                    "compliance": info.to_compliance_tag(),
                    "status": "updated",
                }
            )
        else:
            report["not_found"] += 1
            report["details"].append(
                {
                    "plugin": plugin_module,
                    "cve_id": cve_id,
                    "status": "not_found",
                }
            )

    return report


def run_cve_sync_mode(args) -> int:
    """CVE 同步模式入口

    Args:
        args: CLI 参数

    Returns:
        0 表示成功
    """
    api_key = getattr(args, "nvd_api_key", None)

    # 查询单个 CVE
    cve_id = getattr(args, "cve_id", None)
    if cve_id:
        print(f"[*]查询 CVE: {cve_id}")
        info = lookup_cve(cve_id, api_key=api_key)
        if info:
            print(f"[+]CVE-ID: {info.cve_id}")
            print(f"    数据源: {info.source}")
            print(f"    严重度: {info.severity} (CVSS {info.cvss_score})")
            print(f"    向量: {info.cvss_vector}")
            print(f"    描述: {info.description[:200]}")
            print(f"    CWE: {', '.join(info.cwe)}")
            print(f"    合规: {info.to_compliance_tag()}")
            return 0
        else:
            print(f"[!]未找到 CVE: {cve_id}")
            return 1

    # G1：按组件查离线 CVE 库（内网模式）
    component = getattr(args, "cve_offline", None)
    if component is not None:
        results = search_offline(component=component)
        if not results:
            print(f"[!]离线库中未找到组件 {component or '(全部)'} 的 CVE（可运行 scripts/build_offline_cve.py 更新）")
            return 1
        print(f"[+]离线 CVE 库（{'组件 ' + component if component else '全部'}）: {len(results)} 条")
        for info in results:
            print(f"    {info.cve_id}  CVSS {info.cvss_score}  {info.severity}  {info.description[:60]}")
        return 0

    # 同步所有插件
    print("[*]扫描插件库中的 CVE 编号...")
    plugins_cves = extract_cve_ids_from_plugins()
    print(f"[+]发现 {len(plugins_cves)} 个 CVE 引用")

    if not plugins_cves:
        print("[!]未发现需要同步的 CVE")
        return 0

    # 集合去重后再查询：多个插件引用同一 CVE 只请求一次 NVD
    cve_ids = list({cve for _, cve in plugins_cves})
    print(f"[*]开始同步 {len(cve_ids)} 个唯一 CVE...")

    cve_infos = batch_lookup_cves(cve_ids, api_key=api_key)

    report = build_cve_update_report(plugins_cves, cve_infos)
    print("\n[+]同步完成:")
    print(f"    总插件数: {report['total_plugins']}")
    print(f"    成功更新: {report['updated']}")
    print(f"    未找到: {report['not_found']}")

    # 保存报告
    report_path = os.path.join("reports", "cve_sync_report.json")
    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[+]报告已保存: {report_path}")

    return 0
