# D32：CVE/NVD 自动同步
#
# 从 NVD（National Vulnerability Database）自动同步 CVE 信息，更新插件库的
# cve/cvss_vector/compliance 字段，保持漏洞知识库常新。
#
# 数据源：
#   1. NVD REST API（https://services.nvd.nist.gov/rest/json/cves/2.0）
#   2. NVD JSON Feed（https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz）
#   3. 本地缓存（避免重复请求）
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
import datetime
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from core.logger import get_logger

logger = get_logger(__name__)

# ============================================================
# 常量
# ============================================================

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"
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
    ):
        self.cve_id = cve_id
        self.description = description
        self.cvss_vector = cvss_vector
        self.cvss_score = cvss_score
        self.severity = severity  # LOW/MEDIUM/HIGH/CRITICAL
        self.published = published
        self.last_modified = last_modified
        self.references = references or []
        self.cwe = cwe or []

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

        if not tags:
            tags.append("OWASP:A06:2021;等保2.0:8.1.3")

        return tags[0]

    def to_severity_lower(self) -> str:
        """NVD 严重度转小写"""
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
# 高层接口
# ============================================================


def lookup_cve(cve_id: str, use_cache: bool = True, api_key: str = None) -> Optional[CVEInfo]:
    """查询单个 CVE（缓存优先）

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

    # 查询 NVD API
    cve = query_nvd_api(cve_id, api_key=api_key)
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

    from plugins.base import PluginBase

    results = []
    for pkg_name in ["plugins.ruoyi", "plugins.spring", "plugins.common"]:
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
            print(f"    严重度: {info.severity} (CVSS {info.cvss_score})")
            print(f"    向量: {info.cvss_vector}")
            print(f"    描述: {info.description[:200]}")
            print(f"    CWE: {', '.join(info.cwe)}")
            print(f"    合规: {info.to_compliance_tag()}")
            return 0
        else:
            print(f"[!]未找到 CVE: {cve_id}")
            return 1

    # 同步所有插件
    print("[*]扫描插件库中的 CVE 编号...")
    plugins_cves = extract_cve_ids_from_plugins()
    print(f"[+]发现 {len(plugins_cves)} 个 CVE 引用")

    if not plugins_cves:
        print("[!]未发现需要同步的 CVE")
        return 0

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
