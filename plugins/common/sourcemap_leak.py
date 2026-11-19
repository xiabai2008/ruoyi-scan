# 前端 SourceMap 源码泄露：从 index.html 提取 JS，再取 .map / sourceMappingURL
import json
import re
from urllib.parse import urljoin

from common.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult, UnknownReason
from plugins.base import PluginBase

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']?([^"'\s>]+\.js(?:\?[^"'\s>]*)?)""", re.I)
_SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s'\"<>]+)")
_MAX_SCRIPTS = 8


def _valid_source_map(text: str) -> bool:
    """严格校验 source map JSON，避免把 SPA 兜底 HTML/错误页判成泄露。"""
    try:
        payload = json.loads(text)
    except Exception:
        return False
    if not isinstance(payload, dict) or payload.get("version") != 3:
        return False
    sources = payload.get("sources")
    mappings = payload.get("mappings")
    return isinstance(sources, list) and bool(sources) and isinstance(mappings, str) and bool(mappings)


def _extract_scripts(html: str) -> list:
    return [m.group(1) for m in _SCRIPT_SRC_RE.finditer(html)]


class SourceMapLeakPlugin(PluginBase):
    """探测前端构建产物未关闭 sourcemap，导致 .map 源码映射可被下载"""

    name = "前端 SourceMap 源码泄露"
    cve = "N/A"
    severity = SEVERITY_MEDIUM
    # 前端 dist 在站点根，不能跟随 /prod-api 等后端前缀
    path_scope = "root"
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    description = "前端构建产物保留了 sourcemap，攻击者可下载 .map 还原完整前端源码、接口与注释"
    fix = "生产构建关闭 sourcemap（webpack devtool=false / Vite build.sourcemap=false），并删除已部署的 .map 文件"
    fix_detail = (
        "【构建配置】webpack：production.devtool=false；Vite：build.sourcemap=false\n"
        "【构建产物】部署前删除 *.map、*.js.map，Nginx 对 .map 返回 404\n"
        "【配置加固】location ~* \\.map$ { deny all; }\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 从首页找 JS：\n"
        "curl -s http://target/ | grep -oE 'src=[^ >]+\\.js'\n"
        "# 2. 取 sourceMappingURL 或直接拼 .map：\n"
        "curl -i http://target/static/js/app.d647f972.js.map\n"
        '# 预期：HTTP 200 + {"version":3,"sources":[...],"mappings":"..."}'
    )

    def verify(self, target, session):
        try:
            root_resp = session.get(target)
        except Exception as e:
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                unknown_reason=UnknownReason.UNREACHABLE.value,
                evidence=f"首页请求失败：{e}",
            )
        root_text = getattr(root_resp, "text", "") or ""
        scripts = _extract_scripts(root_text)[:_MAX_SCRIPTS]
        if not scripts:
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_SAFE,
                evidence="首页未发现前端 script 资源，无 sourcemap 暴露面",
            )

        got_response = False
        for src in scripts:
            script_url = src if src.startswith(("http://", "https://")) else urljoin(target, src)
            try:
                js_resp = session.get(script_url)
                got_response = True
            except Exception:
                continue
            js_text = getattr(js_resp, "text", "") or ""
            map_url = ""
            m = _SOURCE_MAP_RE.search(js_text)
            if m:
                ref = m.group(1).strip()
                if ref and not ref.startswith("data:"):
                    map_url = ref if ref.startswith(("http://", "https://")) else urljoin(script_url, ref)
            if not map_url:
                map_url = script_url + ".map"
            try:
                map_resp = session.get(map_url)
                got_response = True
            except Exception:
                continue
            map_text = getattr(map_resp, "text", "") or ""
            if not _valid_source_map(map_text):
                continue
            try:
                source_count = len(json.loads(map_text).get("sources") or [])
            except Exception:
                source_count = 0
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=map_url,
                evidence=f"可下载 sourcemap：{map_url}（version=3，sources={source_count}）",
                fix=self.fix,
            )
        if got_response:
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_SAFE,
                evidence="前端 JS 未暴露可解析的 sourcemap（.map 不存在或返回兜底页）",
            )
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_UNKNOWN,
            unknown_reason=UnknownReason.UNREACHABLE.value,
            evidence="前端 JS/sourcemap 请求全部网络异常，无法判定",
        )
