# D14 JS 端点提取：从 JavaScript 文件中提取 API 端点、路径、URL
#
# 设计目标：
#   1. 纯正则提取，无 JS 引擎依赖（不用 js2py/PyMiniRacer）
#   2. 多模式覆盖：
#      - 绝对 URL：http(s)://...
#      - 相对路径：/api/...、/admin/...
#      - fetch/axios/$.ajax 调用参数
#      - 字符串字面量中的路径
#   3. 去重 + 来源记录（每条端点记录来源 JS URL）
#   4. 过滤噪声（排除 node_modules、第三方库常见路径）
#
# 用法：
#   from lib.js_extractor import JSExtractor
#   ext = JSExtractor()
#   endpoints = ext.extract_from_text(js_code, source_url='http://x/main.js')
#   endpoints = ext.extract_from_urls(['http://x/main.js', 'http://x/app.js'], session)
import re
from typing import List, Set, Optional, Dict
from dataclasses import dataclass, field
from urllib.parse import urlparse


# 正则模式：路径样式（/word/word...，至少 2 段以降低噪声）
# 例：/api/user、/admin/list、/prod-api/system/user
PATH_PATTERN = re.compile(
    r'["\'`](/(?:[a-zA-Z0-9_\-]+/){1,6}[a-zA-Z0-9_\-]+)["\'`]'
)

# 正则模式：绝对 URL
URL_PATTERN = re.compile(
    r'["\'`](https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)["\'`]'
)

# 正则模式：fetch/axios 调用
FETCH_PATTERN = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete|patch|request)|\$\.ajax)\s*\(\s*["\'`]([^"\'`]+)["\'`]',
    re.IGNORECASE
)

# 第三方库噪声路径前缀（这些不是真正的 API 端点）
NOISE_PREFIXES = (
    'node_modules/', 'webpack/', 'babel/', 'core-js/', 'tslib/',
    'polyfill', 'chunk-', 'vendor/', 'sourcemap',
)


@dataclass
class Endpoint:
    """提取的端点信息"""
    url: str                                # 端点 URL（绝对或相对路径）
    source: str = ''                        # 来源 JS 文件 URL
    method: str = ''                        # HTTP 方法（如果能识别）
    line_no: int = 0                        # 行号（近似）
    is_absolute: bool = False               # 是否绝对 URL
    contexts: List[str] = field(default_factory=list)  # 出现的上下文（fetch/url/string）

    def __hash__(self):
        return hash((self.url, self.source))

    def __eq__(self, other):
        if not isinstance(other, Endpoint):
            return False
        return self.url == other.url and self.source == other.source


class JSExtractor:
    """JavaScript 端点提取器

    用法：
        ext = JSExtractor()
        # 从 JS 文本提取
        endpoints = ext.extract_from_text(js_code, source_url='http://x/main.js')
        # 从多个 JS URL 提取（自动 fetch）
        endpoints = ext.extract_from_urls(['http://x/main.js'], session)
    """

    def __init__(self,
                 min_path_segments: int = 2,
                 include_noise: bool = False,
                 include_third_party: bool = False):
        """初始化提取器

        Args:
            min_path_segments: 最小路径段数（/api/x 是 2 段，过滤 /a 这种噪声）
            include_noise: 是否包含已知噪声路径（默认 False）
            include_third_party: 是否包含第三方库路径（默认 False）
        """
        self.min_path_segments = min_path_segments
        self.include_noise = include_noise
        self.include_third_party = include_third_party

    def extract_from_text(self, js_text: str, source_url: str = '') -> List[Endpoint]:
        """从 JS 文本提取端点

        Args:
            js_text: JavaScript 源码
            source_url: 来源 URL（用于记录）

        Returns:
            端点列表（去重）
        """
        if not js_text:
            return []

        seen: Set[str] = set()
        endpoints: List[Endpoint] = []
        lines = js_text.split('\n')

        # 按行扫描（便于记录行号）
        for line_no, line in enumerate(lines, start=1):
            # 1. 绝对 URL
            for match in URL_PATTERN.finditer(line):
                url = match.group(1).rstrip('/').rstrip('\\')
                if self._is_noise(url):
                    continue
                key = f'{url}|{source_url}'
                if key in seen:
                    continue
                seen.add(key)
                endpoints.append(Endpoint(
                    url=url, source=source_url, line_no=line_no,
                    is_absolute=True, contexts=['url']
                ))

            # 2. fetch/axios 调用（高置信度，标注方法）
            for match in FETCH_PATTERN.finditer(line):
                url = match.group(1)
                if self._is_noise(url):
                    continue
                # 识别方法（fetch 默认 GET，axios.X 用 X）
                method = 'GET'
                if 'axios.post' in line.lower():
                    method = 'POST'
                elif 'axios.put' in line.lower():
                    method = 'PUT'
                elif 'axios.delete' in line.lower():
                    method = 'DELETE'
                elif 'axios.patch' in line.lower():
                    method = 'PATCH'
                key = f'{url}|{source_url}'
                if key in seen:
                    # 已存在则补 method
                    for ep in endpoints:
                        if ep.url == url and ep.source == source_url:
                            if method and method not in ep.contexts:
                                ep.contexts.append(f'fetch:{method}')
                            break
                    continue
                seen.add(key)
                endpoints.append(Endpoint(
                    url=url, source=source_url, line_no=line_no,
                    method=method, contexts=[f'fetch:{method}']
                ))

            # 3. 相对路径（/api/... 等）
            for match in PATH_PATTERN.finditer(line):
                path = match.group(1)
                if self._is_noise(path):
                    continue
                # 段数过滤
                segments = [s for s in path.split('/') if s]
                if len(segments) < self.min_path_segments:
                    continue
                key = f'{path}|{source_url}'
                if key in seen:
                    continue
                seen.add(key)
                endpoints.append(Endpoint(
                    url=path, source=source_url, line_no=line_no,
                    is_absolute=False, contexts=['path']
                ))

        return endpoints

    def extract_from_urls(self, js_urls: List[str], session=None) -> List[Endpoint]:
        """从多个 JS URL 提取端点（自动下载）

        Args:
            js_urls: JS 文件 URL 列表
            session: SessionManager 实例

        Returns:
            端点列表（合并所有 JS 的结果）
        """
        all_endpoints: List[Endpoint] = []
        for js_url in js_urls:
            try:
                if session is not None:
                    resp = session.get(js_url)
                else:
                    import requests as _requests
                    resp = _requests.get(js_url, timeout=10)
                if resp.status_code != 200:
                    continue
                # 仅处理 JS 响应
                ct = resp.headers.get('Content-Type', '').lower()
                if 'javascript' not in ct and 'text' not in ct and not js_url.lower().endswith('.js'):
                    continue
                endpoints = self.extract_from_text(resp.text, source_url=js_url)
                all_endpoints.extend(endpoints)
            except Exception:
                continue
        return all_endpoints

    def _is_noise(self, url_or_path: str) -> bool:
        """判断是否为噪声路径（应跳过）"""
        if not url_or_path:
            return True
        lower = url_or_path.lower()
        # 用户已选择包含噪声
        if self.include_noise:
            return False
        # 排除已知噪声前缀
        if not self.include_third_party:
            for prefix in NOISE_PREFIXES:
                if prefix in lower:
                    return True
        # 排除 sourcemap
        if lower.endswith('.map'):
            return True
        # 排除 data: URI
        if lower.startswith('data:'):
            return True
        return False

    def filter_by_host(self, endpoints: List[Endpoint], host: str) -> List[Endpoint]:
        """按 host 过滤端点（仅保留同 host 或相对路径）

        Args:
            endpoints: 端点列表
            host: 目标 host

        Returns:
            过滤后的端点列表
        """
        result = []
        for ep in endpoints:
            if not ep.is_absolute:
                # 相对路径直接保留
                result.append(ep)
            else:
                # 绝对 URL 仅保留同 host
                ep_host = urlparse(ep.url).hostname or ''
                if ep_host == host:
                    result.append(ep)
        return result


# === 便捷函数 ===

def extract_endpoints(js_text: str, source_url: str = '') -> List[str]:
    """便捷提取函数：从 JS 文本提取端点 URL（仅返回 URL 列表，去重）"""
    ext = JSExtractor()
    endpoints = ext.extract_from_text(js_text, source_url=source_url)
    # 去重 URL
    seen = set()
    urls = []
    for ep in endpoints:
        if ep.url not in seen:
            seen.add(ep.url)
            urls.append(ep.url)
    return urls


def extract_from_urls(js_urls: List[str], session=None) -> List[str]:
    """便捷提取函数：从多个 JS URL 提取端点（返回 URL 列表）"""
    ext = JSExtractor()
    endpoints = ext.extract_from_urls(js_urls, session=session)
    seen = set()
    urls = []
    for ep in endpoints:
        if ep.url not in seen:
            seen.add(ep.url)
            urls.append(ep.url)
    return urls
