# D14 主动爬虫：BFS 抓取目标站点页面
#
# 设计目标：
#   1. 纯标准库（requests + html.parser，不引入 scrapy/beautifulsoup）
#   2. BFS 算法，可控深度（max_depth）与最大页面数（max_pages）
#   3. 同源限制（默认仅抓取与起始 URL 同 host 的链接，可放开）
#   4. 提取链接：<a href>、<form action>、<iframe src>、<script src>、<link href>
#   5. 过滤静态资源（默认跳过 .png/.jpg/.css/.pdf 等，可配置 include_static）
#   6. 与 SessionManager 集成（复用代理/UA/超时配置）
#
# 用法：
#   from lib.crawler import Crawler
#   c = Crawler(max_depth=2, max_pages=20)
#   urls = c.crawl('http://target/', session)  # 返回所有发现的 URL（含起始）
import threading
from collections import deque
from html.parser import HTMLParser
from typing import Callable, List, Optional, Set
from urllib.parse import urldefrag, urljoin, urlparse

from core.logger import get_logger

logger = get_logger(__name__)

# 默认跳过的静态资源后缀（按 .gitignore 风格小写匹配）
# 注：.js 默认排除（避免常规爬虫抓取 JS），但 crawl_with_js_urls 临时移除以收集 JS URL
DEFAULT_EXCLUDED_EXT = {
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".svg",
    ".ico",
    ".webp",
    ".css",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".7z",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".flv",
    ".webm",
    ".exe",
    ".dmg",
    ".apk",
    ".ipa",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
}


class LinkExtractor(HTMLParser):
    """HTML 链接抽取器：从 <a>/<form>/<iframe>/<script>/<link> 提取 URL

    用法：
        p = LinkExtractor()
        p.feed(html_text)
        urls = p.links
    """

    # 标签 -> 取 URL 的属性
    LINK_ATTRS = {
        "a": "href",
        "form": "action",
        "iframe": "src",
        "script": "src",
        "link": "href",
        "area": "href",
        "embed": "src",
        "source": "src",
    }

    def __init__(self):
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        tag_lower = tag.lower()
        attr_name = self.LINK_ATTRS.get(tag_lower)
        if not attr_name:
            return
        for name, value in attrs:
            if name.lower() == attr_name and value:
                self.links.append(value)


def is_same_host(url1: str, url2: str) -> bool:
    """判断两个 URL 是否同 host"""
    return urlparse(url1).hostname == urlparse(url2).hostname


def is_static_resource(url: str, excluded_ext: Set[str] = None) -> bool:
    """判断 URL 是否为静态资源（按后缀过滤）"""
    excluded = excluded_ext or DEFAULT_EXCLUDED_EXT
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in excluded)


def normalize_link(base: str, link: str) -> Optional[str]:
    """规范化链接：相对转绝对、去 fragment、过滤非 http/https

    Returns:
        规范化后的绝对 URL，无效链接返回 None
    """
    if not link:
        return None
    link = link.strip()
    if not link or link.startswith("#"):
        return None
    # javascript: / mailto: / data: 等非 HTTP 协议跳过
    if ":" in link and not link.startswith(("http://", "https://")):
        # 处理 protocol-relative URL（//host/path）
        if link.startswith("//"):
            scheme = urlparse(base).scheme or "http"
            link = f"{scheme}:{link}"
        else:
            return None
    # 拼接为绝对 URL
    absolute = urljoin(base, link)
    # 去 fragment
    absolute, _ = urldefrag(absolute)
    # 仅保留 http/https
    if urlparse(absolute).scheme not in ("http", "https"):
        return None
    return absolute


class Crawler:
    """主动爬虫（BFS）

    用法：
        c = Crawler(max_depth=2, max_pages=20)
        urls = c.crawl('http://target/', session)
    """

    def __init__(
        self,
        max_depth: int = 2,
        max_pages: int = 50,
        same_host_only: bool = True,
        include_static: bool = False,
        excluded_ext: Optional[Set[str]] = None,
        delay: float = 0.0,
        on_page: Optional[Callable[[str, str], None]] = None,
    ):
        """初始化爬虫

        Args:
            max_depth: 最大抓取深度（1=仅起始页，2=起始页+1 层链接）
            max_pages: 最大抓取页面数（防止失控）
            same_host_only: 仅抓取同 host 链接（默认 True）
            include_static: 是否包含静态资源（默认 False）
            excluded_ext: 自定义排除后缀集合（None=用默认）
            delay: 每次请求间隔（秒，0=不延迟）
            on_page: 每抓到一个页面的回调 (url, html_text) -> None
        """
        self.max_depth = max(max_depth, 1)
        self.max_pages = max(max_pages, 1)
        self.same_host_only = same_host_only
        self.include_static = include_static
        self.excluded_ext = excluded_ext if excluded_ext is not None else DEFAULT_EXCLUDED_EXT
        self.delay = delay
        self.on_page = on_page
        # 统计信息
        self.visited: Set[str] = set()
        self.discarded: List[str] = []  # 被过滤的链接
        self.errors: List[str] = []
        self._lock = threading.Lock()

    def crawl(self, start_url: str, session=None) -> List[str]:
        """从起始 URL 开始 BFS 抓取

        Args:
            start_url: 起始 URL
            session: SessionManager 实例（None 则内部创建）

        Returns:
            所有抓取到的 URL 列表（含起始 URL，按访问顺序）
        """
        # 规范化起始 URL
        start_url = normalize_link("", start_url) or start_url
        if not start_url:
            return []

        # BFS 队列：(url, depth)
        queue = deque([(start_url, 1)])
        results: List[str] = []

        while queue and len(results) < self.max_pages:
            url, depth = queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)

            # 抓取页面
            html_text = ""
            try:
                if session is not None:
                    resp = session.get(url)
                    if resp.status_code == 200:
                        # 仅处理 HTML 响应（按 Content-Type）
                        ct = resp.headers.get("Content-Type", "")
                        if "html" in ct.lower() or "text" in ct.lower():
                            html_text = resp.text
                        else:
                            # 非 HTML 响应（如 JS、JSON）只记录 URL，不解析
                            pass
                    else:
                        with self._lock:
                            self.errors.append(f"{url} -> HTTP {resp.status_code}")
                else:
                    # 无 session 时使用 requests
                    import requests as _requests

                    resp = _requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        ct = resp.headers.get("Content-Type", "")
                        if "html" in ct.lower() or "text" in ct.lower():
                            html_text = resp.text
            except Exception as e:
                with self._lock:
                    self.errors.append(f"{url} -> {type(e).__name__}: {e}")
                continue

            results.append(url)
            if self.on_page:
                try:
                    self.on_page(url, html_text)
                except Exception:
                    logger.debug("执行页面回调失败", exc_info=True)

            # 达到最大深度则不再扩展
            if depth >= self.max_depth or not html_text:
                if self.delay:
                    import time as _t

                    _t.sleep(self.delay)
                continue

            # 提取链接
            parser = LinkExtractor()
            try:
                parser.feed(html_text)
            except Exception:
                logger.debug("解析 HTML 提取链接失败", exc_info=True)

            for link in parser.links:
                absolute = normalize_link(url, link)
                if not absolute:
                    continue
                # 去重
                if absolute in self.visited or any(absolute == q[0] for q in queue):
                    continue
                # 同 host 限制
                if self.same_host_only and not is_same_host(start_url, absolute):
                    continue
                # 静态资源过滤
                if not self.include_static and is_static_resource(absolute, self.excluded_ext):
                    with self._lock:
                        self.discarded.append(absolute)
                    continue
                queue.append((absolute, depth + 1))

            if self.delay:
                import time as _t

                _t.sleep(self.delay)

        return results

    def crawl_with_js_urls(self, start_url: str, session=None) -> dict:
        """抓取并返回分类 URL（HTML 页面 + JS 文件）

        用于 D14：JS 提取需要单独获取所有 JS 文件 URL

        Returns:
            {
                'pages': [url1, url2, ...],     # HTML 页面
                'js': [url1, url2, ...],        # JS 文件
                'all': [url1, url2, ...],       # 所有 URL
            }
        """
        # 临时移除 .js 排除（让 JS 文件通过过滤，但仍过滤图片/CSS 等）
        original_excluded = self.excluded_ext
        try:
            self.excluded_ext = {ext for ext in original_excluded if ext != ".js"}
            all_urls = self.crawl(start_url, session)
        finally:
            self.excluded_ext = original_excluded

        pages = [u for u in all_urls if not u.lower().endswith(".js")]
        js_urls = [u for u in all_urls if u.lower().endswith(".js")]
        return {
            "pages": pages,
            "js": js_urls,
            "all": all_urls,
        }


# === 便捷函数 ===


def crawl_target(target: str, session=None, max_depth: int = 2, max_pages: int = 50) -> List[str]:
    """便捷爬取函数（快速调用）"""
    c = Crawler(max_depth=max_depth, max_pages=max_pages)
    return c.crawl(target, session)


def extract_links_from_html(html_text: str, base_url: str = "") -> List[str]:
    """从 HTML 文本提取链接（不走网络，纯解析）

    Args:
        html_text: HTML 内容
        base_url: 用于将相对链接转为绝对 URL 的基础 URL

    Returns:
        规范化后的 URL 列表
    """
    parser = LinkExtractor()
    parser.feed(html_text)
    if base_url:
        return [normalize_link(base_url, link) for link in parser.links if normalize_link(base_url, link)]
    return parser.links
