# D14 主动信息收集测试
#
# 覆盖：
#   1. lib/crawler.py：BFS 爬虫、链接提取、同 host 过滤、静态资源过滤
#   2. lib/subdomain.py：子域名枚举（crt.sh mock + 字典 + DNS 验证）
#   3. lib/js_extractor.py：JS 端点提取（路径、URL、fetch 调用）
#   4. orchestrator 集成：ScanRequest.crawl/subdomain/js_extract 字段
import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.crawler import (
    Crawler,
    LinkExtractor,
    crawl_target,
    extract_links_from_html,
    is_same_host,
    is_static_resource,
    normalize_link,
)
from lib.js_extractor import (
    Endpoint,
    JSExtractor,
    extract_endpoints,
)
from lib.subdomain import (
    SubdomainEnumerator,
    enumerate_subdomains,
    get_default_word_list,
)

# === fixtures ===

class FakeResp:
    """模拟 requests.Response"""
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {'Content-Type': 'text/html'}
        self.content = text.encode('utf-8') if text else b''

    def json(self):
        """解析 JSON 响应（模拟 requests.Response.json）"""
        return json.loads(self.text)


class FakeSession:
    """按 URL 映射返回固定响应的 mock session"""

    def __init__(self, responses):
        self.responses = responses
        self.request_count = 0

    def get(self, url, **kw):
        self.request_count += 1
        return self.responses.get(url, FakeResp('', 404))

    def post(self, url, **kw):
        self.request_count += 1
        return self.responses.get(url, FakeResp('', 404))

    def close(self):
        pass


# ============================================================
# 1. lib/crawler.py 测试
# ============================================================

class TestLinkExtractor:
    """HTML 链接提取器测试"""

    def test_extract_anchor_links(self):
        """从 <a href> 提取链接"""
        html = '<a href="/page1">P1</a><a href="/page2">P2</a>'
        parser = LinkExtractor()
        parser.feed(html)
        assert len(parser.links) == 2
        assert '/page1' in parser.links
        assert '/page2' in parser.links

    def test_extract_form_action(self):
        """从 <form action> 提取链接"""
        html = '<form action="/login" method="post"></form>'
        parser = LinkExtractor()
        parser.feed(html)
        assert '/login' in parser.links

    def test_extract_script_src(self):
        """从 <script src> 提取链接"""
        html = '<script src="/js/app.js"></script>'
        parser = LinkExtractor()
        parser.feed(html)
        assert '/js/app.js' in parser.links

    def test_extract_iframe_src(self):
        """从 <iframe src> 提取链接"""
        html = '<iframe src="/embed"></iframe>'
        parser = LinkExtractor()
        parser.feed(html)
        assert '/embed' in parser.links

    def test_extract_link_href(self):
        """从 <link href> 提取链接"""
        html = '<link rel="stylesheet" href="/style.css">'
        parser = LinkExtractor()
        parser.feed(html)
        assert '/style.css' in parser.links

    def test_empty_html(self):
        """空 HTML 不提取链接"""
        parser = LinkExtractor()
        parser.feed('')
        assert parser.links == []


class TestNormalizeLink:
    """链接规范化测试"""

    def test_absolute_url_unchanged(self):
        """绝对 URL 保持不变"""
        assert normalize_link('http://x.com/', 'http://x.com/page') == 'http://x.com/page'

    def test_relative_to_absolute(self):
        """相对链接转绝对"""
        assert normalize_link('http://x.com/', '/page') == 'http://x.com/page'

    def test_relative_no_leading_slash(self):
        """无前导斜杠的相对链接"""
        assert normalize_link('http://x.com/', 'page') == 'http://x.com/page'

    def test_fragment_removed(self):
        """去 fragment"""
        assert normalize_link('http://x.com/', '/page#section') == 'http://x.com/page'

    def test_protocol_relative(self):
        """protocol-relative URL"""
        result = normalize_link('https://x.com/', '//cdn.x.com/lib.js')
        assert result == 'https://cdn.x.com/lib.js'

    def test_javascript_scheme_skipped(self):
        """javascript: 协议跳过"""
        assert normalize_link('http://x.com/', 'javascript:void(0)') is None

    def test_mailto_skipped(self):
        """mailto: 协议跳过"""
        assert normalize_link('http://x.com/', 'mailto:a@b.com') is None

    def test_hash_only_skipped(self):
        """纯 fragment 跳过"""
        assert normalize_link('http://x.com/', '#section') is None

    def test_empty_link_skipped(self):
        """空链接跳过"""
        assert normalize_link('http://x.com/', '') is None


class TestIsSameHost:
    """同 host 判断测试"""

    def test_same_host(self):
        assert is_same_host('http://x.com/', 'http://x.com/page') is True

    def test_different_host(self):
        assert is_same_host('http://x.com/', 'http://y.com/page') is False

    def test_different_subdomain(self):
        """不同子域视为不同 host"""
        assert is_same_host('http://x.com/', 'http://www.x.com/') is False


class TestIsStaticResource:
    """静态资源判断测试"""

    def test_image_is_static(self):
        assert is_static_resource('http://x.com/img.png') is True

    def test_css_is_static(self):
        assert is_static_resource('http://x.com/style.css') is True

    def test_js_is_static(self):
        """JS 也被默认排除（爬虫专门处理）"""
        assert is_static_resource('http://x.com/app.js') is True

    def test_html_not_static(self):
        assert is_static_resource('http://x.com/page.html') is False

    def test_api_path_not_static(self):
        assert is_static_resource('http://x.com/api/users') is False


class TestCrawler:
    """BFS 爬虫测试"""

    def test_crawl_single_page_no_links(self):
        """单页无链接 → 返回仅起始 URL"""
        sess = FakeSession({
            'http://x.com/': FakeResp('<html><body>hello</body></html>', 200),
        })
        c = Crawler(max_depth=2, max_pages=10)
        urls = c.crawl('http://x.com/', sess)
        assert urls == ['http://x.com/']

    def test_crawl_follows_links(self):
        """跟随链接抓取"""
        sess = FakeSession({
            'http://x.com/': FakeResp('<a href="/page1">P1</a><a href="/page2">P2</a>', 200),
            'http://x.com/page1': FakeResp('<a href="/page3">P3</a>', 200),
            'http://x.com/page2': FakeResp('page2', 200),
            'http://x.com/page3': FakeResp('page3', 200),
        })
        c = Crawler(max_depth=2, max_pages=10)
        urls = c.crawl('http://x.com/', sess)
        # 起始页 + page1 + page2（depth=2 不到 page3）
        assert 'http://x.com/' in urls
        assert 'http://x.com/page1' in urls
        assert 'http://x.com/page2' in urls
        # page3 在 depth=3，不应被抓取
        assert 'http://x.com/page3' not in urls

    def test_crawl_depth_limit(self):
        """深度限制：max_depth=1 仅抓起始页"""
        sess = FakeSession({
            'http://x.com/': FakeResp('<a href="/page1">P1</a>', 200),
            'http://x.com/page1': FakeResp('page1', 200),
        })
        c = Crawler(max_depth=1, max_pages=10)
        urls = c.crawl('http://x.com/', sess)
        assert urls == ['http://x.com/']

    def test_crawl_max_pages_limit(self):
        """最大页面数限制"""
        sess = FakeSession({
            'http://x.com/': FakeResp('<a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a>', 200),
            'http://x.com/p1': FakeResp('p1', 200),
            'http://x.com/p2': FakeResp('p2', 200),
            'http://x.com/p3': FakeResp('p3', 200),
        })
        c = Crawler(max_depth=3, max_pages=2)
        urls = c.crawl('http://x.com/', sess)
        assert len(urls) <= 2

    def test_crawl_filters_other_host(self):
        """过滤跨 host 链接"""
        sess = FakeSession({
            'http://x.com/': FakeResp('<a href="http://y.com/page">Y</a>', 200),
        })
        c = Crawler(max_depth=2, max_pages=10, same_host_only=True)
        urls = c.crawl('http://x.com/', sess)
        assert urls == ['http://x.com/']

    def test_crawl_filters_static_resources(self):
        """过滤静态资源"""
        sess = FakeSession({
            'http://x.com/': FakeResp(
                '<a href="/img.png">IMG</a><a href="/page">P</a>', 200),
            'http://x.com/page': FakeResp('page', 200),
        })
        c = Crawler(max_depth=2, max_pages=10, include_static=False)
        urls = c.crawl('http://x.com/', sess)
        assert 'http://x.com/page' in urls
        assert 'http://x.com/img.png' not in urls

    def test_crawl_handles_404(self):
        """404 响应不解析链接"""
        sess = FakeSession({
            'http://x.com/': FakeResp('<a href="/p1">P1</a>', 404),
            'http://x.com/p1': FakeResp('p1', 200),
        })
        c = Crawler(max_depth=2, max_pages=10)
        urls = c.crawl('http://x.com/', sess)
        # 404 仍记录 URL，但不抓取子链接
        assert 'http://x.com/' in urls
        assert 'http://x.com/p1' not in urls

    def test_crawl_handles_request_error(self):
        """请求异常不中断爬虫"""
        sess = FakeSession({
            'http://x.com/': FakeResp('<a href="/p1">P1</a>', 200),
        })
        # p1 不在 responses 中 → FakeResp 404
        c = Crawler(max_depth=2, max_pages=10)
        urls = c.crawl('http://x.com/', sess)
        assert 'http://x.com/' in urls

    def test_crawl_no_duplicate_visits(self):
        """同一 URL 不重复访问"""
        sess = FakeSession({
            'http://x.com/': FakeResp('<a href="/">home</a><a href="/p1">P1</a>', 200),
            'http://x.com/p1': FakeResp('<a href="/">home</a>', 200),
        })
        c = Crawler(max_depth=3, max_pages=10)
        urls = c.crawl('http://x.com/', sess)
        # 起始 URL 只出现一次
        assert urls.count('http://x.com/') == 1

    def test_crawl_with_js_urls(self):
        """crawl_with_js_urls 分类返回 HTML 页面和 JS 文件"""
        sess = FakeSession({
            'http://x.com/': FakeResp(
                '<script src="/app.js"></script><a href="/page">P</a>', 200),
            'http://x.com/app.js': FakeResp(
                'var x=1;', 200, {'Content-Type': 'application/javascript'}),
            'http://x.com/page': FakeResp('page', 200),
        })
        c = Crawler(max_depth=2, max_pages=10)
        result = c.crawl_with_js_urls('http://x.com/', sess)
        assert 'http://x.com/' in result['pages']
        assert 'http://x.com/page' in result['pages']
        assert 'http://x.com/app.js' in result['js']
        assert 'http://x.com/app.js' in result['all']

    def test_on_page_callback(self):
        """on_page 回调被调用"""
        callback_calls = []
        sess = FakeSession({
            'http://x.com/': FakeResp('<a href="/p1">P1</a>', 200),
            'http://x.com/p1': FakeResp('p1', 200),
        })

        def on_page(url, html):
            callback_calls.append((url, html))

        c = Crawler(max_depth=2, max_pages=10, on_page=on_page)
        c.crawl('http://x.com/', sess)
        assert len(callback_calls) >= 1
        assert callback_calls[0][0] == 'http://x.com/'


class TestCrawlerHelpers:
    """便捷函数测试"""

    def test_crawl_target_helper(self):
        sess = FakeSession({
            'http://x.com/': FakeResp('<a href="/p1">P1</a>', 200),
            'http://x.com/p1': FakeResp('p1', 200),
        })
        urls = crawl_target('http://x.com/', session=sess, max_depth=2)
        assert 'http://x.com/' in urls
        assert 'http://x.com/p1' in urls

    def test_extract_links_from_html_no_base(self):
        """extract_links_from_html 无 base URL"""
        html = '<a href="/p1">P1</a><a href="/p2">P2</a>'
        links = extract_links_from_html(html)
        assert '/p1' in links
        assert '/p2' in links

    def test_extract_links_from_html_with_base(self):
        """extract_links_from_html 带 base URL → 绝对 URL"""
        html = '<a href="/p1">P1</a>'
        links = extract_links_from_html(html, base_url='http://x.com/')
        assert 'http://x.com/p1' in links


# ============================================================
# 2. lib/subdomain.py 测试
# ============================================================

class TestSubdomainEnumerator:
    """子域名枚举器测试"""

    def test_clean_domain(self):
        """域名清理"""
        enum = SubdomainEnumerator(use_crtsh=False, use_dictionary=False)
        assert enum._clean_domain('http://example.com/path') == 'example.com'
        assert enum._clean_domain('https://example.com:8080/x') == 'example.com'
        assert enum._clean_domain('example.com/') == 'example.com'
        assert enum._clean_domain('EXAMPLE.COM') == 'example.com'
        assert enum._clean_domain('') == ''

    def test_dictionary_enumeration(self):
        """字典枚举：加入 word.example.com"""
        enum = SubdomainEnumerator(
            use_crtsh=False, use_dictionary=True,
            word_list=['www', 'api', 'dev'], verify_dns=False,
        )
        subs = enum.enumerate('example.com')
        assert 'example.com' in subs  # 主域
        assert 'www.example.com' in subs
        assert 'api.example.com' in subs
        assert 'dev.example.com' in subs

    def test_default_word_list_size(self):
        """默认字典至少 50 个"""
        words = get_default_word_list()
        assert len(words) >= 50
        assert 'www' in words
        assert 'api' in words
        assert 'admin' in words

    def test_crtsh_enumeration_mocked(self):
        """crt.sh 枚举（mock 响应）"""
        # crt.sh 返回 JSON 数组
        mock_crtsh_response = [
            {'name_value': 'example.com'},
            {'name_value': 'www.example.com'},
            {'name_value': 'api.example.com\ndev.example.com'},  # 多行
            {'name_value': '*.example.com'},  # 通配符跳过
            {'name_value': 'other.com'},  # 非同主域跳过
        ]
        sess = FakeSession({
            'https://crt.sh/?q=%25.example.com&output=json': FakeResp(
                json.dumps(mock_crtsh_response), 200,
                {'Content-Type': 'application/json'}),
        })
        enum = SubdomainEnumerator(
            use_crtsh=True, use_dictionary=False, verify_dns=False,
        )
        subs = enum.enumerate('example.com', session=sess)
        assert 'example.com' in subs
        assert 'www.example.com' in subs
        assert 'api.example.com' in subs
        assert 'dev.example.com' in subs
        # 通配符和其他主域被过滤
        assert '*.example.com' not in subs
        assert 'other.com' not in subs

    def test_crtsh_http_error_no_crash(self):
        """crt.sh 返回错误不崩溃"""
        sess = FakeSession({
            'https://crt.sh/?q=%25.example.com&output=json': FakeResp('', 500),
        })
        enum = SubdomainEnumerator(
            use_crtsh=True, use_dictionary=False, verify_dns=False,
        )
        subs = enum.enumerate('example.com', session=sess)
        # 主域仍应被加入
        assert 'example.com' in subs
        # 错误被记录
        assert len(enum.errors) > 0

    def test_crtsh_invalid_json_no_crash(self):
        """crt.sh 返回非 JSON 不崩溃"""
        sess = FakeSession({
            'https://crt.sh/?q=%25.example.com&output=json': FakeResp(
                'not json', 200, {'Content-Type': 'text/html'}),
        })
        enum = SubdomainEnumerator(
            use_crtsh=True, use_dictionary=False, verify_dns=False,
        )
        subs = enum.enumerate('example.com', session=sess)
        assert 'example.com' in subs

    def test_dns_verify_with_mock(self):
        """DNS 验证（mock socket）"""
        enum = SubdomainEnumerator(
            use_crtsh=False, use_dictionary=True,
            word_list=['www'], verify_dns=True,
        )
        with patch('socket.gethostbyname') as mock_dns:
            mock_dns.return_value = '1.2.3.4'
            subs = enum.enumerate('example.com')
            assert 'www.example.com' in subs

    def test_dns_verify_fails_silently(self):
        """DNS 验证失败不崩溃"""
        enum = SubdomainEnumerator(
            use_crtsh=False, use_dictionary=True,
            word_list=['nonexistent'], verify_dns=True,
        )
        with patch('socket.gethostbyname', side_effect=socket_error()):
            subs = enum.enumerate('example.com')
            # www 不存在 → DNS 失败 → 不加入
            assert 'nonexistent.example.com' not in subs

    def test_on_found_callback(self):
        """on_found 回调被调用"""
        found = []
        enum = SubdomainEnumerator(
            use_crtsh=False, use_dictionary=True,
            word_list=['www'], verify_dns=False,
            on_found=lambda s: found.append(s),
        )
        enum.enumerate('example.com')
        assert 'www.example.com' in found

    def test_sources_recorded(self):
        """来源被记录"""
        enum = SubdomainEnumerator(
            use_crtsh=False, use_dictionary=True,
            word_list=['www'], verify_dns=False,
        )
        enum.enumerate('example.com')
        assert 'www.example.com' in enum.sources
        assert 'dict' in enum.sources['www.example.com']

    def test_enumerate_subdomains_helper(self):
        """便捷函数（禁用 crt.sh 避免真实网络请求）"""
        subs = enumerate_subdomains(
            'example.com', verify_dns=False, use_crtsh=False,
        )
        # 默认字典至少 50 个 + 主域
        assert len(subs) >= 50
        assert 'example.com' in subs


def socket_error():
    """生成 socket 异常"""
    import socket
    return socket.gaierror(1, 'not found')


# ============================================================
# 3. lib/js_extractor.py 测试
# ============================================================

class TestJSExtractor:
    """JS 端点提取器测试"""

    def test_extract_relative_paths(self):
        """提取相对路径 /api/..."""
        js = '''
        var url1 = "/api/user/list";
        var url2 = '/admin/system/config';
        var url3 = `/prod-api/login`;
        '''
        ext = JSExtractor()
        endpoints = ext.extract_from_text(js, source_url='http://x.com/app.js')
        urls = [ep.url for ep in endpoints]
        assert '/api/user/list' in urls
        assert '/admin/system/config' in urls
        assert '/prod-api/login' in urls

    def test_extract_absolute_urls(self):
        """提取绝对 URL"""
        js = '''
        var api = "https://api.example.com/v1/users";
        var cdn = 'http://cdn.example.com/static';
        '''
        ext = JSExtractor()
        endpoints = ext.extract_from_text(js, source_url='http://x.com/app.js')
        urls = [ep.url for ep in endpoints]
        assert 'https://api.example.com/v1/users' in urls
        assert 'http://cdn.example.com/static' in urls

    def test_extract_fetch_calls(self):
        """提取 fetch() 调用"""
        js = '''
        fetch("/api/data").then(r => r.json());
        axios.post("/api/login", {user: 1});
        axios.get('/api/user/info');
        $.ajax({url: "/api/save"});
        '''
        ext = JSExtractor()
        endpoints = ext.extract_from_text(js, source_url='http://x.com/app.js')
        urls = [ep.url for ep in endpoints]
        assert '/api/data' in urls
        assert '/api/login' in urls
        assert '/api/user/info' in urls
        assert '/api/save' in urls

    def test_method_identification(self):
        """识别 HTTP 方法"""
        js = '''
        axios.post("/api/login", {});
        axios.get("/api/user");
        axios.delete("/api/user/1");
        '''
        ext = JSExtractor()
        endpoints = ext.extract_from_text(js, source_url='http://x.com/app.js')
        # 找到 POST /api/login
        post_eps = [ep for ep in endpoints if ep.url == '/api/login']
        assert len(post_eps) >= 1
        # 方法被记录到 contexts
        methods = [c for c in post_eps[0].contexts if c.startswith('fetch:')]
        assert any('POST' in m for m in methods)

    def test_noise_filtering(self):
        """噪声过滤：node_modules、webpack 等跳过"""
        js = '''
        var x = "/node_modules/react/index";
        var y = "/webpack/bundle";
        var z = "/api/real";
        '''
        ext = JSExtractor()
        endpoints = ext.extract_from_text(js, source_url='http://x.com/app.js')
        urls = [ep.url for ep in endpoints]
        assert '/api/real' in urls
        assert '/node_modules/react/index' not in urls
        assert '/webpack/bundle' not in urls

    def test_include_noise_option(self):
        """include_noise=True 保留噪声"""
        js = 'var x = "/node_modules/react/index";'
        ext = JSExtractor(include_noise=True)
        endpoints = ext.extract_from_text(js, source_url='http://x.com/app.js')
        urls = [ep.url for ep in endpoints]
        # 包含 node_modules 路径
        assert any('node_modules' in u for u in urls)

    def test_min_path_segments(self):
        """最小路径段数过滤"""
        js = '''
        var a = "/x";          # 1 段，应被过滤
        var b = "/api/x";      # 2 段，保留
        var c = "/a/b/c";      # 3 段，保留
        '''
        ext = JSExtractor(min_path_segments=2)
        endpoints = ext.extract_from_text(js, source_url='http://x.com/app.js')
        urls = [ep.url for ep in endpoints]
        # /x 是 1 段，应被过滤
        path_eps = [u for u in urls if u.startswith('/') and not u.startswith('http')]
        assert '/x' not in path_eps
        assert '/api/x' in path_eps

    def test_filter_by_host(self):
        """按 host 过滤"""
        endpoints = [
            Endpoint(url='https://x.com/api', source='', is_absolute=True),
            Endpoint(url='https://y.com/api', source='', is_absolute=True),
            Endpoint(url='/api/local', source='', is_absolute=False),
        ]
        ext = JSExtractor()
        filtered = ext.filter_by_host(endpoints, host='x.com')
        urls = [ep.url for ep in filtered]
        assert 'https://x.com/api' in urls
        assert 'https://y.com/api' not in urls  # 跨 host 被过滤
        assert '/api/local' in urls  # 相对路径保留

    def test_extract_from_urls_with_session(self):
        """extract_from_urls 通过 session 抓取 JS"""
        js1 = 'var a = "/api/from_js1";'
        js2 = 'var b = "/api/from_js2";'
        sess = FakeSession({
            'http://x.com/a.js': FakeResp(js1, 200, {'Content-Type': 'application/javascript'}),
            'http://x.com/b.js': FakeResp(js2, 200, {'Content-Type': 'application/javascript'}),
        })
        ext = JSExtractor()
        endpoints = ext.extract_from_urls(
            ['http://x.com/a.js', 'http://x.com/b.js'], session=sess)
        urls = [ep.url for ep in endpoints]
        assert '/api/from_js1' in urls
        assert '/api/from_js2' in urls

    def test_extract_from_urls_handles_404(self):
        """404 JS 文件跳过"""
        sess = FakeSession({
            'http://x.com/ok.js': FakeResp('var a="/api/x";', 200,
                                            {'Content-Type': 'application/javascript'}),
        })
        # missing.js 不在 responses → 404
        ext = JSExtractor()
        endpoints = ext.extract_from_urls(
            ['http://x.com/ok.js', 'http://x.com/missing.js'], session=sess)
        urls = [ep.url for ep in endpoints]
        assert '/api/x' in urls  # 来自 ok.js

    def test_extract_empty_text(self):
        """空 JS 文本返回空列表"""
        ext = JSExtractor()
        assert ext.extract_from_text('') == []
        assert ext.extract_from_text(None) == []

    def test_extract_no_endpoints(self):
        """无端点的 JS 返回空列表"""
        js = 'var x = 1; function f() { return 2; }'
        ext = JSExtractor()
        assert ext.extract_from_text(js) == []

    def test_endpoint_dataclass(self):
        """Endpoint 数据类"""
        ep = Endpoint(url='/api/x', source='http://x.com/app.js',
                      method='GET', line_no=10, is_absolute=False)
        assert ep.url == '/api/x'
        assert ep.source == 'http://x.com/app.js'
        assert ep.method == 'GET'
        assert ep.line_no == 10
        assert ep.is_absolute is False

    def test_endpoint_dedup(self):
        """同 URL + source 去重"""
        js = '''
        var a = "/api/dup";
        var b = "/api/dup";
        var c = "/api/dup";
        '''
        ext = JSExtractor()
        endpoints = ext.extract_from_text(js, source_url='http://x.com/app.js')
        # /api/dup 只出现一次
        dup_eps = [ep for ep in endpoints if ep.url == '/api/dup']
        assert len(dup_eps) == 1

    def test_extract_endpoints_helper(self):
        """extract_endpoints 便捷函数"""
        js = 'var a = "/api/x"; fetch("/api/y");'
        urls = extract_endpoints(js)
        assert '/api/x' in urls
        assert '/api/y' in urls


# ============================================================
# 4. orchestrator 集成测试
# ============================================================

class TestOrchestratorD14Integration:
    """D14 ScanRequest 字段 + _run_recon 集成测试"""

    def test_scan_request_d14_fields_default(self):
        """ScanRequest D14 字段默认值"""
        from core.orchestrator import ScanRequest
        req = ScanRequest(target='http://x.com/')
        assert req.crawl is False
        assert req.crawl_depth == 2
        assert req.crawl_max_pages == 50
        assert req.subdomain is False
        assert req.js_extract is False

    def test_scan_request_d14_fields_set(self):
        """ScanRequest D14 字段可设置"""
        from core.orchestrator import ScanRequest
        req = ScanRequest(
            target='http://x.com/',
            crawl=True,
            crawl_depth=3,
            crawl_max_pages=100,
            subdomain=True,
            js_extract=True,
        )
        assert req.crawl is True
        assert req.crawl_depth == 3
        assert req.crawl_max_pages == 100
        assert req.subdomain is True
        assert req.js_extract is True

    def test_run_recon_no_flags(self):
        """_run_recon 在所有 flag 关闭时返回空结果"""
        from core.orchestrator import ScanOrchestrator, ScanRequest
        orch = ScanOrchestrator()
        req = ScanRequest(target='http://x.com/')
        result = orch._run_recon(req, 'http://x.com/', lambda *a: None, 'test-task')
        assert result == {
            'crawled_urls': [],
            'subdomains': [],
            'js_endpoints': [],
        }

    def test_run_recon_subdomain_only(self):
        """_run_recon 仅 subdomain 时返回子域"""
        from core.orchestrator import ScanOrchestrator, ScanRequest
        orch = ScanOrchestrator()
        req = ScanRequest(
            target='http://example.com/',
            subdomain=True,
            crawl=False,
            js_extract=False,
        )
        # mock SubdomainEnumerator.enumerate
        with patch('lib.subdomain.SubdomainEnumerator.enumerate',
                   return_value=['example.com', 'www.example.com']):
            result = orch._run_recon(req, 'http://example.com/',
                                     lambda *a: None, 'test-task')
        assert 'example.com' in result['subdomains']
        assert 'www.example.com' in result['subdomains']
        assert result['crawled_urls'] == []
        assert result['js_endpoints'] == []

    def test_run_recon_crawl_only(self):
        """_run_recon 仅 crawl 时返回抓取 URL"""
        from core.orchestrator import ScanOrchestrator, ScanRequest
        orch = ScanOrchestrator()
        req = ScanRequest(
            target='http://x.com/',
            crawl=True,
            crawl_depth=2,
            crawl_max_pages=10,
            js_extract=False,
        )
        # mock Crawler.crawl_with_js_urls
        mock_result = {
            'pages': ['http://x.com/', 'http://x.com/p1'],
            'js': [],
            'all': ['http://x.com/', 'http://x.com/p1'],
        }
        with patch('lib.crawler.Crawler.crawl_with_js_urls',
                   return_value=mock_result):
            result = orch._run_recon(req, 'http://x.com/',
                                     lambda *a: None, 'test-task')
        assert 'http://x.com/' in result['crawled_urls']
        assert 'http://x.com/p1' in result['crawled_urls']
        assert result['subdomains'] == []
        assert result['js_endpoints'] == []

    def test_run_recon_crawl_and_js_extract(self):
        """_run_recon crawl + js_extract 同时启用"""
        from core.orchestrator import ScanOrchestrator, ScanRequest
        orch = ScanOrchestrator()
        req = ScanRequest(
            target='http://x.com/',
            crawl=True,
            js_extract=True,
        )
        mock_crawl = {
            'pages': ['http://x.com/'],
            'js': ['http://x.com/app.js'],
            'all': ['http://x.com/', 'http://x.com/app.js'],
        }
        mock_endpoints = [
            Endpoint(url='/api/from_js', source='http://x.com/app.js'),
            Endpoint(url='https://x.com/abs', source='http://x.com/app.js',
                     is_absolute=True),
        ]
        with patch('lib.crawler.Crawler.crawl_with_js_urls',
                   return_value=mock_crawl), \
             patch('lib.js_extractor.JSExtractor.extract_from_urls',
                   return_value=mock_endpoints):
            result = orch._run_recon(req, 'http://x.com/',
                                     lambda *a: None, 'test-task')
        assert '/api/from_js' in result['js_endpoints']
        assert 'https://x.com/abs' in result['js_endpoints']


# ============================================================
# 5. CLI 参数测试（main.py）
# ============================================================

class TestD14CLIArgs:
    """D14 CLI 参数解析测试"""

    def test_d14_args_default(self):
        """D14 参数默认值"""
        import main
        parser = main.build_parser()
        args = parser.parse_args(['-u', 'http://x.com/'])
        assert args.crawl is False
        assert args.crawl_depth == 2
        assert args.crawl_max_pages == 50
        assert args.subdomain is False
        assert args.js_extract is False

    def test_d14_crawl_flag(self):
        """--crawl 启用爬虫"""
        import main
        parser = main.build_parser()
        args = parser.parse_args(['-u', 'http://x.com/', '--crawl'])
        assert args.crawl is True

    def test_d14_crawl_depth(self):
        """--crawl-depth 设置深度"""
        import main
        parser = main.build_parser()
        args = parser.parse_args(['-u', 'http://x.com/', '--crawl', '--crawl-depth', '3'])
        assert args.crawl_depth == 3

    def test_d14_crawl_max_pages(self):
        """--crawl-max-pages 设置最大页面数"""
        import main
        parser = main.build_parser()
        args = parser.parse_args(['-u', 'http://x.com/', '--crawl', '--crawl-max-pages', '100'])
        assert args.crawl_max_pages == 100

    def test_d14_subdomain_flag(self):
        """--subdomain 启用子域名枚举"""
        import main
        parser = main.build_parser()
        args = parser.parse_args(['-u', 'http://x.com/', '--subdomain'])
        assert args.subdomain is True

    def test_d14_js_extract_flag(self):
        """--js-extract 启用 JS 端点提取"""
        import main
        parser = main.build_parser()
        args = parser.parse_args(['-u', 'http://x.com/', '--js-extract'])
        assert args.js_extract is True

    def test_d14_all_flags_together(self):
        """所有 D14 标志同时启用"""
        import main
        parser = main.build_parser()
        args = parser.parse_args([
            '-u', 'http://x.com/',
            '--crawl', '--crawl-depth', '3', '--crawl-max-pages', '20',
            '--subdomain', '--js-extract',
        ])
        assert args.crawl is True
        assert args.crawl_depth == 3
        assert args.crawl_max_pages == 20
        assert args.subdomain is True
        assert args.js_extract is True


# ============================================================
# 端到端：JS 提取典型场景
# ============================================================

class TestJSExtractRealWorld:
    """模拟真实 JS 文件的端到端测试"""

    def test_ruoyi_js_extract(self):
        """模拟若依管理系统前端 JS 提取"""
        # 模拟若依登录页 JS
        js = '''
        var RuoyiConfig = {
            baseUrl: "/prod-api",
            captchaUrl: "/captcha/image"
        };

        function login() {
            axios.post("/login", {username: "admin", password: "123"});
        }

        function getUserInfo() {
            fetch("/getInfo").then(r => r.json());
        }

        function listUsers() {
            axios.get("/system/user/list");
        }

        // 第三方库（应被过滤）
        var jquery = "/node_modules/jquery/dist/jquery.js";
        var lodash = "/webpack/lodash.js";
        '''
        ext = JSExtractor()
        endpoints = ext.extract_from_text(js, source_url='http://x.com/ruoyi.js')
        urls = [ep.url for ep in endpoints]

        # 应提取到若依典型 API 端点
        assert '/login' in urls
        assert '/getInfo' in urls
        assert '/system/user/list' in urls
        assert '/captcha/image' in urls
        # 第三方库被过滤
        assert all('node_modules' not in u for u in urls)
        assert all('webpack' not in u for u in urls)


if __name__ == '__main__':
    # 直接运行模式
    import pytest
    sys.exit(pytest.main([__file__, '-v']))
