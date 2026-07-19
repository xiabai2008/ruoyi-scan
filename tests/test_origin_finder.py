# D7.1 源站 IP 探测单元测试
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.origin_finder import OriginIPFinder


class MockResponse:
    def __init__(self, headers=None, text=''):
        self.headers = headers or {}
        self.text = text


class MockSession:
    def __init__(self, headers=None, text=''):
        self._headers = headers or {}
        self._text = text

    def get(self, url, **kwargs):
        return MockResponse(headers=self._headers, text=self._text)

    def close(self):
        pass


def test_is_cdn_ip_cloudflare():
    """Cloudflare IP 识别"""
    finder = OriginIPFinder()
    assert finder._is_cdn_ip('104.16.1.1') is True
    assert finder._is_cdn_ip('172.64.1.1') is True

def test_is_cdn_ip_aliyun():
    """阿里云 CDN IP 识别"""
    finder = OriginIPFinder()
    assert finder._is_cdn_ip('47.246.1.1') is True

def test_is_cdn_ip_non_cdn():
    """非 CDN IP 识别"""
    finder = OriginIPFinder()
    assert finder._is_cdn_ip('192.168.1.1') is False
    assert finder._is_cdn_ip('10.0.0.1') is False

def test_build_origin_url_http():
    """构建源站直连 URL（HTTP）"""
    finder = OriginIPFinder()
    result = finder.build_origin_url('http://example.com/path?q=1', '1.2.3.4')
    assert '1.2.3.4' in result
    assert '/path' in result
    assert 'q=1' in result

def test_build_origin_url_https():
    """构建源站直连 URL（HTTPS，保留端口）"""
    finder = OriginIPFinder()
    result = finder.build_origin_url('https://example.com:8443/path', '1.2.3.4')
    assert '1.2.3.4' in result
    assert '8443' in result

def test_check_response_headers_leak():
    """响应头泄漏源站 IP"""
    finder = OriginIPFinder()
    session = MockSession(headers={'X-Originating-IP': '10.0.0.5'})
    ips = finder._check_response_headers('example.com', session)
    assert '10.0.0.5' in ips

def test_check_response_headers_no_leak():
    """无泄漏头返回空"""
    finder = OriginIPFinder()
    session = MockSession(headers={})
    ips = finder._check_response_headers('example.com', session)
    assert ips == []

def test_find_origin_ip_returns_list():
    """find_origin_ip 返回列表"""
    finder = OriginIPFinder()
    # mock 所有探测方法返回空
    with patch.object(finder, '_check_response_headers', return_value=[]), \
         patch.object(finder, '_check_subdomains', return_value=[]), \
         patch.object(finder, '_check_ssl_san', return_value=[]), \
         patch('socket.gethostbyname', side_effect=Exception('mock')):
        ips = finder.find_origin_ip('example.com', session=None)
    assert isinstance(ips, list)

def test_find_origin_ip_with_header_leak():
    """响应头泄漏 + 子域名解析综合"""
    finder = OriginIPFinder()
    session = MockSession(headers={'X-Real-IP': '192.168.1.100'})
    # mock 子域名和 SSL 探测返回空，避免网络调用
    with patch.object(finder, '_check_subdomains', return_value=[]), \
         patch.object(finder, '_check_ssl_san', return_value=[]), \
         patch('socket.gethostbyname', side_effect=Exception('mock')):
        ips = finder.find_origin_ip('example.com', session=session)
    assert '192.168.1.100' in ips


if __name__ == '__main__':
    test_is_cdn_ip_cloudflare()
    test_is_cdn_ip_aliyun()
    test_is_cdn_ip_non_cdn()
    test_build_origin_url_http()
    test_build_origin_url_https()
    test_check_response_headers_leak()
    test_check_response_headers_no_leak()
    test_find_origin_ip_returns_list()
    test_find_origin_ip_with_header_leak()
    print('All D7.1 origin finder tests passed!')
