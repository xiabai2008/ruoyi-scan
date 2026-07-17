# 会话封装：Cookie / 代理 / 重试 / keep-alive
import sys

import requests

from config import settings


class SessionManager:
    """requests.Session 封装，统一 UA / 代理 / 超时 / keep-alive"""

    def __init__(self, proxy=None, timeout=None, ua=None, debug=False):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': ua or settings.DEFAULT_UA
        })
        self.proxy = proxy if proxy is not None else settings.PROXY
        self.timeout = timeout or settings.TIMEOUT
        if self.proxy:
            self.session.proxies.update({'http': self.proxy, 'https': self.proxy})
        # keep-alive 复用连接
        self.session.keep_alive = True
        # 请求计数（报告摘要用）
        self.request_count = 0
        # 调试模式：打印每个请求的方法/URL/状态/响应大小到 stderr（不影响正常输出）
        self.debug = bool(debug)

    def _log_debug(self, method, url, resp):
        """调试日志：方法 URL 状态码 响应字节，输出到 stderr"""
        if not self.debug:
            return
        try:
            code = resp.status_code
            size = len(resp.content or b'')
        except Exception:
            code = '?'
            size = '?'
        print(f'[debug] {method} {url} -> {code} ({size} bytes)', file=sys.stderr)

    def get(self, url, headers=None, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        self.request_count += 1
        resp = self.session.get(url, headers=headers, **kwargs)
        self._log_debug('GET', url, resp)
        return resp

    def post(self, url, headers=None, data=None, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        self.request_count += 1
        resp = self.session.post(url, headers=headers, data=data, **kwargs)
        self._log_debug('POST', url, resp)
        return resp

    def close(self):
        self.session.close()
