# 会话封装：Cookie / 代理 / 重试 / keep-alive
import requests

from config import settings


class SessionManager:
    """requests.Session 封装，统一 UA / 代理 / 超时 / keep-alive"""

    def __init__(self, proxy=None, timeout=None, ua=None):
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

    def get(self, url, headers=None, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        return self.session.get(url, headers=headers, **kwargs)

    def post(self, url, headers=None, data=None, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        return self.session.post(url, headers=headers, data=data, **kwargs)

    def close(self):
        self.session.close()
