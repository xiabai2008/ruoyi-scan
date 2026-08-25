# 指纹识别请求级缓存（阶段五）：同一 URL 的 GET 结果在单次 detect_cms 中只发一次
# 用于多 CMS 遍历时共享根响应与 favicon 响应，避免重复请求


class FingerprintCache:
    """请求级缓存：缓存 session.get(url) 结果，避免重复请求

    用于 detect_cms 遍历多 CMS 时共享根路径/favicon 响应。
    异常时缓存 None，调用方需容忍 resp 为 None（detect 内部已有 try/except 保护）。
    """

    def __init__(self, session):
        """初始化请求级缓存（绑定会话对象）

        Args:
            session: 用于发起请求的 SessionManager 实例
        """
        self._cache = {}
        self._session = session

    def get(self, url):
        """返回缓存响应或发起请求并缓存结果（异常缓存 None）

        命中缓存时不调用 session.get，因此 request_count 不会增加，
        可用 --debug 观察请求数减少以验证缓存生效。
        """
        if url not in self._cache:
            try:
                self._cache[url] = self._session.get(url)
            except Exception:
                # 网络异常等缓存 None，调用方 detect() 的 try/except 会跳过
                self._cache[url] = None
        return self._cache[url]

    def __len__(self):
        """已缓存 URL 数量"""
        return len(self._cache)

    def keys(self):
        """已缓存的 URL 列表（调试/测试用）"""
        return list(self._cache.keys())
