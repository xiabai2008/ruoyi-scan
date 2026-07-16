# HTTP 工具：URL 归一化等


def normalize_target(url):
    """目标归一化：确保以 / 结尾（对齐原 self.url += '/' 逻辑）"""
    if not url:
        return url
    if not url.endswith('/'):
        url = url + '/'
    return url


def join_url(base, path):
    """拼接 URL，处理双斜杠（对齐原 path_scan 归一化逻辑）

    原逻辑：if self.url[-1] == '/' and path[0] == '/': path = path[1:]
    """
    if base.endswith('/') and path.startswith('/'):
        return base + path[1:]
    return base + path


def host_of(url):
    """提取 host（去掉协议前缀），用于原脚本 headers 的 Host 字段"""
    if '://' in url:
        return url.split('://', 1)[1]
    return url
