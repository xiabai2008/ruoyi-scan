# HTTP 工具：URL 归一化等


def normalize_target(url):
    """目标归一化：确保以 / 结尾（对齐原 self.url += '/' 逻辑）"""
    if not url:
        return url
    if not url.endswith("/"):
        url = url + "/"
    return url


def join_url(base, path):
    """拼接 URL，处理双斜杠（对齐原 path_scan 归一化逻辑）

    原逻辑：if self.url[-1] == '/' and path[0] == '/': path = path[1:]
    """
    if base.endswith("/") and path.startswith("/"):
        return base + path[1:]
    return base + path


def host_of(url):
    """提取 host:port（去掉协议与路径），用于原脚本 headers 的 Host 字段

    注意：必须只返回 netloc，不能带路径（如尾斜杠），否则 Host/Origin/Referer
    头会变成 '127.0.0.1:8080/' 这类非法值，Tomcat 直接返回 400 Bad Request，
    导致依赖这些头的 POST 型插件（如 SQL 报错注入）误判 SAFE。
    """
    if "://" in url:
        rest = url.split("://", 1)[1]
    else:
        rest = url
    # 去掉路径部分，只保留 host[:port]
    return rest.split("/", 1)[0]
