# Redis 未授权访问检测（F7 中间件包）
# 非破坏性：socket 连接目标 6379 端口发送 INFO 命令，响应含 redis_version 即未授权
import socket

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from plugins.base import PluginBase


class RedisUnauthPlugin(PluginBase):
    name = "Redis 未授权访问"
    cve = "CVE-2021-32761"
    severity = "high"
    category = "vuln"
    description = "Redis 服务未设置认证（requirepass 为空），任意连接可执行 INFO/CONFIG 等命令"
    fix = "为 Redis 设置 requirepass；bind 仅内网；禁用 CONFIG 命令"
    fix_detail = (
        "【配置加固】redis.conf 设置 requirepass 强密码：\n"
        "  requirepass <强随机密码>\n"
        "【网络加固】bind 127.0.0.1 或内网网段；云安全组不放通 6379 公网\n"
        "【代码修复】使用 redis 客户端时启用 AUTH 认证\n"
        "【WAF 规则】网络层拦截 6379 公网入站流量\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4"
    )
    reproduce = (
        "python -c \"import socket;s=socket.create_connection(('target',6379),timeout=5);"
        "s.sendall(b'INFO\\r\\n');print(s.recv(2048).decode(errors='ignore'))\"\n"
        "# 预期响应：输出含 redis_version 字段（无需认证即未授权）\n"
        "\n"
        "# 或使用 redis-cli：\n"
        "# redis-cli -h target -p 6379 info"
    )
    affected_versions = ""
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.4;OWASP:A05:2021"
    vuln_type = "unauth"
    supports_waf_bypass = False

    def verify(self, target, session):
        from urllib.parse import urlparse

        # 从目标 URL 提取 host（Redis 走独立端口，默认 6379）
        parsed = urlparse(target)
        host = parsed.hostname or ""
        if not host:
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=target, evidence="无法解析目标主机"
            )
        port = 6379
        url = "%s:%d" % (host, port)
        try:
            sock = socket.create_connection((host, port), timeout=5)
            try:
                sock.sendall(b"INFO\r\n")
                sock.settimeout(5)
                data = b""
                try:
                    while len(data) < 2048:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                except socket.timeout:
                    pass
            finally:
                sock.close()
        except Exception as e:
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence="连接失败: %s" % e)
        text = data.decode("utf-8", errors="ignore")
        # 未授权判定：INFO 返回 redis 版本信息（有 auth 时返回 -NOAUTH）
        if "redis_version" in text and "-NOAUTH" not in text and "DENIED" not in text:
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="无认证执行 INFO（响应含 redis_version）",
                fix=self.fix,
                extra={"vuln_type": "unauth", "plugin_name": "redis_unauth"},
            )
        if "-NOAUTH" in text or "DENIED" in text:
            return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence="Redis 已启用认证")
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url, evidence="非 Redis 服务或无未授权")
