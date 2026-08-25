# .env 配置文件泄露 — GET /.env 检测数据库/密钥关键字
from common.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase


class EnvLeakPlugin(PluginBase):
    """检测目标是否存在 .env 配置文件泄露（数据库密码 / APP_KEY 等敏感信息暴露）"""

    name = ".env 配置文件泄露"
    cve = "N/A"
    severity = SEVERITY_HIGH
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    description = "目标 Web 根目录下存在可访问的 .env 文件，其中包含数据库凭据、应用密钥等敏感信息"
    fix = "在 Web 服务器配置中禁止对 .env 等配置文件的外网访问，添加规则阻止下载隐藏文件"
    fix_detail = (
        "【配置加固·nginx】禁止所有隐藏文件访问（含 .env/.config）：\n"
        "  location ~ /\\. { deny all; return 404; }\n"
        "  location ~ /\\.env { deny all; return 404; }\n"
        '【配置加固·Apache】<FilesMatch "^\\."> Require all denied </FilesMatch>\n'
        '  或 <Files ".env"> Require all denied </Files>\n'
        "【配置加固·IIS】web.config 添加 requestFiltering hiddenSegments：\n"
        '  <add segment=".env" />\n'
        "【代码修复】配置通过环境变量 / Secrets Manager / Vault 注入，.env 文件不入版本仓库：\n"
        '  echo ".env" >> .gitignore\n'
        "  生产使用 docker run --env-file /run/secrets/.env（仅容器内可读）\n"
        "【WAF 规则】拦截 /.env、/.config、/.env.bak、/.env.local、/config.php 等敏感配置路径\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测 .env 主文件：\n"
        'curl -i "http://target/.env"\n'
        "\n"
        "# 预期响应（漏洞存在）：HTTP/1.1 200，响应体含键值对：\n"
        "#   DB_HOST=127.0.0.1\n"
        "#   DB_PASSWORD=P@ssw0rd\n"
        "#   APP_KEY=base64:xxxxxxxxxxxx\n"
        "#   REDIS_PASSWORD=xxxxxx\n"
        "#   MAIL_PASSWORD=xxxxxx\n"
        "\n"
        "# 2. 探测 .env 变体与备份：\n"
        'curl -i "http://target/.env.bak"\n'
        'curl -i "http://target/.env.local"\n'
        'curl -i "http://target/.env.production"\n'
        'curl -i "http://target/.env.example"\n'
        "\n"
        "# 3. 探测其他常见配置文件：\n"
        'curl -i "http://target/config.php"\n'
        'curl -i "http://target/config/database.yml"\n'
        'curl -i "http://target/application.properties"\n'
        "\n"
        "# 4. 利用 APP_KEY 反序列化 RCE（Laravel < 8.4.2，需 key 泄露）：\n"
        'php artisan tinker --execute="..." # 结合 CVE-2021-3129 利用链'
    )

    # 正向关键字：典型 .env 文件中的键名
    _ENV_KEYWORDS = [
        "DB_HOST",
        "DB_DATABASE",
        "DB_USERNAME",
        "DB_PASSWORD",
        "APP_KEY",
        "APP_SECRET",
        "REDIS_PASSWORD",
        "MAIL_PASSWORD",
    ]

    def verify(self, target, session) -> ScanResult:
        """检测 /.env 是否可访问且泄露环境变量键名（数据库/密钥关键字）

        @param target: 目标站点 URL
        @param session: 已配置的 HTTP 会话
        @return: STATUS_CONFIRMED（命中关键字）或 STATUS_SAFE
        @exception: 请求异常返回 STATUS_UNKNOWN
        """
        url = join_url(target, "/.env")
        try:
            resp = session.get(url)
            text = resp.text or ""
            # 非 200 直接判 SAFE：.env 若可访问必然以明文 200 返回
            if resp.status_code != 200:
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_SAFE,
                    url=url,
                    evidence=f"状态码={resp.status_code}",
                )
            # 检查是否包含典型环境变量关键字
            hits = [kw for kw in self._ENV_KEYWORDS if kw in text]
            if hits:
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=f"状态码=200, 命中关键字: {', '.join(hits[:3])}",
                    fix=self.fix,
                )
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=url,
                # 仅 200 不足为证：SPA/框架可能对未知路径回退空 200，须命中键名风格关键字才坐实泄露
                evidence="状态码=200 但未命中环境变量关键字",
            )
        # 网络异常置 UNKNOWN，避免把目标不可达误判为安全
        except Exception as e:
            return ScanResult(kind="error", name=self.name, status=STATUS_UNKNOWN, evidence=f"请求异常: {e}")
