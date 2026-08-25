# 目录遍历探测 — 探测常见路径是否开启目录列表
from common.models import SEVERITY_LOW, STATUS_CONFIRMED, STATUS_SAFE, ScanResult
from core.http import join_url
from plugins.base import PluginBase


class DirListingPlugin(PluginBase):
    """检测目标 Web 服务器是否开启了目录列表功能（Directory Listing）"""

    name = "目录遍历探测"
    cve = "N/A"
    severity = SEVERITY_LOW
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "recon"
    description = "目标服务器开启了目录列表功能，攻击者可浏览目录结构发现隐藏文件和敏感路径"
    fix = "在 Web 服务器配置中关闭目录列表功能（nginx: autoindex off; apache: Options -Indexes）"
    fix_detail = (
        "【配置加固·nginx】确保未在 location 块显式开启 autoindex，必要时显式关闭：\n"
        "  location /uploads/ { autoindex off; }\n"
        "  location /backup/  { autoindex off; deny all; }\n"
        "【配置加固·Apache】httpd.conf 或 .htaccess 添加：Options -Indexes\n"
        '  <Directory "/var/www/html"> Options -Indexes </Directory>\n'
        "【配置加固·Tomcat】conf/web.xml 中 DefaultServlet 的 listings 参数设为 false：\n"
        "  <param-name>listings</param-name><param-value>false</param-value>\n"
        "【部署清理】仅上传必要静态资源，敏感目录（backup/logs/tmp）禁止放到 Web 根目录\n"
        '【WAF 规则】拦截响应体含 "Index of"、"Directory Listing"、"Parent Directory" 的 200 响应\n'
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测常见静态资源目录是否开启目录列表：\n"
        'curl -i "http://target/uploads/"\n'
        'curl -i "http://target/backup/"\n'
        'curl -i "http://target/static/"\n'
        'curl -i "http://target/files/"\n'
        "\n"
        "# 预期响应（漏洞存在）：HTTP/1.1 200，响应体含：\n"
        "#   <title>Index of /uploads/</title>\n"
        "#   <h1>Directory Listing for /uploads/</h1>\n"
        '#   <a href="../">Parent Directory</a>\n'
        "\n"
        "# 2. 批量探测（结合 fuzzer）：\n"
        "for p in uploads backup static assets images files css js logs tmp; do\n"
        '  echo "[*] $p"; curl -s -o /dev/null -w "%{http_code}\\n" "http://target/$p/"\n'
        "done"
    )

    # 常见可能开启目录列表的路径
    _DIR_PATHS = [
        "/uploads/",
        "/backup/",
        "/static/",
        "/assets/",
        "/images/",
        "/files/",
        "/css/",
        "/js/",
        "/logs/",
        "/tmp/",
    ]

    # 目录列表的正/负向特征
    _POSITIVE = ["<title>Index of", "Directory Listing", "Parent Directory"]
    _NEGATIVE = ["<title>404", "<title>Error", "Page Not Found"]

    def verify(self, target, session) -> ScanResult:
        """探测常见静态资源目录是否开启目录列表（Directory Listing）

        @param target: 目标站点 URL
        @param session: 已配置的 HTTP 会话
        @return: STATUS_CONFIRMED（发现可列表目录）或 STATUS_SAFE
        """
        found = []
        for path in self._DIR_PATHS:
            url = join_url(target, path)
            try:
                resp = session.get(url)
                # 目录列表页必然以 200 返回；404/403 等直接跳过，不做无谓的内容匹配
                if resp.status_code != 200:
                    continue
                # 统一转空串：部分服务器对未知目录返回空 body，避免 None 参与关键字匹配
                text = resp.text or ""
                # 正向命中 + 负向排除
                pos = any(kw in text for kw in self._POSITIVE)
                # 剔除负向特征：自定义 404 页常返回 200 且含 "Not Found"，不排除会误报为目录列表
                neg = any(kw in text for kw in self._NEGATIVE)
                if pos and not neg:
                    found.append(path)
            except Exception:
                continue
        if found:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=target,
                evidence=f"发现 {len(found)} 个目录可列表: {', '.join(found)}",
                extra={"paths": found},
                fix=self.fix,
            )
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=target,
            evidence="未发现开启目录列表的路径",
        )
