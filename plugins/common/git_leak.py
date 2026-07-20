# .git 源码泄露探测 — GET /.git/HEAD 检测 ref: 关键字
from core.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.http import join_url
from plugins.base import PluginBase


class GitLeakPlugin(PluginBase):
    """检测目标是否存在 .git 目录泄露（源码 / 版本历史暴露）"""

    name = ".git 源码泄露"
    cve = "N/A"
    severity = SEVERITY_HIGH
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    description = "目标 Web 根目录下存在可访问的 .git 目录，攻击者可下载源码及提交历史"
    fix = "在 Web 服务器配置中禁止对 .git 目录的访问，或在部署时删除 .git 目录"
    fix_detail = (
        "【配置加固·nginx】禁止所有 .git 路径访问（含子路径）：\n"
        "  location ~ /\\.git { deny all; return 404; }\n"
        '【配置加固·Apache】<DirectoryMatch "/^\\.git"> Require all denied </DirectoryMatch>\n'
        '  或 RewriteRule "^/\\.git" - [F]\n'
        '【配置加固·IIS】web.config 添加 <security><requestFiltering><hiddenSegments><add segment=".git"/></hiddenSegments></requestFiltering></security>\n'
        "【部署清理】生产构建使用 git archive 导出干净代码，而非拷贝工作目录：\n"
        "  git archive --format=tar.gz --prefix=app/ HEAD -o app.tar.gz\n"
        "  部署脚本中显式删除：rm -rf /var/www/html/.git\n"
        "【WAF 规则】拦截 /.git/、/.svn/、/.hg/、/.git/HEAD、/.git/config 等路径访问\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测 .git/HEAD 是否可访问（核心特征）：\n"
        'curl -i "http://target/.git/HEAD"\n'
        "\n"
        "# 预期响应（漏洞存在）：HTTP/1.1 200，响应体为：\n"
        "#   ref: refs/heads/master\n"
        "\n"
        "# 2. 进一步下载 .git 关键文件还原仓库结构：\n"
        'curl -i "http://target/.git/config"\n'
        'curl -i "http://target/.git/index"\n'
        'curl -i "http://target/.git/logs/HEAD"\n'
        'curl -i "http://target/.git/refs/heads/master"\n'
        "\n"
        "# 3. 使用 GitHack / git-dumper 一键还原源码：\n"
        "python GitHack.py http://target/.git/\n"
        "pip install git-dumper && git-dumper http://target/.git/ ./dumped-src\n"
        "\n"
        "# 4. 还原后查看历史提交、密钥泄露：\n"
        'cd dumped-src && git log --oneline && git grep -i "password\\|secret\\|key"'
    )

    def verify(self, target, session) -> ScanResult:
        url = join_url(target, "/.git/HEAD")
        try:
            resp = session.get(url)
            text = resp.text or ""
            if "ref:" in text and (resp.status_code == 200):
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=f"状态码={resp.status_code}, 响应含 ref: 头部引用",
                    fix=self.fix,
                )
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=url,
                evidence=f"状态码={resp.status_code}, 未检测到 .git 泄露特征",
            )
        except Exception as e:
            return ScanResult(kind="error", name=self.name, status=STATUS_UNKNOWN, evidence=f"请求异常: {e}")
