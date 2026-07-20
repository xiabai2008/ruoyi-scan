# 源码泄露探测 — IDE / SCM 残留文件（.svn/.hg/.idea/.vscode 等）
from core.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, ScanResult
from lib.http import join_url
from plugins.base import PluginBase


class SourceLeakPlugin(PluginBase):
    """探测 IDE 项目配置、SCM 版本控制残留文件是否可被外网访问"""

    name = "IDE/SCM 残留文件泄露"
    cve = "N/A"
    severity = SEVERITY_MEDIUM
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    description = "目标服务器上存在 IDE 配置或版本控制残留文件，可能泄露项目结构、源码路径等敏感信息"
    fix = "禁止 Web 服务器对外提供 .svn/.hg/.idea/.vscode 等隐藏目录的访问，部署时清理这些目录"
    fix_detail = (
        "【配置加固·nginx】禁止所有 SCM/IDE 隐藏目录访问：\n"
        "  location ~ /\\.(svn|hg|bzr|git|idea|vscode|project|classpath) { deny all; return 404; }\n"
        "  location ~ /\\.(project|classpath)$ { deny all; }\n"
        '【配置加固·Apache】<DirectoryMatch "/\\.(svn|hg|bzr|idea|vscode)"> Require all denied </DirectoryMatch>\n'
        "  或 RedirectMatch 404 /\\.(svn|hg|bzr|idea|vscode)\n"
        "【配置加固·IIS】web.config requestFiltering hiddenSegments 添加 .svn/.hg/.idea/.vscode\n"
        "【部署清理】CI/CD 构建脚本在打包产物时清理残留目录：\n"
        '  find . -type d \\( -name ".svn" -o -name ".hg" -o -name ".idea" -o -name ".vscode" \\) -prune -exec rm -rf {} +\n'
        '  rsync -avz --exclude=".svn" --exclude=".hg" --exclude=".idea" --exclude=".vscode" src/ dest/\n'
        "【代码修复】package-lock.json/composer.lock/Gemfile.lock 不应部署到 Web 可访问目录；使用 .dockerignore 排除\n"
        "【WAF 规则】拦截 /.svn/、/.hg/、/.bzr/、/.idea/、/.vscode/、/.project、/.classpath 路径\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测 SCM 版本控制残留：\n"
        'curl -i "http://target/.svn/entries"\n'
        'curl -i "http://target/.svn/wc.db"\n'
        'curl -i "http://target/.hg/store/fncache"\n'
        'curl -i "http://target/.bzr/branch-format"\n'
        "\n"
        "# 预期响应（漏洞存在）：HTTP/1.1 200，响应体含目录结构 / 版本元数据\n"
        "\n"
        "# 2. 探测 IDE 配置残留：\n"
        'curl -i "http://target/.idea/workspace.xml"\n'
        'curl -i "http://target/.idea/modules.xml"\n'
        'curl -i "http://target/.vscode/settings.json"\n'
        'curl -i "http://target/.project"\n'
        'curl -i "http://target/.classpath"\n'
        "\n"
        "# 3. 探测依赖锁文件（泄露依赖版本，辅助 CVE 匹配）：\n"
        'curl -i "http://target/package-lock.json" | python -m json.tool | head -50\n'
        'curl -i "http://target/composer.lock"\n'
        'curl -i "http://target/yarn.lock"\n'
        'curl -i "http://target/Gemfile.lock"\n'
        "\n"
        "# 4. SVN 完整源码还原（使用 ripsvn / svn-extractor）：\n"
        'python svn-extractor.py --url "http://target/.svn/" --output ./svn-dumped'
    )

    # IDE/SCM 残留探测：path + 判定关键字
    _TARGETS = [
        # SCM 版本控制
        ("/.svn/entries", "dir"),
        ("/.hg/store/fncache", "data"),
        ("/.bzr/branch-format", "Bazaar"),
        # IDE 配置
        ("/.idea/workspace.xml", "<?xml"),
        ("/.vscode/settings.json", "{"),
        ("/.project", "<?xml"),
        ("/.classpath", "<?xml"),
        # 其他常见泄露
        ("/package-lock.json", '"name"'),
        ("/composer.lock", '"packages"'),
        ("/yarn.lock", "# yarn"),
        ("/Gemfile.lock", "GEM"),
    ]

    def verify(self, target, session) -> ScanResult:
        found = []
        for path, keyword in self._TARGETS:
            url = join_url(target, path)
            try:
                resp = session.get(url)
                if resp.status_code == 200 and keyword in (resp.text or ""):
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
                evidence=f"发现 {len(found)} 个残留文件: {', '.join(found[:5])}",
                extra={"paths": found},
                fix=self.fix,
            )
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=target,
            evidence="未发现 IDE/SCM 残留文件",
        )
