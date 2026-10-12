# 源码泄露探测 — IDE / SCM 残留文件（.svn/.hg/.idea/.vscode 等）
import json
import re

from common.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.soft404 import Soft404Baseline
from plugins.base import PluginBase


def _is_json_object(text: str) -> bool:
    """文本是否为可解析的 JSON 对象（.vscode/settings.json 的形态校验）

    关键字 "{" 几乎出现在任何 HTML/JS/JSON 响应中，必须解析成功且为对象才算命中。
    """
    try:
        return isinstance(json.loads(text), dict)
    except Exception:
        return False


def _is_svn_entries(text: str) -> bool:
    """文本是否为 SVN 1.6 entries 文件（含独立的 dir/file 类型行，CRLF 容忍）

    关键字 "dir" 过于泛用（任意说明文字/JS 均可能包含），故改为行级结构校验。
    """
    return re.search(r"(?m)^(dir|file)\r?$", text) is not None


# 关键字过于泛用的路径 → 改用结构化校验函数（键与 _TARGETS 中的路径对齐）
_STRUCT_CHECKS = {
    "/.vscode/settings.json": _is_json_object,
    "/.svn/entries": _is_svn_entries,
}


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
    # 注：/.vscode/settings.json 与 /.svn/entries 的关键字过于泛用（"{" / "dir"），
    #     实际判定走 _STRUCT_CHECKS 的结构化校验，元组中的关键字仅作说明
    _TARGETS = [
        # SCM 版本控制
        ("/.svn/entries", "dir"),
        # 关键字收紧：原为 "data"，过于泛用——载荷中的 dataScope 等词即可命中。
        # hg fncache 的真实内容是一行一个 repo 内路径，形如 data/foo/bar.i
        ("/.hg/store/fncache", "data/"),
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
        """探测 IDE/SCM 残留文件及依赖锁文件是否可被外网访问

        判定说明：路径存在性先过软 404 基线（随机不存在路径探测）。站点存在兜底路由时，
        任意路径都返回 2xx，仅凭状态码 + 泛用关键字会把整站误报成残留文件泄露；
        此时要求响应内容与兜底页不同方可计入。

        三态说明：全部探测路径均因网络异常失败时返回 UNKNOWN（测不到 ≠ 安全），
        只有至少一个路径拿到有效响应，SAFE 才是可信结论。

        @param target: 目标站点 URL
        @param session: 已配置的 HTTP 会话
        @return: STATUS_CONFIRMED（发现残留文件）/ STATUS_SAFE / STATUS_UNKNOWN（全部网络异常）
        """
        found = []
        got_response = False
        baseline = Soft404Baseline.probe(target, session)
        # 每项 = 路径 + 判定关键字：须同时满足「基线判定为真实文件」与关键字命中，
        # 双条件避免仅凭状态码误报
        for path, keyword in self._TARGETS:
            url = join_url(target, path)
            try:
                resp = session.get(url)
                got_response = True
                text = resp.text or ""
                # 关键字过于泛用的路径改用结构化校验（JSON 对象 / SVN entries 行格式），
                # 其余路径仍用「(resp.text or "")」防御空响应体：无 body 的 200 一律视为未命中
                checker = _STRUCT_CHECKS.get(path)
                matched = checker(text) if checker is not None else keyword in text
                if baseline.looks_like_real_file(resp) and matched:
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
                evidence=(f"发现 {len(found)} 个残留文件: {', '.join(found[:5])}；{baseline.describe()}"),
                extra={"paths": found, "baseline": baseline.describe()},
                fix=self.fix,
            )
        # 全部请求异常 → 不可判定（网络故障不得判 SAFE）
        if not got_response:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=target,
                evidence=f"所有探测路径请求均网络异常，无法判定；{baseline.describe()}",
            )
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=target,
            evidence=f"未发现 IDE/SCM 残留文件；{baseline.describe()}",
        )
