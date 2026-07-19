# 备份文件扫描 — 常见备份/交换/IDE 文件后缀拼接探测
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, SEVERITY_MEDIUM
from lib.http import join_url


class BackupScanPlugin(PluginBase):
    """探测常见备份文件、交换文件、系统残留文件是否可被外网访问"""
    name = '备份文件泄露'
    cve = 'N/A'
    severity = SEVERITY_MEDIUM
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
    compliance = '等保2.0:8.1.4;OWASP:A05:2021'
    category = 'vuln'
    description = '目标服务器上存在可访问的备份文件（.bak/.swp/.DS_Store 等），可能泄露源码或配置'
    fix = '禁止 Web 服务器对外提供备份/交换/系统文件的访问，或在部署时清理此类文件'
    fix_detail = (
        '【配置加固·nginx】拒绝备份/交换/系统文件后缀访问：\n'
        '  location ~ \\.(bak|back|swp|swo|swn|save|old|orig|tar|tar\\.gz|zip|rar|7z|DS_Store)$ { deny all; return 404; }\n'
        '  location ~ /\\~$ { deny all; }   # 编辑器交换文件 trailing ~\n'
        '【配置加固·Apache】<FilesMatch "\\.(bak|swp|swo|old|orig|zip|tar\\.gz|DS_Store)$"> Require all denied </FilesMatch>\n'
        '【部署清理】CI/CD 打包脚本在构建产物中清理：\n'
        '  find . -name "*.bak" -o -name "*.swp" -o -name ".DS_Store" | xargs rm -f\n'
        '  rsync -avz --exclude="*.bak" --exclude="*.swp" --exclude=".DS_Store" src/ dest/\n'
        '【代码修复】禁止将 .sql/.tar.gz 备份文件放至 Web 可访问目录；macOS 开发机关闭 .DS_Store 生成\n'
        '【WAF 规则】拦截 .bak/.swp/.old/.orig/.tar.gz/.zip/.DS_Store/~ 等后缀请求\n'
        '【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制'
    )
    reproduce = (
        '# 1. 探测常见备份文件后缀：\n'
        'curl -i "http://target/index.bak"\n'
        'curl -i "http://target/index.php.bak"\n'
        'curl -i "http://target/config.old"\n'
        'curl -i "http://target/web.zip"\n'
        'curl -i "http://target/backup.tar.gz" -o backup.tar.gz\n'
        '\n'
        '# 2. 探测编辑器交换文件与系统残留：\n'
        'curl -i "http://target/.index.php.swp" -o .index.php.swp\n'
        'curl -i "http://target/index.php~"\n'
        'curl -i "http://target/.DS_Store"\n'
        '\n'
        '# 预期响应（漏洞存在）：HTTP/1.1 200，Content-Type: application/octet-stream\n'
        '# 下载后可直接查看源码：cat .index.php.swp | strings | head\n'
        '\n'
        '# 3. .DS_Store 解析（泄露同目录文件名清单）：\n'
        'python ds_store_exp.py "http://target/.DS_Store"'
    )

    # 常见备份 / 交换 / 系统残留后缀
    _BACKUP_SUFFIXES = [
        '.bak', '.back', '.swp', '.save', '.old', '.orig', '.tar.gz', '.zip',
        '.DS_Store', '~', '.swp', '.swo', '.swn',
    ]

    def verify(self, target, session) -> ScanResult:
        found = []
        # 探测根路径的几个常见配置文件名组合
        base_names = ['index', 'config', '.env', 'web', 'app']
        for base in base_names:
            for suf in self._BACKUP_SUFFIXES:
                path = f'/{base}{suf}' if suf.startswith('.') or base.startswith('.') else f'/{base}{suf}'
                url = join_url(target, path)
                try:
                    resp = session.get(url)
                    if resp.status_code == 200 and len(resp.content or b'') > 0:
                        found.append(path)
                except Exception:
                    continue
        if found:
            return ScanResult(
                kind=self.category, name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=target,
                evidence=f'发现 {len(found)} 个可访问备份文件: {", ".join(found[:5])}',
                extra={'paths': found},
                fix=self.fix
            )
        return ScanResult(
            kind=self.category, name=self.name, severity=self.severity,
            status=STATUS_SAFE, url=target,
            evidence='未发现可访问的备份/交换文件'
        )
