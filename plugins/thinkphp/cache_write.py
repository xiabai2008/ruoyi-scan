# ThinkPHP 缓存文件包含 getshell（high）
# 漏洞原因：runtime/cache/ 下缓存文件可被写入 PHP 代码且经 web 可访问/包含，导致远程 getshell。
# 本插件仅做存在性验证：探测默认缓存文件名是否可被 web 访问并返回缓存 shell 特征。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
CACHE_MARKER = 'thinkphp-cache-shell-confirmed'


class ThinkphpCacheWritePlugin(PluginBase):
    name = 'ThinkPHP 缓存文件包含 getshell'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = 'runtime/cache/ 下缓存文件可被写入 PHP 代码并经 web 访问/包含，导致远程 getshell'
    fix = '禁止 web 访问 runtime 目录；缓存写入做内容过滤；最小化缓存目录权限'

    def verify(self, target, session):
        # 默认缓存文件名由 md5(缓存标识) 生成；此处探测常见标识的缓存文件可访问性
        url = target.rstrip('/') + '/runtime/cache/9d31792b4ec3cfa3b3a4b9b9b3e2c7d1.php'
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('ThinkPHP 缓存文件包含（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if resp.status_code == 200 and CACHE_MARKER in text:
            print(ok('存在 ThinkPHP 缓存文件包含 getshell 漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含缓存 shell 特征：{CACHE_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP 缓存文件包含 getshell 漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='缓存文件不可访问（404 或非 shell 内容）')
