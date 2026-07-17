# 泛微 e-cology 配置文件 / 数据库连接泄露
# 漏洞原因：/weaver/ecology.properties 等配置文件可被匿名下载，
#   泄露数据库连接串、账号与密钥。
# 本插件仅做存在性验证：GET 配置文件路径，检测响应签名判定是否泄露。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/weaver_server.py vuln 模式一致）
LEAK_MARKER = 'weaver-info-leak-confirmed'


class WeaverInfoLeakPlugin(PluginBase):
    name = '泛微 e-cology 配置文件泄露'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = '/weaver/ecology.properties 配置文件可匿名下载，泄露数据库连接与密钥'
    fix = '配置文件禁止 web 直接访问；迁移到受保护目录；Web 服务器限制 .properties 等后缀访问'

    def verify(self, target, session):
        url = join_url(target, '/weaver/ecology.properties')
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('泛微配置文件泄露（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if LEAK_MARKER in text:
            print(ok('存在泛微 e-cology 配置文件泄露'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含配置文件泄露特征：{LEAK_MARKER}',
                fix=self.fix,
            )
        print(no('不存在泛微 e-cology 配置文件泄露'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含配置文件泄露特征（文件不可达或已限制访问）')
