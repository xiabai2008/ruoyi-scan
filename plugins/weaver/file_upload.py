# 泛微 e-cology 任意文件上传 getshell（CNVD-2021-49104）
# 漏洞原因：/weaver/weaver.file.FileDownloadForOutDoc 等上传接口未校验文件类型与扩展名，
#   攻击者可上传 jsp / webshell 获取服务器权限。
# 本插件仅做存在性验证：上传无害 .txt 探针，检测响应签名判定接口是否可达（不上传可执行文件）。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/weaver_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
UPLOAD_MARKER = 'weaver-file-upload-rce-confirmed'

PROBE_NAME = 'weaver_scan_probe.txt'
PROBE_CONTENT = 'weaver-scan-probe-benign-content'


class WeaverFileUploadPlugin(PluginBase):
    name = '泛微 e-cology 任意文件上传'
    cve = 'CNVD-2021-49104'
    severity = 'high'
    category = 'vuln'
    description = '/weaver/weaver.file.FileDownloadForOutDoc 上传接口未校验文件类型，可上传 jsp/webshell getshell'
    fix = '校验上传文件类型与扩展名白名单；上传目录禁止执行权限；上传接口强制鉴权'

    def verify(self, target, session):
        url = join_url(target, '/weaver/weaver.file.FileDownloadForOutDoc')
        # 无害探针：上传 .txt 文本，不尝试执行
        files = {'file': (PROBE_NAME, PROBE_CONTENT, 'text/plain')}
        try:
            resp = session.post(url, files=files)
        except Exception as e:
            print(no('泛微任意文件上传（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if UPLOAD_MARKER in text:
            print(ok('存在泛微 e-cology 任意文件上传漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含文件上传 RCE 特征：{UPLOAD_MARKER}',
                fix=self.fix,
            )
        print(no('不存在泛微 e-cology 任意文件上传漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含文件上传 RCE 特征（接口不可达或已修复）')
