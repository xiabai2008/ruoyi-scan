# ThinkPHP 5.0.x 多语言远程代码执行（CVE-2022-25481）
# 漏洞原因：多语言功能 lang 参数未做过滤，结合 php://filter 文件包含链可触发变量覆盖与 RCE。
# 本插件仅做存在性验证：构造 lang 文件包含探针，检测响应特征判定接口是否可达（不执行破坏性命令）。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/thinkphp_server.py vuln 模式一致；仅用于对拍，非真实利用输出）
LANG_RCE_MARKER = 'thinkphp-lang-rce-confirmed'


class ThinkphpLangRcePlugin(PluginBase):
    name = 'ThinkPHP 5.0.x 多语言远程代码执行'
    cve = 'CVE-2022-25481'
    severity = 'high'
    category = 'vuln'
    description = '多语言功能 lang 参数未过滤，结合 php://filter 文件包含可触发 RCE（影响 5.0.x 多版本）'
    fix = '升级 ThinkPHP 至 5.0.x 安全版本；禁用多语言功能或对 lang 参数做白名单校验'

    def verify(self, target, session):
        url = join_url(target, '/index.php')
        # 探针：lang 文件包含链（仅触发签名，不执行任何破坏性命令）
        params = {
            'lang': 'php://filter/convert.base64-decode/resource=thinkphp/base.php',
        }
        try:
            resp = session.get(url, params=params)
        except Exception as e:
            print(no('ThinkPHP 5.0.x 多语言 RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if LANG_RCE_MARKER in text:
            print(ok('存在 ThinkPHP 5.0.x 多语言远程代码执行漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含多语言 RCE 特征：{LANG_RCE_MARKER}',
                fix=self.fix,
            )
        print(no('不存在 ThinkPHP 5.0.x 多语言远程代码执行漏洞'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含多语言 RCE 特征（可能已修复或接口不可达）')
