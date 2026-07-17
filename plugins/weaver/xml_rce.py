# 泛微 e-cology XMLDecoder 反序列化 RCE
# 漏洞原因：/weaver/xml_endpoint 等接口接收 XML 并以 XMLDecoder 解析，
#   构造恶意 XML 可触发反序列化执行任意命令（影响泛微 e-cology 多版本）。
# 本插件仅做存在性验证：POST 无害 XML 探针，检测响应签名判定接口是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/weaver_server.py vuln 模式一致）
XML_MARKER = 'weaver-xml-rce-confirmed'


class WeaverXmlRcePlugin(PluginBase):
    name = '泛微 e-cology XMLDecoder 反序列化 RCE'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = '/weaver/xml_endpoint 接收 XML 并以 XMLDecoder 解析，恶意 XML 触发反序列化 RCE'
    fix = '禁用 XMLDecoder 解析外部 XML；改用安全 XML 解析器并禁用外部实体（XXE 防护）；接口强制鉴权'

    def verify(self, target, session):
        url = join_url(target, '/weaver/xml_endpoint')
        # 无害探针 XML（不触发真实命令执行，仅探测接口是否解析 XML）
        payload = '<?xml version="1.0"?><probe>weaver-scan</probe>'
        headers = {'Content-Type': 'application/xml'}
        try:
            resp = session.post(url, data=payload, headers=headers)
        except Exception as e:
            print(no('泛微 XMLDecoder RCE（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if XML_MARKER in text:
            print(ok('存在泛微 e-cology XMLDecoder 反序列化 RCE'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 XML 反序列化 RCE 特征：{XML_MARKER}',
                fix=self.fix,
            )
        print(no('不存在泛微 e-cology XMLDecoder 反序列化 RCE'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 XML 反序列化 RCE 特征（接口不可达或已修复）')
