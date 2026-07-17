# 泛微 e-cology 反射型 XSS
# 漏洞原因：/weaver/search.jsp 的 keyword 参数未过滤，攻击者可注入 JavaScript 脚本，
#   在用户浏览器中执行，窃取 Cookie / 会话令牌或进行钓鱼。
# 本插件仅做存在性验证：GET 带 <script>alert(1)</script> 探针，检测响应签名判定反射点是否可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/weaver_server.py vuln 模式一致）
XSS_MARKER = 'weaver-xss-confirmed'


class WeaverXssPlugin(PluginBase):
    name = '泛微 e-cology 反射型 XSS'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = '/weaver/search.jsp 的 keyword 参数未过滤，反射型 XSS 可注入 JavaScript'
    fix = '对 keyword 参数做 HTML 实体编码；输出转义；启用 CSP 限制脚本来源'

    def verify(self, target, session):
        url = join_url(target, '/weaver/search.jsp')
        # 反射型 XSS 探针：注入 <script>alert(1)</script>
        params = {'keyword': '<script>alert(1)</script>'}
        try:
            resp = session.get(url, params=params)
        except Exception as e:
            print(no('泛微反射型 XSS（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        if XSS_MARKER in text:
            print(ok('存在泛微 e-cology 反射型 XSS'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 XSS 特征：{XSS_MARKER}',
                fix=self.fix,
            )
        print(no('不存在泛微 e-cology 反射型 XSS'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence='响应未含 XSS 特征（反射点不可达或已修复）')
