# 泛微 e-cology 未授权访问 / 敏感信息泄露
# 漏洞原因：/weaver/ 内部 OA 路径未强制鉴权，匿名访问可获取内部接口与数据。
# 本插件仅做存在性验证：GET /weaver/ 内部路径，200 + 含 weaver 关键字即判 CONFIRMED
#   （不需要 marker，类似 plugins/spring/actuator_unauth.py 模式）。
# 判定细节：
#   - 200 + weaver 关键字 + 未重定向（直接访问到内部内容）→ CONFIRMED
#   - 重定向到登录页（resp.history 非空）/ 401 / 403 → SAFE（已保护）
#   - 404 / 无关键字 → SAFE（不可达或无特征）
#   - 网络异常 → UNKNOWN（绝不判 SAFE）
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url


class WeaverUnauthPlugin(PluginBase):
    name = '泛微 e-cology 未授权访问'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = '/weaver/ 内部 OA 路径未鉴权，匿名访问可获取内部接口与数据'
    fix = '/weaver/** 强制鉴权；内部路径接入统一登录框架；下线调试与监控面板'

    # 内部内容特征关键字（命中任一即视为访问到内部 OA 内容）
    INTERNAL_KEYWORDS = ['weaver', 'e-cology', '泛微']

    def verify(self, target, session):
        url = join_url(target, '/weaver/')
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('泛微未授权访问（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        code = getattr(resp, 'status_code', 0)
        text = resp.text or ''
        # requests 默认跟随重定向；resp.history 非空表示曾被重定向（多半被引导到登录页）
        redirected = bool(getattr(resp, 'history', None))

        # 200 + 内部关键字 + 未重定向（直接匿名访问到内部内容）→ CONFIRMED
        if code == 200 and not redirected and any(k in text for k in self.INTERNAL_KEYWORDS):
            print(ok('存在泛微 e-cology 未授权访问'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'/weaver/ 可匿名访问，响应前 200 字节：{text[:200]}',
                fix=self.fix,
            )

        # 其余情形均为已保护 / 不可达 → SAFE（基于明确证据）
        if redirected:
            reason = '重定向到登录页（已保护）'
        elif code in (401, 403):
            reason = f'HTTP {code} 鉴权拦截'
        elif code == 404:
            reason = 'HTTP 404 端点不存在'
        else:
            reason = f'HTTP {code} 响应未含 weaver 内部特征'
        print(no(f'不存在泛微未授权访问（{reason}）'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence=reason)
