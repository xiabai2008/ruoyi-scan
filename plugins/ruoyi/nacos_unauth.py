# Nacos 未授权访问：若依集成 Nacos 配置中心，/nacos/v1/auth/users 未授权可获取用户列表
# 漏洞原因：Nacos 默认未开启身份认证（nacos.core.auth.enabled=false），
#   攻击者匿名访问 /nacos/v1/auth/users 即可获取全部用户名与密码哈希，
#   进而离线破解或直接利用默认密钥伪造 token 接管配置中心。
# 本插件仅做存在性验证：GET 用户列表接口，检测响应签名判定是否未授权可达。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/server.py vuln 模式一致）
NACOS_UNAUTH_MARKER = 'ruoyi-nacos-unauth-confirmed'


class RuoyiNacosUnauthPlugin(PluginBase):
    name = 'Nacos 未授权访问'
    cve = ''
    severity = 'medium'
    category = 'vuln'
    description = (
        '若依集成 Nacos 配置中心，/nacos/v1/auth/users 未授权可获取用户列表，'
        '导致配置中心账号泄露，可进一步接管服务配置'
    )
    fix = (
        '开启 Nacos 身份认证（nacos.core.auth.enabled=true）；'
        '修改默认密钥；/nacos/** 路径强制鉴权；生产环境限制 Nacos 端口仅内网访问'
    )

    def verify(self, target, session):
        url = join_url(target, '/nacos/v1/auth/users?pageNo=1&pageSize=10')
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('Nacos 未授权访问（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        code = getattr(resp, 'status_code', 0)

        # 响应含签名 marker → 确认未授权可访问用户列表
        if NACOS_UNAUTH_MARKER in text:
            print(ok('存在 Nacos 未授权访问漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含 Nacos 未授权访问签名：{NACOS_UNAUTH_MARKER}',
                fix=self.fix,
            )

        # 401/403/404/无 marker → SAFE（接口已鉴权或不存在）
        if code in (401, 403):
            reason = f'HTTP {code} 鉴权拦截'
        elif code == 404:
            reason = 'HTTP 404 端点不存在'
        else:
            reason = f'响应未含签名 marker（HTTP {code}）'
        print(no(f'不存在 Nacos 未授权访问漏洞（{reason}）'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence=reason)
