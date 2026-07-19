# 链 2 专用插件：默认口令 → 登录链 → 任意文件上传 → webshell
#
# 两个原子步骤：
#   1. DefaultPasswordLoginPlugin: 默认口令登录验证（extra: login_token, username）
#   2. FileUploadVerifyPlugin: 任意文件上传验证（上传 JSP 探针，非真实 webshell）
#
# 注意：本链仅验证可利用性，不实际上传真实 webshell。
import re

from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.http import join_url


# Ruoyi 常见默认口令（仅用于授权测试）
_DEFAULT_CREDS = [
    ('admin', 'admin123'),
    ('ry', 'admin123'),
    ('admin', 'admin'),
]


class DefaultPasswordLoginPlugin(PluginBase):
    """默认口令登录验证（链 2 步骤 1）

    尝试常见默认口令登录 Ruoyi 系统，成功时 extra.login_token 存储登录凭证。
    """
    name = '默认口令登录'
    severity = 'high'
    category = 'vuln'
    description = '尝试 Ruoyi 常见默认口令登录'
    fix = '强制修改默认口令，启用密码复杂度策略，限制登录失败次数'

    def verify(self, target, session):
        login_url = join_url(target, '/login')
        captcha_url = join_url(target, '/captchaImage')

        # 尝试获取验证码（部分版本可能关闭验证码）
        try:
            captcha_resp = session.get(captcha_url)
            captcha_enabled = 'uuid' in captcha_resp.text
        except Exception:
            captcha_enabled = False

        if captcha_enabled:
            # 验证码开启，默认口令链路不可行（需配合 D3 验证码绕过）
            return ScanResult(kind='chain', name=self.name, status=STATUS_SAFE,
                              url=login_url,
                              evidence='验证码已开启，默认口令链路不可行')

        # 尝试默认口令
        for username, password in _DEFAULT_CREDS:
            try:
                resp = session.post(login_url, json={
                    'username': username,
                    'password': password,
                })
                text = resp.text
                # Ruoyi 登录成功特征：返回 token
                if 'token' in text.lower() or '"code":0' in text or '"code":200' in text:
                    token_match = re.search(r'"token"\s*:\s*"([^"]+)"', text)
                    token = token_match.group(1) if token_match else ''
                    return ScanResult(kind='chain', name=self.name, severity=self.severity,
                                      status=STATUS_CONFIRMED, url=login_url,
                                      evidence=f'默认口令登录成功: {username}/{password}',
                                      fix=self.fix,
                                      extra={'login_token': token, 'username': username,
                                             'vuln_type': 'default_password'})
            except Exception:
                continue

        return ScanResult(kind='chain', name=self.name, status=STATUS_SAFE,
                          url=login_url, evidence='默认口令登录失败')


class FileUploadVerifyPlugin(PluginBase):
    """任意文件上传验证（链 2 步骤 2）

    验证 /common/upload 接口是否可上传 JSP 文件（仅验证接口可达性和权限，
    不实际上传恶意文件，仅发送一个无害的探针请求）。
    """
    name = '任意文件上传验证'
    severity = 'high'
    category = 'vuln'
    description = '验证文件上传接口可上传 JSP 文件（仅探针，非真实 webshell）'
    fix = '限制上传文件类型白名单，禁止 JSP/JSPX，上传目录禁止执行权限'

    def verify(self, target, session):
        upload_url = join_url(target, '/common/upload')
        # 构造一个无害的探针文件（仅验证接口响应，不实际上传可执行文件）
        probe_content = 'probe_' + str(hash(target))  # 无害内容
        try:
            # 发送一个合法后缀文件验证接口可达性
            files = {'file': ('test.txt', probe_content, 'text/plain')}
            resp = session.post(upload_url, files=files)
            text = resp.text
        except Exception as e:
            return ScanResult(kind='chain', name=self.name, status=STATUS_UNKNOWN,
                              url=upload_url, evidence=f'网络异常: {e}')

        # 上传成功特征：返回 fileName 或 url
        if 'fileName' in text or 'url' in text:
            # 进一步检查是否允许 JSP（通过错误消息推断）
            try:
                jsp_files = {'file': ('probe.jsp', '<%-- probe --%>', 'application/octet-stream')}
                jsp_resp = session.post(upload_url, files=jsp_files)
                jsp_text = jsp_resp.text
                if 'fileName' in jsp_text or 'url' in jsp_text:
                    return ScanResult(kind='chain', name=self.name, severity=self.severity,
                                      status=STATUS_CONFIRMED, url=upload_url,
                                      evidence='文件上传接口允许 JSP 文件（webshell 风险）',
                                      fix=self.fix,
                                      extra={'upload_endpoint': '/common/upload',
                                             'jsp_allowed': True,
                                             'vuln_type': 'file_upload_jsp'})
                # JSP 被拦截
                return ScanResult(kind='chain', name=self.name, severity='medium',
                                  status=STATUS_CONFIRMED, url=upload_url,
                                  evidence='文件上传接口可达但 JSP 被拦截',
                                  fix=self.fix,
                                  extra={'upload_endpoint': '/common/upload',
                                         'jsp_allowed': False,
                                         'vuln_type': 'file_upload_txt_only'})
            except Exception:
                pass

            # 仅 txt 上传成功
            return ScanResult(kind='chain', name=self.name, severity='medium',
                              status=STATUS_CONFIRMED, url=upload_url,
                              evidence='文件上传接口可达（仅验证 txt 上传）',
                              fix=self.fix,
                              extra={'upload_endpoint': '/common/upload',
                                     'vuln_type': 'file_upload_reachable'})

        # 需鉴权或不可达
        if 'login' in text.lower() or resp.status_code in (302, 401, 403):
            return ScanResult(kind='chain', name=self.name, status=STATUS_SAFE,
                              url=upload_url, evidence='上传接口需鉴权')

        return ScanResult(kind='chain', name=self.name, status=STATUS_SAFE,
                          url=upload_url, evidence='上传接口不可达或无特征')
