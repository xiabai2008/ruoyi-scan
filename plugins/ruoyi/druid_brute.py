# Druid 弱口令爆破：6 用户 × password.txt 字典，POST /druid/submitLogin，判定 'success' in t
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.colors import ok, no
from lib.http import join_url
from config import settings


class DruidBrutePlugin(PluginBase):
    name = 'Druid 弱口令爆破'
    cve = ''
    severity = 'high'
    category = 'brute'
    description = '对 /druid/submitLogin 用 6 个默认用户名 + password.txt 字典爆破，命中 success 即成功'
    fix = '修改 Druid 监控默认口令，限制访问来源 IP，关闭未授权的 /druid 路径'

    def verify(self, target, session):
        # 用户名清单严格保留（6 个）
        user_list = settings.DRUID_USERS
        # 原脚本：self.url + 'druid/submitLogin'（self.url 以 / 结尾，故仅一个斜杠）
        url = join_url(target, 'druid/submitLogin')
        # 字典原样读取（splitlines 保留空行口令、'NULL' 字符串等，勿 strip）
        try:
            with open(settings.PASSWORD_DICT, 'r', encoding='utf-8') as f:
                password_list = f.read().splitlines()
        except Exception as e:
            print(no(f'Druid 爆破字典读取失败：{e}'))
            return ScanResult(kind='brute', name=self.name, status=STATUS_UNKNOWN,
                              url=url, evidence=str(e))

        got_response = False  # 是否至少收到一次响应（避免全网络异常误判 SAFE）
        for user in user_list:
            for password in password_list:
                data = {
                    "loginUsername": user,
                    "loginPassword": password
                }
                try:
                    login_response = session.post(url, data=data)
                except Exception as e:
                    # 网络异常：红色提示，继续尝试下一组（不阻断）
                    print(no(f'请求异常,用户名:{user},密码:{password}'))
                    continue
                got_response = True
                # 判定：解析 JSON 严格比对 success == True（布尔），避免 {"success":false} 误报
                # 原始 'success' in text 子串匹配会把失败响应 "success":false 也判为命中（假阳性）
                success_ok = False
                try:
                    j = login_response.json()
                    success_ok = (j.get('success') is True)
                except Exception:
                    # 非 JSON：Druid 真实响应为纯文本 success(正确)/error(错误)
                    # 也可能返回 JSON {"success":true}，故同时兼容两种形态
                    low = login_response.text.lower().strip()
                    success_ok = (low == 'success') or '"success":true' in low or '"success": true' in low
                if success_ok:
                    # 成功=绿色（对齐原脚本成功配色）
                    print(ok(f'登录成功,用户名:{user},密码:{password}'))
                    return ScanResult(kind='brute', name=self.name, severity=self.severity,
                                      status=STATUS_CONFIRMED, url=url,
                                      evidence=f'命中 success，用户名={user} 密码={password}',
                                      extra={'username': user, 'password': password}, fix=self.fix)
                else:
                    # 失败=红色（修正原脚本误用绿色，见 agents.md §3.4）
                    print(no(f'登录失败,用户名:{user},密码:{password}'))
        # 全部未命中：若至少收到一次响应，判 SAFE；否则 UNKNOWN
        if got_response:
            return ScanResult(kind='brute', name=self.name, status=STATUS_SAFE, url=url,
                              evidence='全部组合未命中 success')
        return ScanResult(kind='brute', name=self.name, status=STATUS_UNKNOWN, url=url,
                          evidence='全部请求网络异常，无法判定')
