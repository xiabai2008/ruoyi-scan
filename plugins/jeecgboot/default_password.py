# JeecgBoot 默认口令：admin/123456 登录探测（brute 类，存在性验证）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from plugins.base import PluginBase


class JeecgDefaultPasswordPlugin(PluginBase):
    name = "JeecgBoot 默认口令"
    cve = "N/A"
    severity = "medium"
    category = "brute"
    description = "JeecgBoot 后台默认口令 admin/123456（未修改则可直接登录）"
    fix = "修改默认口令 admin/123456；启用强密码策略"
    fix_detail = (
        "【配置加固】首次登录强制修改默认口令 admin/123456\n"
        "【代码修复】开启密码强度校验（8 位以上含数字字母）\n"
        "【合规】OWASP A07:2021 身份认证失败；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl -X POST "http://target/jeecg-boot/sys/login" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"username":"admin","password":"123456","code":"","checkKey":""}\'\n'
        "# 预期响应：JSON 含 token 字段（登录成功）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.4;OWASP:A07:2021"
    vuln_type = "auth"
    supports_waf_bypass = False

    def verify(self, target, session):
        """探测 JeecgBoot 后台默认口令 admin/123456 能否直接登录。

        @param target: 目标站点根 URL，用于拼接登录接口路径
        @param session: 复用的 HTTP 会话（带连接池与超时配置）
        @return: ScanResult —— 登录成功 CONFIRMED；口令无效 SAFE；网络异常 UNKNOWN
        """
        url = join_url(target, "/jeecg-boot/sys/login")
        try:
            resp = session.post(
                url,
                # 验证码字段 code/checkKey 留空：多数版本登录接口不强制校验验证码，可空值直达
                data='{"username":"admin","password":"123456","code":"","checkKey":""}',
                headers={"Content-Type": "application/json"},
            )
            text = resp.text or ""
        except Exception as e:
            # 网络异常无法证明口令状态：归 UNKNOWN 而非 SAFE，避免把"测不到"误报成"安全"
            print(no("JeecgBoot 默认口令（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 以 token 字段为登录成功唯一 oracle：该接口成功响应必然携带 token，避免误判其他页面
        if resp.status_code == 200 and "token" in text:
            print(ok("存在 JeecgBoot 默认口令"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="admin/123456 登录成功（响应含 token）",
                fix=self.fix,
                extra={"vuln_type": "default_password", "plugin_name": "jeecg_default_pw"},
            )
        print(no("不存在 JeecgBoot 默认口令"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
