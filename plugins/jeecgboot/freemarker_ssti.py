# JeecgBoot Freemarker SSTI（CVE-2022-26809 家族）：/jmreport/testConnection 报表数据源测试接口
# 存在性验证：提交含 ${7*7} 的模板，响应含 49 即确认（不落地 RCE payload）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from plugins.base import PluginBase


class JeecgFreemarkerSstiPlugin(PluginBase):
    name = "JeecgBoot 报表 SSTI"
    cve = "CVE-2022-26809"
    severity = "high"
    category = "vuln"
    description = "JeecgBoot 报表模块 /jmreport/testConnection 存在 Freemarker 模板注入，可 RCE"
    fix = "升级 JeecgBoot 至 3.5.3+；限制报表模块访问权限"
    fix_detail = (
        "【升级方案】升级至 JeecgBoot 3.5.3+（修复 testConnection 模板注入）\n"
        "【代码修复】TestConnectionController 使用 Freemarker 时禁用默认对象访问：\n"
        "  Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);\n"
        "  cfg.setObjectWrapper(new DefaultObjectWrapperBuilder(...).build());  # 禁止任意对象方法调用\n"
        "【配置加固】/jmreport/** 接口加鉴权（Nginx 层限制内网访问）\n"
        "【WAF 规则】拦截请求体含 ${ 与 7*7 / freemarker 关键字的请求\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3"
    )
    reproduce = (
        'curl -X POST "http://target/jeecg-boot/jmreport/testConnection" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"dbType":"MYSQL","dbName":"test","url":"jdbc:mysql://127.0.0.1:3306/test",'
        '"userName":"root","password":"x","connUrl":"jdbc:mysql://127.0.0.1:3306/test?query='
        "${7*7}\"}'\n"
        "# 预期响应：响应体含 49（Freemarker 表达式求值成功）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    vuln_type = "ssti"
    supports_waf_bypass = False

    def verify(self, target, session):
        url = join_url(target, "/jeecg-boot/jmreport/testConnection")
        body = (
            '{"dbType":"MYSQL","dbName":"test","url":"jdbc:mysql://127.0.0.1:3306/test",'
            '"userName":"root","password":"x","connUrl":"jdbc:mysql://127.0.0.1:3306/test?query='
            '${7*7}"}'
        )
        try:
            resp = session.post(url, data=body, headers={"Content-Type": "application/json"})
            text = resp.text or ""
        except Exception as e:
            print(no("JeecgBoot 报表 SSTI（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        if resp.status_code == 200 and "49" in text:
            print(ok("存在 JeecgBoot 报表 SSTI"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 49（${7*7} 模板求值）",
                fix=self.fix,
                extra={"vuln_type": "ssti", "plugin_name": "jeecg_ssti"},
            )
        print(no("不存在 JeecgBoot 报表 SSTI"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
