# JeecgBoot Freemarker SSTI（CVE-2022-26809 家族）：/jmreport/testConnection 报表数据源测试接口
# 存在性验证：提交含 ${7*7} 的模板，响应含 49 即确认（不落地 RCE payload）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
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
        """检测 /jmreport/testConnection 是否存在 Freemarker 模板注入。

        @param target: 目标站点根 URL
        @param session: 复用的 HTTP 会话
        @return: ScanResult —— 模板被求值 CONFIRMED；未命中 SAFE；网络异常 UNKNOWN
        """
        url = join_url(target, "/jeecg-boot/jmreport/testConnection")
        # 注入点藏在 JDBC 连接串 query 参数中：connUrl 会被整体交给 Freemarker 渲染
        body = (
            '{"dbType":"MYSQL","dbName":"test","url":"jdbc:mysql://127.0.0.1:3306/test",'
            '"userName":"root","password":"x","connUrl":"jdbc:mysql://127.0.0.1:3306/test?query='
            '${7*7}"}'
        )
        try:
            resp = session.post(url, data=body, headers={"Content-Type": "application/json"})
            text = resp.text or ""
        except Exception as e:
            # 网络异常归 UNKNOWN：测不到 ≠ 安全，避免漏报
            emit(no("JeecgBoot 报表 SSTI（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 加固判定：必须同时满足三个条件
        #   1) 响应为 JSON 业务响应——JeecgBoot 报表接口返回 JSON，正常 HTML 页面不可能满足
        #   2) 含求值结果 49
        #   3) 不含原始表达式 7*7（排除载荷被原样回显）
        # 历史缺陷：原判定仅 `status==200 and "49" in text`，
        # 任何正文含「49」（页码、行号、商品数量等）的 200 页面都会被误报为 SSTI。
        content_type = (resp.headers.get("Content-Type") or "").lower()
        is_json_resp = "application/json" in content_type
        if resp.status_code == 200 and is_json_resp and "49" in text and "7*7" not in text:
            emit(ok("存在 JeecgBoot 报表 SSTI"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="JSON 响应含 49（${7*7} 模板求值）且无载荷回显",
                fix=self.fix,
                extra={"vuln_type": "ssti", "plugin_name": "jeecg_ssti"},
            )
        emit(no("不存在 JeecgBoot 报表 SSTI"))
        return ScanResult(kind="info", name=self.name, status=STATUS_SAFE, url=url)
