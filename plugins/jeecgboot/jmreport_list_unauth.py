# JeecgBoot 报表列表未授权：/jmreport/list 无需认证返回报表数据
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_all
from plugins.base import PluginBase


class JeecgJmreportListUnauthPlugin(PluginBase):
    name = "JeecgBoot 报表未授权"
    cve = "CVE-2023-1454"
    severity = "medium"
    category = "vuln"
    description = "JeecgBoot 报表模块 /jmreport/list 未授权访问，泄露报表列表与配置"
    fix = "升级 JeecgBoot；/jmreport/** 接口强制鉴权"
    fix_detail = (
        "【升级方案】升级至 JeecgBoot 3.5.2+\n"
        "【配置加固】sa-token 拦截器配置中移除 /jmreport/** 白名单：\n"
        "  # application.yml\n  sa-token:\n    exclude-path-list: []  # 移除 jmreport 免鉴权\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl "http://target/jeecg-boot/jmreport/list?current=1&size=10"\n'
        "# 预期响应：JSON 含 records 字段与报表列表数据（未授权可访问）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "unauth"
    supports_waf_bypass = False

    def verify(self, target, session):
        """检测 /jmreport/list 是否未授权返回报表列表。

        @param target: 目标站点根 URL
        @param session: 复用的 HTTP 会话
        @return: ScanResult —— 命中 CONFIRMED；未命中 SAFE；网络异常 UNKNOWN
        """
        url = join_url(target, "/jeecg-boot/jmreport/list?current=1&size=10")
        try:
            # 分页参数命中列表分支：未授权返回 records 数据，鉴权拦截返回 401/403
            resp = session.get(url)
            text = resp.text or ""
        except Exception as e:
            # 网络异常归 UNKNOWN：测不到 ≠ 安全，避免漏报
            print(no("JeecgBoot 报表未授权（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 未授权 + 业务 JSON（records 字段）→ 确认
        if resp.status_code == 200 and match_all(text, ["records", "code"]):
            print(ok("存在 JeecgBoot 报表未授权"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="未授权返回报表列表 JSON",
                fix=self.fix,
                extra={"vuln_type": "unauth", "plugin_name": "jeecg_jmreport_list"},
            )
        print(no("不存在 JeecgBoot 报表未授权"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
