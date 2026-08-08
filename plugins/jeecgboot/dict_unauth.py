# JeecgBoot 字典越权：/sys/dict/list 未授权返回字典配置（信息泄露）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_all
from plugins.base import PluginBase


class JeecgDictUnauthPlugin(PluginBase):
    name = "JeecgBoot 字典越权"
    cve = "CVE-2023-1454"
    severity = "medium"
    category = "vuln"
    description = "JeecgBoot /sys/dict/list 未授权访问，泄露系统字典配置"
    fix = "升级 JeecgBoot；sys 接口强制鉴权"
    fix_detail = (
        "【升级方案】升级至 JeecgBoot 3.5.2+\n"
        "【配置加固】sa-token 拦截器移除 /sys/** 免鉴权白名单\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl "http://target/jeecg-boot/sys/dict/list?current=1&size=10"\n'
        "# 预期响应：JSON 含 records 字段与字典数据（未授权可访问）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "unauth"
    supports_waf_bypass = False

    def verify(self, target, session):
        url = join_url(target, "/jeecg-boot/sys/dict/list?current=1&size=10")
        try:
            resp = session.get(url)
            text = resp.text or ""
        except Exception as e:
            print(no("JeecgBoot 字典越权（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        if resp.status_code == 200 and match_all(text, ["records", "code"]):
            print(ok("存在 JeecgBoot 字典越权"))
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity, status=STATUS_CONFIRMED,
                url=url, evidence="未授权返回字典列表 JSON",
                fix=self.fix, extra={"vuln_type": "unauth", "plugin_name": "jeecg_dict_unauth"},
            )
        print(no("不存在 JeecgBoot 字典越权"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
