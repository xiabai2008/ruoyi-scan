# RocketMQ Dashboard 未授权访问检测（F7 中间件包）
# 非破坏性：GET /rocketmq/ 与常见 dashboard 路径，无鉴权返回控制台即确认
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_positive
from plugins.base import PluginBase


class RocketmqUnauthPlugin(PluginBase):
    name = "RocketMQ Dashboard 未授权"
    cve = "CVE-2023-33246"
    severity = "medium"
    category = "vuln"
    description = "RocketMQ Dashboard 控制台未授权访问（可查看/操作集群）"
    fix = "为 RocketMQ Dashboard 配置认证；限制管理端口访问来源"
    fix_detail = (
        "【配置加固】rocketmq-dashboard 部署时配置登录认证（nginx basic auth 或应用内认证）\n"
        "【网络加固】Dashboard 端口（8080/8081）仅内网访问；禁止暴露公网\n"
        "【升级方案】升级 RocketMQ 至 4.9.4+/5.1.1+（修复 CVE-2023-33246）\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl "http://target/rocketmq/"\n'
        "# 预期响应：返回 RocketMQ Dashboard HTML（含 rocketmq 标题/图表资源）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "unauth"
    supports_waf_bypass = False

    def verify(self, target, session):
        paths = ["/rocketmq/", "/dashboard/", "/rocketmq-console-ng/"]
        evidence_url = ""
        for p in paths:
            url = join_url(target, p.lstrip("/"))
            try:
                resp = session.get(url)
                text = resp.text or ""
            except Exception as e:
                print(no("RocketMQ Dashboard 未授权（网络异常）"))
                return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
            if resp.status_code == 200 and match_positive(
                text.lower(),
                ["rocketmq", "dashboard", "mqnamesrv", "topic"],
                negatives=["login", "sign in"],
            ):
                evidence_url = url
                break
        if evidence_url:
            print(ok("存在 RocketMQ Dashboard 未授权"))
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity, status=STATUS_CONFIRMED,
                url=evidence_url, evidence="未授权返回 Dashboard 页面",
                fix=self.fix, extra={"vuln_type": "unauth", "plugin_name": "rocketmq_unauth"},
            )
        print(no("不存在 RocketMQ Dashboard 未授权"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=target)
