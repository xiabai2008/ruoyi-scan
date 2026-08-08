# RuoYi-Plus 定时任务未授权探测（variant='ruoyi-plus' 专项）
# Plus 版 /monitor/job 定时任务管理接口：未登录可访问即存在越权（存在性验证）
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_positive
from plugins.base import PluginBase


class PlusJobUnauthPlugin(PluginBase):
    name = "RuoYi-Plus 定时任务未授权"
    cve = "N/A"
    severity = "high"
    category = "vuln"
    description = "RuoYi-Vue-Plus 定时任务模块 /monitor/job/list 未登录可访问（越权查看/调度任务）"
    fix = "确认 /monitor/** 接口已加 Sa-Token 鉴权；移除排除路径白名单"
    fix_detail = (
        "【配置加固】application.yml 的 sa-token.exclude-path-list 中移除 /monitor/**\n"
        "【代码修复】MonitorJobController 增加 @SaCheckPermission 注解\n"
        "【WAF 规则】拦截未携带 satoken 的 /monitor/job/** 请求\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl "http://target/prod-api/monitor/job/list?pageNum=1&pageSize=10"\n'
        "# 预期响应：未携带 token 时返回业务 JSON（code=200 + rows）即未授权可访问"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "unauth"
    supports_waf_bypass = False
    variant = "ruoyi-plus"

    def verify(self, target, session):
        url = join_url(target, "/prod-api/monitor/job/list?pageNum=1&pageSize=10")
        try:
            resp = session.get(url)
            text = resp.text or ""
        except Exception as e:
            print(no("RuoYi-Plus 定时任务未授权（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        # 未授权 + 业务 JSON（rows 字段）→ 确认；401/403 视为已鉴权
        if resp.status_code == 200 and match_positive(
            text, ["rows", "total", "code"], negatives=["login", "unauthorized"]
        ):
            print(ok("存在 RuoYi-Plus 定时任务未授权"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="未携带 token 返回任务列表 JSON",
                fix=self.fix,
                extra={"vuln_type": "unauth", "plugin_name": "plus_job_unauth"},
            )
        print(no("不存在 RuoYi-Plus 定时任务未授权"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=url)
