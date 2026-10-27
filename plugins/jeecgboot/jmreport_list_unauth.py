# JeecgBoot 报表列表未授权：/jmreport/list 无需认证返回报表数据
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase

# 复用同目录 dict_unauth 的分页列表结构判定（records/rows + total/success + code==200）
from plugins.jeecgboot.dict_unauth import _is_dict_list_json


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

    # 候选路径：JeecgBoot 默认 context-path 是 /jeecg-boot，但该配置可改为根路径
    CANDIDATE_PATHS = ["/jmreport/list?current=1&size=10", "/jeecg-boot/jmreport/list?current=1&size=10"]

    def verify(self, target, session):
        """依次探测候选路径，检测 jmreport 列表接口是否未授权返回报表数据。

        @param target: 目标站点根 URL
        @param session: 复用的 HTTP 会话
        @return: ScanResult —— 命中 CONFIRMED；未命中 SAFE；全部请求异常 UNKNOWN
        """
        got_response = False
        last_error = None
        last_url = join_url(target, self.CANDIDATE_PATHS[0])
        for path in self.CANDIDATE_PATHS:
            url = join_url(target, path)
            last_url = url
            try:
                # 分页参数命中列表分支：未授权返回 records 数据，鉴权拦截返回 401/403。
                # allow_redirects=False：默认跟随重定向会把「302 → 登录页(200)」透明转成 200，
                # 登录页正文可能恰好含 records/code 字样而被误判为未授权；此处把 3xx 显式归为非命中。
                resp = session.get(url, allow_redirects=False)
            except Exception as e:
                # 单路径请求异常继续尝试其余候选路径，只有全部失败才归 UNKNOWN（测不到 ≠ 安全）
                last_error = e
                continue
            got_response = True
            # 结构化判定：解析 JSON 并校验分页结构（code==200 且 records/rows 为 list 且有 total/success）；
            # 裸子串 "records"+"code" 会把登录页/任意 HTML 误报为未授权
            if resp.status_code == 200 and _is_dict_list_json(resp):
                emit(ok("存在 JeecgBoot 报表未授权"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence="未授权返回报表列表 JSON（records + 业务外壳字段）",
                    fix=self.fix,
                    extra={"vuln_type": "unauth", "plugin_name": "jeecg_jmreport_list"},
                )
        if not got_response:
            emit(no("JeecgBoot 报表未授权（网络异常）"))
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=last_url, evidence=str(last_error)
            )
        emit(no("不存在 JeecgBoot 报表未授权"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE, url=last_url)
