# 芋道 Druid 监控页未授权：/druid/*.json 匿名可读数据源/SQL/URI 监控
#
# 与 common 包里那个「Druid 弱口令爆破」的区别
# ==========================================
# 那个插件判的是「能不能用弱口令登录控制台」——需要爆破，有速率风险。
# 本插件判的是「监控数据接口**根本不需要登录**」——更严重也更确定：
#
#   芋道默认配置里 stat-view-servlet 的 login-username / login-password **都是空的**
#   （实测 Y1 的 application-local.yaml 第 22-23 行），此时 Druid 控制台
#   对 /druid/*.json 这类数据接口**完全不做鉴权**，直接返回 JSON。
#
# 实测（2026-11-03 Y1 真实站）：
#   GET /druid/datasource.json → 200 {"ResultCode":1,"Content":[{"Name":"master",
#                                        "DbType":"mysql","DriverClassName":"com.mysql.cj...",...}]}
#   GET /druid/sql.json        → 200 {"ResultCode":1,"Content":[...]}   （2 条 SQL 记录）
#   GET /druid/weburi.json     → 200 {"ResultCode":1,"Content":[...]}   （9 条 URI 记录）
#
# 泄露内容：数据库连接串/驱动/账号池配置、真实执行的 SQL 语句、全部访问过的 URI。
# 对攻击者这是「内部结构地图」——比一个密码更值钱。
#
# 判定口径
# ========
# Druid 的数据接口统一返回 `{"ResultCode":1,"Content":[...]}`：
#   - ResultCode == 1 表示成功（Druid 的口径，不是 HTTP 状态码）
#   - Content 必须是非空数组——空的 Content 只说明「暂无数据」，不构成泄露证据
# 只看 HTTP 200 会把任意返回 200 的页面（SPA 兜底、登录页）算成命中。
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import parse_json_body
from lib.reporter import emit
from plugins.base import PluginBase

# 三个数据接口，任一命中即确认。按「泄露价值」排序：
#   datasource → 数据源配置（含连接串、账号池）——最敏感
#   sql        → 真实执行的 SQL 语句
#   weburi     → 全部访问过的 URI（内网拓扑地图）
CANDIDATE_PATHS = (
    "/druid/datasource.json",
    "/druid/sql.json",
    "/druid/weburi.json",
)


def _is_druid_data(resp):
    """判定响应是否为 Druid 真实监控数据

    Returns:
        (hit, reason, count)
    """
    body = parse_json_body(resp)
    if not isinstance(body, dict):
        return False, "响应非 JSON 对象", 0
    # Druid 自己的成功码是 1（不是 HTTP 状态，也不是若依/芋道的 code）
    if body.get("ResultCode") != 1:
        return False, f"ResultCode={body.get('ResultCode')}（非 1，不是有效数据响应）", 0
    content = body.get("Content")
    if not isinstance(content, list):
        return False, "Content 不是数组", 0
    if not content:
        # 空数组只说明「暂无数据」，不是泄露证据
        return False, "Content 为空（暂无数据，不构成泄露）", 0
    return True, f"Druid 监控数据匿名可读（{len(content)} 条记录）", len(content)


class YudaoDruidMonitorUnauthPlugin(PluginBase):
    name = "芋道 Druid 监控未授权"
    cve = "N/A"
    severity = "high"
    category = "vuln"
    description = (
        "芋道默认把 Druid 监控页的 login-username/login-password 留空，"
        "导致 /druid/*.json 数据接口匿名可读——泄露数据源配置、真实 SQL 语句与全部访问 URI"
    )
    fix = "为 Druid 控制台设置强口令，或直接在生产环境关闭 stat-view-servlet"
    fix_detail = (
        "【配置加固】application.yaml 中给 Druid 控制台设置强口令：\n"
        "  spring.datasource.druid.stat-view-servlet:\n"
        "    enabled: true\n"
        "    login-username: <强用户名>\n"
        "    login-password: <强随机密码>\n"
        "    allow: 127.0.0.1        # 限制来源 IP，不要留空（留空=允许所有）\n"
        "【生产最佳实践】生产环境直接关闭：enabled: false\n"
        "【WAF 规则】拦截外网对 /druid/* 的访问\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 匿名请求 Druid 数据接口：\n"
        'curl -s "http://target/druid/datasource.json"\n'
        "\n"
        "# 预期响应（漏洞存在）：HTTP 200，ResultCode 为 1\n"
        '#   {"ResultCode":1,"Content":[{"Name":"master","DbType":"mysql",...}]}\n'
        "\n"
        "# 同时可读真实 SQL 与访问 URI：\n"
        'curl -s "http://target/druid/sql.json"\n'
        'curl -s "http://target/druid/weburi.json"'
    )
    affected_versions = ""
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A05:2021"
    vuln_type = "unauth_access"
    supports_waf_bypass = False
    # 注意：**不设** variant。yudao 是 cms 不是 variant——
    # Router.candidates() 按 variant 过滤时会拿 fingerprint.variant（空串）
    # 与插件声明比对，若这里写 "yudao" 会导致整个包被过滤掉、路由为空。
    # （2026-11-03 实测：cms=yudao 但 resolve() 返回 []，插件一个都不跑）
    anonymous_probe = True
    # v1.6：Druid 挂在**站点根**，不在 /admin-api 业务前缀下。
    # 实测 Y1：/druid/datasource.json → 200+真实数据；
    #           /admin-api/druid/datasource.json → 200 但 ResultCode=None（错误页）
    # 与 Swagger 同一类问题：网关架构下「业务接口」走前缀，「运维页面」走根。
    # 声明 both 让引擎对两个基准各探一次。
    path_scope = "both"

    def verify(self, target, session):
        """入口：用匿名会话探测（声明 anonymous_probe）"""
        # 判定的是「**不登录**能不能读到」，必须在匿名会话上探测。
        # anonymous_probe 只是声明，真正的隔离动作在这里（与 nacos/minio 同款）：
        # 共享会话可能已被默认口令插件登录污染，带着凭据拿到的 200 只证明「登录后可读」。
        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        try:
            return self._verify_anonymous(target, probe)
        finally:
            if probe is not session:
                probe.close()

    def _verify_anonymous(self, target, session):
        """匿名读取 Druid 监控数据（只 GET，非破坏性）

        @param target: 目标站点基准
        @param session: 引擎注入的匿名会话
        @return: CONFIRMED / SAFE / UNKNOWN
        """
        hits = []
        got_response = False
        last_url = join_url(target, CANDIDATE_PATHS[0])
        for path in CANDIDATE_PATHS:
            url = join_url(target, path)
            last_url = url
            try:
                resp = session.get(url)
            except Exception:
                continue
            got_response = True
            hit, reason, count = _is_druid_data(resp)
            if hit:
                hits.append((path, reason, count))

        if hits:
            emit(ok("存在芋道 Druid 监控未授权"))
            detail = "；".join(f"{p}（{c} 条）" for p, _r, c in hits)
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=join_url(target, hits[0][0]),
                evidence=f"Druid 监控数据匿名可读：{detail}——泄露数据源配置、SQL 与访问 URI",
                fix=self.fix,
                extra={
                    "vuln_type": "unauth_access",
                    "payload_class": "yudao_druid_monitor",
                    "plugin_name": "yudao_druid_monitor_unauth",
                    "endpoints": [p for p, _r, _c in hits],
                },
            )

        if not got_response:
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=last_url,
                evidence="全部候选路径请求失败（网络异常），无法判定",
            )
        emit(no("不存在芋道 Druid 监控未授权"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=last_url,
            evidence=f"已探测 {len(CANDIDATE_PATHS)} 条 Druid 数据接口，均未返回有效监控数据（ResultCode≠1 或 Content 为空）",
        )
