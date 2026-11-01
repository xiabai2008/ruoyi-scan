# JeecgBoot Freemarker SSTI：/jmreport/testConnection 报表数据源测试接口
# 存在性验证：提交含 ${7*7} 的模板，响应含独立数字 49 即确认（不落地 RCE payload）
# 注：该类 jmreport 模板注入与 CVE-2022-26809（Windows RPC Runtime RCE）无关，不引用该 CVE
import re

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase

# jmreport 接口的「鉴权拒绝」响应特征。
#
# 真实 JeecgBoot（实测 3.6.3）对无 Token 的 /jeecg-boot/jmreport/** 返回：
#   HTTP 200
#   {"code":500,"success":false,"message":"Token校验失败，无权限访问！","timestamp":...}
#
# 三个坑叠在一起，导致通用兜底（lib/reachability._DENY_RE）抓不到：
#   1. HTTP 状态码是 200，不是 401/403
#   2. body 里的 code 是 500（不是 401）
#   3. 文案是「无权限访问」而不是「认证失败」
# 因此本插件必须自己做这一层判定，否则会把"没资格测"判成 SAFE。
_AUTH_WALL_RE = re.compile(
    r"Token校验失败|token验证失败|无权限访问|请先登录|未登录|"
    # 若依自身与 JeecgBoot 共用的分离版标准文案：
    #   {"code":401,"msg":"认证失败，无法访问系统资源"}
    r"认证失败|登录已过期|会话已失效|"
    r"invalid\s+token|unauthorized|access\s+denied",
    re.IGNORECASE,
)


def _jmreport_auth_wall(resp) -> str:
    """判断 jmreport 响应是否是「要求鉴权」，返回原因；不是则返回空串。

    只在响应体确实是 JSON 业务包装时才判定 —— 避免把普通 HTML 错误页
    里偶然出现的"No permission"当成鉴权墙。
    """
    text = (getattr(resp, "text", "") or "")[:2000]
    if not text:
        return ""
    # 只认 JSON 业务响应（真实 jmreport 恒返回 JSON）；HTML 页面另走既有逻辑
    looks_json = (
        text.lstrip().startswith("{")
        or "application/json" in str((getattr(resp, "headers", {}) or {}).get("Content-Type", "")).lower()
    )
    if not looks_json:
        return ""
    m = _AUTH_WALL_RE.search(text)
    if not m:
        return ""
    return f"响应含鉴权拒绝特征「{m.group(0)}」：{text[:120]}"


# 探测请求体（reproduce 示例与 verify 实际请求共用同一份，避免两处手写体静默漂移）
PROBE_BODY = (
    '{"dbType":"MYSQL","dbName":"test","url":"jdbc:mysql://127.0.0.1:3306/test",'
    '"userName":"root","password":"x","connUrl":"jdbc:mysql://127.0.0.1:3306/test?query='
    '${7*7}"}'
)


class JeecgFreemarkerSstiPlugin(PluginBase):
    name = "JeecgBoot 报表 SSTI"
    # 该类 jmreport/testConnection 模板注入无对应 CVE（CVE-2022-26809 属 Windows RPC RCE，系误标）
    cve = "N/A"
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
        "  -d '" + PROBE_BODY + "'\n"
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
        body = PROBE_BODY
        try:
            resp = session.post(url, data=body, headers={"Content-Type": "application/json"})
            text = resp.text or ""
        except Exception as e:
            # 网络异常归 UNKNOWN：测不到 ≠ 安全，避免漏报
            emit(no("JeecgBoot 报表 SSTI（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        # 鉴权失败 → UNKNOWN（测不到 ≠ 不存在）。
        #
        # 真实 JeecgBoot 的 jmreport 接口要 Token，未授权响应形如：
        #   HTTP 200 + {"code":500,"success":false,"message":"Token校验失败，无权限访问！"}
        # 注意它 **HTTP 状态码是 200、body code 是 500**，既不是 401/403，
        # 也不含"认证失败"字样 —— lib/reachability 的 _DENY_RE 兜底抓不到，
        # 于是旧实现按"没命中 SSTI 特征"判 SAFE，把"没资格测"写成了"确认不存在"。
        #
        # 实测（2026-11-01 R10 JeecgBoot 3.6.3）：该接口匿名 POST 恒返回上式，
        # 旧实现判 SAFE —— 这就是本插件历史上从未 CONFIRMED 的直接原因之一。
        wall = _jmreport_auth_wall(resp)
        if wall:
            emit(no("JeecgBoot 报表 SSTI（需鉴权，无法判定）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                evidence=f"接口要求鉴权，SSTI 无法验证（{wall}）；需带有效 Token 复测",
            )

        # 加固判定：必须同时满足三个条件
        #   1) 响应为 JSON 业务响应——JeecgBoot 报表接口返回 JSON，正常 HTML 页面不可能满足
        #   2) 含独立数字 49（正则数字边界）——原 `"49" in text` 会把 490/1490/1949/时间戳等误判
        #   3) 不含原始表达式 7*7（排除载荷被原样回显）
        # 历史缺陷：原判定仅 `status==200 and "49" in text`，
        # 任何正文含「49」（页码、行号、商品数量等）的 200 页面都会被误报为 SSTI。
        content_type = (resp.headers.get("Content-Type") or "").lower()
        is_json_resp = "application/json" in content_type
        has_eval_result = re.search(r"(?<!\d)49(?!\d)", text) is not None
        if resp.status_code == 200 and is_json_resp and has_eval_result and "7*7" not in text:
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
