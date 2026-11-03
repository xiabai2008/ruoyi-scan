# 芋道 yudao 租户列表未授权访问：/system/tenant/simple-list 匿名可读全部租户
#
# 为什么这是一个漏洞而不是特性
# ==========================
# 芋道是多租户 SaaS 框架，`TenantController.simpleList()` 上标了
# `@PermitAll @TenantIgnore`——设计意图是给**登录页**用（用户输入租户名时联想），
# 所以匿名可读是刻意的。但代价是：
#   - 外部可枚举出全部租户 ID 与名称（多租户隔离的起点情报）
#   - 拿到 tenant-id 后可以定向尝试该租户下的弱口令/越权
#   - 二开项目常把这份清单当内部数据，泄露即事故
#
# 实测（2026-11-03 Y1 真实站，Spring Boot 2.7.18 / 2026.10-jdk8-SNAPSHOT）：
#   GET /admin-api/system/tenant/simple-list
#   200 {"code":0,"msg":"","data":[{"id":1,"name":"芋道源码",...},...]}  （4 个租户）
#
# 判定口径
# ========
# **必须**是真实租户数据，不能只看 code==0：
#   - 芋道的成功码是 0（**不是 200**），这是它与若依最明显的区别
#   - data 必须是非空数组，且元素含 id + name 两个字段
# 单看 code==0 会被任意「空成功响应」骗到（实测 /tenant/get-id-by-name 也返回
# {"code":0,"data":null}，那是查不到，不是泄露）。
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import parse_json_body
from lib.reporter import emit
from plugins.base import PluginBase

# 芋道的 API 前缀。用双候选：网关部署在 /admin-api 下，单体直连时在根路径。
CANDIDATE_PATHS = (
    "/admin-api/system/tenant/simple-list",
    "/system/tenant/simple-list",
)


def _is_tenant_list(resp):
    """判定响应是否为芋道真实租户列表

    正向证据（全部满足）：
    - 可解析为 JSON 对象
    - code == 0（芋道成功码）
    - data 是非空 list
    - 至少一个元素同时含 id 与 name（只认结构，不认具体租户名）
    """
    body = parse_json_body(resp)
    if not isinstance(body, dict):
        return False, "响应非 JSON 对象"
    # 芋道成功码是 0；不是 0 一律不认（401 是「账号未登录」）
    if body.get("code") != 0:
        return False, f"业务码 code={body.get('code')}（非 0，不是成功响应）"
    data = body.get("data")
    if not isinstance(data, list):
        return False, "data 不是数组"
    if not data:
        return False, "data 为空数组（可能是查不到，不是泄露）"
    if not any(isinstance(it, dict) and "id" in it and "name" in it for it in data):
        return False, "数组元素不含 id+name（不是租户结构）"
    return True, f"未授权返回 {len(data)} 个租户"


class YudaoTenantUnauthPlugin(PluginBase):
    name = "芋道租户列表未授权"
    cve = "N/A"
    severity = "medium"
    category = "vuln"
    description = (
        "芋道 yudao 的 /system/tenant/simple-list 接口匿名可读，"
        "泄露全部租户 ID 与名称——多租户隔离的起点情报，可用于定向攻击"
    )
    fix = "为 /system/tenant/simple-list 增加鉴权，或只返回当前域名对应的单个租户"
    fix_detail = (
        "【代码修复】TenantController.simpleList() 去掉 @PermitAll，改为 @PreAuthenticated：\n"
        "  公开的登录页只需要 get-id-by-name / get-by-website 这类按名查询接口，\n"
        "  不需要把「全部租户」列出来。\n"
        "【配置加固】若确实要给登录页用，限制返回字段为 id 与 name，去掉联系方式等内部信息。\n"
        "【WAF 规则】对未携带 token 的 /admin-api/system/tenant/simple-list 请求返回 401。\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 未携带任何凭证请求租户列表：\n"
        'curl -s "http://target/admin-api/system/tenant/simple-list"\n'
        "\n"
        "# 预期响应（漏洞存在）：HTTP 200，业务码是 0（芋道口径，不是 200）\n"
        '#   {"code":0,"msg":"","data":[{"id":1,"name":"芋道源码",...}, ...]}\n'
        "\n"
        "# 修复后应为：\n"
        '#   {"code":401,"msg":"账号未登录","data":null}'
    )
    # 芋道版本号是日历式（2026.10），与若依 4.x 无关，故不参与若依版本过滤
    affected_versions = ""
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "info_leak"
    supports_waf_bypass = False
    # 注意：**不设** variant。yudao 是 cms 不是 variant——
    # Router.candidates() 按 variant 过滤时会拿 fingerprint.variant（空串）
    # 与插件声明比对，若这里写 "yudao" 会导致整个包被过滤掉、路由为空。
    # （2026-11-03 实测：cms=yudao 但 resolve() 返回 []，插件一个都不跑）
    # 判定的是「**不登录**能不能读到租户清单」
    anonymous_probe = True
    # 路径自带 /admin-api 前缀（芋道固定形态），不要让引擎再追加
    self_prefixes = ("/admin-api",)

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
        """未授权读取租户列表（非破坏性，只 GET 一次）

        @param target: 目标站点基准（可能是带前缀的 /admin-api/，也可能是站点根）
        @param session: 引擎注入的匿名会话（本插件声明了 anonymous_probe）
        @return: CONFIRMED（读真实租户数据）/ SAFE（鉴权拦截或结构不符）/ UNKNOWN（全部请求失败）
        """
        got_response = False
        last_url = join_url(target, CANDIDATE_PATHS[0])
        last_reason = "未探测"
        for path in CANDIDATE_PATHS:
            url = join_url(target, path)
            last_url = url
            try:
                resp = session.get(url)
            except Exception:
                continue
            got_response = True
            hit, reason = _is_tenant_list(resp)
            if hit:
                emit(ok("存在芋道租户列表未授权访问"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=f"{reason}（匿名可读，泄露租户 ID 与名称）",
                    fix=self.fix,
                    extra={
                        "vuln_type": "info_leak",
                        "payload_class": "yudao_tenant_list",
                        "plugin_name": "yudao_tenant_unauth",
                    },
                )
            last_reason = reason

        if not got_response:
            # 三态纪律：全部请求失败 ≠ 不存在
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=last_url,
                evidence="全部候选路径请求失败（网络异常），无法判定",
            )
        emit(no("不存在芋道租户列表未授权"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=last_url,
            evidence=f"已探测 {len(CANDIDATE_PATHS)} 条候选路径，未返回真实租户列表：{last_reason}",
        )
