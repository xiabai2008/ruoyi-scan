# RocketMQ Dashboard 未授权访问检测（F7 中间件包）
# 非破坏性：GET /rocketmq/ 与常见 dashboard 路径，无鉴权返回控制台即确认
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_positive
from lib.reporter import emit
from plugins.base import PluginBase


class RocketmqUnauthPlugin(PluginBase):
    """检测 RocketMQ Dashboard 未授权访问（F7 中间件）：可无鉴权访问控制台即确认"""

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
    reproduce = 'curl "http://target/rocketmq/"\n# 预期响应：返回 RocketMQ Dashboard HTML（含 rocketmq 标题/图表资源）'
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "unauth"
    # v1.6：被测命题是「**不登录**就能访问」。共享会话可能已被默认口令/爆破插件
    # 登录污染，带着 admin 的 cookie 探到这里拿到的 200 只证明「登录后能访问」，
    # 不构成未授权漏洞（客户现场：Swagger 开了但配了认证 → 误报「未授权访问」）。
    # 声明后引擎会在会话被污染时注入干净的 SessionManager。
    anonymous_probe = True
    supports_waf_bypass = False

    def verify(self, target, session):
        """未授权判定必须用**匿名会话**：高权会话下的 200 是「登录后可读」，不是未授权。

        与 unauth_batch / ruoyi_swagger_unauth 同一口径（core.session.SessionManager.anonymous）。
        复用共享会话时，若调用方注入了 cookie/token（--auth / --auth-login），
        本插件会把「已鉴权的正常响应」误读成「未授权暴露」——客户现场最常见的形态是
        「接口开了但配了认证」，此时报告会写「未授权访问」，复核时被当场打回。
        """
        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        try:
            return self._verify_anonymous(target, probe)
        finally:
            if probe is not session:
                probe.close()

    def _verify_anonymous(self, target, session):
        """探测 RocketMQ Dashboard 常见路径，命中且无登录墙即确认未授权

        @param target: 目标站点 URL
        @param session: 已配置的 HTTP 会话
        @return: ScanResult（CONFIRMED 表示可无凭证访问控制台）
        """
        # 探测路径。顺序即优先级：
        #   1. "/"            —— **真实 rocketmq-dashboard 的默认位置**
        #   2. "/rocketmq/"    —— 少数反向代理按前缀挂载时
        #   3. "/dashboard/"   —— 二开项目常见自定义前缀
        #   4. "/rocketmq-console-ng/" —— 旧版 war 包部署名
        #
        # 为什么把 "/" 放第一位：rocketmq-console-ng（现 rocketmq-dashboard）是**独立的
        # Spring Boot Web 应用**，官方发布包默认 context-path 为空，控制台直接挂在根路径。
        # 旧实现只探后三条（都是"猜前缀"），真实部署一条都命中不了。
        #
        # 实测（2026-11-01 C4-3 靶场，复刻真实 dashboard 路由）：
        #   GET /                    → 200，正文含 mqnamesrv / RocketMQ Dashboard
        #   GET /rocketmq/           → 404
        #   GET /dashboard/          → 404
        #   GET /rocketmq-console-ng/ → 404
        #   → 旧实现判 SAFE（漏报），这就是该插件历史上从未 CONFIRMED 过的原因。
        paths = ["/", "/rocketmq/", "/dashboard/", "/rocketmq-console-ng/"]
        evidence_url = ""
        # SAFE 证据用最后探测的 URL：只报裸 target 无法说明实际探测到哪个路径（与 CONFIRMED 的 evidence_url 对齐）
        last_url = ""
        got_response = False
        last_error = None
        for p in paths:
            # 统一去掉前导 /：与 join_url 的双斜杠归一化配合，保证各候选路径拼接结果一致
            url = join_url(target, p.lstrip("/"))
            last_url = url
            try:
                resp = session.get(url)
                text = resp.text or ""
            except Exception as e:
                # 单路径网络异常不阻断其余候选路径：直接 return UNKNOWN 会漏掉后续可用路径
                last_error = e
                continue
            got_response = True
            # 控制台特征 + 排除登录页：命中 RocketMQ 专有标识但含 login/sign in 说明有鉴权，不算未授权
            # 历史缺陷：positives 曾含 "dashboard"/"topic" 等泛化词，任意含 "topics" 的普通页面即误报；
            # 现在只认 RocketMQ 专有标识（rocketmq / mqnamesrv）
            #
            # request_path 必传：catch-all 路由（如 Spring 的 `/**`）会把请求路径写进页面，
            # 于是 /rocketmq/ 的响应体里天然含 "rocketmq" —— 不传路径就会 100% 误报。
            # 实测 2026-11-01 盲测 v2 C4-6：
            #   GET /rocketmq/ → <html><body><h2>页面: rocketmq/</h2></body></html>
            if resp.status_code == 200 and match_positive(
                text.lower(),
                ["rocketmq", "mqnamesrv"],
                negatives=["login", "sign in"],
                request_path=p,
            ):
                evidence_url = url
                break
        if evidence_url:
            emit(ok("存在 RocketMQ Dashboard 未授权"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=evidence_url,
                evidence="未授权返回 Dashboard 页面",
                fix=self.fix,
                extra={"vuln_type": "unauth", "plugin_name": "rocketmq_unauth"},
            )
        if not got_response:
            # 所有候选路径均请求失败：测不到 ≠ 安全，归 UNKNOWN
            emit(no("RocketMQ Dashboard 未授权（网络异常）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=join_url(target, paths[0].lstrip("/")),
                evidence=str(last_error),
            )
        emit(no("不存在 RocketMQ Dashboard 未授权"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=last_url or target,
            evidence=f"{len(paths)} 个 dashboard 路径均未命中 RocketMQ 控制台特征（最后探测 {last_url or target}）",
        )
