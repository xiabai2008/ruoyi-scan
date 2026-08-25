"""未授权访问批量检测——Actuator / Druid / Swagger / 后台用户列表端点。"""
# 未授权访问批量检测：Actuator / Druid / Swagger / 后台 列表接口
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_positive
from plugins.base import PluginBase


class UnauthBatchPlugin(PluginBase):
    name = "未授权访问（批量）"
    cve = "N/A"
    severity = "medium"
    category = "vuln"
    description = (
        "批量探测若依/Spring 常见未授权端点：Actuator env、Druid 监控、Swagger UI、后台用户列表。"
        "任一端点未授权暴露即存在信息泄露风险"
    )
    fix = (
        "生产环境关闭 Actuator 或加鉴权；Druid 监控路径限制 IP 白名单并修改默认口令；"
        "Swagger 仅在测试环境启用；后台接口接入统一鉴权框架"
    )
    fix_detail = (
        "【Actuator 加固】application.yml 仅暴露必要端点：\n"
        "  management.endpoints.web.exposure.include: health,info\n"
        "  management.endpoint.env.enabled: false  # 禁用 env 端点\n"
        '【Actuator 鉴权】SecurityConfig.configure(): .antMatchers("/actuator/**").hasRole("ADMIN")\n'
        "【Druid 加固】修改默认口令 + IP 白名单：\n"
        "  spring.datasource.druid.stat-view-servlet.login-username: <强口令>\n"
        "  spring.datasource.druid.stat-view-servlet.allow: 127.0.0.1\n"
        "【Swagger 加固】生产环境禁用：swagger.enabled: false\n"
        "【后台鉴权】/system/user/list 等接口添加 @PreAuthorize(\"@ss.hasPermi('system:user:list')\")\n"
        "【WAF 规则】拦截外网对 /actuator, /druid, /swagger, /system/user/* 的访问\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. Actuator env 泄露（含数据库密码、Redis 密码等）：\n"
        'curl "http://target/actuator/env" | python -m json.tool | head -50\n'
        "\n"
        "# 2. Actuator heapdump 下载内存快照（可提取密码）：\n"
        'curl "http://target/actuator/heapdump" -o heapdump.bin\n'
        '  # 使用 Eclipse MAT 或 jhat 分析 heapdump.bin，搜索 "password" 关键字\n'
        "\n"
        "# 3. Druid 监控未授权访问：\n"
        'curl -i "http://target/druid/index.html"\n'
        "\n"
        "# 4. 后台用户列表未授权（敏感接口）：\n"
        'curl "http://target/system/user/list" | python -m json.tool\n'
        "  # 返回 JSON 含用户名、手机号、邮箱等敏感信息即未授权"
    )
    # D2：未授权访问全版本存在（取决于配置）
    affected_versions = ""  # 未授权访问检测为配置类风险，全版本适用
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # D7: WAF 绕过支持
    vuln_type = "info_leak"
    supports_waf_bypass = True

    # 各端点判定规则：路径 + 特征关键字（任一命中即视为该端点未授权暴露）
    ENDPOINTS = [
        {
            "name": "Spring Actuator env",
            "path": "actuator/env",
            "keywords": ["propertySources", "activeProfiles", "applicationConfig", "environment"],
            "need_json": True,
        },
        {
            "name": "Druid 监控",
            "path": "druid/index.html",
            "keywords": ["Druid Stat Index", "druid-stat", "Druid Monitor"],
            "need_json": False,
        },
        {
            "name": "Swagger UI",
            "path": "swagger-ui.html",
            "keywords": ["Swagger UI", "swagger-ui", "SwaggerBootstrap"],
            "need_json": False,
        },
        {
            "name": "后台用户列表",
            "path": "system/user/list",
            "keywords": ['"rows"', '"code":200', "admin", "userId"],
            "need_json": True,
        },
    ]

    # 鉴权拦截关键字（命中即视为该端点已保护）
    AUTH_BLOCK_KEYWORDS = ["登录", "请先登录", "unauthorized", "认证失败", "无法访问系统资源", "signin", "login"]

    def verify(self, target, session):
        """批量探测多个常见未授权端点，对每个端点单独评定（已鉴权 / 未授权 / 网络异常）。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（SessionManager 管理连接复用）
        @return: ScanResult — 任一端点未授权暴露则 CONFIRMED；全部已保护则 SAFE；全部网络异常则 UNKNOWN
        """
        hit_endpoints = []  # 命中端点详情
        all_status = []  # 各端点状态（CONFIRMED/SAFE/UNKNOWN）
        got_response = False

        for ep in self.ENDPOINTS:
            url = join_url(target, ep["path"])
            try:
                resp = session.get(url)
            except Exception:
                all_status.append((ep["name"], "UNKNOWN", "网络异常"))
                continue
            got_response = True
            text = resp.text or ""
            # getattr 兜底：兼容无 status_code 属性的响应对象（如测试桩），缺失时按 0 参与后续判定
            code = getattr(resp, "status_code", 0)
            ctype = resp.headers.get("Content-Type", "") if hasattr(resp, "headers") else ""

            # 1) 鉴权拦截关键字命中 → 该端点已保护（使用 match_positive 统一降误报）
            if match_positive(text, self.AUTH_BLOCK_KEYWORDS):
                all_status.append((ep["name"], "SAFE", "已鉴权拦截"))
                continue

            # 2) 状态码 401/403 → 鉴权拦截
            if code in (401, 403):
                all_status.append((ep["name"], "SAFE", f"HTTP {code} 鉴权拦截"))
                continue

            # 3) 特征关键字命中（且 JSON 端点要求响应确实是 JSON）
            matched_kw = [kw for kw in ep["keywords"] if kw.lower() in text.lower()]
            # 无 JSON Content-Type 时用响应体首字符（{ 或 [）推断 JSON，兼容未声明类型的自研接口
            is_json = "json" in ctype.lower() or text.lstrip().startswith("{") or text.lstrip().startswith("[")
            if ep.get("need_json") and not is_json:
                all_status.append((ep["name"], "SAFE", "响应非 JSON"))
                continue

            if matched_kw:
                # 进一步控误报（P1 修复）：
                # Druid/Swagger 等 HTML 端点必须 HTTP 200（避免 404 自定义错误页含关键字而误报）；
                # JSON 端点（Actuator/user/list）已在上方 need_json 兜底
                if not ep.get("need_json") and code != 200:
                    all_status.append((ep["name"], "SAFE", f"含关键字 {matched_kw} 但 HTTP {code} 非 200"))
                    continue
                hit_endpoints.append(
                    {
                        "name": ep["name"],
                        "url": url,
                        "code": code,
                        "matched_keywords": matched_kw,
                        "snippet": text[:200],
                    }
                )
                all_status.append((ep["name"], "CONFIRMED", f"命中关键字 {matched_kw} HTTP {code}"))
                continue

            # 4) 无特征关键字：可能是 404 或其他业务响应，判 SAFE（该端点不构成未授权暴露）
            all_status.append((ep["name"], "SAFE", f"无特征关键字 HTTP {code}"))

        # 汇总判定：任一端点命中即 CONFIRMED
        if hit_endpoints:
            hit_names = [h["name"] for h in hit_endpoints]
            print(ok(f"存在未授权访问（命中端点：{','.join(hit_names)}）"))
            evidence_lines = [f"{h['name']}({h['url']}) 命中 {h['matched_keywords']}" for h in hit_endpoints]
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=target,
                evidence="; ".join(evidence_lines),
                extra={
                    "hit_endpoints": hit_endpoints,
                    "all_status": [{"name": n, "status": s, "detail": d} for n, s, d in all_status],
                },
                fix=self.fix,
            )

        # 全部端点未命中
        if got_response:
            print(no("不存在未授权访问漏洞（所有端点均已鉴权或无特征）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_SAFE,
                url=target,
                evidence="; ".join(f"{n}:{s}({d})" for n, s, d in all_status),
            )

        print(no("未授权访问检测：所有端点网络异常，无法判定"))
        return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=target, evidence="所有端点均网络异常")
