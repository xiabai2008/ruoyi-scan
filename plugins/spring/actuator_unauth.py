# Spring Boot Actuator 未授权访问（信息泄露 / 配置暴露）
# 漏洞原因：Actuator 端点未配置认证，/actuator/env 等暴露配置、环境变量、密码与密钥。
# 本插件仅做存在性验证：探测 /actuator 与 /actuator/env 是否均可匿名访问。
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_spring_actuator_env
from lib.reporter import emit
from plugins.base import PluginBase


class SpringActuatorUnauthPlugin(PluginBase):
    name = "Spring Boot Actuator 未授权访问"
    cve = "N/A"
    severity = "medium"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    # v1.6：判定的是「**未登录**能否访问」，必须用匿名会话探测
    # （实际隔离动作在 verify() 里，见 core/session.py::SessionManager.anonymous）。
    anonymous_probe = True
    description = "Actuator 端点 /actuator/env 可匿名访问，泄露环境变量、配置属性与密钥"
    fix = "引入 spring-boot-starter-security 为 Actuator 端点配置认证；或设置 management.endpoints.web.exposure.include 白名单"
    fix_detail = (
        "【引入依赖】pom.xml 添加 Spring Security：\n"
        "  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>\n"
        "【配置鉴权】application.yml 为 Actuator 端点配置角色：\n"
        "  management.endpoints.web.exposure.include: health,info  # 仅暴露必要端点\n"
        "  management.endpoint.env.enabled: false  # 禁用 env 端点\n"
        "  management.endpoint.heapdump.enabled: false  # 禁用 heapdump\n"
        "【SecurityConfig】SecurityConfig.configure():\n"
        '  .antMatchers("/actuator/**").hasRole("ADMIN")\n'
        "【端口隔离】management.server.port: 9090  # 管理端口与业务端口分离，仅内网访问\n"
        "【WAF 规则】拦截外网对 /actuator, /actuator/env, /actuator/heapdump 的访问\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测 Actuator 根端点：\n"
        'curl -i "http://target/actuator"\n'
        '  # 返回 200 + JSON 含 "_links" 字段即 Actuator 启用\n'
        "\n"
        "# 2. 读取环境变量与配置（含数据库密码、JWT 密钥）：\n"
        'curl "http://target/actuator/env" | python -m json.tool\n'
        "  # propertySources 含 application.yml、系统环境变量等\n"
        "\n"
        "# 3. 下载内存快照（可提取密码、token）：\n"
        'curl "http://target/actuator/heapdump" -o heapdump.bin\n'
        '  # 使用 Eclipse MAT 或 jhat 分析，搜索 "password" 关键字\n'
        "\n"
        "# 4. 列出所有已注册的 Bean（信息收集）：\n"
        'curl "http://target/actuator/beans" | python -m json.tool | head -100'
    )
    # D2：Actuator 未授权全版本存在（取决于配置）
    affected_versions = ""

    def verify(self, target, session):
        """未授权判定必须用**匿名会话**：高权会话下的 200 是「登录后可读」，不是未授权。

        与 ruoyi 侧的 nacos/minio/unauth_batch 同一口径（core.session.SessionManager.anonymous）。
        复用共享会话时，若调用方注入了 cookie/token（--auth / --auth-login），
        本插件会把「已鉴权的正常响应」误读成「未授权暴露」——
        客户现场最常见的形态是「Actuator 开了但配了认证」，此时报告会写
        「可匿名访问」，复核时被当场打回（2026-11-02 能力缺口调研 P1-13）。
        """
        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        try:
            return self._verify_anonymous(target, probe)
        finally:
            if probe is not session:
                probe.close()

    def _verify_anonymous(self, target, session):
        """验证 Actuator 未授权访问：先 /actuator 后 /actuator/env 两关探测是否均可匿名访问。
        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话
        @return: ScanResult——两关均通过返回 CONFIRMED，任一失败返回 SAFE，网络异常返回 UNKNOWN
        """
        # 第一关：/actuator 是否可访问（返回 HAL JSON）
        url_root = join_url(target, "/actuator")
        try:
            r1 = session.get(url_root)
        except Exception as e:
            emit(no("Spring Boot Actuator 未授权（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url_root, evidence=str(e))

        # /actuator 根端点必须返回 JSON 响应：Actuator 返回
        # application/vnd.spring-boot.actuator.v3+json 等厂商标型（不含字面量 application/json），
        # 故按 JSON 子类型判定，避免真实目标被误判为不可达；纯 200 HTML 错误页无效
        if r1.status_code != 200 or "json" not in (r1.headers.get("Content-Type", "") or "").lower():
            # 401/403 = 端点**存在但拒绝访问**，与「不存在」是两件事。
            # 判 SAFE 会让「Actuator 开了但配了认证」的现场被写成「确认不存在」，
            # 而报告读者据此会认为该系统没开 Actuator（2026-11-02 C5 靶场实测）。
            if r1.status_code in (401, 403):
                emit(no("Spring Boot Actuator 存在但需认证"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    status=STATUS_UNKNOWN,
                    url=url_root,
                    evidence=(
                        f"/actuator 返回 HTTP {r1.status_code}：端点存在但要求认证。"
                        "本次以未授权视角探测，无法确认是否存在未授权暴露"
                    ),
                )
            emit(no("不存在 Spring Boot Actuator 未授权（/actuator 不可达）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                status=STATUS_SAFE,
                url=url_root,
                evidence="/actuator 不可达（404 或非 JSON 响应）",
            )

        # 第二关：/actuator/env 是否可访问（含配置属性）
        url_env = join_url(target, "/actuator/env")
        try:
            r2 = session.get(url_env)
        except Exception as e:
            # 与第一关保持一致的输出：否则同一插件两阶段的控制台提示不对称
            emit(no("Spring Boot Actuator 未授权（/actuator/env 网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url_env, evidence=str(e))

        # 第二关通过才确认：/actuator 可达但 env 需认证时属“已保护”场景，不算未授权漏洞
        # Content-Type 同样按 JSON 子类型判定（Actuator 常用 v3/v2 厂商标型）；
        # 并且响应体必须是真实 env 结构（propertySources/activeProfiles 等），
        # 避免任意 200 JSON 页面（如统一错误 JSON）被误判为未授权
        env_text = r2.text or ""
        if (
            r2.status_code == 200
            and "json" in (r2.headers.get("Content-Type", "") or "").lower()
            and match_spring_actuator_env(env_text)
        ):
            emit(ok("存在 Spring Boot Actuator 未授权访问"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url_env,
                evidence="/actuator/env 可匿名访问且返回真实 env 结构（propertySources/activeProfiles）",
                fix=self.fix,
            )
        emit(no("不存在 Spring Boot Actuator 未授权（/actuator/env 需认证）"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=url_env,
            evidence="/actuator 可达但 /actuator/env 需认证（端点已保护）",
        )
