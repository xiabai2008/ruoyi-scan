# Spring Boot Actuator 未授权访问（信息泄露 / 配置暴露）
# 漏洞原因：Actuator 端点未配置认证，/actuator/env 等暴露配置、环境变量、密码与密钥。
# 本插件仅做存在性验证：探测 /actuator 与 /actuator/env 是否均可匿名访问。
from core.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.colors import no, ok
from lib.http import join_url
from plugins.base import PluginBase


class SpringActuatorUnauthPlugin(PluginBase):
    name = "Spring Boot Actuator 未授权访问"
    cve = "N/A"
    severity = "medium"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
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
        # 第一关：/actuator 是否可访问（返回 HAL JSON）
        url_root = join_url(target, "/actuator")
        try:
            r1 = session.get(url_root)
        except Exception as e:
            print(no("Spring Boot Actuator 未授权（网络异常）"))
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url_root, evidence=str(e))

        if r1.status_code != 200 or "application/json" not in (r1.headers.get("Content-Type", "") or ""):
            print(no("不存在 Spring Boot Actuator 未授权（/actuator 不可达）"))
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
            return ScanResult(kind="vuln", name=self.name, status=STATUS_UNKNOWN, url=url_env, evidence=str(e))

        if r2.status_code == 200 and "application/json" in (r2.headers.get("Content-Type", "") or ""):
            print(ok("存在 Spring Boot Actuator 未授权访问"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url_env,
                evidence="/actuator/env 可匿名访问，泄露环境变量与配置属性",
                fix=self.fix,
            )
        print(no("不存在 Spring Boot Actuator 未授权（/actuator/env 需认证）"))
        return ScanResult(
            kind="vuln",
            name=self.name,
            status=STATUS_SAFE,
            url=url_env,
            evidence="/actuator 可达但 /actuator/env 需认证（端点已保护）",
        )
