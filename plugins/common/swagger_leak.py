# Swagger/OpenAPI 文档泄露 — 常见 API 文档路径探测
import json

from common.logger import get_logger
from common.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase

logger = get_logger(__name__)


class SwaggerLeakPlugin(PluginBase):
    """检测目标是否存在 Swagger/OpenAPI/Knife4j 等 API 文档未授权访问"""

    name = "Swagger API 文档泄露"
    cve = "N/A"
    severity = SEVERITY_MEDIUM
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    # v1.6：被测命题是「**不登录**就能访问」。共享会话可能已被默认口令/爆破插件
    # 登录污染，带着 admin 的 cookie 探到这里拿到的 200 只证明「登录后能访问」，
    # 不构成未授权漏洞（客户现场：Swagger 开了但配了认证 → 误报「未授权访问」）。
    # 声明后引擎会在会话被污染时注入干净的 SessionManager。
    anonymous_probe = True
    description = "目标存在未授权的 API 文档界面，攻击者可了解全部 API 接口、参数及数据结构，辅助进一步攻击"
    fix = "为 Swagger/API 文档添加访问认证，或在生产环境中禁用 Swagger 端点"
    fix_detail = (
        "【配置加固·Spring Boot】application.yml 生产环境禁用文档端点：\n"
        "  springdoc.api-docs.enabled: false\n"
        "  springdoc.swagger-ui.enabled: false\n"
        "  springfox.documentation.enabled: false          # springfox 旧版\n"
        "  knife4j.production: true                        # Knife4j 生产环境屏蔽\n"
        "【代码修复·Spring Security】SecurityConfig.configure() 强制鉴权：\n"
        '  http.antMatchers("/swagger-ui/**", "/swagger-ui.html",\n'
        '                   "/swagger-resources/**", "/v2/api-docs", "/v3/api-docs/**",\n'
        '                   "/doc.html", "/druid/**").authenticated()\n'
        "【配置加固·nginx】为文档端点加 Basic Auth 或限制内网访问：\n"
        '  location /swagger-ui/ { auth_basic "Restricted"; auth_basic_user_file /etc/nginx/.htpasswd; }\n'
        "  location /v3/api-docs { allow 10.0.0.0/8; deny all; }\n"
        "【配置加固·Druid】StatViewServlet 配置 loginUsername / loginPassword，并设置 allow IP 白名单\n"
        "【WAF 规则】拦截 /swagger-ui.html、/swagger-resources、/v2/api-docs、/v3/api-docs、/doc.html、/druid/index.html 外网访问\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 探测 Swagger UI 主界面：\n"
        'curl -i "http://target/swagger-ui.html"\n'
        'curl -i "http://target/swagger-ui/index.html"\n'
        'curl -i "http://target/doc.html"   # Knife4j\n'
        "\n"
        '# 预期响应（漏洞存在）：HTTP/1.1 200，HTML 含 "Swagger UI" / "knife4j" / "OpenAPI"\n'
        "\n"
        "# 2. 直接读取 API 定义 JSON（含全部接口、参数、模型）：\n"
        'curl "http://target/v2/api-docs" | python -m json.tool | head -100\n'
        'curl "http://target/v3/api-docs" | python -m json.tool\n'
        'curl "http://target/swagger-resources" | python -m json.tool\n'
        "\n"
        '# 预期响应：JSON 含 "swagger":"2.0" 或 "openapi":"3.0.x"，paths 列出全部接口\n'
        "\n"
        "# 3. Druid 监控台未授权（同属信息泄露）：\n"
        'curl -i "http://target/druid/index.html"\n'
        'curl -i "http://target/druid/sql.html"   # 可查看慢 SQL、执行过的语句\n'
        "\n"
        "# 4. 基于泄露的 API 文档批量调用敏感接口：\n"
        'curl "http://target/api/admin/users"     # 利用文档发现的越权接口\n'
        'curl -X POST "http://target/api/admin/user" -H "Content-Type: application/json" -d \'{"name":"test"}\''
    )

    # 常见 API 文档路径
    _SWAGGER_PATHS = [
        "/swagger-ui.html",
        "/swagger-ui/",
        "/swagger-ui/index.html",
        "/swagger-resources",
        "/swagger-resources/configuration/ui",
        "/v2/api-docs",
        "/v3/api-docs",
        "/v3/api-docs/swagger-config",
        "/doc.html",
        "/api-docs",
        "/api.html",
    ]

    @classmethod
    def _is_swagger_payload(cls, payload) -> bool:
        """结构化识别 Swagger 文档，不做子串匹配。

        F7-4：只有 **有内容** 的文档才算泄露。C3 蜜罐的 /v2/api-docs 返回
        {"swagger":"2.0","paths":{}}，旧实现只看 swagger 键就 CONFIRMED（B 类硬误报）。

        支持：
          - 文档对象：paths 是 dict 且非空
          - springfox /swagger-resources 数组：非空且元素含 swaggerVersion
          - springdoc swagger-config：urls 非空
        """
        if isinstance(payload, dict):
            paths = payload.get("paths")
            if isinstance(paths, dict) and paths:
                return True
            urls = payload.get("urls")
            if isinstance(urls, list) and urls:
                return True
            return False
        if isinstance(payload, list):
            return bool(payload) and all(isinstance(item, dict) and "swaggerVersion" in item for item in payload)
        return False

    def verify(self, target, session) -> ScanResult:
        """未授权判定必须用**匿名会话**：高权会话下的 200 是「登录后可读」，不是未授权。

        与 file_upload / unauth_batch 同一口径，避免 P1-0 登录修复后把登录后可见的
        Swagger/OpenAPI 文档误报成「未授权公开」。
        """
        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        try:
            return self._verify_with_session(target, probe)
        finally:
            if probe is not session:
                probe.close()

    def _verify_with_session(self, target, session) -> ScanResult:
        """探测常见 Swagger/OpenAPI/Knife4j/Druid 文档端点是否可匿名访问

        @param target: 目标站点 URL
        @param session: 匿名（或测试用）HTTP 会话
        @return: STATUS_CONFIRMED（发现公开文档端点）、STATUS_SAFE（确认未暴露）或 STATUS_UNKNOWN（全部探测失败）
        """
        found = []
        failed = 0
        for path in self._SWAGGER_PATHS:
            url = join_url(target, path)
            try:
                resp = session.get(url)
                if resp.status_code != 200:
                    continue
                full_text = resp.text or ""
                ct = (resp.headers.get("Content-Type") or "").lower()
                # F7-4：只有可解析且有实际接口的文档 JSON 才算 swagger_leak。
                # 纯 UI 页面（/swagger-ui.html 可访问但文档为空）交给
                # ruoyi_swagger_unauth 报「UI 可访问」，不在本插件计为文档泄露。
                if "json" not in ct:
                    continue
                try:
                    payload = json.loads(full_text)
                except (TypeError, ValueError):
                    payload = None
                if self._is_swagger_payload(payload):
                    found.append(path)
            except Exception:
                # 单个路径失败不中断整体探测，但必须计数：全部失败时不能当"确认未暴露"（SAFE）
                failed += 1
                logger.debug("Swagger 探测请求失败: %s", url, exc_info=True)
                continue
        if found:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=target,
                evidence=f"发现 {len(found)} 个 API 文档端点: {', '.join(found)}",
                extra={"paths": found},
                fix=self.fix,
            )
        # 所有路径均请求失败（网络异常等）→ 无法判定，按契约返回 UNKNOWN，绝不判 SAFE
        if failed == len(self._SWAGGER_PATHS):
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=target,
                evidence=f"{failed} 个文档路径全部请求失败（网络异常），无法判定",
            )
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=target,
            evidence="未发现公开的 Swagger/OpenAPI/Knife4j 文档端点（Druid 由未授权访问插件单独判定）",
        )
