"""RuoYi Swagger/Knife4j API 文档未授权访问检测（信息泄露类）。"""

# RuoYi Swagger 未授权 API 文档泄露
import requests

from common.logger import get_logger
from common.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase

logger = get_logger(__name__)


class RuoyiSwaggerUnauthPlugin(PluginBase):
    name = "RuoYi Swagger 未授权访问"
    cve = "N/A"
    severity = SEVERITY_MEDIUM
    category = "vuln"
    description = "RuoYi 的 Swagger/Knife4j API 文档可被未授权访问，暴露全部 API 接口及参数"
    fix = "在 SecurityConfig 中为 Swagger 相关路径添加认证拦截，或在生产环境禁用 Swagger"
    fix_detail = (
        "【代码修复】SecurityConfig.configure() 添加 Swagger 路径鉴权：\n"
        '  .antMatchers("/swagger-ui.html", "/swagger-resources/**", "/webjars/**",\n'
        '               "/v2/api-docs", "/doc.html", "/swagger-ui/**").authenticated()\n'
        "【生产禁用】application.yml 关闭 Swagger：\n"
        "  swagger.enabled: false\n"
        "  knife4j.production: true  # Knife4j 生产模式\n"
        "【Profile 隔离】仅在 dev profile 启用 Swagger：\n"
        '  @Profile({"dev","test"}) @EnableSwagger2\n'
        "【WAF 规则】拦截外网对 /swagger-ui.html, /v2/api-docs, /doc.html 路径的访问\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 探测 Swagger UI 是否可访问：\n"
        'curl -i "http://target/swagger-ui.html"\n'
        '  # 返回 200 + 含 "Swagger UI" 字样即未授权可访问\n'
        "\n"
        "# 探测 Knife4j 文档（若依常用）：\n"
        'curl -i "http://target/doc.html"\n'
        "\n"
        "# 拉取 OpenAPI JSON（包含全部 API 接口定义）：\n"
        'curl "http://target/v2/api-docs" | python -m json.tool | head -50\n'
        "  # 返回的 JSON 含所有接口路径、参数定义、响应模型"
    )
    # D2：Swagger 未授权全版本存在（取决于配置）
    affected_versions = ""  # springfox/springdoc 未授权文档各版本均存在风险，全版本适用
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # D7: WAF 绕过支持
    vuln_type = "info_leak"
    supports_waf_bypass = True

    def verify(self, target, session) -> ScanResult:
        """批量探测 Swagger/Knife4j 常见文档路径是否未授权公开。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（SessionManager 管理连接复用）
        @return: ScanResult — 任一路径命中文档特征则 CONFIRMED，全部无特征则 SAFE，全部请求失败则 UNKNOWN（不误判 SAFE）
        """
        # P3 三态补全：所有请求异常 → UNKNOWN，不误判为 SAFE
        any_success = False
        # 依次覆盖三种文档形态：springfox（swagger-ui.html）、knife4j（doc.html）、OpenAPI JSON（v2/api-docs）
        # SpringDoc / RuoYi-Cloud 用 /swagger-ui/index.html（3.6.8 实测：200 + 真 Swagger UI 页面，
        # 而 /swagger-ui.html 不存在），漏掉这条会把真实暴露判成 SAFE。
        for path in ["/swagger-ui.html", "/swagger-ui/index.html", "/doc.html", "/v2/api-docs"]:
            url = join_url(target, path)
            try:
                resp = session.get(url)
            except requests.exceptions.RequestException as e:
                # 仅吞掉传输异常（并留痕）：单路径不可达不中断整体探测，编程错误不再被静默吞没
                logger.debug("Swagger 路径探测请求失败（%s）: %s", url, e, exc_info=True)
                continue
            any_success = True
            if resp.status_code == 200:
                # 匹配整个响应体（resp.text 已物化，[:500] 截断会在大型文档上漏掉标题标记）；
                # 统一转小写比较，覆盖 "Swagger UI" 等大写形态；原 '"swagger"' 为 "swagger" 的子串冗余
                body = (resp.text or "").lower()
                if any(kw in body for kw in ["swagger", "knife4j", "接口文档"]):
                    return ScanResult(
                        kind=self.category,
                        name=self.name,
                        severity=self.severity,
                        status=STATUS_CONFIRMED,
                        url=url,
                        evidence=f"{path} 可未授权访问",
                        fix=self.fix,
                    )
        if not any_success:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=target,
                evidence="所有 Swagger 路径请求失败（网络异常）",
            )
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=target,
            evidence="Swagger/Doc 路径未公开",
        )
