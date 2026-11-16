"""RuoYi Swagger/Knife4j API 文档未授权访问检测（信息泄露类）。"""

# RuoYi Swagger 未授权 API 文档泄露
import json

import requests

from common.logger import get_logger
from common.models import SEVERITY_MEDIUM, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.matcher import is_not_real_resource, is_real_swagger_doc
from plugins.base import PluginBase

logger = get_logger(__name__)

# UI 页面特征：仅证明「UI 可打开」，不证明「接口定义可读」
_UI_KEYWORDS = [
    "swagger-ui",
    "swagger ui",
    "swagger-ui-bundle",
    "swagger-resources",
    "knife4j",
    "接口文档",
    '"swagger"',
    '"openapi"',
]

# 文档 JSON 端点：只有这些返回「有实际接口」的结构化文档才判 CONFIRMED
_DOC_PATHS = (
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/api-docs/swagger-config",
    "/swagger-resources",
)

# UI 页面端点：可达但拿不到非空文档时，不作为未授权泄露证据
_UI_PATHS = (
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/doc.html",
)


class RuoyiSwaggerUnauthPlugin(PluginBase):
    name = "RuoYi Swagger 未授权访问"
    cve = "N/A"
    severity = SEVERITY_MEDIUM
    category = "vuln"
    # v1.6：文档端点位置随框架而异——分离版在 {base}/v3/api-docs，
    # 而芋道这类网关架构在**站点根**（实测 Y1：根 200+373KB，/admin-api/v3/api-docs
    # 只有 48 字节错误页）。声明 both 让引擎对两个基准各探一次。
    path_scope = "both"
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
    # v1.6：被测命题是「**不登录**就能访问」。共享会话可能已被默认口令/爆破插件
    # 登录污染，带着 admin 的 cookie 探到这里拿到的 200 只证明「登录后能访问」，
    # 不构成未授权漏洞（客户现场：Swagger 开了但配了认证 → 误报「未授权访问」）。
    # 声明后引擎会在会话被污染时注入干净的 SessionManager。
    anonymous_probe = True
    supports_waf_bypass = True

    def verify(self, target, session) -> ScanResult:
        """未授权判定必须用**匿名会话**：高权会话下的 200 是「登录后可读」，不是未授权。

        与 file_upload / unauth_batch 同一口径：插件判定的是「未授权可达」，不能复用
        调用方注入的 admin cookie/token；否则 P1-0 登录修复后会把登录后可见的 Swagger
        误报成「未授权访问」。
        """
        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        try:
            return self._verify_with_session(target, probe)
        finally:
            if probe is not session:
                probe.close()

    def _verify_with_session(self, target, session) -> ScanResult:
        """批量探测 Swagger/Knife4j 文档是否未授权公开。

        C3 蜜罐实测（2026-11-16）：`/swagger-ui.html` 返回 200 + 一个真的
        Swagger UI 骨架页，但它引用的 `/v2/api-docs` 是
        `{"swagger":"2.0","paths":{}}`。旧实现命中 UI 页关键字就判 CONFIRMED，
        把「假 UI 页」当成接口泄露（B 类误报）。UI 页本身不泄露接口，因此：

        - 文档端点：必须是可解析 JSON 且 `paths`/`urls`/`swagger-resources`
          有实际内容（见 `lib.matcher.is_real_swagger_doc`）；
        - UI 页：只记为「可达」，不能单独成立；拿不到非空文档时判 SAFE。

        @param target: 目标站点根 URL
        @param session: 匿名（或测试用）HTTP 会话
        @return: ScanResult — 有非空文档 CONFIRMED；UI 可达但文档为空 SAFE；
                 全部请求失败/无法确认 UNKNOWN（不误判 SAFE）
        """
        any_success = False
        doc_requests_ok = False
        ui_reachable = False
        ui_url = ""

        # 1) 文档 JSON：唯一能证明「接口定义真的泄露」的证据
        for path in _DOC_PATHS:
            url = join_url(target, path)
            try:
                resp = session.get(url)
            except requests.exceptions.RequestException as e:
                # 仅吞掉传输异常（并留痕）：单路径不可达不中断整体探测，编程错误不再被静默吞没
                logger.debug("Swagger 文档端点请求失败（%s）: %s", url, e, exc_info=True)
                continue
            any_success = True
            doc_requests_ok = True
            if resp.status_code != 200:
                continue
            text = resp.text or ""
            # 先排除 catch-all 路径回显：`/**` 兜底会把请求路径写进正文
            if is_not_real_resource(text, path):
                continue
            ctype = (resp.headers.get("Content-Type") or "").lower() if hasattr(resp, "headers") else ""
            if "json" not in ctype and not text.lstrip().startswith(("{", "[")):
                continue
            try:
                payload = json.loads(text)
            except (TypeError, ValueError):
                continue
            if is_real_swagger_doc(payload):
                if isinstance(payload, dict):
                    count = len(payload.get("paths") or payload.get("urls") or {})
                else:
                    count = len(payload)
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=f"{path} 返回可用 API 文档（{count} 条接口定义）",
                    fix=self.fix,
                )

        # 2) UI 页面：只记录可达性，不单独构成「未授权访问」证据
        for path in _UI_PATHS:
            url = join_url(target, path)
            try:
                resp = session.get(url)
            except requests.exceptions.RequestException as e:
                logger.debug("Swagger UI 探测请求失败（%s）: %s", url, e, exc_info=True)
                continue
            any_success = True
            if resp.status_code != 200:
                continue
            text = resp.text or ""
            if is_not_real_resource(text, path):
                continue
            if any(kw in text.lower() for kw in _UI_KEYWORDS):
                ui_reachable = True
                ui_url = url

        if not any_success:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=target,
                evidence="所有 Swagger 路径请求失败（网络异常）",
            )
        if ui_reachable and not doc_requests_ok:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=ui_url,
                evidence="Swagger UI 页面可达，但所有文档端点请求失败，无法确认接口定义是否泄露",
            )
        if ui_reachable:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=ui_url,
                evidence="Swagger UI 页面可达但文档 JSON 为空或不可用（假 UI 页/文档未启用），不构成接口泄露",
            )
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=target,
            evidence="Swagger/Doc 路径未公开",
        )
