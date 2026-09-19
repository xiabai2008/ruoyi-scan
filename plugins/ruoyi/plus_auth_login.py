"""RuoYi-Plus 认证服务 /auth/login 接口存在性探测（Sa-Token 架构确认，无破坏性 payload）。"""

# RuoYi-Plus 登录接口未授权探测（variant='ruoyi-plus' 专项）
# Plus 版使用 Sa-Token 认证，登录接口为 /auth/login（独立认证服务）
# 存在性验证：POST 空凭据探测接口存在性 + 是否返回业务 JSON（未配置登录限制时）
import json

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase


class PlusAuthLoginProbePlugin(PluginBase):
    name = "RuoYi-Plus 认证接口探测"
    cve = "N/A"
    severity = "low"
    category = "vuln"
    description = "RuoYi-Vue-Plus 认证服务 /auth/login 接口探测（Sa-Token 架构确认 + 登录风控检查）"
    fix = "确认 /auth/login 启用验证码与登录限流（Plus 需配置 captchaEnabled 与登录失败锁定）"
    fix_detail = (
        "【配置加固】application.yml 确认 captchaEnabled: true 且启用登录失败次数限制\n"
        "【代码修复】登录接口加 RateLimit 注解（Sa-Token 内置限流）\n"
        "【合规】OWASP A07:2021 身份认证失败；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl -X POST "http://target/auth/login" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{"username":"admin","password":"x"}\'\n'
        "# 预期响应：JSON 含 code/msg 字段（认证服务存在且可探测）"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A07:2021"
    vuln_type = "auth"
    supports_waf_bypass = False
    # F6：仅 ruoyi-plus 变体执行
    variant = "ruoyi-plus"

    def verify(self, target, session):
        """探测 /auth/login 认证接口是否存在，确认 RuoYi-Plus 的 Sa-Token 认证服务架构。

        判定说明（2026-09-17 多版本矩阵实测后加固）
        ------------------------------------------
        真实缺陷：RuoYi 单体版（非 Plus）对未知路径 `/auth/login` 返回 **302 → /login**。
        原实现未禁用重定向，requests 自动跟随到登录页 HTML（HTTP 200），
        而该 HTML 含验证码字段名 `code`，与判定用的 `match_positive(text, ["code","msg"])`
        子串匹配叠加后，**在一个纯 4.7.8 实例上误报 CONFIRMED**。
        （该缺陷由 lab/version_matrix 真实环境扫描发现，mock 基线无法覆盖。）

        加固后需同时满足：
          1. 状态码不是 3xx（重定向到登录页 = 该路径不是独立认证服务）；
          2. 响应声明 JSON Content-Type；
          3. 能解析成 JSON 且**同时含 code 与 msg 两个键**（键存在性判断，而非子串匹配）。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（SessionManager 管理连接复用）
        @return: ScanResult — 满足上述三条则 CONFIRMED，否则 SAFE，网络异常则 UNKNOWN
        """
        url = join_url(target, "/auth/login")
        try:
            # 固定假凭据（admin/x）：仅触发服务端返回业务响应，不做真实账号登录尝试
            # allow_redirects=False 是关键：禁止跟随 302 落到登录页 HTML
            resp = session.post(
                url,
                data='{"username":"admin","password":"x"}',
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            )
        except Exception as e:
            emit(no("RuoYi-Plus 认证接口探测（网络异常）"))
            return ScanResult(kind="info", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))

        # 1) 3xx：重定向到登录页，说明该路径不是独立的 Plus 认证服务
        if 300 <= resp.status_code < 400:
            emit(no("未探测到 RuoYi-Plus 认证服务（响应为重定向，非独立认证接口）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_SAFE,
                url=url,
                evidence=f"HTTP {resp.status_code} 重定向至 {resp.headers.get('Location', '')}，非独立认证服务",
            )

        # 2) 认证服务可能返回 200/400/401/500；404/405 等代表接口不存在
        if resp.status_code not in (200, 400, 401, 500):
            emit(no("未探测到 RuoYi-Plus 认证服务"))
            return ScanResult(
                kind="info", name=self.name, status=STATUS_SAFE, url=url, evidence=f"HTTP {resp.status_code}"
            )

        # 3) 必须声明 JSON 且能解析出 code/msg 两个键——不用子串匹配（HTML 里的 captcha 字段名即可命中）
        content_type = (resp.headers.get("Content-Type") or "").lower()
        if "application/json" not in content_type:
            emit(no("未探测到 RuoYi-Plus 认证服务（响应非 JSON）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_SAFE,
                url=url,
                evidence=f"HTTP {resp.status_code} 但 Content-Type={content_type or '(空)'}，非业务 JSON",
            )
        try:
            body = resp.json()
        except Exception:
            # 回退 json.loads(text)：兼容未实现 .json() 的轻量响应替身（测试用），
            # 不削弱判定强度——仍要求解析出合法 JSON 且同时含 code/msg 键。
            try:
                body = json.loads(resp.text or "")
            except Exception:
                body = None
        if isinstance(body, dict) and "code" in body and "msg" in body:
            emit(ok("确认 RuoYi-Plus 认证服务（建议人工验证登录风控）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"认证接口返回业务 JSON（含 code/msg 键，HTTP {resp.status_code}）",
                fix=self.fix,
                extra={"vuln_type": "auth", "plugin_name": "plus_auth_probe"},
            )
        emit(no("未探测到 RuoYi-Plus 认证服务"))
        return ScanResult(
            kind="info",
            name=self.name,
            status=STATUS_SAFE,
            url=url,
            evidence="JSON 响应缺少 code/msg 键，判为非 Sa-Token 认证服务",
        )
