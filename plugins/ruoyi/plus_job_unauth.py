"""RuoYi-Plus 定时任务管理接口（/monitor/job）未授权访问探测（存在性验证）。"""

# RuoYi-Plus 定时任务未授权探测（variant='ruoyi-plus' 专项）
# Plus 版 /monitor/job 定时任务管理接口：未登录可访问即存在越权（存在性验证）
import json

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from config import settings
from core.http import join_url
from core.session import SessionManager
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase


class PlusJobUnauthPlugin(PluginBase):
    name = "RuoYi-Plus 定时任务未授权"
    cve = "N/A"
    severity = "high"
    category = "vuln"
    description = "RuoYi-Vue-Plus 定时任务模块 /monitor/job/list 未登录可访问（越权查看/调度任务）"
    fix = "确认 /monitor/** 接口已加 Sa-Token 鉴权；移除排除路径白名单"
    fix_detail = (
        "【配置加固】application.yml 的 sa-token.exclude-path-list 中移除 /monitor/**\n"
        "【代码修复】MonitorJobController 增加 @SaCheckPermission 注解\n"
        "【WAF 规则】拦截未携带 satoken 的 /monitor/job/** 请求\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4"
    )
    reproduce = (
        'curl "http://target/prod-api/monitor/job/list?pageNum=1&pageSize=10"\n'
        "# 预期响应：未携带 token 时返回业务 JSON（code=200 + rows）即未授权可访问"
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    vuln_type = "unauth"
    supports_waf_bypass = False
    variant = "ruoyi-plus"

    def verify(self, target, session):
        """不带认证凭证访问定时任务列表接口，验证未授权访问是否成立。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（SessionManager 管理连接复用）；若已残留认证态则改用独立无凭据会话
        @return: ScanResult — 返回 rows/total 任务列表 JSON 且无登录特征则 CONFIRMED，401/403 或无特征则 SAFE，网络异常则 UNKNOWN
        """
        # Plus 版对外请求统一经 /prod-api 网关前缀转发，探测路径须保留此前缀
        url = join_url(target, "/prod-api/monitor/job/list?pageNum=1&pageSize=10")

        # 裸请求（不携带任何 Cookie/Token）：若仍返回业务数据即说明 Sa-Token 鉴权未生效。
        # 但共享 SessionManager 可能已被其它插件登录污染（认证状态泄漏，见 core/engine.py），
        # 此时复用共享会话发出的请求实际已鉴权，会把「已鉴权可访问」误报成「未授权可访问」；
        # 检测到认证态残留即改用独立的无凭据会话发探测请求。
        probe_session = session
        own_session = None
        try:
            if self._has_auth_state(session):
                own_session = SessionManager(timeout=settings.TIMEOUT)
                probe_session = own_session
            # allow_redirects=False：默认跟随重定向会把「302 → /login」透明转成 200 登录页，
            # 使下方 3xx「重定向 → 鉴权生效」分支不可达（与 plus_auth_login.py 保持一致）
            resp = probe_session.get(url, allow_redirects=False)
        except Exception as e:
            emit(no("RuoYi-Plus 定时任务未授权（网络异常）"))
            return ScanResult(kind="info", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
        finally:
            if own_session is not None:
                own_session.close()
        # 判定（2026-09-17 多版本矩阵实测后加固）
        # 真实缺陷：原判定为 `status==200 and match_positive(text, ["rows","total","code"],
        # negatives=["login","unauthorized"])`。问题有三：
        #   1. positives 中的 "code" 过于泛用——任何含验证码字段的 HTML 都命中；
        #   2. negatives 用小写 "login"，而真若依登录页里是 `id="formLogin"`（大写 L），排除失效；
        #   3. 未校验响应是 JSON。
        # 三者叠加后，在纯 RuoYi 单体实例的登录页 HTML 上误报「未授权任务列表」。
        # 加固后要求：非 3xx + JSON Content-Type + 解析出的 JSON 同时含 rows 与 total 键。
        if 300 <= resp.status_code < 400:
            emit(no("不存在 RuoYi-Plus 定时任务未授权（响应为重定向）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_SAFE,
                url=url,
                evidence=f"HTTP {resp.status_code} 重定向至 {resp.headers.get('Location', '')}，鉴权生效",
            )

        content_type = (resp.headers.get("Content-Type") or "").lower()
        body = None
        if resp.status_code == 200 and "application/json" in content_type:
            # 优先 resp.json()；失败则回退 json.loads(text)。
            # 回退是为了兼容未实现 .json() 的轻量响应替身（测试用），
            # 不削弱判定强度——仍要求解析出合法 JSON 且含 rows/total 键。
            try:
                body = resp.json()
            except Exception:
                try:
                    body = json.loads(resp.text or "")
                except Exception:
                    body = None

        # 未授权 + 真正的业务列表 JSON（rows 与 total 两个键同时存在）→ 确认
        if isinstance(body, dict) and "rows" in body and "total" in body:
            emit(ok("存在 RuoYi-Plus 定时任务未授权"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=f"未携带 token 返回任务列表 JSON（rows/total 键存在，HTTP {resp.status_code}）",
                fix=self.fix,
                extra={"vuln_type": "unauth", "plugin_name": "plus_job_unauth"},
            )
        emit(no("不存在 RuoYi-Plus 定时任务未授权"))
        return ScanResult(
            kind="info",
            name=self.name,
            status=STATUS_SAFE,
            url=url,
            evidence=f"HTTP {resp.status_code} / Content-Type={content_type or '(空)'}，非未授权业务 JSON",
        )

    @staticmethod
    def _has_auth_state(session):
        """共享会话是否残留认证态（Cookie / Authorization 头）

        其它插件（如后台默认口令登录）在共享 SessionManager 上登录后，凭证会一直保留
        （认证状态泄漏）。本插件的「裸请求」前提随即失效，必须改用独立的无凭据会话发探测，
        否则「已鉴权可访问」会被误判为「未授权可访问」。
        """
        inner = getattr(session, "session", None)  # SessionManager 内部的 requests.Session
        if inner is None:
            return False
        try:
            if len(list(inner.cookies)) > 0:
                return True
            headers = inner.headers or {}
            return any(str(k).lower() == "authorization" for k in headers)
        except Exception:
            return False
