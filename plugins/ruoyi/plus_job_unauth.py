"""RuoYi-Plus 定时任务管理接口（/monitor/job）未授权访问探测（存在性验证）。"""

# RuoYi-Plus 定时任务未授权探测（variant='ruoyi-plus' 专项）
# Plus 版 /monitor/job 定时任务管理接口：未登录可访问即存在越权（存在性验证）
import json

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase

# 若依 AjaxResult 里表示「路由/端点不存在」的业务码。
# 若依对未知路由返回 HTTP 200 + code=404（不是 HTTP 404），所以必须看业务码。
_ENDPOINT_MISSING_CODES = frozenset({"404"})


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
    # 版本范围（2026-11-02 v1.5.6 WP3 实测补正）：
    # Plus 5.6.2 的定时任务已迁到 **SnailJob**（独立调度中心，依赖 snail-job-client-*），
    # 源码里**根本没有 SysJobController**，/monitor/job/** 返回 code=404「请求地址不存在」。
    # 此前 affected_versions 为空 = 全版本适用，等于对 5.6.2 这种结构性无该端点的站点
    # 也照样探测并判 SAFE——把「端点不存在」和「鉴权生效」混为一谈。
    #
    # 上限取 <5.6：5.6 系列起改用 SnailJob。更早的 5.x（含 5.5）仍是 Quartz +
    # MonitorJobController 形态，插件适用。
    # ⚠ 该上限是按「5.6.2 实测无该端点 + 5.6 引入 SnailJob」推定的，未逐一验证
    # 5.0–5.5 每个小版本；若现场遇到 5.5.x 也判 SAFE，应先确认端点是否真的存在。
    affected_versions = ">=5.0,<5.6"
    # v1.5.6 WP1：本插件路径里**自带** /prod-api（Plus 的固定对外前缀）。
    # 站点真实 context-path 也是 /prod-api 时，引擎不能再把它追加到基准上，
    # 否则拼成 /prod-api/prod-api/... 双前缀 → 302 登录墙 → 判 SAFE（假阴性）。
    # 两者不同时（如 D1 的 /portal）不豁免，基准仍推进到真实 context-path。
    path_scope = "api"
    self_prefixes = ("/prod-api",)
    # v1.6：本插件原本手写了一套「共享会话有认证态就改用独立会话」的逻辑
    # （_has_auth_state + 自建 SessionManager）。该逻辑已下沉到引擎：
    # 声明 anonymous_probe=True 即可，引擎统一处理，不必每个插件各写一套。
    # 手写实现保留了一段时间，现由基类能力接管，避免「各抄一遍然后各自漂移」
    # （file_read / file_read_path 各自维护 passwd 判定最后必须抽到 lib/matcher 就是前车之鉴）。
    anonymous_probe = True

    def verify(self, target, session):
        """不带认证凭证访问定时任务列表接口，验证未授权访问是否成立。

        @param target: 目标站点根 URL
        @param session: 探测会话。引擎已在会话被登录污染时注入干净会话
            （本插件声明了 anonymous_probe=True，见类属性说明）
        @return: ScanResult — 返回 rows/total 任务列表 JSON 且无登录特征则 CONFIRMED，401/403 或无特征则 SAFE，网络异常则 UNKNOWN
        """
        # Plus 版对外请求统一经 /prod-api 网关前缀转发，探测路径须保留此前缀
        url = join_url(target, "/prod-api/monitor/job/list?pageNum=1&pageSize=10")

        # 裸请求（不携带任何 Cookie/Token）：若仍返回业务数据即说明 Sa-Token 鉴权未生效。
        # 会话隔离由引擎统一处理（anonymous_probe），此处直接使用传入的会话。
        try:
            # allow_redirects=False：默认跟随重定向会把「302 → /login」透明转成 200 登录页，
            # 使下方 3xx「重定向 → 鉴权生效」分支不可达（与 plus_auth_login.py 保持一致）
            resp = session.get(url, allow_redirects=False)
        except Exception as e:
            emit(no("RuoYi-Plus 定时任务未授权（网络异常）"))
            return ScanResult(kind="info", name=self.name, status=STATUS_UNKNOWN, url=url, evidence=str(e))
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
        # 端点结构性不存在 → UNKNOWN，不能判 SAFE（2026-11-02 WP3 实测）
        #
        # Plus 5.6.2 的定时任务已迁到 SnailJob（独立调度中心），源码里根本没有
        # SysJobController，/monitor/job/** 返回 code=404「请求地址不存在」。
        # 这与「接口存在但鉴权生效」是两件完全不同的事：
        #   - 鉴权生效 → SAFE（确认安全）
        #   - 端点不存在 → UNKNOWN（没有可测的东西，不能宣称"确认不存在漏洞"）
        # 旧实现把两者都归到 SAFE，等于用「地址错了」冒充「系统是安全的」。
        #
        # 判据用若依 AjaxResult 的业务错误码，不猜 HTTP 状态（若依未知路由也返回 200）：
        #   {"code":404,"msg":"请求地址不存在","data":null}
        if isinstance(body, dict) and str(body.get("code")) in _ENDPOINT_MISSING_CODES:
            emit(no("RuoYi-Plus 定时任务端点不存在（版本已改用 SnailJob）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                evidence=(
                    f"业务码 code={body.get('code')}（{body.get('msg') or '请求地址不存在'}）："
                    "该站点无 /monitor/job/** 端点（Plus 5.6+ 定时任务改用 SnailJob），"
                    "本项无从判定，不构成「不存在漏洞」"
                ),
            )
        emit(no("不存在 RuoYi-Plus 定时任务未授权"))
        return ScanResult(
            kind="info",
            name=self.name,
            status=STATUS_SAFE,
            url=url,
            evidence=f"HTTP {resp.status_code} / Content-Type={content_type or '(空)'}，非未授权业务 JSON",
        )
