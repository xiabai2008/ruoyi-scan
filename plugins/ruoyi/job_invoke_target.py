# -*- coding: utf-8 -*-
"""RuoYi 定时任务 invokeTarget 未做白名单校验（可写入任意调用目标）

漏洞
====
`SysJobController.editSave` 在 4.7.0 之前**只校验 Cron 表达式与 `rmi://` 关键字**，
不限制 invokeTarget 能调用什么方法：

    漏洞版（<=4.6.x，v4.6.2 实测）：
        if (!CronUtils.isValid(job.getCronExpression()))        return error("Cron表达式不正确");
        else if (StringUtils.containsIgnoreCase(invokeTarget, Constants.LOOKUP_RMI))
                                                                return error("目标字符串不允许'rmi://'调用");
        return toAjax(jobService.updateJob(job));               // ← 任意 invokeTarget 直接入库

    修复版（>=4.7.0，v4.7.8 实测）：
        ...(Cron / rmi 同前)...
        else if (containsAnyIgnoreCase(invokeTarget, {LOOKUP_LDAP, LOOKUP_LDAPS}))  return error("不允许'ldap'调用");
        else if (containsAnyIgnoreCase(invokeTarget, {HTTP, HTTPS}))                return error("不允许'http(s)'调用");
        else if (containsAnyIgnoreCase(invokeTarget, JOB_ERROR_STR))                return error("目标字符串存在违规");
        else if (!ScheduleUtils.whiteList(invokeTarget))                            return error("目标字符串不在白名单内");

`ScheduleUtils.whiteList`（4.7.0 新增）对单级 `beanName.method(args)` 走「bean 包名」判定：
包名需含 `com.ruoyi` 且**不得命中** `JOB_ERROR_STR`：

    JOB_ERROR_STR = { "java.net.URL", "javax.naming.InitialContext", "org.yaml.snakeyaml",
                      "org.springframework", "org.apache",
                      "com.ruoyi.common.utils.file", "com.ruoyi.common.config" }

影响：可写入 `ruoYiConfig.setProfile(...)`（配置项被改，是任意文件读取链的一环）、
`org.springframework.*`（JNDI/反序列化面）等调用目标，进而提权到 RCE。
本插件确认的是**这个前提缺陷**（白名单缺失），而不是替用户执行破坏性载荷。

判定方式：**只写不执行**（2026-09-19 校准）
==========================================
原实现走「写 `setProfile('/etc/passwd')` → run → 下载 2.txt → 看是否含 passwd 特征」的
完整利用链，但有两个硬伤，已废弃：

1. **下载路径拼错**：`resourceDownload` 的
   `downloadPath = RuoYiConfig.getProfile() + substringAfter(resource, "/profile")`，
   原实现发 `resource=2.txt`（不含 `/profile` 前缀）→ `substringAfter` 返回空串
   → 拼出的是**目录本身** → `FileInputStream` 读目录抛异常被 catch 吞掉 → 响应恒为 0 字节。
   无论目标有没有漏洞都读不到内容。
2. **`setProfile` 一旦执行就无法还原**：profile 目录（上传根）被改掉后，我们无法从
   HTTP 侧读回原值（该值只在 application.yml 里），目标的上传/下载会一直错到重启。
   扫描器不应留下这种状态。

现在改为直接判定**白名单是否生效**——这正是版本边界所在，且全程无破坏性副作用：

  1. 读任务列表拿真实 jobId 与原 invokeTarget/status；
  2. edit 写入判别载荷 `ruoYiConfig.setProfile('<随机标记>')`，**同时 status='1'（暂停）**
     避免 cron 在探测窗口内把载荷真跑起来；
  3. 判定 edit 响应：
     - `{"code":0}` → 载荷被接受 → **CONFIRMED**
     - `目标字符串不在白名单内` → **SAFE**
     - HTML（权限页）→ **UNKNOWN**（账号权限不足，不能当结论）
  4. **回读任务列表确认写入生效**（证据可审计），随后还原原 invokeTarget/status 并二次确认。

选用 `ruoYiConfig` 作判别载荷的原因：它所在的包 `com.ruoyi.common.config` 在 4.7.0+ 的
`JOB_ERROR_STR` 黑名单里 → 修复版必拒；而 `ryTask.ryParams` 这类自带示例任务在修复版
仍被放行（白名单允许 `com.ruoyi` 包），**无法区分版本**——这一点是实测踩出来的。
"""

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from config import settings
from core.auth_chain import LOGIN_CAPTCHA, isolated_auth_session
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase

logger = get_logger(__name__)

# 修复版在白名单校验失败时返回的文案（服务端生成，非页面静态文本）
WHITELIST_MARKER = "不在白名单内"
# 判别载荷：bean 位于 com.ruoyi.common.config —— 4.7.0+ 的 JOB_ERROR_STR 会拒绝
PAYLOAD_TEMPLATE = "ruoYiConfig.setProfile('{marker}')"
# 探测载荷在任务列表里的关键片段（用于回读确认写入生效）
PAYLOAD_KEY = "ruoYiConfig.setProfile"


class JobInvokeTargetPlugin(PluginBase):
    """定时任务 invokeTarget 白名单缺失检测"""

    name = "定时任务调用目标未校验"
    cve = "N/A"  # 无专属 CVE（invokeTarget 白名单缺失，CNVD-2021-01931 相关但不专属）
    severity = "high"
    category = "vuln"
    vuln_type = "rce"  # 判定的是「任意调用目标可写入」——RCE 的前提
    supports_waf_bypass = True  # edit 写入可能被 WAF 拦，支持绕过重试
    description = "RuoYi <=4.6.x 的定时任务 edit 不限制 invokeTarget，可写入任意方法调用（任意文件读取/RCE 前提）"
    # D2: 影响版本（实测：4.6.2 接受任意调用目标；4.7.8/4.8.0/4.8.2/4.8.3 均拒绝）
    # 注意：运算符与版本号之间不能有空格（version_in_range 的正则会静默跳过带空格的条件）
    affected_versions = ">=4.0,<4.7"
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A01:2021"
    fix = "升级至 RuoYi 4.7.0+（editSave 增加 ScheduleUtils.whiteList 白名单校验 + JOB_ERROR_STR 黑名单）"
    fix_detail = (
        "【升级方案】升级到 RuoYi 4.7.0 或更高版本\n"
        "【代码修复】在 SysJobController.editSave 中补白名单：ScheduleUtils.whiteList(invokeTarget)，"
        "并维护 JOB_ERROR_STR 黑名单（org.springframework/org.apache/javax.naming/java.net.URL/"
        "com.ruoyi.common.config/com.ruoyi.common.utils.file）\n"
        "【权限加固】为 /monitor/job/edit 强制 monitor:job:edit 权限（4.x 各版本已带，勿因其存在而误判风险）\n"
        "【WAF 规则】拦截 /monitor/job/edit 请求体中 invokeTarget 含 ruoYiConfig/org.springframework 的写入\n"
        "【审计】对所有 invokeTarget 变更留痕并定期审计\n"
        "【合规】等保2.0 8.1.3 访问控制；OWASP A01:2021"
    )
    reproduce = (
        "# 1. 登录取会话（账号需具备 monitor:job:edit 权限）\n"
        "curl -c c.txt -X POST 'http://target/login' -d 'username=lowpriv&password=***&validateCode=***'\n"
        "\n"
        "# 2. 写入判别载荷（不执行；status=1 暂停任务以免 cron 触发）\n"
        "curl -b c.txt -X POST 'http://target/monitor/job/edit' \\\n"
        '  -d "jobId=1&jobName=x&jobGroup=DEFAULT&cronExpression=0/10+*+*+*+*+?" \\\n'
        '  -d "status=1&misfirePolicy=1&concurrent=1" \\\n'
        "  -d \"invokeTarget=ruoYiConfig.setProfile('/tmp/ruoyi_scan_probe')\"\n"
        "\n"
        '# 预期（漏洞版 <=4.6.x）：{"msg":"操作成功","code":0} —— 任意调用目标被接受\n'
        '# 预期（修复版 >=4.7.0）：{"msg":"修改任务...失败，目标字符串不在白名单内","code":500}'
    )

    def verify(self, target, session):
        """在**独立会话**中判定 invokeTarget 白名单是否生效（只写不执行）

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（本插件不使用——需鉴权，必须隔离）
        @return: ScanResult —— 载荷被接受为 CONFIRMED；被白名单拒绝为 SAFE；其余为 UNKNOWN
        """
        with isolated_auth_session(
            target,
            settings.RuoYiLowPriv.USERNAME,
            settings.RuoYiLowPriv.PASSWORD,
            timeout=settings.RuoYiAuth.TIMEOUT,
        ) as (sess, ok_login, reason):
            if not ok_login:
                hint = "（该验证需要具备 monitor:job:edit 权限的账号）" if reason != LOGIN_CAPTCHA else ""
                emit(no(f"定时任务调用目标未校验（登录失败：{reason}）{hint}"))
                return ScanResult(
                    kind="info",
                    name=self.name,
                    status=STATUS_UNKNOWN,
                    evidence=f"低权账号 {settings.RuoYiLowPriv.USERNAME} 登录失败：{reason}{hint}",
                )

            # Step 1：发现真实任务（动态，不硬编码 jobId）
            jobs = self._list_jobs(target, sess)
            if not jobs:
                emit(no("定时任务调用目标未校验（任务列表不可读）"))
                return ScanResult(
                    kind="info",
                    name=self.name,
                    status=STATUS_UNKNOWN,
                    url=join_url(target, "/monitor/job/list"),
                    evidence="登录成功但任务列表不可读（可能缺 monitor:job:list 权限），拿不到可用任务，不予判定",
                )
            job = jobs[0]
            job_id = job.get("jobId")
            orig_target = job.get("invokeTarget") or ""
            orig_status = str(job.get("status", "0"))

            # Step 2：写入判别载荷（status=1 暂停，避免 cron 在探测窗口内执行载荷）
            marker = "ruoyi_scan_" + _rand_token()
            payload = PAYLOAD_TEMPLATE.format(marker=marker)
            edit_url = join_url(target, "/monitor/job/edit")
            resp = self._edit_job(sess, url=edit_url, job=job, invoke_target=payload, status="1")
            body = resp.text or ""
            kind = self._classify(resp)

            # 权限被拦（HTML 权限页/登录页）：是账号能力问题，不是漏洞结论
            if kind == "denied":
                emit(no("定时任务调用目标未校验（账号无 monitor:job:edit 权限）"))
                return ScanResult(
                    kind="info",
                    name=self.name,
                    status=STATUS_UNKNOWN,
                    url=edit_url,
                    evidence=(
                        f"账号 {settings.RuoYiLowPriv.USERNAME} 调用 /monitor/job/edit 被权限门拦截"
                        f"（非 JSON 响应），说明其缺少 monitor:job:edit 权限——无法判定白名单是否存在"
                    ),
                )

            # Step 3：回读确认写入是否生效（证据可审计）
            written = any(PAYLOAD_KEY in str(j.get("invokeTarget") or "") for j in self._list_jobs(target, sess))

            # Step 4：还原（并二次确认）
            self._edit_job(sess, url=edit_url, job=job, invoke_target=orig_target, status=orig_status)
            restored = any(
                str(j.get("jobId")) == str(job_id) and str(j.get("invokeTarget") or "") == orig_target
                for j in self._list_jobs(target, sess)
            )
            restore_note = "，任务已还原" if restored else "，**任务还原失败，请人工核查**"

            if kind == "accepted" and written:
                emit(ok("存在定时任务调用目标未校验（可写入任意 invokeTarget）"))
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=edit_url,
                    evidence=(
                        f"/monitor/job/edit 接受了任意调用目标并写入生效（回读确认 invokeTarget="
                        f"{PAYLOAD_KEY}(...)），服务端未做白名单校验 ⇒ 可写入 ruoYiConfig.setProfile("
                        f"任意文件读取链的一环)/org.springframework.*(JNDI 面) 等调用目标。"
                        f"载荷未执行（status 置 1 暂停）{restore_note}"
                    ),
                    fix=self.fix,
                    extra={
                        "vuln_type": "rce",
                        "plugin_name": "job_invoke_target",
                        "job_id": job_id,
                        "payload": payload,
                        "write_verified": True,
                    },
                )

            if kind == "rejected" or WHITELIST_MARKER in body:
                emit(no("不存在定时任务调用目标未校验"))
                return ScanResult(
                    kind="info",
                    name=self.name,
                    status=STATUS_SAFE,
                    url=edit_url,
                    evidence=(
                        f"写入判别载荷被服务端拒绝：「{self._extract_msg(body)}」⇒ "
                        f"ScheduleUtils.whiteList 白名单校验生效{restore_note}"
                    ),
                )

            emit(no("定时任务调用目标未校验（响应形态无法定性）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=edit_url,
                evidence=(
                    f"edit 响应既非「操作成功」也非白名单拒绝（HTTP {resp.status_code}，写入生效={written}），"
                    f"形态不确定，不予判定{restore_note}"
                ),
            )

    # ── 辅助 ────────────────────────────────────────────────────

    @staticmethod
    def _list_jobs(target, session):
        """读任务列表（返回 rows；不可读返回 []）"""
        try:
            resp = session.post(join_url(target, "/monitor/job/list"), data={"pageNum": 1, "pageSize": 20})
            ct = (resp.headers.get("Content-Type") or "").lower()
            if "application/json" not in ct:
                return []
            body = resp.json()
            rows = body.get("rows") or [] if isinstance(body, dict) else []
            return [r for r in rows if r.get("jobId") is not None]
        except Exception:
            logger.debug("读取任务列表失败", exc_info=True)
            return []

    @staticmethod
    def _edit_job(session, url, job, invoke_target, status):
        """提交任务编辑（沿用任务原有字段，只替换 invokeTarget/status）"""
        data = {
            "jobId": job.get("jobId"),
            "updateBy": "admin",
            "jobName": job.get("jobName") or "ruoyi_scan_probe",
            "jobGroup": job.get("jobGroup") or "DEFAULT",
            "invokeTarget": invoke_target,
            "cronExpression": job.get("cronExpression") or "0/10 * * * * ?",
            "misfirePolicy": job.get("misfirePolicy") or "1",
            "concurrent": job.get("concurrent") or "1",
            "status": status,
            "remark": job.get("remark") or "",
        }
        try:
            return session.post(url, data=data)
        except Exception as e:
            logger.debug("任务编辑请求异常", exc_info=True)
            raise e

    @staticmethod
    def _classify(resp):
        """把 edit 响应归类：accepted / rejected / denied / other

        判定基于**解析后的 JSON 字段**而非原始响应文本的子串——服务端可能以
        unicode 转义形式返回中文（任何 json.dumps 的默认行为都是转义），
        直接对 resp.text 做中文子串匹配会漏判（实测踩到，导致 SAFE 被误判为 UNKNOWN）。
        """
        ct = (resp.headers.get("Content-Type") or "").lower()
        if "json" not in ct:
            return "denied"  # HTML：权限页/登录页，属账号能力问题
        try:
            body = resp.json()
        except Exception:
            return "other"
        if not isinstance(body, dict):
            return "other"
        code = body.get("code")
        msg = str(body.get("msg", ""))
        if WHITELIST_MARKER in msg:
            return "rejected"
        if code in (0, 200) and "失败" not in msg:
            return "accepted"
        return "other"

    @staticmethod
    def _extract_msg(body):
        """从 JSON 响应里取 msg（取不到返回原文片段）"""
        try:
            import json as _json

            return str(_json.loads(body).get("msg", "")) or body[:80]
        except Exception:
            return (body or "")[:80]


def _rand_token() -> str:
    """随机标记（避免与目标上已有内容混淆，并让证据可定位到本次探测）"""
    import secrets

    return secrets.token_hex(6)
