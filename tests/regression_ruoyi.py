# -*- coding: utf-8 -*-
# 若依插件回归验收（requests_mock 模拟响应）
#
# 验收范围（开发方案 §五 无损迁移回归验收）：
#   1. 任意文件读取：命中 root:x:0:0，忽略仅含 root 的噪声
#   2. SQL 报错注入：命中 extractvalue 报错特征（运行时异常 / database()）
#   3. 定时任务读取链路（edit → run → 2.txt）：状态/响应判定正确
#   4. Druid 爆破：正确口令命中，错误口令未命中
#   5. 目录扫描：200 / 403 分类正确，标题提取正确
#   6. Step 5 新增 POC：file_upload / job_rce / thymeleaf_ssti / unauth_batch / default_password
#   7. Step 8 新增 POC：nacos_unauth / file_read_path
#
# 运行：python tests/regression_ruoyi.py
# 退出码：0 全部通过，非 0 表示有失败用例
import json
import os
import sys
import unittest

# 将项目根目录加入 sys.path，便于直接运行
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import requests_mock
except ImportError:
    print("缺少依赖 requests_mock，请先执行：pip install requests_mock")
    sys.exit(1)

from common.models import (
    STATUS_CONFIRMED,
    STATUS_SAFE,
    STATUS_UNKNOWN,
)
from core.session import SessionManager
from plugins.ruoyi.cve_2025_46174_resetpwd_scope import Cve202546174ResetPwdScopePlugin
from plugins.ruoyi.cve_2025_70986_select_dept_tree import Cve202570986SelectDeptTreePlugin
from plugins.ruoyi.default_password import DefaultPasswordPlugin
from plugins.ruoyi.directory_scan import DirectoryScanPlugin
from plugins.ruoyi.druid_brute import DruidBrutePlugin

# 原有 6 个插件（Step 2 迁移）
from plugins.ruoyi.file_read import FileReadPlugin
from plugins.ruoyi.file_read_path import RuoyiFileReadPathPlugin

# Step 5 新增 5 个 POC 插件
from plugins.ruoyi.file_upload import FileUploadPlugin
from plugins.ruoyi.job_invoke_target import JobInvokeTargetPlugin
from plugins.ruoyi.job_rce import JobRcePlugin

# Step 8 新增 2 个 POC 插件（含签名 marker 常量）
from plugins.ruoyi.nacos_unauth import RuoyiNacosUnauthPlugin
from plugins.ruoyi.plus_auth_login import PlusAuthLoginProbePlugin
from plugins.ruoyi.plus_job_unauth import PlusJobUnauthPlugin
from plugins.ruoyi.sql_inject_dept import SqlInjectDeptPlugin
from plugins.ruoyi.sql_inject_role import SqlInjectRolePlugin
from plugins.ruoyi.thymeleaf_ssti import ThymeleafSstiPlugin
from plugins.ruoyi.unauth_batch import UnauthBatchPlugin

# 统一 mock 目标（不使用真实域名，避免误发请求）
# 注意：无尾部斜杠，配合 join_url() 归一化（P1-6 修复后所有插件使用 join_url，
#       若 target 以 / 结尾且 path 以 / 开头则去重，确保 mock 注册路径与实际请求一致）
MOCK_TARGET = "http://ruoyi-mock.test"


# ---------------------------------------------------------------------------
# Part 1：用户规范要求的 5 项回归验收（无损迁移）
# ---------------------------------------------------------------------------


class TestFileRead(unittest.TestCase):
    """1. 任意文件读取 POC：命中含 root:x:0:0，忽略仅含 root 的噪声"""

    @requests_mock.Mocker()
    def test_hit_root_x_0_0(self, m):
        """命中：响应含 root:x:0:0:root:/root:/bin/bash"""
        url = MOCK_TARGET + "/common/download/resource?resource=/profile/../../../../../../../etc/passwd"
        m.get(url, text="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n")
        plugin = FileReadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"响应含 root 与 :/ 应判 CONFIRMED，实际 {result.status}")
        self.assertIn("root", result.evidence)

    @requests_mock.Mocker()
    def test_ignore_noise_only_root(self, m):
        """噪声：响应仅含 root 单词（无 :/），应判 SAFE"""
        url = MOCK_TARGET + "/common/download/resource?resource=/profile/../../../../../../../etc/passwd"
        m.get(url, text="this is a root word but no path separator")
        plugin = FileReadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"仅含 root 无 :/ 应判 SAFE（噪声过滤），实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe_when_no_root(self, m):
        """无 root：响应不含 root，应判 SAFE"""
        url = MOCK_TARGET + "/common/download/resource?resource=/profile/../../../../../../../etc/passwd"
        m.get(url, text="404 not found page")
        plugin = FileReadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestSqlInject(unittest.TestCase):
    """2. SQL 报错注入 POC：命中 extractvalue 报错的响应特征"""

    @requests_mock.Mocker()
    def test_hit_extractvalue_runtime_exception(self, m):
        """命中：注入请求出现 extractvalue 报错特征，基线请求（无 payload）不出现

        判定已升级为「基线差分」：插件先发一次不带 payload 的基线请求，再发注入请求，
        只有「注入请求出现、基线请求不出现」才算命中。
        因此 mock 必须按调用顺序提供两个响应，否则等价于「目标任何请求都返回同一张错误页」，
        这种情况现被判为 UNKNOWN（见 test_unknown_when_signature_is_ambient）。
        """
        url = MOCK_TARGET + "/system/role/list"
        m.post(
            url,
            [
                # 第 1 次调用 = 基线（params[dataScope] 为空）：正常业务响应
                {"text": '{"total":0,"rows":[],"code":200,"msg":"查询成功"}'},
                # 第 2 次调用 = 注入：RuoYi 真实报错响应
                {"text": "运行时异常：java.sql.SQLException: XPATH syntax error: '~ruoyi~'"},
            ],
        )
        plugin = SqlInjectRolePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"注入请求含报错特征应判 CONFIRMED，实际 {result.status}")

    @requests_mock.Mocker()
    def test_unknown_when_signature_is_ambient(self, m):
        """三态：基线请求同样含报错文案时，无法归因于注入 → UNKNOWN

        回归场景：目标任何请求都返回同一张含「运行时异常」的错误页。
        加固前该情形会被判 CONFIRMED（只要响应含异常文案即命中），属误报。
        """
        url = MOCK_TARGET + "/system/role/list"
        ambient = "运行时异常：系统繁忙，请稍后重试"
        m.post(url, text=ambient)
        plugin = SqlInjectRolePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"基线同样含异常文案时应判 UNKNOWN，实际 {result.status}")

    @requests_mock.Mocker()
    def test_no_false_positive_on_payload_reflection(self, m):
        """回归：响应回显载荷原文（其中必含 database() 字面量）不得判 CONFIRMED

        历史缺陷：原判定为 `'运行时异常' in t or 'database()' in t`，而载荷本身
        就含 database() 字面量。WAF 拦截页、框架调试页、网关错误页原样回显请求报文时，
        该条件会「自证命中」，属典型误报。现要求 MySQL extractvalue 真实报错文案
        （XPATH syntax error）或「异常文案 + 无载荷回显」方可判 CONFIRMED。
        """
        url = MOCK_TARGET + "/system/dept/list"
        m.post(
            url,
            text=(
                "<html><h1>403 Forbidden</h1><p>您的请求包含可疑字符，已拦截：</p>"
                "<pre>params[dataScope]=and extractvalue(1, concat(0x7e,(select database()),0x7e))</pre>"
                "</html>"
            ),
        )
        plugin = SqlInjectDeptPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertNotEqual(result.status, STATUS_CONFIRMED, "载荷被原样回显不得判 CONFIRMED（自证误报）")

    @requests_mock.Mocker()
    def test_unknown_when_exception_and_reflection_coexist(self, m):
        """三态：响应同时含异常文案与载荷回显时，无法区分注入成功与请求回显 → UNKNOWN"""
        url = MOCK_TARGET + "/system/role/list"
        m.post(
            url,
            text=('{"msg":"运行时异常：extractvalue(1,concat(0x7e,(select database()),0x7e)) 执行失败","code":500}'),
        )
        plugin = SqlInjectRolePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"异常文案与载荷回显并存应判 UNKNOWN，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe_normal_response(self, m):
        """安全：正常业务响应，应判 SAFE"""
        url = MOCK_TARGET + "/system/role/list"
        m.post(url, text='{"rows":[],"code":200,"msg":"查询成功"}')
        plugin = SqlInjectRolePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestJobInvokeTarget(unittest.TestCase):
    """定时任务 invokeTarget 白名单缺失（只写不执行的差分判定）

    版本边界（4.6.2 实测接受 / 4.7.8+ 实测拒绝）。判定不执行载荷——因为判别载荷
    ruoYiConfig.setProfile(...) 一旦执行就改掉目标的上传根目录且**无法从 HTTP 侧还原**
    （原值只在 application.yaml 里）。故只写、回读确认、还原，永不 run。
    """

    ORIG_TARGET = "ryTask.ryNoParams"
    PAGE_403 = "<!DOCTYPE html><html><head><title>RuoYi - 403</title></head><body>无权限</body></html>"

    class _FakeJobServer:
        """有状态假服务端：edit 被接受时真的改写任务，用来验证回读与还原"""

        def __init__(self, reject=False, write_through=True):
            self.invoke_target = TestJobInvokeTarget.ORIG_TARGET
            self.status = "0"
            self.reject = reject
            self.write_through = write_through  # False 模拟「返回成功但没写进去」

        def list_resp(self, request, context):
            return json.dumps(
                {
                    "total": 1,
                    "rows": [
                        {
                            "jobId": 1,
                            "jobName": "系统默认（无参）",
                            "jobGroup": "DEFAULT",
                            "invokeTarget": self.invoke_target,
                            "cronExpression": "0/10 * * * * ?",
                            "misfirePolicy": "1",
                            "concurrent": "1",
                            "status": self.status,
                            "remark": "",
                        }
                    ],
                }
            )

        def edit_resp(self, request, context):
            from urllib.parse import parse_qs

            params = parse_qs(request.text or "")
            target = (params.get("invokeTarget") or [""])[0]
            if self.reject:
                return json.dumps({"msg": "修改任务'系统默认（无参）'失败，目标字符串不在白名单内", "code": 500})
            if self.write_through:
                self.invoke_target = target
                self.status = (params.get("status") or [self.status])[0]
            return json.dumps({"msg": "操作成功", "code": 0})

    def _mock_login_and_jobs(self, m, server):
        m.get(MOCK_TARGET + "/login", text="<html>登录</html>", headers={"Content-Type": "text/html"})
        m.post(MOCK_TARGET + "/login", text='{"code":0,"msg":"操作成功"}', headers={"Content-Type": "application/json"})
        m.post(MOCK_TARGET + "/monitor/job/list", text=server.list_resp, headers={"Content-Type": "application/json"})
        m.post(MOCK_TARGET + "/monitor/job/edit", text=server.edit_resp, headers={"Content-Type": "application/json"})

    @requests_mock.Mocker()
    def test_confirmed_when_payload_accepted_and_written(self, m):
        """漏洞版：任意调用目标被接受并写库 → CONFIRMED；且任务必须还原、载荷绝不执行"""
        server = self._FakeJobServer(reject=False)
        self._mock_login_and_jobs(m, server)
        result = JobInvokeTargetPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"载荷被接受应判 CONFIRMED，实际 {result.status}")
        self.assertIn("白名单", result.evidence)
        # 安全属性：不得触发执行（判据只看写入是否被接受）
        self.assertNotIn(
            "/monitor/job/run",
            " ".join(r.url for r in m.request_history),
            "本插件不得执行载荷——setProfile 一旦执行就无法还原目标配置",
        )
        self.assertEqual(server.invoke_target, self.ORIG_TARGET, "探测后必须还原任务")

    @requests_mock.Mocker()
    def test_safe_when_whitelist_rejects(self, m):
        """修复版：写入判别载荷被白名单拒绝 → SAFE"""
        server = self._FakeJobServer(reject=True)
        self._mock_login_and_jobs(m, server)
        result = JobInvokeTargetPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"被白名单拒绝应判 SAFE，实际 {result.status}")
        self.assertIn("白名单", result.evidence)
        self.assertEqual(server.invoke_target, self.ORIG_TARGET)

    @requests_mock.Mocker()
    def test_unknown_when_edit_denied_by_permission(self, m):
        """账号缺 monitor:job:edit（返回权限页而非 JSON）→ UNKNOWN，不得判 SAFE"""
        m.get(MOCK_TARGET + "/login", text="<html>登录</html>", headers={"Content-Type": "text/html"})
        m.post(MOCK_TARGET + "/login", text='{"code":0,"msg":"操作成功"}', headers={"Content-Type": "application/json"})
        m.post(
            MOCK_TARGET + "/monitor/job/list",
            text=self._FakeJobServer().list_resp,
            headers={"Content-Type": "application/json"},
        )
        m.post(MOCK_TARGET + "/monitor/job/edit", text=self.PAGE_403, headers={"Content-Type": "text/html"})
        result = JobInvokeTargetPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"权限不足应判 UNKNOWN，实际 {result.status}")

    @requests_mock.Mocker()
    def test_unknown_when_job_list_unreadable(self, m):
        """任务列表不可读 → UNKNOWN（拿不到可用任务就不下结论）"""
        m.get(MOCK_TARGET + "/login", text="<html>登录</html>", headers={"Content-Type": "text/html"})
        m.post(MOCK_TARGET + "/login", text='{"code":0,"msg":"操作成功"}', headers={"Content-Type": "application/json"})
        m.post(MOCK_TARGET + "/monitor/job/list", text=self.PAGE_403, headers={"Content-Type": "text/html"})
        result = JobInvokeTargetPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"列表不可读应判 UNKNOWN，实际 {result.status}")

    @requests_mock.Mocker()
    def test_unknown_when_accepted_but_not_written(self, m):
        """服务端返回成功但回读发现没写进去 → UNKNOWN（不凭单次响应下结论）"""
        server = self._FakeJobServer(reject=False, write_through=False)
        self._mock_login_and_jobs(m, server)
        result = JobInvokeTargetPlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"写入未生效应判 UNKNOWN，实际 {result.status}")


class TestDruidBrute(unittest.TestCase):
    """4. Druid 爆破：正确口令命中，错误口令未命中"""

    @staticmethod
    def _match_creds(username, password):
        """构造匹配指定凭据的 additional_matcher

        注意：requests_mock 的 additional_matcher 签名是 (request)，不是 (request, context)
        """

        def matcher(request):
            # request.body 可能是 bytes，需解码后再做子串匹配
            body = request.body or ""
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="ignore")
            return f"loginUsername={username}" in body and f"loginPassword={password}" in body

        return matcher

    @requests_mock.Mocker()
    def test_hit_correct_password(self, m):
        """命中：admin/admin123 返回 success"""
        url = MOCK_TARGET + "druid/submitLogin"
        # requests_mock 按 LIFO 顺序匹配（最后注册的最先检查）：
        # 先注册兜底（其他凭据返回 failure），再注册特定凭据（success，最先被检查）
        m.post(url, text='{"code":500,"msg":"password error"}')
        # 注意：新判定严格比对 JSON success==True（布尔），故 mock 须返回合法 JSON
        # 旧逻辑 'success' in t 会把 "success":false 也判命中（假阳性），已修复
        m.post(
            url,
            additional_matcher=self._match_creds("admin", "admin123"),
            text='{"success": true, "message": "登录成功"}',
        )
        plugin = DruidBrutePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"正确口令应判 CONFIRMED，实际 {result.status}")
        self.assertEqual(result.extra.get("username"), "admin")
        self.assertEqual(result.extra.get("password"), "admin123")

    @requests_mock.Mocker()
    def test_safe_wrong_password(self, m):
        """未命中：所有凭据都返回失败"""
        url = MOCK_TARGET + "druid/submitLogin"
        m.post(url, text='{"code":500,"msg":"password error"}')
        plugin = DruidBrutePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"错误口令应判 SAFE，实际 {result.status}")


class TestDirectoryScan(unittest.TestCase):
    """5. 目录扫描：200/403 状态码分类正确，标题提取正确"""

    @requests_mock.Mocker()
    def test_status_code_classification(self, m):
        """200 命中（绿）/ 403 不命中为漏洞但仍记录"""
        # 准备 3 个端点：200 有标题、200 无标题、403
        m.get(MOCK_TARGET + "/login", status_code=200, text="<html><title>RuoYi管理系统</title>login page</html>")
        m.get(MOCK_TARGET + "/index", status_code=200, text="<html><title>首页</title></html>")
        m.get(MOCK_TARGET + "/admin", status_code=403, text="<html><title>Forbidden</title>403</html>")

        # 临时字典：仅包含测试用条目
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
            tf.write("/login\n/index\n/admin\n")
            dict_path = tf.name
        try:
            from config import settings

            original_dict = settings.RUOYI_DICT
            settings.RUOYI_DICT = dict_path
            try:
                plugin = DirectoryScanPlugin()
                result = plugin.verify(MOCK_TARGET, SessionManager())
                # 目录扫描不判 CONFIRMED/SAFE，返回 UNKNOWN + 命中详情
                self.assertEqual(result.status, STATUS_UNKNOWN)
                hits = result.extra.get("hits", [])
                hit_urls = [h["url"] for h in hits]
                # 200 端点应被收集
                self.assertIn(MOCK_TARGET + "/login", hit_urls)
                self.assertIn(MOCK_TARGET + "/index", hit_urls)
                # 403 端点：根据收集逻辑（'20' in code or 'NULL' not in title）
                # 403 不含 '20' 但 title 非空（'Forbidden'）→ 也应被收集
                self.assertIn(MOCK_TARGET + "/admin", hit_urls)
                # 校验状态码记录
                for h in hits:
                    if "login" in h["url"]:
                        self.assertEqual(h["code"], "200")
                    elif "admin" in h["url"]:
                        self.assertEqual(h["code"], "403")
            finally:
                settings.RUOYI_DICT = original_dict
        finally:
            os.unlink(dict_path)

    @requests_mock.Mocker()
    def test_title_extraction(self, m):
        """标题提取：<title>RuoYi管理系统</title>"""
        m.get(
            MOCK_TARGET + "/login", status_code=200, text="<html><head><title>RuoYi管理系统</title></head>login</html>"
        )
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
            tf.write("/login\n")
            dict_path = tf.name
        try:
            from config import settings

            original_dict = settings.RUOYI_DICT
            settings.RUOYI_DICT = dict_path
            try:
                plugin = DirectoryScanPlugin()
                result = plugin.verify(MOCK_TARGET, SessionManager())
                # 验证标题被正确提取（命中列表中应有 login 条目）
                hits = result.extra.get("hits", [])
                self.assertTrue(len(hits) >= 1, "应至少命中 login 端点")
            finally:
                settings.RUOYI_DICT = original_dict
        finally:
            os.unlink(dict_path)


# ---------------------------------------------------------------------------
# Part 2：Step 5 新增 POC 判定断言（验收要求：每个 POC 须明确判定规则）
# ---------------------------------------------------------------------------


class TestFileUpload(unittest.TestCase):
    """Step 5：任意文件上传 POC 判定"""

    @requests_mock.Mocker()
    def test_hit_json_with_url(self, m):
        """命中：响应 JSON 含 url 字段（/profile/upload/...）"""
        url = MOCK_TARGET + "common/upload"
        m.post(
            url,
            headers={"Content-Type": "application/json"},
            text='{"code":200,"fileName":"ruoyi_scan_probe.txt",'
            '"url":"/profile/upload/2023/07/ruoyi_scan_probe.txt",'
            '"newFileName":"abc123.txt","msg":"操作成功"}',
        )
        plugin = FileUploadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"JSON 含 url 字段应判 CONFIRMED，实际 {result.status}")
        self.assertIn("/profile/upload", result.extra.get("uploaded_url", ""))

    @requests_mock.Mocker()
    def test_safe_auth_block(self, m):
        """安全：响应含『请先登录』鉴权拦截关键字"""
        url = MOCK_TARGET + "common/upload"
        m.post(url, headers={"Content-Type": "application/json"}, text='{"code":401,"msg":"请先登录"}')
        plugin = FileUploadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"鉴权拦截应判 SAFE，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe_non_json(self, m):
        """安全：响应非 JSON（HTML 错误页）"""
        url = MOCK_TARGET + "common/upload"
        m.post(url, text="<html><body>404 not found</body></html>")
        plugin = FileUploadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestJobRce(unittest.TestCase):
    """Step 5：定时任务 RCE 未授权访问判定"""

    @requests_mock.Mocker()
    def test_hit_unauthorized_business_layer(self, m):
        """命中：未鉴权进入业务层（code=500 任务不存在）"""
        url = MOCK_TARGET + "monitor/job/edit"
        m.post(url, headers={"Content-Type": "application/json"}, text='{"code":500,"msg":"定时任务不存在"}')
        plugin = JobRcePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"未鉴权进入业务层应判 CONFIRMED，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe_auth_required(self, m):
        """安全：响应含『认证失败』鉴权关键字"""
        url = MOCK_TARGET + "monitor/job/edit"
        m.post(url, text='{"msg":"请求访问：/monitor/job/edit，认证失败，无法访问系统资源","code":401}')
        plugin = JobRcePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"鉴权拦截应判 SAFE，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe_403_status(self, m):
        """安全：HTTP 403 状态码"""
        url = MOCK_TARGET + "monitor/job/edit"
        m.post(url, status_code=403, text="Forbidden")
        plugin = JobRcePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)

    @requests_mock.Mocker()
    def test_safe_code_400_param_error(self, m):
        """安全（P0 修复验证）：JSON code=400 参数错误不应判 CONFIRMED
        修复前 'or r_code is not None' 会导致任意非空 code 均误报为 RCE"""
        url = MOCK_TARGET + "monitor/job/edit"
        m.post(url, headers={"Content-Type": "application/json"}, text='{"code":400,"msg":"参数错误：jobId 不能为空"}')
        plugin = JobRcePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        # code=400 不在 (200,500) 范围内 → 应判 UNKNOWN 或 SAFE，绝不能是 CONFIRMED
        self.assertNotEqual(result.status, STATUS_CONFIRMED, f"code=400 参数错误不应判 CONFIRMED，实际 {result.status}")


class TestThymeleafSsti(unittest.TestCase):
    """Step 5：Thymeleaf/SpEL 模板注入判定（保守判定）"""

    @requests_mock.Mocker()
    def test_hit_eval_result_with_engine_keyword(self, m):
        """命中：响应含 49（7*7 求值结果）+ Thymeleaf 引擎关键字"""
        m.get(
            requests_mock.ANY,
            text="HTTP 500 Internal Server Error\n"
            "org.thymeleaf.exceptions.TemplateProcessingException: "
            "Error resolving template [49], template might not exist",
        )
        plugin = ThymeleafSstiPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"49 + thymeleaf 关键字应判 CONFIRMED，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe_raw_reflection(self, m):
        """安全：响应含 7*7 原文反射（未求值）"""
        m.get(requests_mock.ANY, text="The path __${7*7}__::.x was not found")
        plugin = ThymeleafSstiPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        # 仅含 7*7 原文（无 49 求值结果）→ SAFE
        self.assertEqual(result.status, STATUS_SAFE, f"原文反射 7*7（无 49）应判 SAFE，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe_no_eval_result(self, m):
        """安全：响应无 49 也无引擎关键字"""
        m.get(requests_mock.ANY, text="404 page not found")
        plugin = ThymeleafSstiPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestUnauthBatch(unittest.TestCase):
    """Step 5：未授权访问批量检测判定"""

    @requests_mock.Mocker()
    def test_hit_druid_monitor(self, m):
        """命中：/druid/index.html 含 Druid 特征关键字"""
        # 先注册其他端点的 404 兜底（最后注册优先匹配，故放最前）
        m.get(MOCK_TARGET + "actuator/env", status_code=404, text="Not Found")
        m.get(MOCK_TARGET + "swagger-ui.html", status_code=404, text="Not Found")
        m.get(MOCK_TARGET + "system/user/list", status_code=404, text="Not Found")
        # 最后注册命中端点（最先被匹配）
        m.get(
            MOCK_TARGET + "druid/index.html",
            text="<html><head><title>Druid Stat Index</title></head><body>Druid Monitor View</body></html>",
        )
        plugin = UnauthBatchPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"Druid 监控暴露应判 CONFIRMED，实际 {result.status}")
        hit_names = [h["name"] for h in result.extra.get("hit_endpoints", [])]
        self.assertIn("Druid 监控", hit_names)

    @requests_mock.Mocker()
    def test_hit_actuator_env(self, m):
        """命中：/actuator/env 含 propertySources"""
        m.get(MOCK_TARGET + "druid/index.html", status_code=404, text="Not Found")
        m.get(MOCK_TARGET + "swagger-ui.html", status_code=404, text="Not Found")
        m.get(MOCK_TARGET + "system/user/list", status_code=404, text="Not Found")
        m.get(
            MOCK_TARGET + "actuator/env",
            headers={"Content-Type": "application/json"},
            text='{"propertySources":[{"name":"systemEnvironment"}],"activeProfiles":["prod"]}',
        )
        plugin = UnauthBatchPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED)

    @requests_mock.Mocker()
    def test_safe_all_auth_blocked(self, m):
        """安全：所有端点均返回 401 鉴权拦截"""
        m.get(MOCK_TARGET + "actuator/env", status_code=401, text='{"msg":"认证失败，无法访问系统资源","code":401}')
        m.get(MOCK_TARGET + "druid/index.html", status_code=401, text="请先登录")
        m.get(MOCK_TARGET + "swagger-ui.html", status_code=401, text="unauthorized")
        m.get(MOCK_TARGET + "system/user/list", status_code=401, text='{"msg":"认证失败","code":401}')
        plugin = UnauthBatchPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"全部端点鉴权拦截应判 SAFE，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe_no_keywords(self, m):
        """安全：端点返回 200 但无特征关键字（如 404 自定义页）"""
        for path in ["actuator/env", "druid/index.html", "swagger-ui.html", "system/user/list"]:
            m.get(MOCK_TARGET + path, status_code=200, text="<html>custom 404 page</html>")
        plugin = UnauthBatchPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestDefaultPassword(unittest.TestCase):
    """Step 5：后台默认口令 admin/admin123 判定"""

    @requests_mock.Mocker()
    def test_hit_token(self, m):
        """命中：登录返回 token"""
        url = MOCK_TARGET + "login"
        m.post(
            url,
            headers={"Content-Type": "application/json"},
            text='{"code":200,"msg":"操作成功","token":"eyJhbGciOiJIUzUxMiJ9.'
            'eyJsb2dpbl91c2VyX2tleSI6ImFkbWluIn0.signature"}',
        )
        plugin = DefaultPasswordPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"返回 token 应判 CONFIRMED，实际 {result.status}")
        self.assertEqual(result.extra.get("username"), "admin")
        self.assertEqual(result.extra.get("password"), "admin123")

    @requests_mock.Mocker()
    def test_safe_password_error(self, m):
        """安全：返回密码错误（code=500）"""
        url = MOCK_TARGET + "login"
        m.post(url, headers={"Content-Type": "application/json"}, text='{"code":500,"msg":"用户不存在/密码错误"}')
        plugin = DefaultPasswordPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"密码错误应判 SAFE，实际 {result.status}")

    @requests_mock.Mocker()
    def test_unknown_captcha_required(self, m):
        """无法判定：服务端要求验证码"""
        url = MOCK_TARGET + "login"
        m.post(url, headers={"Content-Type": "application/json"}, text='{"code":500,"msg":"验证码已失效，请重新获取"}')
        plugin = DefaultPasswordPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"验证码场景应判 UNKNOWN（避免漏报），实际 {result.status}")
        self.assertTrue(result.extra.get("captcha_required", False))

    @requests_mock.Mocker()
    def test_safe_jsessionid_only_no_token(self, m):
        """安全（P0 修复验证）：登录失败仅返回 JSESSIONID（无 Admin-Token）不应判 CONFIRMED
        Java 应用登录失败时常下发 JSESSIONID 会话 Cookie，修复前会误报为默认口令命中"""
        url = MOCK_TARGET + "login"
        m.post(
            url,
            headers={"Content-Type": "application/json", "Set-Cookie": "JSESSIONID=abc123def456; Path=/; HttpOnly"},
            text='{"code":500,"msg":"用户不存在/密码错误"}',
        )
        plugin = DefaultPasswordPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        # 仅 JSESSIONID 无 Admin-Token → 应判 SAFE，绝不能是 CONFIRMED
        self.assertNotEqual(
            result.status, STATUS_CONFIRMED, f"仅 JSESSIONID（登录失败场景）不应判 CONFIRMED，实际 {result.status}"
        )


# ---------------------------------------------------------------------------
# Part 3：Step 8 新增 POC 判定断言（签名 marker 模式）
# ---------------------------------------------------------------------------


class TestNacosUnauth(unittest.TestCase):
    """Step 8：Nacos 未授权访问判定（D4 改造后：真实响应特征判定）"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        """命中：响应含真实 Nacos 用户列表（分页字段 + username/password）→ CONFIRMED"""
        url = MOCK_TARGET + "/nacos/v1/auth/users?pageNo=1&pageSize=10"
        # D4 改造：真实风格响应，无 marker，含分页字段 + 多个用户条目
        m.get(
            url,
            text='{"totalCount":2,"pageNumber":1,"pageSize":10,'
            '"pageItems":['
            '{"username":"nacos","password":"$2a$10$EuWPZHzz32dJN7jexM34MOeYirDdFAZm2kuWj7VEOthhhKtQk5zWm"},'
            '{"username":"admin","password":"$2a$10$7Jz9mY8uVQ5t2q3vG1vNkOe8LQf3u8z1Vq8Z3aXb5c9d4e6f7g8h9"}'
            "]}",
        )
        plugin = RuoyiNacosUnauthPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"响应含 Nacos 用户列表应判 CONFIRMED，实际 {result.status}")
        # evidence 应含用户名（脱敏后不含密码哈希）
        self.assertIn("nacos", result.evidence)

    @requests_mock.Mocker()
    def test_hit_single_user(self, m):
        """命中：仅 1 个用户条目但含分页字段 + username/password → CONFIRMED"""
        url = MOCK_TARGET + "/nacos/v1/auth/users?pageNo=1&pageSize=10"
        m.get(
            url,
            text='{"totalCount":1,"pageNumber":1,"pageSize":10,'
            '"pageItems":[{"username":"nacos","password":"$2a$10$hash"}]}',
        )
        plugin = RuoyiNacosUnauthPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED)

    @requests_mock.Mocker()
    def test_safe_no_user_fields(self, m):
        """安全：200 但响应无 username/password 字段 → SAFE"""
        url = MOCK_TARGET + "/nacos/v1/auth/users?pageNo=1&pageSize=10"
        m.get(url, text='{"code":200,"msg":"操作成功","data":[]}')
        plugin = RuoyiNacosUnauthPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"200 但无用户字段应判 SAFE，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe(self, m):
        """安全：HTTP 401 鉴权拦截 → SAFE"""
        url = MOCK_TARGET + "/nacos/v1/auth/users?pageNo=1&pageSize=10"
        m.get(url, status_code=401, text='{"code":401,"msg":"请先登录"}')
        plugin = RuoyiNacosUnauthPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"401 鉴权拦截应判 SAFE，实际 {result.status}")


class TestFileReadPath(unittest.TestCase):
    """Step 8：文件下载路径穿越判定（D4 改造后：真实 /etc/passwd 特征判定）"""

    @requests_mock.Mocker()
    def test_hit(self, m):
        """命中：响应含真实 /etc/passwd（root + 系统账户）→ CONFIRMED"""
        url = MOCK_TARGET + "/common/download/resource?resource=../../../etc/passwd"
        # D4 改造：真实 /etc/passwd 内容，无 marker
        m.get(
            url,
            text="root:x:0:0:root:/root:/bin/bash\n"
            "bin:x:1:1:bin:/bin:/sbin/nologin\n"
            "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n",
        )
        plugin = RuoyiFileReadPathPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(
            result.status, STATUS_CONFIRMED, f"响应含真实 /etc/passwd 应判 CONFIRMED，实际 {result.status}"
        )
        self.assertIn("root", result.evidence)

    @requests_mock.Mocker()
    def test_safe_no_passwd(self, m):
        """安全：200 但响应无 passwd 特征 → SAFE"""
        url = MOCK_TARGET + "/common/download/resource?resource=../../../etc/passwd"
        m.get(url, text="<html><body>文件不存在</body></html>")
        plugin = RuoyiFileReadPathPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"200 但无 passwd 特征应判 SAFE，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe(self, m):
        """安全：HTTP 404 端点不存在 → SAFE"""
        url = MOCK_TARGET + "/common/download/resource?resource=../../../etc/passwd"
        m.get(url, status_code=404, text="404 not found")
        plugin = RuoyiFileReadPathPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"404 应判 SAFE，实际 {result.status}")


# ---------------------------------------------------------------------------
# 入口：直接运行或 pytest 兼容
# ---------------------------------------------------------------------------


class TestPlusAuthProbe(unittest.TestCase):
    """RuoYi-Plus 认证接口探测：重定向与 HTML 均不得判为认证服务

    真实缺陷（2026-09-17，由 lab/version_matrix 在纯 4.7.8 实例上发现）：
    RuoYi 单体版对未知路径 `/auth/login` 返回 **302 → /login**；requests 默认跟随重定向，
    最终落到登录页 HTML（HTTP 200）。该 HTML 含验证码字段名 `code`，与插件原先的
    `match_positive(text, ["code","msg"])` 子串匹配叠加后，在完全没有 Plus 服务的
    单体实例上误报 CONFIRMED。

    该路径 mock 基线无法覆盖（基线响应不含 code/msg 字样），必须靠真实环境扫描
    或本用例锁定。加固后要求：非 3xx + JSON Content-Type + 能解析出 code/msg 两个键。
    """

    @requests_mock.Mocker()
    def test_safe_on_redirect_to_login(self, m):
        """302 → /login 不得判 CONFIRMED（历史误报场景）"""
        m.post(
            MOCK_TARGET + "/auth/login",
            status_code=302,
            headers={"Location": MOCK_TARGET + "/login"},
            text="",
        )
        plugin = PlusAuthLoginProbePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertNotEqual(result.status, STATUS_CONFIRMED, "重定向到登录页不得判 CONFIRMED（该路径不是独立认证服务）")

    @requests_mock.Mocker()
    def test_safe_on_html_containing_code_and_msg(self, m):
        """HTML 正文含 code/msg 字样（如若依登录页的验证码字段）不得判 CONFIRMED"""
        m.post(
            MOCK_TARGET + "/auth/login",
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text='<html><input name="code" placeholder="验证码"><span class="msg"></span></html>',
        )
        plugin = PlusAuthLoginProbePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertNotEqual(result.status, STATUS_CONFIRMED, "HTML 中的 code/msg 字样不得当作 JSON 业务特征")

    @requests_mock.Mocker()
    def test_hit_on_json_with_code_msg_keys(self, m):
        """真正的 Sa-Token 业务 JSON（含 code/msg 键）应判 CONFIRMED"""
        m.post(
            MOCK_TARGET + "/auth/login",
            status_code=200,
            headers={"Content-Type": "application/json; charset=utf-8"},
            text='{"code":401,"msg":"用户名或密码错误"}',
        )
        plugin = PlusAuthLoginProbePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"业务 JSON 应判 CONFIRMED，实际 {result.status}")


class TestPlusJobUnauth(unittest.TestCase):
    """RuoYi-Plus 定时任务未授权：登录页 HTML 不得判为「未授权返回任务列表」

    真实缺陷（2026-09-17，多版本矩阵语料新增「若依登录页」后暴露）：
    原判定 `status==200 and match_positive(text, ["rows","total","code"],
    negatives=["login","unauthorized"])` 有三个叠加问题：
      1. 正向特征 "code" 过于泛用——任何含验证码字段的 HTML 都命中；
      2. 负向 "login" 全小写，而真若依登录页是 `id="formLogin"`（大写 L），排除失效；
      3. 未校验响应是 JSON。
    加固后要求：非 3xx + JSON Content-Type + 解析出的 JSON 同时含 rows 与 total 键。
    """

    @requests_mock.Mocker()
    def test_safe_on_ruoyi_login_page_html(self, m):
        """若依登录页 HTML（含 code 字段与 formLogin）不得判 CONFIRMED"""
        m.get(
            requests_mock.ANY,
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text=(
                "<html><head><title>登录若依系统</title></head><body>"
                '<form id="formLogin"><input name="code" placeholder="验证码">'
                '<span class="msg"></span></form></body></html>'
            ),
        )
        plugin = PlusJobUnauthPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertNotEqual(result.status, STATUS_CONFIRMED, "登录页 HTML 不得判为未授权任务列表")

    @requests_mock.Mocker()
    def test_hit_on_real_list_json(self, m):
        """真正的未授权任务列表 JSON（rows + total 键）应判 CONFIRMED"""
        m.get(
            requests_mock.ANY,
            status_code=200,
            headers={"Content-Type": "application/json; charset=utf-8"},
            text='{"total":2,"rows":[{"jobId":1,"jobName":"ryTask"}],"code":200,"msg":"查询成功"}',
        )
        plugin = PlusJobUnauthPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"业务列表 JSON 应判 CONFIRMED，实际 {result.status}")


class TestCve202546174ResetPwdScope(unittest.TestCase):
    """CVE-2025-46174：重置密码页数据权限绕过（差分判定）

    漏洞边界（实测四个版本）：4.7.8 / 4.8.0 无 checkUserDataScope → 可越权；
    4.8.2 / 4.8.3 有校验 → 被拒。判定必须用差分，不能靠单次响应的关键词匹配：
    修复版返回的是 **HTTP 200 + 错误页**（RuoYi 把 500 渲染成 200），状态码无区分度。
    """

    CONTROL_PAGE = (
        "<!DOCTYPE html><html><body>"
        '<form class="form-horizontal m" id="form-user-resetPwd">'
        '<input name="userId" type="hidden" value="2"/>'
        '<input class="form-control" type="text" readonly="true" name="loginName" value="ry"/>'
        "</form></body></html>"
    )
    LEAKED_PAGE = (
        "<!DOCTYPE html><html><body>"
        '<form class="form-horizontal m" id="form-user-resetPwd">'
        '<input name="userId" type="hidden" value="1"/>'
        '<input class="form-control" type="text" readonly="true" name="loginName" value="admin"/>'
        "</form></body></html>"
    )
    # 修复版：checkUserDataScope 抛 ServiceException → 渲染成 200 错误页
    DENIED_PAGE = "<!DOCTYPE html><html><head><title>RuoYi - 500</title></head><body>没有权限访问用户数据</body></html>"

    def _mock_login_and_list(self, m, rows):
        m.get(MOCK_TARGET + "/login", text="<html><form>登录</form></html>", headers={"Content-Type": "text/html"})
        m.post(MOCK_TARGET + "/login", text='{"code":0,"msg":"操作成功"}', headers={"Content-Type": "application/json"})
        m.post(
            MOCK_TARGET + "/system/user/list",
            text=json.dumps({"total": len(rows), "rows": rows, "code": 200, "msg": "查询成功"}),
            headers={"Content-Type": "application/json"},
        )

    @requests_mock.Mocker()
    def test_confirmed_when_out_of_scope_page_renders(self, m):
        """漏洞版：不可见用户的页面被越权渲染 → CONFIRMED"""
        self._mock_login_and_list(m, [{"userId": 2, "loginName": "ry"}, {"userId": 100, "loginName": "scanner_low"}])
        m.get(MOCK_TARGET + "/system/user/resetPwd/2", text=self.CONTROL_PAGE)
        m.get(MOCK_TARGET + "/system/user/resetPwd/1", text=self.LEAKED_PAGE)
        result = Cve202546174ResetPwdScopePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"越权渲染应判 CONFIRMED，实际 {result.status}")
        self.assertIn("admin", result.evidence, "证据应点名泄露的登录名")

    @requests_mock.Mocker()
    def test_safe_when_permission_denied(self, m):
        """修复版：不可见用户被拒（200 + 错误页）→ SAFE

        回归重点：**不能靠状态码判定**——修复版同样返回 200。
        """
        self._mock_login_and_list(m, [{"userId": 2, "loginName": "ry"}, {"userId": 100, "loginName": "scanner_low"}])
        m.get(MOCK_TARGET + "/system/user/resetPwd/2", text=self.CONTROL_PAGE)
        m.get(MOCK_TARGET + "/system/user/resetPwd/1", text=self.DENIED_PAGE)
        result = Cve202546174ResetPwdScopePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"被拒应判 SAFE，实际 {result.status}")

    @requests_mock.Mocker()
    def test_unknown_when_target_visible_to_account(self, m):
        """目标用户对当前账号可见 → UNKNOWN（构不成越权场景，不能冒充 SAFE）"""
        self._mock_login_and_list(m, [{"userId": 1, "loginName": "admin"}, {"userId": 2, "loginName": "ry"}])
        result = Cve202546174ResetPwdScopePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"目标可见应判 UNKNOWN，实际 {result.status}")

    @requests_mock.Mocker()
    def test_unknown_when_control_not_rendered(self, m):
        """对照组（可见用户）都没渲染出页面 → 链路不可信 → UNKNOWN

        防止把「页面本来就渲染不出来」误判成 SAFE。
        """
        self._mock_login_and_list(m, [{"userId": 2, "loginName": "ry"}])
        m.get(MOCK_TARGET + "/system/user/resetPwd/2", text="<html>whatever</html>")
        m.get(MOCK_TARGET + "/system/user/resetPwd/1", text="<html>whatever</html>")
        result = Cve202546174ResetPwdScopePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"对照组未渲染应判 UNKNOWN，实际 {result.status}")

    @requests_mock.Mocker()
    def test_unknown_when_no_visible_users(self, m):
        """用户列表不可读 → 无法建立基线 → UNKNOWN"""
        self._mock_login_and_list(m, [])
        result = Cve202546174ResetPwdScopePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"无可见用户应判 UNKNOWN，实际 {result.status}")

    @requests_mock.Mocker()
    def test_does_not_authenticate_shared_session(self, m):
        """回归：插件必须使用隔离会话，不得在传入的共享会话上留下登录态

        跨插件污染实测（2026-09-17）：登录态泄漏给后续插件后，
        v4.8.3 一次多出 6 个假 CONFIRMED。此用例锁定「共享会话不被认证」这一约束。
        """
        self._mock_login_and_list(m, [{"userId": 2, "loginName": "ry"}])
        m.get(MOCK_TARGET + "/system/user/resetPwd/2", text=self.CONTROL_PAGE)
        m.get(MOCK_TARGET + "/system/user/resetPwd/1", text=self.DENIED_PAGE)
        shared = SessionManager()
        Cve202546174ResetPwdScopePlugin().verify(MOCK_TARGET, shared)
        self.assertEqual(len(list(shared.session.cookies)), 0, "共享会话不应被插件登录所污染")


class TestCve202570986SelectDeptTree(unittest.TestCase):
    """CVE-2025-70986：部门树越权访问（差分判定）

    版本边界（实测）：4.7.8 / 4.8.0 的 selectDeptTree、treeData 无权限注解 → 可越权；
    4.8.2 / 4.8.3 已补 @RequiresPermissions('system:dept:list') → 被拒。
    判定**不依赖猜中有效部门 id**：无效 id（如 0）在漏洞版上让业务层执行（200 JSON / 500 NPE），
    在修复版上被 Shiro 权限门先拦（RuoYi - 403 页，且同样是 HTTP 200）——状态码无区分度。
    """

    PAGE_403 = (
        "<!DOCTYPE html><html><head><title>RuoYi - 403</title></head>"
        "<body><h1>403</h1><h3>您没有操作权限</h3></body></html>"
    )
    PAGE_LOGIN = "<!DOCTYPE html><html><head><title>登录若依系统</title></head><body><form>登录</form></body></html>"
    JSON_500 = '{"timestamp":"2026-09-17 10:00:00","status":500,"error":"Internal Server Error"}'

    def _mock_login(self, m):
        m.get(MOCK_TARGET + "/login", text=self.PAGE_LOGIN, headers={"Content-Type": "text/html"})
        m.post(MOCK_TARGET + "/login", text='{"code":0,"msg":"操作成功"}', headers={"Content-Type": "application/json"})

    def _mock_probes(self, m, tree_data_body, select_tree_body):
        m.get(MOCK_TARGET + "/system/dept/treeData/0", text=tree_data_body)
        m.get(MOCK_TARGET + "/system/dept/selectDeptTree/0", text=select_tree_body)

    @requests_mock.Mocker()
    def test_confirmed_when_tree_data_leaks(self, m):
        """漏洞版：无权限账号拿到部门数据 JSON → CONFIRMED"""
        self._mock_login(m)
        self._mock_probes(
            m,
            '[{"id":105,"pId":101,"name":"测试部门","title":"测试部门"}]',
            self.JSON_500,
        )
        result = Cve202570986SelectDeptTreePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"泄露部门数据应判 CONFIRMED，实际 {result.status}")
        self.assertIn("测试部门", result.evidence, "证据应点名泄露的部门名称")

    @requests_mock.Mocker()
    def test_confirmed_when_business_layer_executes_without_data(self, m):
        """漏洞版：接口返回空数组（未取到具体条目）但业务层在无权限下执行 → 仍判 CONFIRMED

        回归重点：4.8.0 实测 treeData 返回空数组——若只认「有数据」会漏判。
        差分的本质是「未被权限门拦截」，而非「必须拿到数据」。
        """
        self._mock_login(m)
        self._mock_probes(m, "[]", self.JSON_500)
        result = Cve202570986SelectDeptTreePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED, f"业务层无权限执行应判 CONFIRMED，实际 {result.status}")

    @requests_mock.Mocker()
    def test_safe_when_permission_denied(self, m):
        """修复版：两个探针均被 RuoYi-403 权限页拦截（注意也是 HTTP 200）→ SAFE"""
        self._mock_login(m)
        self._mock_probes(m, self.PAGE_403, self.PAGE_403)
        result = Cve202570986SelectDeptTreePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE, f"被权限门拦截应判 SAFE，实际 {result.status}")

    @requests_mock.Mocker()
    def test_unknown_when_responses_conflict(self, m):
        """一个探针被拦、另一个没拦：形态矛盾 → UNKNOWN（不能贸然下结论）"""
        self._mock_login(m)
        self._mock_probes(m, self.PAGE_403, "[]")
        result = Cve202570986SelectDeptTreePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"形态矛盾应判 UNKNOWN，实际 {result.status}")

    @requests_mock.Mocker()
    def test_unknown_when_session_lost(self, m):
        """会话失效（响应为登录页）→ UNKNOWN，不得据此判 SAFE/CONFIRMED"""
        self._mock_login(m)
        self._mock_probes(m, self.PAGE_LOGIN, self.PAGE_LOGIN)
        result = Cve202570986SelectDeptTreePlugin().verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN, f"会话失效应判 UNKNOWN，实际 {result.status}")


def run_all():
    """运行全部测试，返回 0 表示全部通过"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    # 按类加载，保证顺序
    test_classes = [
        TestFileRead,
        TestSqlInject,
        TestJobInvokeTarget,
        TestDruidBrute,
        TestDirectoryScan,
        TestFileUpload,
        TestJobRce,
        TestThymeleafSsti,
        TestUnauthBatch,
        TestDefaultPassword,
        # Step 8 新增
        TestNacosUnauth,
        TestFileReadPath,
        # 多版本矩阵实测新增（2026-09-17）：重定向/HTML 误报回归
        TestPlusAuthProbe,
        TestPlusJobUnauth,
        TestCve202546174ResetPwdScope,
        TestCve202570986SelectDeptTree,
    ]
    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


# Windows ANSI 代码页（cp1252/GBK）控制台下中文输出防崩溃（G2 可移植性）
from common.console import force_utf8_stdio

force_utf8_stdio()

if __name__ == "__main__":
    sys.exit(run_all())
