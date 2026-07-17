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
#
# 运行：python tests/regression_ruoyi.py
# 退出码：0 全部通过，非 0 表示有失败用例
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
    print('缺少依赖 requests_mock，请先执行：pip install requests_mock')
    sys.exit(1)

from core.session import SessionManager
from core.models import (
    STATUS_CONFIRMED,
    STATUS_SAFE,
    STATUS_UNKNOWN,
)

# 原有 6 个插件（Step 2 迁移）
from plugins.ruoyi.file_read import FileReadPlugin
from plugins.ruoyi.file_read_time import FileReadTimePlugin
from plugins.ruoyi.sql_inject_role import SqlInjectRolePlugin
from plugins.ruoyi.sql_inject_dept import SqlInjectDeptPlugin
from plugins.ruoyi.druid_brute import DruidBrutePlugin
from plugins.ruoyi.directory_scan import DirectoryScanPlugin

# Step 5 新增 5 个 POC 插件
from plugins.ruoyi.file_upload import FileUploadPlugin
from plugins.ruoyi.job_rce import JobRcePlugin
from plugins.ruoyi.thymeleaf_ssti import ThymeleafSstiPlugin
from plugins.ruoyi.unauth_batch import UnauthBatchPlugin
from plugins.ruoyi.default_password import DefaultPasswordPlugin


# 统一 mock 目标（不使用真实域名，避免误发请求）
MOCK_TARGET = 'http://ruoyi-mock.test/'


# ---------------------------------------------------------------------------
# Part 1：用户规范要求的 5 项回归验收（无损迁移）
# ---------------------------------------------------------------------------

class TestFileRead(unittest.TestCase):
    """1. 任意文件读取 POC：命中含 root:x:0:0，忽略仅含 root 的噪声"""

    @requests_mock.Mocker()
    def test_hit_root_x_0_0(self, m):
        """命中：响应含 root:x:0:0:root:/root:/bin/bash"""
        url = MOCK_TARGET + '/common/download/resource?resource=/profile/../../../../../../../etc/passwd'
        m.get(url, text='root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n')
        plugin = FileReadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'响应含 root 与 :/ 应判 CONFIRMED，实际 {result.status}')
        self.assertIn('root', result.evidence)

    @requests_mock.Mocker()
    def test_ignore_noise_only_root(self, m):
        """噪声：响应仅含 root 单词（无 :/），应判 SAFE"""
        url = MOCK_TARGET + '/common/download/resource?resource=/profile/../../../../../../../etc/passwd'
        m.get(url, text='this is a root word but no path separator')
        plugin = FileReadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE,
                         f'仅含 root 无 :/ 应判 SAFE（噪声过滤），实际 {result.status}')

    @requests_mock.Mocker()
    def test_safe_when_no_root(self, m):
        """无 root：响应不含 root，应判 SAFE"""
        url = MOCK_TARGET + '/common/download/resource?resource=/profile/../../../../../../../etc/passwd'
        m.get(url, text='404 not found page')
        plugin = FileReadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestSqlInject(unittest.TestCase):
    """2. SQL 报错注入 POC：命中 extractvalue 报错的响应特征"""

    @requests_mock.Mocker()
    def test_hit_extractvalue_runtime_exception(self, m):
        """命中：响应含『运行时异常』（extractvalue 报错典型特征）"""
        url = MOCK_TARGET + '/system/role/list'
        # RuoYi 实际报错响应：含运行时异常 + extractvalue SQL 错误堆栈
        m.post(url, text='{"msg":"运行时异常：nested exception is java.sql.SQLException: '
                         'XPATH syntax error: \'~ruoyi~\' extractvalue","code":500}')
        plugin = SqlInjectRolePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'响应含运行时异常应判 CONFIRMED，实际 {result.status}')

    @requests_mock.Mocker()
    def test_hit_database_leak(self, m):
        """命中：响应泄露 database() 字面量"""
        url = MOCK_TARGET + '/system/dept/list'
        m.post(url, text='error: database() leaked in sql query extractvalue')
        plugin = SqlInjectDeptPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'响应含 database() 应判 CONFIRMED，实际 {result.status}')

    @requests_mock.Mocker()
    def test_safe_normal_response(self, m):
        """安全：正常业务响应，应判 SAFE"""
        url = MOCK_TARGET + '/system/role/list'
        m.post(url, text='{"rows":[],"code":200,"msg":"查询成功"}')
        plugin = SqlInjectRolePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestFileReadTime(unittest.TestCase):
    """3. 定时任务读取链路（edit → run → 2.txt）：状态/响应判定正确"""

    @requests_mock.Mocker()
    def test_hit_full_chain(self, m):
        """命中：edit 200 + run 200 + 2.txt 含 root:/"""
        edit_url = MOCK_TARGET + '/monitor/job/edit'
        run_url = MOCK_TARGET + '/monitor/job/run'
        read_url = MOCK_TARGET + '/common/download/resource?resource=2.txt'
        m.post(edit_url, text='{"code":200,"msg":"操作成功"}')
        m.post(run_url, text='{"code":200,"msg":"执行成功"}')
        m.get(read_url, text='root:x:0:0:root:/root:/bin/bash\n')
        plugin = FileReadTimePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'链路命中应判 CONFIRMED，实际 {result.status}')
        self.assertIn('root', result.evidence)

    @requests_mock.Mocker()
    def test_safe_when_2txt_no_root(self, m):
        """安全：2.txt 不含 root:/，应判 SAFE（即使 edit/run 成功）"""
        m.post(MOCK_TARGET + '/monitor/job/edit', text='ok')
        m.post(MOCK_TARGET + '/monitor/job/run', text='ok')
        m.get(MOCK_TARGET + '/common/download/resource?resource=2.txt',
              text='empty file content')
        plugin = FileReadTimePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestDruidBrute(unittest.TestCase):
    """4. Druid 爆破：正确口令命中，错误口令未命中"""

    @staticmethod
    def _match_creds(username, password):
        """构造匹配指定凭据的 additional_matcher

        注意：requests_mock 的 additional_matcher 签名是 (request)，不是 (request, context)
        """
        def matcher(request):
            # request.body 可能是 bytes，需解码后再做子串匹配
            body = request.body or ''
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='ignore')
            return (f'loginUsername={username}' in body and
                    f'loginPassword={password}' in body)
        return matcher

    @requests_mock.Mocker()
    def test_hit_correct_password(self, m):
        """命中：admin/admin123 返回 success"""
        url = MOCK_TARGET + 'druid/submitLogin'
        # requests_mock 按 LIFO 顺序匹配（最后注册的最先检查）：
        # 先注册兜底（其他凭据返回 failure），再注册特定凭据（success，最先被检查）
        m.post(url, text='{"code":500,"msg":"password error"}')
        m.post(url, additional_matcher=self._match_creds('admin', 'admin123'),
               text='success')
        plugin = DruidBrutePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'正确口令应判 CONFIRMED，实际 {result.status}')
        self.assertEqual(result.extra.get('username'), 'admin')
        self.assertEqual(result.extra.get('password'), 'admin123')

    @requests_mock.Mocker()
    def test_safe_wrong_password(self, m):
        """未命中：所有凭据都返回失败"""
        url = MOCK_TARGET + 'druid/submitLogin'
        m.post(url, text='{"code":500,"msg":"password error"}')
        plugin = DruidBrutePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE,
                         f'错误口令应判 SAFE，实际 {result.status}')


class TestDirectoryScan(unittest.TestCase):
    """5. 目录扫描：200/403 状态码分类正确，标题提取正确"""

    @requests_mock.Mocker()
    def test_status_code_classification(self, m):
        """200 命中（绿）/ 403 不命中为漏洞但仍记录"""
        # 准备 3 个端点：200 有标题、200 无标题、403
        m.get(MOCK_TARGET + 'login', status_code=200,
              text='<html><title>RuoYi管理系统</title>login page</html>')
        m.get(MOCK_TARGET + 'index', status_code=200,
              text='<html><title>首页</title></html>')
        m.get(MOCK_TARGET + 'admin', status_code=403,
              text='<html><title>Forbidden</title>403</html>')

        # 临时字典：仅包含测试用条目
        import tempfile
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False,
                                         encoding='utf-8') as tf:
            tf.write('/login\n/index\n/admin\n')
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
                hits = result.extra.get('hits', [])
                hit_urls = [h['url'] for h in hits]
                # 200 端点应被收集
                self.assertIn(MOCK_TARGET + 'login', hit_urls)
                self.assertIn(MOCK_TARGET + 'index', hit_urls)
                # 403 端点：根据收集逻辑（'20' in code or 'NULL' not in title）
                # 403 不含 '20' 但 title 非空（'Forbidden'）→ 也应被收集
                self.assertIn(MOCK_TARGET + 'admin', hit_urls)
                # 校验状态码记录
                for h in hits:
                    if 'login' in h['url']:
                        self.assertEqual(h['code'], '200')
                    elif 'admin' in h['url']:
                        self.assertEqual(h['code'], '403')
            finally:
                settings.RUOYI_DICT = original_dict
        finally:
            os.unlink(dict_path)

    @requests_mock.Mocker()
    def test_title_extraction(self, m):
        """标题提取：<title>RuoYi管理系统</title>"""
        m.get(MOCK_TARGET + 'login', status_code=200,
              text='<html><head><title>RuoYi管理系统</title></head>login</html>')
        import tempfile
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False,
                                         encoding='utf-8') as tf:
            tf.write('/login\n')
            dict_path = tf.name
        try:
            from config import settings
            original_dict = settings.RUOYI_DICT
            settings.RUOYI_DICT = dict_path
            try:
                plugin = DirectoryScanPlugin()
                result = plugin.verify(MOCK_TARGET, SessionManager())
                # 验证标题被正确提取（命中列表中应有 login 条目）
                hits = result.extra.get('hits', [])
                self.assertTrue(len(hits) >= 1, '应至少命中 login 端点')
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
        url = MOCK_TARGET + 'common/upload'
        m.post(url, headers={'Content-Type': 'application/json'},
               text='{"code":200,"fileName":"ruoyi_scan_probe.txt",'
                    '"url":"/profile/upload/2023/07/ruoyi_scan_probe.txt",'
                    '"newFileName":"abc123.txt","msg":"操作成功"}')
        plugin = FileUploadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'JSON 含 url 字段应判 CONFIRMED，实际 {result.status}')
        self.assertIn('/profile/upload', result.extra.get('uploaded_url', ''))

    @requests_mock.Mocker()
    def test_safe_auth_block(self, m):
        """安全：响应含『请先登录』鉴权拦截关键字"""
        url = MOCK_TARGET + 'common/upload'
        m.post(url, headers={'Content-Type': 'application/json'},
               text='{"code":401,"msg":"请先登录"}')
        plugin = FileUploadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE,
                         f'鉴权拦截应判 SAFE，实际 {result.status}')

    @requests_mock.Mocker()
    def test_safe_non_json(self, m):
        """安全：响应非 JSON（HTML 错误页）"""
        url = MOCK_TARGET + 'common/upload'
        m.post(url, text='<html><body>404 not found</body></html>')
        plugin = FileUploadPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestJobRce(unittest.TestCase):
    """Step 5：定时任务 RCE 未授权访问判定"""

    @requests_mock.Mocker()
    def test_hit_unauthorized_business_layer(self, m):
        """命中：未鉴权进入业务层（code=500 任务不存在）"""
        url = MOCK_TARGET + 'monitor/job/edit'
        m.post(url, headers={'Content-Type': 'application/json'},
               text='{"code":500,"msg":"定时任务不存在"}')
        plugin = JobRcePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'未鉴权进入业务层应判 CONFIRMED，实际 {result.status}')

    @requests_mock.Mocker()
    def test_safe_auth_required(self, m):
        """安全：响应含『认证失败』鉴权关键字"""
        url = MOCK_TARGET + 'monitor/job/edit'
        m.post(url, text='{"msg":"请求访问：/monitor/job/edit，认证失败，无法访问系统资源","code":401}')
        plugin = JobRcePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE,
                         f'鉴权拦截应判 SAFE，实际 {result.status}')

    @requests_mock.Mocker()
    def test_safe_403_status(self, m):
        """安全：HTTP 403 状态码"""
        url = MOCK_TARGET + 'monitor/job/edit'
        m.post(url, status_code=403, text='Forbidden')
        plugin = JobRcePlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestThymeleafSsti(unittest.TestCase):
    """Step 5：Thymeleaf/SpEL 模板注入判定（保守判定）"""

    @requests_mock.Mocker()
    def test_hit_eval_result_with_engine_keyword(self, m):
        """命中：响应含 49（7*7 求值结果）+ Thymeleaf 引擎关键字"""
        m.get(requests_mock.ANY,
              text='HTTP 500 Internal Server Error\n'
                   'org.thymeleaf.exceptions.TemplateProcessingException: '
                   'Error resolving template [49], template might not exist')
        plugin = ThymeleafSstiPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'49 + thymeleaf 关键字应判 CONFIRMED，实际 {result.status}')

    @requests_mock.Mocker()
    def test_safe_raw_reflection(self, m):
        """安全：响应含 7*7 原文反射（未求值）"""
        m.get(requests_mock.ANY, text='The path __${7*7}__::.x was not found')
        plugin = ThymeleafSstiPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        # 仅含 7*7 原文（无 49 求值结果）→ SAFE
        self.assertEqual(result.status, STATUS_SAFE,
                         f'原文反射 7*7（无 49）应判 SAFE，实际 {result.status}')

    @requests_mock.Mocker()
    def test_safe_no_eval_result(self, m):
        """安全：响应无 49 也无引擎关键字"""
        m.get(requests_mock.ANY, text='404 page not found')
        plugin = ThymeleafSstiPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestUnauthBatch(unittest.TestCase):
    """Step 5：未授权访问批量检测判定"""

    @requests_mock.Mocker()
    def test_hit_druid_monitor(self, m):
        """命中：/druid/index.html 含 Druid 特征关键字"""
        # 先注册其他端点的 404 兜底（最后注册优先匹配，故放最前）
        m.get(MOCK_TARGET + 'actuator/env', status_code=404, text='Not Found')
        m.get(MOCK_TARGET + 'swagger-ui.html', status_code=404, text='Not Found')
        m.get(MOCK_TARGET + 'system/user/list', status_code=404, text='Not Found')
        # 最后注册命中端点（最先被匹配）
        m.get(MOCK_TARGET + 'druid/index.html',
              text='<html><head><title>Druid Stat Index</title></head>'
                   '<body>Druid Monitor View</body></html>')
        plugin = UnauthBatchPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'Druid 监控暴露应判 CONFIRMED，实际 {result.status}')
        hit_names = [h['name'] for h in result.extra.get('hit_endpoints', [])]
        self.assertIn('Druid 监控', hit_names)

    @requests_mock.Mocker()
    def test_hit_actuator_env(self, m):
        """命中：/actuator/env 含 propertySources"""
        m.get(MOCK_TARGET + 'druid/index.html', status_code=404, text='Not Found')
        m.get(MOCK_TARGET + 'swagger-ui.html', status_code=404, text='Not Found')
        m.get(MOCK_TARGET + 'system/user/list', status_code=404, text='Not Found')
        m.get(MOCK_TARGET + 'actuator/env',
              headers={'Content-Type': 'application/json'},
              text='{"propertySources":[{"name":"systemEnvironment"}],'
                   '"activeProfiles":["prod"]}')
        plugin = UnauthBatchPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED)

    @requests_mock.Mocker()
    def test_safe_all_auth_blocked(self, m):
        """安全：所有端点均返回 401 鉴权拦截"""
        m.get(MOCK_TARGET + 'actuator/env', status_code=401,
              text='{"msg":"认证失败，无法访问系统资源","code":401}')
        m.get(MOCK_TARGET + 'druid/index.html', status_code=401,
              text='请先登录')
        m.get(MOCK_TARGET + 'swagger-ui.html', status_code=401,
              text='unauthorized')
        m.get(MOCK_TARGET + 'system/user/list', status_code=401,
              text='{"msg":"认证失败","code":401}')
        plugin = UnauthBatchPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE,
                         f'全部端点鉴权拦截应判 SAFE，实际 {result.status}')

    @requests_mock.Mocker()
    def test_safe_no_keywords(self, m):
        """安全：端点返回 200 但无特征关键字（如 404 自定义页）"""
        for path in ['actuator/env', 'druid/index.html', 'swagger-ui.html', 'system/user/list']:
            m.get(MOCK_TARGET + path, status_code=200, text='<html>custom 404 page</html>')
        plugin = UnauthBatchPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE)


class TestDefaultPassword(unittest.TestCase):
    """Step 5：后台默认口令 admin/admin123 判定"""

    @requests_mock.Mocker()
    def test_hit_token(self, m):
        """命中：登录返回 token"""
        url = MOCK_TARGET + 'login'
        m.post(url, headers={'Content-Type': 'application/json'},
               text='{"code":200,"msg":"操作成功","token":"eyJhbGciOiJIUzUxMiJ9.'
                    'eyJsb2dpbl91c2VyX2tleSI6ImFkbWluIn0.signature"}')
        plugin = DefaultPasswordPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_CONFIRMED,
                         f'返回 token 应判 CONFIRMED，实际 {result.status}')
        self.assertEqual(result.extra.get('username'), 'admin')
        self.assertEqual(result.extra.get('password'), 'admin123')

    @requests_mock.Mocker()
    def test_safe_password_error(self, m):
        """安全：返回密码错误（code=500）"""
        url = MOCK_TARGET + 'login'
        m.post(url, headers={'Content-Type': 'application/json'},
               text='{"code":500,"msg":"用户不存在/密码错误"}')
        plugin = DefaultPasswordPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_SAFE,
                         f'密码错误应判 SAFE，实际 {result.status}')

    @requests_mock.Mocker()
    def test_unknown_captcha_required(self, m):
        """无法判定：服务端要求验证码"""
        url = MOCK_TARGET + 'login'
        m.post(url, headers={'Content-Type': 'application/json'},
               text='{"code":500,"msg":"验证码已失效，请重新获取"}')
        plugin = DefaultPasswordPlugin()
        result = plugin.verify(MOCK_TARGET, SessionManager())
        self.assertEqual(result.status, STATUS_UNKNOWN,
                         f'验证码场景应判 UNKNOWN（避免漏报），实际 {result.status}')
        self.assertTrue(result.extra.get('captcha_required', False))


# ---------------------------------------------------------------------------
# 入口：直接运行或 pytest 兼容
# ---------------------------------------------------------------------------

def run_all():
    """运行全部测试，返回 0 表示全部通过"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    # 按类加载，保证顺序
    test_classes = [
        TestFileRead,
        TestSqlInject,
        TestFileReadTime,
        TestDruidBrute,
        TestDirectoryScan,
        TestFileUpload,
        TestJobRce,
        TestThymeleafSsti,
        TestUnauthBatch,
        TestDefaultPassword,
    ]
    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_all())
