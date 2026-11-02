# 未授权类插件的会话隔离（v1.6 A2）
#
# 背景：未授权类插件的被测命题是「**不需要登录**就能访问」。
# 共享 SessionManager 可能已被默认口令/爆破插件登录污染，此时拿到的 200
# 只证明「登录后能访问」，不构成未授权漏洞。
#
# 真实会出事的场景（客户现场）：
#   Swagger 开了但配了认证 → 扫描器先跑「后台默认口令」拿到会话
#   → Swagger 插件复用该会话 → 200 + 真实页面 → 报「Swagger 未授权访问」
#   → 客户复核「我们明明加了认证」，报告可信度归零。
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.matcher import looks_authenticated  # noqa: E402

# ============================================================
# 1. looks_authenticated() 判据本身
# ============================================================


def test_detects_ruoyi_user_info():
    assert looks_authenticated('{"code":200,"user":{"userId":1,"userName":"admin"}}')[0] is True


def test_detects_permission_list():
    assert looks_authenticated('{"permissions":["*:*:*"],"roles":["admin"]}')[0] is True


def test_detects_jwt_token():
    assert looks_authenticated('{"access_token":"eyJhbGciOiJIUzI1NiJ9.abcdefgh"}')[0] is True


def test_detects_session_cookie_issued():
    assert looks_authenticated("{}", {"Set-Cookie": "JSESSIONID=abc123; Path=/"})[0] is True


def test_plain_business_list_is_not_authenticated():
    """普通业务列表不能误判——否则真漏洞会被降级成 UNKNOWN（假阴性）"""
    assert looks_authenticated('{"code":200,"total":2,"rows":[{"jobId":1}]}')[0] is False


def test_plain_html_is_not_authenticated():
    assert looks_authenticated("<html><body>Welcome</body></html>")[0] is False


def test_auth_failure_message_is_not_authenticated():
    """「认证失败」是**未**认证的证据，不能当成已认证"""
    assert looks_authenticated('{"code":401,"msg":"认证失败"}')[0] is False


def test_ordinary_cookie_is_not_authenticated():
    """普通埋点 cookie 不是会话凭证"""
    assert looks_authenticated("{}", {"Set-Cookie": "visited=1; Path=/"})[0] is False


def test_empty_response_is_not_authenticated():
    assert looks_authenticated("")[0] is False


# ============================================================
# 2. 插件用匿名会话探测
# ============================================================


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self.content = text.encode()

    def json(self):
        import json

        return json.loads(self.text)


class _Session:
    """记录是否调用了 anonymous()，并用固定响应作答"""

    def __init__(self, resp, anonymous_resp=None):
        self.resp = resp
        self.anonymous_resp = anonymous_resp or resp
        self.anonymous_called = False
        self.session = SimpleNamespace(cookies={}, headers={})

    def get(self, url, **kw):
        return self.resp

    def anonymous(self):
        self.anonymous_called = True
        inner = self
        class _Anon:
            def get(self, url, **kw):
                return inner.anonymous_resp
            def close(self):
                pass
        return _Anon()


def test_unauth_plugins_use_anonymous_session():
    """4 个原本裸用共享会话的插件，现在都必须走 anonymous()"""
    from plugins.common.minio_unauth import MinioUnauthPlugin
    from plugins.common.rocketmq_unauth import RocketmqUnauthPlugin
    from plugins.ruoyi.nacos_unauth import RuoyiNacosUnauthPlugin
    from plugins.ruoyi.ruoyi_cloud_nacos import RuoyiCloudNacosPlugin

    for cls in (MinioUnauthPlugin, RuoyiNacosUnauthPlugin, RocketmqUnauthPlugin, RuoyiCloudNacosPlugin):
        sess = _Session(_Resp("{}"))
        cls().verify("http://t/", sess)
        assert sess.anonymous_called, f"{cls.__name__} 必须用匿名会话探测"


def test_nacos_confirms_on_real_unauth_response():
    """真实 Nacos 未授权响应 → CONFIRMED

    形状：{"totalCount":1,"pageNumber":1,"pageItems":[{"username":"nacos",
           "password":"$2a$10$..."}]}
    注意这里的 username/password 是**列表数据**，不是「当前登录用户」——
    looks_authenticated 不该把它误判成已认证，否则真漏洞会被降级掉（假阴性）。
    """
    from plugins.ruoyi.nacos_unauth import RuoyiNacosUnauthPlugin

    body = (
        '{"totalCount":1,"pageNumber":1,"pageSize":10,'
        '"pageItems":[{"username":"nacos","password":"$2a$10$abcdefghijklmnop"}]}'
    )
    sess = _Session(_Resp("{}"), anonymous_resp=_Resp(body))
    res = RuoyiNacosUnauthPlugin().verify("http://t/", sess)
    assert res.status == "CONFIRMED", f"真实未授权响应应 CONFIRMED，实际 {res.status}: {res.evidence}"


def test_nacos_unknown_when_response_has_login_user():
    """Nacos 响应里出现「当前登录用户」身份回显 → UNKNOWN

    与上一个用例的区别：那里 username 在 pageItems 数组里（用户列表数据），
    这里 userName/nickName 出现在顶层（当前会话的身份）——后者说明带着有效凭据。
    """
    from plugins.ruoyi.nacos_unauth import RuoyiNacosUnauthPlugin

    body = (
        '{"totalCount":1,"pageNumber":1,'
        '"userName":"nacos","nickName":"运维管理员",'
        '"pageItems":[{"username":"nacos","password":"$2a$10$abcdefghijklmnop"}]}'
    )
    sess = _Session(_Resp("{}"), anonymous_resp=_Resp(body))
    res = RuoyiNacosUnauthPlugin().verify("http://t/", sess)
    assert res.status == "UNKNOWN", f"带身份回显应降级 UNKNOWN，实际 {res.status}: {res.evidence}"
    assert "已认证" in res.evidence or "无法确认" in res.evidence


# ============================================================
# 3. 能力标志互斥校验
# ============================================================


def test_conflicting_capability_flags_rejected():
    """requires_auth 与 anonymous_probe 同时为 True 是语义矛盾，加载期就该报错"""
    from core.loader import _validate_capability_flags
    from plugins.base import PluginBase

    class _Bad(PluginBase):
        name = "矛盾插件"
        requires_auth = True
        anonymous_probe = True

        def verify(self, target, session):
            raise NotImplementedError

    try:
        _validate_capability_flags(_Bad)
    except ValueError as e:
        assert "互斥" in str(e)
    else:
        raise AssertionError("互斥标志应被拒绝")


def test_normal_plugin_passes_validation():
    from core.loader import _validate_capability_flags
    from plugins.base import PluginBase

    class _Ok(PluginBase):
        name = "正常插件"

        def verify(self, target, session):
            raise NotImplementedError

    _validate_capability_flags(_Ok)  # 不应抛异常


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)


# ============================================================
# 4. 降级证据的「解锁提示」（A2 配套）
# ============================================================


def _mk_safe(name, cap):
    from common.models import ScanResult

    r = ScanResult(kind="info", name=name, status="SAFE", evidence="状态码=200, 未检测到特征")
    r.extra = {"plugin_capability": cap}
    return r


def test_unauth_plugin_hint_warns_against_login_rescan():
    """未授权类必须明确「登录后重扫结论无效」——给错建议比不给更糟"""
    from lib.reachability import downgrade_auth_wall_safe

    r = _mk_safe("未授权类", {"path_scope": "api", "anonymous_probe": True, "requires_auth": False})
    downgrade_auth_wall_safe([r], {"wall": True, "reason": "200 登录页"})
    assert r.status == "UNKNOWN"
    assert "登录后重扫得到的结论无效" in r.evidence


def test_root_scope_plugin_hint_mentions_static_files():
    """.git/.env 类提示「登录后放行才能探测 web 根」"""
    from lib.reachability import downgrade_auth_wall_safe

    r = _mk_safe(".git 泄露", {"path_scope": "root", "anonymous_probe": False, "requires_auth": False})
    downgrade_auth_wall_safe([r], {"wall": True, "reason": "200 登录页"})
    assert "--auth-login" in r.evidence
    assert "静态文件" in r.evidence


def test_requires_auth_plugin_hint_mentions_high_priv_account():
    from lib.reachability import downgrade_auth_wall_safe

    r = _mk_safe("需会话类", {"path_scope": "api", "anonymous_probe": False, "requires_auth": True})
    downgrade_auth_wall_safe([r], {"wall": True, "reason": "200 登录页"})
    assert "--auth-login" in r.evidence
    assert "高权账号" in r.evidence


def test_missing_capability_falls_back_to_generic_hint():
    """没有能力元信息时退化到通用提示，不能崩"""
    from common.models import ScanResult
    from lib.reachability import downgrade_auth_wall_safe

    r = ScanResult(kind="info", name="无元信息", status="SAFE", evidence="状态码=200")
    downgrade_auth_wall_safe([r], {"wall": True, "reason": "200 登录页"})
    assert r.status == "UNKNOWN"
    assert "--auth-login" in r.evidence


def test_enrich_writes_capability_metadata():
    """PluginBase.enrich() 必须把能力声明带进结果，且幂等"""
    from common.models import ScanResult
    from plugins.ruoyi.nacos_unauth import RuoyiNacosUnauthPlugin

    inst = RuoyiNacosUnauthPlugin()
    r = ScanResult(kind="info", name="x", status="SAFE", evidence="e")
    inst.enrich(r)
    cap = r.extra["plugin_capability"]
    assert cap["anonymous_probe"] is True
    assert cap["path_scope"] == "api"
    # 幂等：再调一次不覆盖
    first = dict(cap)
    inst.enrich(r)
    assert r.extra["plugin_capability"] == first


# ============================================================
# 5. JSON 信封鉴权墙（v1.6 WP-U1）
#
# 芋道/Jeecg 的未授权响应是 HTTP 200 + JSON 业务码（不设 status），
# 旧正则要求 code 后紧跟 [:=]，认不出 "code":401（中间有引号）→
# 插件判的 SAFE 不会被升级成 UNKNOWN → 「把没测到写成确认不存在」。
# 这份语料就是「加新框架时的注册点」：把新框架的未授权响应加进来即可。
# ============================================================

# (响应文本, 是否应被识别为「请求被拒」, 来源框架)
_AUTH_DENY_CORPUS = [
    ('{"code":401,"msg":"账号未登录"}', True, "芋道 yudao"),
    ('{"code":403,"data":null}', True, "芋道 yudao"),
    ('{"code": 401}', True, "芋道（带空格）"),
    ('{"code":"401"}', True, "字符串状态码"),
    ('{"success":false,"code":500,"message":"Token校验失败"}', True, "JeecgBoot"),
    ("状态码=401", True, "若依（插件原生格式）"),
    ("HTTP 403", True, "通用"),
    # 这三类**绝不能**被当成拒绝，否则正常结果会被误降级
    ('{"code":0,"data":[]}', False, "芋道成功（业务码是 0 不是 200）"),
    ('{"code":200,"rows":[]}', False, "若依成功"),
    ('{"totalCount":1,"pageItems":[]}', False, "普通业务数据"),
]


def test_deny_regex_recognizes_json_envelope():
    """JSON 信封形态的鉴权拒绝必须被认出（旧正则会漏掉全部引号形态）"""
    from lib.reachability import _DENY_RE

    for text, expect, source in _AUTH_DENY_CORPUS:
        got = bool(_DENY_RE.search(text))
        assert got == expect, f"{source}: {text!r} 期望 {expect} 实际 {got}"


def test_deny_regex_does_not_match_partial_codes():
    """4010 不能被当成 401"""
    from lib.reachability import _DENY_RE

    assert bool(_DENY_RE.search('{"code":4010}')) is False


def test_upgrade_denied_handles_yudao_envelope():
    """端到端：芋道形态的 SAFE 必须被升级成 UNKNOWN"""
    from common.models import STATUS_SAFE, STATUS_UNKNOWN, ScanResult
    from lib.reachability import upgrade_denied_safe_to_unknown

    r = ScanResult(
        kind="info",
        name="某接口",
        status=STATUS_SAFE,
        evidence='响应 {"code":401,"msg":"账号未登录"}，未命中漏洞特征',
    )
    assert upgrade_denied_safe_to_unknown([r]) == 1
    assert r.status == STATUS_UNKNOWN


def test_upgrade_denied_keeps_business_success_safe():
    """业务成功响应不能被误升级（芋道 code:0 / 若依 code:200）"""
    from common.models import STATUS_SAFE, ScanResult
    from lib.reachability import upgrade_denied_safe_to_unknown

    for body in ('{"code":0,"data":[]}', '{"code":200,"rows":[]}'):
        r = ScanResult(kind="info", name="某接口", status=STATUS_SAFE, evidence=f"响应 {body}，未命中漏洞特征")
        upgrade_denied_safe_to_unknown([r])
        assert r.status == STATUS_SAFE, f"{body} 不应被升级为 UNKNOWN"
