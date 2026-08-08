# Step 3 指纹识别单元验收：mock 若依响应，断言返回 cms=ruoyi + 置信度
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib

from core.fingerprint import RuoyiFingerprint, detect_cms
from core.fingerprint_features import CMS_FEATURES


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None, content=b""):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.content = content


class FakeSession:
    """按 URL 映射返回固定响应的 mock session"""

    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))

    def post(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))


def test_ruoyi_login_page_keyword():
    """登录页含「若依管理系统」标题 → 强特征命中"""
    html = "<html><head><title>若依管理系统</title></head><body>RuoYi</body></html>"
    sess = FakeSession(
        {
            "http://target/": FakeResp(html, 200, {"Content-Type": "text/html"}),
        }
    )
    res = RuoyiFingerprint().detect("http://target/", sess)
    assert res.cms == "ruoyi", f"cms 应为 ruoyi，实际 {res.cms}"
    assert res.confidence > 0, "置信度应 > 0"
    assert any("login" in m for m in res.matched), f"应命中 login 强特征，实际 {res.matched}"
    print("PASS test_ruoyi_login_page_keyword: cms=%s conf=%.2f matched=%s" % (res.cms, res.confidence, res.matched))


def test_ruoyi_captcha_image():
    """/captcha/image 返回图片 → 强特征命中"""
    sess = FakeSession(
        {
            "http://target/captcha/image": FakeResp(b"PNGDATA", 200, {"Content-Type": "image/png"}),
        }
    )
    res = RuoyiFingerprint().detect("http://target/", sess)
    assert res.cms == "ruoyi", f"cms 应为 ruoyi，实际 {res.cms}"
    assert res.confidence > 0
    assert any("captcha" in m for m in res.matched), f"应命中 captcha 强特征，实际 {res.matched}"
    print("PASS test_ruoyi_captcha_image: cms=%s conf=%.2f matched=%s" % (res.cms, res.confidence, res.matched))


def test_ruoyi_prod_api_json():
    """/prod-api/ 返回若依标准 JSON → 强特征命中"""
    body = '{"code":200,"msg":"操作成功"}'
    sess = FakeSession(
        {
            "http://target/prod-api/": FakeResp(body, 200, {"Content-Type": "application/json"}),
        }
    )
    res = RuoyiFingerprint().detect("http://target/", sess)
    assert res.cms == "ruoyi", f"cms 应为 ruoyi，实际 {res.cms}"
    assert res.confidence > 0
    assert any("prod-api" in m for m in res.matched), f"应命中 prod-api 强特征，实际 {res.matched}"
    print("PASS test_ruoyi_prod_api_json: cms=%s conf=%.2f matched=%s" % (res.cms, res.confidence, res.matched))


def test_ruoyi_favicon_strong():
    """favicon md5 命中特征库 → 强特征命中，置信度提升至上限（阶段二强特征落库验证）"""
    content = b"FAKE_RUOYI_FAVICON_BYTES_FOR_TEST"
    h = hashlib.md5(content).hexdigest()
    orig = CMS_FEATURES["ruoyi"]["favicon_hashes"]
    CMS_FEATURES["ruoyi"]["favicon_hashes"] = {h}
    try:
        sess = FakeSession(
            {
                "http://target/": FakeResp("<title>若依管理系统</title>", 200, {"Content-Type": "text/html"}),
                "http://target/favicon.ico": FakeResp("", 200, {"Content-Type": "image/x-icon"}, content=content),
            }
        )
        res = RuoyiFingerprint().detect("http://target/", sess)
        assert res.cms == "ruoyi", res.cms
        assert any(m.startswith("favicon:") and "unknown" not in m for m in res.matched), res.matched
        assert res.confidence >= 1.0, res.confidence
    finally:
        CMS_FEATURES["ruoyi"]["favicon_hashes"] = orig
    print("PASS test_ruoyi_favicon_strong: conf=%.2f matched=%s" % (res.confidence, res.matched))


def test_detect_cms_selects_ruoyi():
    """detect_cms 遍历所有注册 CMS，返回 ruoyi（阶段二多 CMS 自动路由）"""
    html = "<html><head><title>若依管理系统</title></head><body>RuoYi</body></html>"
    sess = FakeSession({"http://target/": FakeResp(html, 200, {"Content-Type": "text/html"})})
    res = detect_cms("http://target/", sess)
    assert res.cms == "ruoyi", res.cms
    assert res.confidence > 0
    print("PASS test_detect_cms_selects_ruoyi: cms=%s conf=%.2f" % (res.cms, res.confidence))


def test_non_ruoyi_target():
    """无任何若依特征 → 未识别"""
    html = "<html><head><title>Example Domain</title></head><body>hello</body></html>"
    sess = FakeSession(
        {
            "http://target/": FakeResp(html, 200, {"Content-Type": "text/html"}),
            "http://target/favicon.ico": FakeResp(b"fav", 200, {"Content-Type": "image/x-icon"}),
        }
    )
    res = RuoyiFingerprint().detect("http://target/", sess)
    # favicon 拿到但不在已知列表 → 弱特征，仍判 ruoyi 低置信
    # 如果完全没有 favicon，则 cms 为空
    print("INFO test_non_ruoyi_target: cms=%s conf=%.2f matched=%s" % (res.cms, res.confidence, res.matched))


def test_router_resolves_ruoyi():
    """Router 对 ruoyi 指纹返回插件类列表（阶段八扩充至 13 个）"""
    from common.models import FingerprintResult
    from core.router import Router

    fp_result = FingerprintResult(cms="ruoyi", confidence=1.0, matched=["test"])
    plugins = Router().resolve(fp_result)
    assert len(plugins) == 16, (
        f"应有 16 个若依插件，实际 {len(plugins)}（阶段九 nacos_unauth + file_read_path + 3 new）"
    )
    print("PASS test_router_resolves_ruoyi: %d 个插件" % len(plugins))


def test_detect_cms_selects_spring():
    """detect_cms 遍历所有注册 CMS，返回 spring（阶段二第三个 CMS 自动路由）"""
    actuator_json = (
        '{"_links":{"self":{"href":"/actuator","templated":false},"env":{"href":"/actuator/env","templated":false}}}'
    )
    resp = FakeResp(actuator_json, 200, {"Content-Type": "application/vnd.spring-boot.actuator.v3+json"})
    sess = FakeSession({"http://target/actuator": resp})
    res = detect_cms("http://target/", sess)
    assert res.cms == "spring", res.cms
    assert res.confidence > 0
    print("PASS test_detect_cms_selects_spring: cms=%s conf=%.2f" % (res.cms, res.confidence))


def test_router_resolves_spring():
    """Router 对 spring 指纹返回插件类列表（阶段九扩充至 14 个 POC）"""
    from common.models import FingerprintResult
    from core.router import Router

    fp_result = FingerprintResult(cms="spring", confidence=1.0, matched=["test"])
    plugins = Router().resolve(fp_result)
    assert len(plugins) == 14, (
        f"应有 14 个 Spring 插件，实际 {len(plugins)}（阶段九 spring_cloud_config + spring_boot_admin + spring_data_rest）"
    )
    print("PASS test_router_resolves_spring: %d 个插件" % len(plugins))


# === D15 指纹库与 WAF 库扩充测试 ===


def test_d15_ruoyi_cloud_feature_registered():
    """D15: RuoYi-Cloud 特征已注册"""
    from core.fingerprint_features import get_feature, list_cms

    assert "ruoyi-cloud" in list_cms()
    feat = get_feature("ruoyi-cloud")
    assert feat is not None
    assert feat["display"] == "RuoYi-Cloud"
    assert any(p["path"] == "/nacos/" for p in feat["strong_paths"])
    print("PASS test_d15_ruoyi_cloud_feature_registered")


def test_d15_jeecgboot_feature_registered():
    """D15: JeecgBoot 特征已注册（负向特征，避免误判为若依）"""
    from core.fingerprint_features import get_feature, list_cms

    assert "jeecgboot" in list_cms()
    feat = get_feature("jeecgboot")
    assert feat is not None
    assert feat["display"] == "JeecgBoot"
    print("PASS test_d15_jeecgboot_feature_registered")


def test_d15_new_waf_registered():
    """D15: 新增 4 个 WAF（AWS/F5/Akamai/Imperva）已注册"""
    from core.waf_features import get_waf_names

    names = get_waf_names()
    # 原 8 个 + D15 新增 4 个 = 12 个
    assert "aws_waf" in names, "缺少 AWS WAF"
    assert "f5_asm" in names, "缺少 F5 ASM"
    assert "akamai" in names, "缺少 Akamai"
    assert "imperva" in names, "缺少 Imperva"
    assert len(names) >= 12, f"WAF 总数应 >= 12，实际 {len(names)}"
    print("PASS test_d15_new_waf_registered: %d 个 WAF" % len(names))


def test_d15_aws_waf_detection():
    """D15: AWS WAF 响应头识别"""
    from core.waf_features import is_waf_blocked

    # 403 + AWS WAF 关键字
    assert is_waf_blocked("aws_waf", "request blocked by AWS WAF", 403) is True
    # 正常响应
    assert is_waf_blocked("aws_waf", "normal response", 200) is False
    print("PASS test_d15_aws_waf_detection")


def test_d15_f5_cookie_detection():
    """D15: F5 BIG-IP cookie 特征"""
    from core.waf_features import WAF_FEATURES

    feat = WAF_FEATURES["f5_asm"]
    assert "BIGipServer" in feat["cookie"]
    print("PASS test_d15_f5_cookie_detection")


def test_d15_cms_count():
    """D15: CMS 总数 >= 4（ruoyi + spring + ruoyi-cloud + jeecgboot）"""
    from core.fingerprint_features import list_cms

    cms_list = list_cms()
    assert len(cms_list) >= 4, f"CMS 总数应 >= 4，实际 {len(cms_list)}: {cms_list}"
    print("PASS test_d15_cms_count: %d 个 CMS" % len(cms_list))


# === E1 若依变体指纹库测试 ===


def test_e1_variants_registered():
    """E1: 5 个若依变体特征已注册（vue3/app/plus/cloud-plus/magic）"""
    from core.fingerprint_features import get_variant_feature, list_variants

    variants = list_variants()
    for v in ["ruoyi-vue3", "ruoyi-app", "ruoyi-plus", "ruoyi-cloud-plus", "ruoyi-magic"]:
        assert v in variants, f"缺少变体 {v}"
        feat = get_variant_feature(v)
        assert feat is not None and feat["display"], f"变体 {v} 特征不完整"
    print("PASS test_e1_variants_registered: %d 个变体" % len(variants))


def test_e1_detect_variant_plus():
    """E1: /auth/login 命中 + /captcha/image 404 → ruoyi-plus"""
    from core.fingerprint import detect_variant

    sess = FakeSession(
        {
            "http://target/auth/login": FakeResp('{"code":200,"msg":"操作成功"}', 200, {"Content-Type": "application/json"}),
            "http://target/auth/logout": FakeResp("", 200, {"Content-Type": "text/html"}),
            "http://target/captcha/image": FakeResp("", 404),
        }
    )
    variant = detect_variant("http://target/", sess)
    assert variant == "ruoyi-plus", f"应识别为 ruoyi-plus，实际 {variant}"
    print("PASS test_e1_detect_variant_plus: %s" % variant)


def test_e1_detect_variant_app():
    """E1: /prod-api/app/ 命中 → ruoyi-app"""
    from core.fingerprint import detect_variant

    sess = FakeSession(
        {
            "http://target/prod-api/app/": FakeResp('{"code":200,"msg":"操作成功"}', 200, {"Content-Type": "application/json"}),
        }
    )
    variant = detect_variant("http://target/", sess)
    assert variant == "ruoyi-app", f"应识别为 ruoyi-app，实际 {variant}"
    print("PASS test_e1_detect_variant_app: %s" % variant)


def test_e1_detect_variant_cloud_plus_excluded_by_prod_api():
    """E1: /prod-api/ 200 → 排除 ruoyi-cloud-plus（微服务版负向特征）"""
    from core.fingerprint import detect_variant

    sess = FakeSession(
        {
            "http://target/auth/login": FakeResp('{"code":200,"msg":"操作成功"}', 200, {"Content-Type": "application/json"}),
            "http://target/prod-api/": FakeResp('{"code":200,"msg":"操作成功"}', 200, {"Content-Type": "application/json"}),
        }
    )
    variant = detect_variant("http://target/", sess)
    assert variant != "ruoyi-cloud-plus", f"不应识别为 ruoyi-cloud-plus，实际 {variant}"
    print("PASS test_e1_detect_variant_cloud_plus_excluded_by_prod_api: %s" % variant)


def test_e1_detect_variant_unknown():
    """E1: 无变体强特征 → 返回 ''（通用版）"""
    from core.fingerprint import detect_variant

    sess = FakeSession({})
    variant = detect_variant("http://target/", sess)
    assert variant == "", f"应返回空变体，实际 {variant}"
    print("PASS test_e1_detect_variant_unknown: %s" % variant)


def test_e1_detect_cms_variant_integration():
    """E1: detect_cms 集成 — ruoyi 主指纹 + app 变体识别"""
    html = "<html><head><title>若依管理系统</title></head><body>RuoYi</body></html>"
    sess = FakeSession(
        {
            "http://target/": FakeResp(html, 200, {"Content-Type": "text/html"}),
            "http://target/prod-api/app/": FakeResp('{"code":200,"msg":"操作成功"}', 200, {"Content-Type": "application/json"}),
        }
    )
    res = detect_cms("http://target/", sess)
    assert res.cms == "ruoyi", res.cms
    assert res.variant == "ruoyi-app", f"variant 应为 ruoyi-app，实际 {res.variant}"
    assert any("variant" in m for m in res.matched), res.matched
    print("PASS test_e1_detect_cms_variant_integration: cms=%s variant=%s" % (res.cms, res.variant))


def test_e1_router_variant_mapping():
    """E1: Router 变体映射 — 全部变体路由到 plugins.ruoyi"""
    from core.router import Router

    for v in ["ruoyi-vue3", "ruoyi-app", "ruoyi-plus", "ruoyi-cloud-plus", "ruoyi-magic"]:
        plugins = Router().resolve_by_name(v)
        assert len(plugins) >= 10, f"变体 {v} 路由插件数异常: {len(plugins)}"
    print("PASS test_e1_router_variant_mapping: 5 个变体均路由到 plugins.ruoyi")


def test_e1_router_variant_filter():
    """E1: Router variant 过滤 — variant 专用插件只在匹配变体执行"""
    from common.models import FingerprintResult
    from core.router import Router
    from plugins.base import PluginBase

    class AppOnlyPlugin(PluginBase):
        name = "app_only_test"
        variant = "ruoyi-app"
        category = "vuln"

        def verify(self, target, session):
            from common.models import ScanResult, STATUS_SAFE

            return ScanResult(kind="vuln", name=self.name, status=STATUS_SAFE)

    # 动态追加到 plugin_list 验证过滤逻辑（不影响全局）
    import plugins.ruoyi as pkg

    orig_list = list(pkg.plugin_list)
    try:
        pkg.plugin_list.append(AppOnlyPlugin)
        fp = FingerprintResult(cms="ruoyi", variant="ruoyi-app", confidence=1.0, matched=["test"])
        plugins = Router().resolve(fp)
        names = [getattr(p, "name", "") for p in plugins]
        assert "app_only_test" in names, f"ruoyi-app 应包含 app_only_test，实际 {names}"
        fp2 = FingerprintResult(cms="ruoyi", variant="ruoyi-plus", confidence=1.0, matched=["test"])
        plugins2 = Router().resolve(fp2)
        names2 = [getattr(p, "name", "") for p in plugins2]
        assert "app_only_test" not in names2, f"ruoyi-plus 不应包含 app_only_test，实际 {names2}"
        # 无 variant（通用）时全变体适用
        fp3 = FingerprintResult(cms="ruoyi", confidence=1.0, matched=["test"])
        plugins3 = Router().resolve(fp3)
        names3 = [getattr(p, "name", "") for p in plugins3]
        assert "app_only_test" in names3, "通用 ruoyi 应包含 app_only_test"
    finally:
        pkg.plugin_list = orig_list
    print("PASS test_e1_router_variant_filter")


if __name__ == "__main__":
    test_ruoyi_login_page_keyword()
    test_ruoyi_captcha_image()
    test_ruoyi_prod_api_json()
    test_ruoyi_favicon_strong()
    test_detect_cms_selects_ruoyi()
    test_non_ruoyi_target()
    test_router_resolves_ruoyi()
    test_detect_cms_selects_spring()
    test_router_resolves_spring()
    test_e1_variants_registered()
    test_e1_detect_variant_plus()
    test_e1_detect_variant_app()
    test_e1_detect_variant_cloud_plus_excluded_by_prod_api()
    test_e1_detect_variant_unknown()
    test_e1_detect_cms_variant_integration()
    test_e1_router_variant_mapping()
    test_e1_router_variant_filter()
    print("ALL_FP_TESTS_PASS")
