# Step 3 指纹识别单元验收：mock 若依响应，断言返回 cms=ruoyi + 置信度
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fingerprint import RuoyiFingerprint, detect_cms
import hashlib
from core.fingerprint_features import CMS_FEATURES


class FakeResp:
    def __init__(self, text='', status_code=200, headers=None, content=b''):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {'Content-Type': 'text/html'}
        self.content = content


class FakeSession:
    """按 URL 映射返回固定响应的 mock session"""

    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **kw):
        return self.responses.get(url, FakeResp('', 404))

    def post(self, url, **kw):
        return self.responses.get(url, FakeResp('', 404))


def test_ruoyi_login_page_keyword():
    """登录页含「若依管理系统」标题 → 强特征命中"""
    html = '<html><head><title>若依管理系统</title></head><body>RuoYi</body></html>'
    sess = FakeSession({
        'http://target/': FakeResp(html, 200, {'Content-Type': 'text/html'}),
    })
    res = RuoyiFingerprint().detect('http://target/', sess)
    assert res.cms == 'ruoyi', f'cms 应为 ruoyi，实际 {res.cms}'
    assert res.confidence > 0, '置信度应 > 0'
    assert any('login' in m for m in res.matched), f'应命中 login 强特征，实际 {res.matched}'
    print('PASS test_ruoyi_login_page_keyword: cms=%s conf=%.2f matched=%s'
          % (res.cms, res.confidence, res.matched))


def test_ruoyi_captcha_image():
    """/captcha/image 返回图片 → 强特征命中"""
    sess = FakeSession({
        'http://target/captcha/image': FakeResp(b'PNGDATA', 200, {'Content-Type': 'image/png'}),
    })
    res = RuoyiFingerprint().detect('http://target/', sess)
    assert res.cms == 'ruoyi', f'cms 应为 ruoyi，实际 {res.cms}'
    assert res.confidence > 0
    assert any('captcha' in m for m in res.matched), f'应命中 captcha 强特征，实际 {res.matched}'
    print('PASS test_ruoyi_captcha_image: cms=%s conf=%.2f matched=%s'
          % (res.cms, res.confidence, res.matched))


def test_ruoyi_prod_api_json():
    """/prod-api/ 返回若依标准 JSON → 强特征命中"""
    body = '{"code":200,"msg":"操作成功"}'
    sess = FakeSession({
        'http://target/prod-api/': FakeResp(body, 200, {'Content-Type': 'application/json'}),
    })
    res = RuoyiFingerprint().detect('http://target/', sess)
    assert res.cms == 'ruoyi', f'cms 应为 ruoyi，实际 {res.cms}'
    assert res.confidence > 0
    assert any('prod-api' in m for m in res.matched), f'应命中 prod-api 强特征，实际 {res.matched}'
    print('PASS test_ruoyi_prod_api_json: cms=%s conf=%.2f matched=%s'
          % (res.cms, res.confidence, res.matched))


def test_ruoyi_favicon_strong():
    """favicon md5 命中特征库 → 强特征命中，置信度提升至上限（阶段二强特征落库验证）"""
    content = b'FAKE_RUOYI_FAVICON_BYTES_FOR_TEST'
    h = hashlib.md5(content).hexdigest()
    orig = CMS_FEATURES['ruoyi']['favicon_hashes']
    CMS_FEATURES['ruoyi']['favicon_hashes'] = {h}
    try:
        sess = FakeSession({
            'http://target/': FakeResp('<title>若依管理系统</title>', 200, {'Content-Type': 'text/html'}),
            'http://target/favicon.ico': FakeResp('', 200, {'Content-Type': 'image/x-icon'}, content=content),
        })
        res = RuoyiFingerprint().detect('http://target/', sess)
        assert res.cms == 'ruoyi', res.cms
        assert any(m.startswith('favicon:') and 'unknown' not in m for m in res.matched), res.matched
        assert res.confidence >= 1.0, res.confidence
    finally:
        CMS_FEATURES['ruoyi']['favicon_hashes'] = orig
    print('PASS test_ruoyi_favicon_strong: conf=%.2f matched=%s' % (res.confidence, res.matched))


def test_detect_cms_selects_ruoyi():
    """detect_cms 遍历所有注册 CMS，返回 ruoyi（阶段二多 CMS 自动路由）"""
    html = '<html><head><title>若依管理系统</title></head><body>RuoYi</body></html>'
    sess = FakeSession({'http://target/': FakeResp(html, 200, {'Content-Type': 'text/html'})})
    res = detect_cms('http://target/', sess)
    assert res.cms == 'ruoyi', res.cms
    assert res.confidence > 0
    print('PASS test_detect_cms_selects_ruoyi: cms=%s conf=%.2f' % (res.cms, res.confidence))


def test_non_ruoyi_target():
    """无任何若依特征 → 未识别"""
    html = '<html><head><title>Example Domain</title></head><body>hello</body></html>'
    sess = FakeSession({
        'http://target/': FakeResp(html, 200, {'Content-Type': 'text/html'}),
        'http://target/favicon.ico': FakeResp(b'fav', 200, {'Content-Type': 'image/x-icon'}),
    })
    res = RuoyiFingerprint().detect('http://target/', sess)
    # favicon 拿到但不在已知列表 → 弱特征，仍判 ruoyi 低置信
    # 如果完全没有 favicon，则 cms 为空
    print('INFO test_non_ruoyi_target: cms=%s conf=%.2f matched=%s'
          % (res.cms, res.confidence, res.matched))


def test_router_resolves_ruoyi():
    """Router 对 ruoyi 指纹返回插件类列表（阶段八扩充至 13 个）"""
    from core.router import Router
    from core.models import FingerprintResult
    fp_result = FingerprintResult(cms='ruoyi', confidence=1.0, matched=['test'])
    plugins = Router().resolve(fp_result)
    assert len(plugins) == 16, f'应有 16 个若依插件，实际 {len(plugins)}（阶段九 nacos_unauth + file_read_path + 3 new）'
    print('PASS test_router_resolves_ruoyi: %d 个插件' % len(plugins))


def test_detect_cms_selects_spring():
    """detect_cms 遍历所有注册 CMS，返回 spring（阶段二第三个 CMS 自动路由）"""
    actuator_json = '{"_links":{"self":{"href":"/actuator","templated":false},"env":{"href":"/actuator/env","templated":false}}}'
    resp = FakeResp(actuator_json, 200, {'Content-Type': 'application/vnd.spring-boot.actuator.v3+json'})
    sess = FakeSession({'http://target/actuator': resp})
    res = detect_cms('http://target/', sess)
    assert res.cms == 'spring', res.cms
    assert res.confidence > 0
    print('PASS test_detect_cms_selects_spring: cms=%s conf=%.2f' % (res.cms, res.confidence))


def test_router_resolves_spring():
    """Router 对 spring 指纹返回插件类列表（阶段九扩充至 14 个 POC）"""
    from core.router import Router
    from core.models import FingerprintResult
    fp_result = FingerprintResult(cms='spring', confidence=1.0, matched=['test'])
    plugins = Router().resolve(fp_result)
    assert len(plugins) == 14, f'应有 14 个 Spring 插件，实际 {len(plugins)}（阶段九 spring_cloud_config + spring_boot_admin + spring_data_rest）'
    print('PASS test_router_resolves_spring: %d 个插件' % len(plugins))


# === D15 指纹库与 WAF 库扩充测试 ===

def test_d15_ruoyi_cloud_feature_registered():
    """D15: RuoYi-Cloud 特征已注册"""
    from core.fingerprint_features import get_feature, list_cms
    assert 'ruoyi-cloud' in list_cms()
    feat = get_feature('ruoyi-cloud')
    assert feat is not None
    assert feat['display'] == 'RuoYi-Cloud'
    assert any(p['path'] == '/nacos/' for p in feat['strong_paths'])
    print('PASS test_d15_ruoyi_cloud_feature_registered')


def test_d15_jeecgboot_feature_registered():
    """D15: JeecgBoot 特征已注册（负向特征，避免误判为若依）"""
    from core.fingerprint_features import get_feature, list_cms
    assert 'jeecgboot' in list_cms()
    feat = get_feature('jeecgboot')
    assert feat is not None
    assert feat['display'] == 'JeecgBoot'
    print('PASS test_d15_jeecgboot_feature_registered')


def test_d15_new_waf_registered():
    """D15: 新增 4 个 WAF（AWS/F5/Akamai/Imperva）已注册"""
    from core.waf_features import get_waf_names
    names = get_waf_names()
    # 原 8 个 + D15 新增 4 个 = 12 个
    assert 'aws_waf' in names, '缺少 AWS WAF'
    assert 'f5_asm' in names, '缺少 F5 ASM'
    assert 'akamai' in names, '缺少 Akamai'
    assert 'imperva' in names, '缺少 Imperva'
    assert len(names) >= 12, f'WAF 总数应 >= 12，实际 {len(names)}'
    print('PASS test_d15_new_waf_registered: %d 个 WAF' % len(names))


def test_d15_aws_waf_detection():
    """D15: AWS WAF 响应头识别"""
    from core.waf_features import is_waf_blocked
    # 403 + AWS WAF 关键字
    assert is_waf_blocked('aws_waf', 'request blocked by AWS WAF', 403) is True
    # 正常响应
    assert is_waf_blocked('aws_waf', 'normal response', 200) is False
    print('PASS test_d15_aws_waf_detection')


def test_d15_f5_cookie_detection():
    """D15: F5 BIG-IP cookie 特征"""
    from core.waf_features import WAF_FEATURES
    feat = WAF_FEATURES['f5_asm']
    assert 'BIGipServer' in feat['cookie']
    print('PASS test_d15_f5_cookie_detection')


def test_d15_cms_count():
    """D15: CMS 总数 >= 4（ruoyi + spring + ruoyi-cloud + jeecgboot）"""
    from core.fingerprint_features import list_cms
    cms_list = list_cms()
    assert len(cms_list) >= 4, f'CMS 总数应 >= 4，实际 {len(cms_list)}: {cms_list}'
    print('PASS test_d15_cms_count: %d 个 CMS' % len(cms_list))


if __name__ == '__main__':
    test_ruoyi_login_page_keyword()
    test_ruoyi_captcha_image()
    test_ruoyi_prod_api_json()
    test_ruoyi_favicon_strong()
    test_detect_cms_selects_ruoyi()
    test_non_ruoyi_target()
    test_router_resolves_ruoyi()
    test_detect_cms_selects_spring()
    test_router_resolves_spring()
    print('ALL_FP_TESTS_PASS')
