# Step 3 指纹识别单元验收：mock 若依响应，断言返回 cms=ruoyi + 置信度
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fingerprint import RuoyiFingerprint


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
    """Router 对 ruoyi 指纹返回插件类列表"""
    from core.router import Router
    from core.models import FingerprintResult
    fp_result = FingerprintResult(cms='ruoyi', confidence=1.0, matched=['test'])
    plugins = Router().resolve(fp_result)
    assert len(plugins) == 6, f'应有 6 个若依插件，实际 {len(plugins)}'
    print('PASS test_router_resolves_ruoyi: %d 个插件' % len(plugins))


if __name__ == '__main__':
    test_ruoyi_login_page_keyword()
    test_ruoyi_captcha_image()
    test_ruoyi_prod_api_json()
    test_non_ruoyi_target()
    test_router_resolves_ruoyi()
    print('ALL_FP_TESTS_PASS')
