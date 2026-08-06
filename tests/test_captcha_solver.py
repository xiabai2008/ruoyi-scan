# D3 验证码 OCR 单元测试
# 运行：python tests/test_captcha_solver.py 或 python -m pytest tests/test_captcha_solver.py -q
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import requests_mock
except ImportError:
    print('缺少依赖 requests_mock，请先执行：pip install requests_mock')
    sys.exit(1)

# 生成一个最小有效 PNG 图片（供 mock 返回）
import io

try:
    from PIL import Image, ImageDraw
    _buf = io.BytesIO()
    _img = Image.new('RGB', (80, 30), color=(255, 255, 255))
    _d = ImageDraw.Draw(_img)
    _d.text((10, 5), '1234', fill=(0, 0, 0))
    _img.save(_buf, format='PNG')
    TEST_PNG_BYTES = _buf.getvalue()
    HAS_PIL = True
except ImportError:
    # PIL 不可用时用最小 PNG
    TEST_PNG_BYTES = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
                      b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00'
                      b'\x00\x00\x0cIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02'
                      b'\xfe\xa3=\x01_\x00\x00\x00\x00IEND\xaeB`\x82')
    HAS_PIL = False

import base64

from core.auth_chain import LOGIN_CAPTCHA, LOGIN_OK, RuoYiAuthChain
from core.captcha_solver import CaptchaSolver
from core.session import SessionManager

MOCK_TARGET = 'http://ruoyi-captcha.test'


def _has_ocr_backend():
    """检查是否有可用的 OCR 后端（ddddocr 或 pytesseract）"""
    try:
        import ddddocr  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        import pytesseract  # noqa: F401
        return True
    except ImportError:
        pass
    return False


class TestDetectCaptcha(unittest.TestCase):
    """验证码接口探测"""

    @requests_mock.Mocker()
    def test_detect_image_captcha(self, m):
        """存在验证码：/captcha/captchaImage 返回 image/png → 探测成功"""
        m.get(MOCK_TARGET + '/captcha/captchaImage',
              content=TEST_PNG_BYTES,
              headers={'Content-Type': 'image/png'})
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        has, path = solver.detect_captcha()
        self.assertTrue(has)
        self.assertEqual(path, '/captcha/captchaImage')

    @requests_mock.Mocker()
    def test_detect_no_captcha(self, m):
        """无验证码：所有候选路径 404 → 探测失败"""
        for p in ['/captcha/captchaImage', '/captcha/image', '/code']:
            m.get(MOCK_TARGET + p, status_code=404)
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        has, path = solver.detect_captcha()
        self.assertFalse(has)
        self.assertEqual(path, '')

    @requests_mock.Mocker()
    def test_detect_base64_json_captcha(self, m):
        """v5 base64 验证码：/code 返回 JSON {img:base64} → 探测成功"""
        b64 = base64.b64encode(TEST_PNG_BYTES).decode()
        m.get(MOCK_TARGET + '/code',
              text='{"code":200,"img":"%s","uuid":"test-uuid"}' % b64,
              headers={'Content-Type': 'application/json'})
        # 前两个路径 404
        m.get(MOCK_TARGET + '/captcha/captchaImage', status_code=404)
        m.get(MOCK_TARGET + '/captcha/image', status_code=404)
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        has, path = solver.detect_captcha()
        self.assertTrue(has)
        self.assertEqual(path, '/code')


class TestSolve(unittest.TestCase):
    """验证码识别"""

    @requests_mock.Mocker()
    def test_solve_with_image(self, m):
        """有验证码图片 → OCR 识别（不检查具体结果，只检查流程跑通）"""
        m.get(MOCK_TARGET + '/captcha/captchaImage',
              content=TEST_PNG_BYTES,
              headers={'Content-Type': 'image/png'})
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        has, code = solver.solve()
        self.assertTrue(has)
        # OCR 结果可能因后端可用性而异，只检查流程跑通（code 可能是 '' 或识别结果）
        # 有 OCR 后端时 code 非空，无后端时 code 为空
        backend = solver.backend_name
        if backend != 'none':
            # 有后端时，PIL 生成的图片应能识别出内容（可能不精确）
            self.assertIsInstance(code, str)

    @requests_mock.Mocker()
    def test_solve_no_captcha(self, m):
        """无验证码接口 → has_captcha=False"""
        for p in ['/captcha/captchaImage', '/captcha/image', '/code']:
            m.get(MOCK_TARGET + p, status_code=404)
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        has, code = solver.solve()
        self.assertFalse(has)
        self.assertEqual(code, '')

    @requests_mock.Mocker()
    def test_solve_empty_image(self, m):
        """有接口但图片为空 → has_captcha=True, code=''"""
        m.get(MOCK_TARGET + '/captcha/captchaImage',
              content=b'',
              headers={'Content-Type': 'image/png'})
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        has, code = solver.solve()
        self.assertTrue(has)
        self.assertEqual(code, '')


class TestMathCaptcha(unittest.TestCase):
    """算术验证码求值"""

    def test_eval_add(self):
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        self.assertEqual(solver._eval_math_captcha('3+5=?'), '8')

    def test_eval_subtract(self):
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        self.assertEqual(solver._eval_math_captcha('9-2=?'), '7')

    def test_eval_multiply(self):
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        self.assertEqual(solver._eval_math_captcha('4*6=?'), '24')

    def test_eval_no_match(self):
        """非算术验证码 → 返回原文"""
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        self.assertEqual(solver._eval_math_captcha('aB3x'), 'aB3x')

    def test_eval_empty(self):
        solver = CaptchaSolver(MOCK_TARGET, SessionManager())
        self.assertEqual(solver._eval_math_captcha(''), '')


class TestAuthChainCaptchaIntegration(unittest.TestCase):
    """RuoYiAuthChain 验证码集成"""

    @unittest.skipIf(not _has_ocr_backend(), "无 OCR 后端（ddddocr/pytesseract），跳过自动识别测试")
    @requests_mock.Mocker()
    def test_login_with_captcha_auto_ocr(self, m):
        """登录链自动 OCR：有验证码接口 + OCR 成功 → 登录成功"""
        # GET /login 返回 HTML（v4 Session）
        m.get(MOCK_TARGET + '/login',
              text='<html><form>登录</form></html>',
              headers={'Content-Type': 'text/html'})
        # 验证码接口返回图片
        m.get(MOCK_TARGET + '/captcha/captchaImage',
              content=TEST_PNG_BYTES,
              headers={'Content-Type': 'image/png'})
        # POST /login 返回成功
        m.post(MOCK_TARGET + '/login',
               text='{"code":0,"msg":"操作成功"}',
               headers={'Content-Type': 'application/json'})
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login()  # captcha_code=None 自动 OCR
        self.assertTrue(ok)
        self.assertEqual(reason, LOGIN_OK)

    @requests_mock.Mocker()
    def test_login_captcha_empty_image(self, m):
        """登录链：有验证码接口但图片空 → LOGIN_CAPTCHA"""
        m.get(MOCK_TARGET + '/login',
              text='<html><form>登录</form></html>',
              headers={'Content-Type': 'text/html'})
        m.get(MOCK_TARGET + '/captcha/captchaImage',
              content=b'',
              headers={'Content-Type': 'image/png'})
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login()
        self.assertFalse(ok)
        self.assertIn(LOGIN_CAPTCHA, reason)

    @requests_mock.Mocker()
    def test_login_captcha_manual_code(self, m):
        """登录链：手动提供验证码 → 直接登录（不探测验证码接口）"""
        m.get(MOCK_TARGET + '/login',
              text='<html><form>登录</form></html>',
              headers={'Content-Type': 'text/html'})
        m.post(MOCK_TARGET + '/login',
               text='{"code":0,"msg":"操作成功"}',
               headers={'Content-Type': 'application/json'})
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login(captcha_code='1234')
        self.assertTrue(ok)
        self.assertEqual(reason, LOGIN_OK)

    @requests_mock.Mocker()
    def test_login_skip_captcha(self, m):
        """登录链：captcha_code='' 跳过验证码 → 登录成功（无验证码环境）"""
        m.get(MOCK_TARGET + '/login',
              text='<html><form>登录</form></html>',
              headers={'Content-Type': 'text/html'})
        m.post(MOCK_TARGET + '/login',
               text='{"code":0,"msg":"操作成功"}',
               headers={'Content-Type': 'application/json'})
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login(captcha_code='')
        self.assertTrue(ok)
        self.assertEqual(reason, LOGIN_OK)


if __name__ == '__main__':
    unittest.main(verbosity=2)
