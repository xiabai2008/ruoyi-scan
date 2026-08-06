# D1 登录链单元测试：RuoYiAuthChain v4 Session / v5 JWT / 验证码处理
# 运行：python tests/test_auth_chain.py 或 python -m pytest tests/test_auth_chain.py -q
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import requests_mock
except ImportError:
    print("缺少依赖 requests_mock，请先执行：pip install requests_mock")
    sys.exit(1)

from core.auth_chain import (
    AUTH_NONE,
    AUTH_V4_SESSION,
    AUTH_V5_JWT,
    LOGIN_CAPTCHA,
    LOGIN_FAIL,
    LOGIN_OK,
    RuoYiAuthChain,
)
from core.session import SessionManager

MOCK_TARGET = "http://ruoyi-auth.test"


class TestDetectAuthMode(unittest.TestCase):
    """鉴权模式探测"""

    @requests_mock.Mocker()
    def test_detect_v4_session(self, m):
        """GET /login 返回 HTML 登录页 → v4 Session"""
        m.get(
            MOCK_TARGET + "/login",
            text="<html><head><title>登录若依系统</title></head><body><form>登录</form></body></html>",
            headers={"Content-Type": "text/html;charset=UTF-8"},
        )
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        mode = chain.detect_auth_mode()
        self.assertEqual(mode, AUTH_V4_SESSION)

    @requests_mock.Mocker()
    def test_detect_v5_jwt(self, m):
        """GET /login 返回 JSON → v5 JWT"""
        m.get(
            MOCK_TARGET + "/login",
            text='{"code":401,"msg":"未登录"}',
            headers={"Content-Type": "application/json;charset=UTF-8"},
        )
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        mode = chain.detect_auth_mode()
        self.assertEqual(mode, AUTH_V5_JWT)

    @requests_mock.Mocker()
    def test_detect_none(self, m):
        """GET /login 返回 404 → 无鉴权"""
        m.get(MOCK_TARGET + "/login", status_code=404)
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        mode = chain.detect_auth_mode()
        self.assertEqual(mode, AUTH_NONE)


class TestLoginV4Session(unittest.TestCase):
    """v4 Session 登录"""

    @requests_mock.Mocker()
    def test_login_success_code_0(self, m):
        """登录成功：code=0（若依标准 success()）"""
        m.get(MOCK_TARGET + "/login", text="<html><form>登录</form></html>", headers={"Content-Type": "text/html"})
        m.post(MOCK_TARGET + "/login", text='{"code":0,"msg":"操作成功"}', headers={"Content-Type": "application/json"})
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login()
        self.assertTrue(ok)
        self.assertEqual(reason, LOGIN_OK)

    @requests_mock.Mocker()
    def test_login_success_code_200(self, m):
        """登录成功：code=200（部分版本）"""
        m.get(MOCK_TARGET + "/login", text="<html><form>登录</form></html>", headers={"Content-Type": "text/html"})
        m.post(
            MOCK_TARGET + "/login", text='{"code":200,"msg":"操作成功"}', headers={"Content-Type": "application/json"}
        )
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login()
        self.assertTrue(ok)
        self.assertEqual(reason, LOGIN_OK)

    @requests_mock.Mocker()
    def test_login_captcha_required(self, m):
        """需要验证码：响应含"验证码错误" → LOGIN_CAPTCHA"""
        m.get(MOCK_TARGET + "/login", text="<html><form>登录</form></html>", headers={"Content-Type": "text/html"})
        m.post(
            MOCK_TARGET + "/login", text='{"code":500,"msg":"验证码错误"}', headers={"Content-Type": "application/json"}
        )
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login()
        self.assertFalse(ok)
        self.assertEqual(reason, LOGIN_CAPTCHA)

    @requests_mock.Mocker()
    def test_login_wrong_password(self, m):
        """密码错误：响应含"用户或密码错误" → LOGIN_FAIL"""
        m.get(MOCK_TARGET + "/login", text="<html><form>登录</form></html>", headers={"Content-Type": "text/html"})
        m.post(
            MOCK_TARGET + "/login",
            text='{"code":500,"msg":"用户或密码错误"}',
            headers={"Content-Type": "application/json"},
        )
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login()
        self.assertFalse(ok)
        self.assertIn(LOGIN_FAIL, reason)


class TestLoginV5Jwt(unittest.TestCase):
    """v5 JWT 登录"""

    @requests_mock.Mocker()
    def test_login_success(self, m):
        """v5 登录成功：code=200 + token → session.headers 带 Authorization"""
        m.get(MOCK_TARGET + "/login", text='{"code":401,"msg":"未登录"}', headers={"Content-Type": "application/json"})
        m.post(
            MOCK_TARGET + "/login",
            text='{"code":200,"msg":"操作成功","token":"eyJhbGciOiJIUzI1NiJ9.test-token"}',
            headers={"Content-Type": "application/json"},
        )
        sess = SessionManager()
        chain = RuoYiAuthChain(MOCK_TARGET, sess)
        ok, reason = chain.login()
        self.assertTrue(ok)
        self.assertEqual(reason, LOGIN_OK)
        # 验证 session.headers 已带 Authorization
        self.assertEqual(sess.session.headers.get("Authorization"), "Bearer eyJhbGciOiJIUzI1NiJ9.test-token")

    @requests_mock.Mocker()
    def test_login_no_token(self, m):
        """v5 登录失败：code=200 但无 token 字段 → LOGIN_FAIL"""
        m.get(MOCK_TARGET + "/login", text='{"code":401,"msg":"未登录"}', headers={"Content-Type": "application/json"})
        m.post(
            MOCK_TARGET + "/login", text='{"code":200,"msg":"操作成功"}', headers={"Content-Type": "application/json"}
        )
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login()
        self.assertFalse(ok)
        self.assertIn(LOGIN_FAIL, reason)

    @requests_mock.Mocker()
    def test_login_captcha(self, m):
        """v5 需要验证码 → LOGIN_CAPTCHA"""
        m.get(MOCK_TARGET + "/login", text='{"code":401,"msg":"未登录"}', headers={"Content-Type": "application/json"})
        m.post(
            MOCK_TARGET + "/login",
            text='{"code":500,"msg":"captcha error"}',
            headers={"Content-Type": "application/json"},
        )
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login()
        self.assertFalse(ok)
        self.assertEqual(reason, LOGIN_CAPTCHA)


class TestLoginNone(unittest.TestCase):
    """无鉴权模式"""

    @requests_mock.Mocker()
    def test_login_skip(self, m):
        """无鉴权：GET /login 404 → login() 直接返回成功"""
        m.get(MOCK_TARGET + "/login", status_code=404)
        chain = RuoYiAuthChain(MOCK_TARGET, SessionManager())
        ok, reason = chain.login()
        self.assertTrue(ok)
        self.assertEqual(reason, LOGIN_OK)


if __name__ == "__main__":
    unittest.main(verbosity=2)
