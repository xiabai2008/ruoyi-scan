# D5 误报率测试单元测试：验证 10 个非若依靶场不被误判为 ruoyi
# 运行：python tests/test_fp_lab.py 或 python -m pytest tests/test_fp_lab.py -q
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

from core.fingerprint import detect_cms
from core.session import SessionManager
from lab.fp_lab.server import TARGETS, render

MOCK_TARGET = 'http://fp-target.test'


class TestFpLabRender(unittest.TestCase):
    """靶场内容渲染测试"""

    def test_all_targets_renderable(self):
        """所有 10 个靶场都能渲染出内容"""
        self.assertEqual(len(TARGETS), 10, '应有 10 个误报靶场')
        for target_id in TARGETS:
            content, ct = render(target_id)
            self.assertIsInstance(content, str, f'{target_id} 渲染应返回字符串')
            self.assertIn('text/html', ct, f'{target_id} Content-Type 应为 text/html')

    def test_blank_is_empty(self):
        """空白靶场返回空字符串"""
        content, _ = render('blank')
        self.assertEqual(content, '')

    def test_wordpress_has_wp_features(self):
        """WordPress 靶场含 wp-content 特征"""
        content, _ = render('wordpress')
        self.assertIn('wp-content', content)
        self.assertIn('WordPress', content)

    def test_weak_ruoyi_keyword_has_ruoyi_text(self):
        """边界靶场含"若依"二字（弱特征命中）"""
        content, _ = render('weak_ruoyi_keyword')
        self.assertIn('若依', content)
        # 但不含若依强特征
        self.assertNotIn('RuoYi', content)
        self.assertNotIn('若依管理系统', content)


class TestFpDetection(unittest.TestCase):
    """指纹识别误报测试：10 个靶场不应被判为 ruoyi"""

    def _mock_target(self, m, target_id):
        """mock 一个靶场的所有路径返回该靶场内容"""
        content, ct = render(target_id)
        headers = {'Content-Type': ct + '; charset=utf-8'}
        # mock 根路径
        m.get(MOCK_TARGET + '/', text=content, headers=headers)
        # mock /login（若依强特征路径之一）
        m.get(MOCK_TARGET + '/login', text=content, headers=headers)
        # mock /favicon.ico（非若依 favicon，返回空）
        m.get(MOCK_TARGET + '/favicon.ico', content=b'', headers={'Content-Type': 'image/x-icon'})
        # mock /prod-api/（若依强特征路径，返回非 JSON）
        m.get(MOCK_TARGET + '/prod-api/', text=content, headers=headers)
        # mock /captcha/image（若依强特征路径，返回非 image）
        m.get(MOCK_TARGET + '/captcha/image', text=content, headers=headers)
        # mock /captcha/captchaImage（若依 4.x 验证码路径）
        m.get(MOCK_TARGET + '/captcha/captchaImage', text=content, headers=headers)
        # mock /getInfo（若依强特征路径，返回非 JSON）
        m.get(MOCK_TARGET + '/getInfo', text=content, headers=headers)
        # mock /actuator（Spring 强特征路径，返回 404 避免误判 spring）
        m.get(MOCK_TARGET + '/actuator', status_code=404)

    def _check_not_ruoyi(self, target_id):
        """断言指定靶场不被判为 ruoyi"""
        with requests_mock.Mocker() as m:
            self._mock_target(m, target_id)
            fp = detect_cms(MOCK_TARGET, SessionManager())
            self.assertNotEqual(fp.cms, 'ruoyi',
                                f'{target_id} 不应被误判为 ruoyi，'
                                f'实际 cms={fp.cms} 置信度={fp.confidence:.2f} 命中={fp.matched}')

    def test_blank_not_ruoyi(self):
        self._check_not_ruoyi('blank')

    def test_generic_html_not_ruoyi(self):
        self._check_not_ruoyi('generic_html')

    def test_wordpress_not_ruoyi(self):
        self._check_not_ruoyi('wordpress')

    def test_joomla_not_ruoyi(self):
        self._check_not_ruoyi('joomla')

    def test_spring_whitelabel_not_ruoyi(self):
        self._check_not_ruoyi('spring_whitelabel')

    def test_django_not_ruoyi(self):
        self._check_not_ruoyi('django')

    def test_nginx_welcome_not_ruoyi(self):
        self._check_not_ruoyi('nginx_welcome')

    def test_apache_welcome_not_ruoyi(self):
        self._check_not_ruoyi('apache_welcome')

    def test_tomcat_default_not_ruoyi(self):
        self._check_not_ruoyi('tomcat_default')

    def test_weak_ruoyi_keyword_not_ruoyi(self):
        """边界测试：含"若依"弱特征但无强特征，不应判为 ruoyi"""
        self._check_not_ruoyi('weak_ruoyi_keyword')

    def test_fp_rate_under_5_percent(self):
        """误报率 <5%（10 个靶场最多 0 个假阳）"""
        false_positives = 0
        for target_id in TARGETS:
            with requests_mock.Mocker() as m:
                self._mock_target(m, target_id)
                fp = detect_cms(MOCK_TARGET, SessionManager())
                if fp.cms == 'ruoyi':
                    false_positives += 1
        total = len(TARGETS)
        fp_rate = false_positives / total * 100
        self.assertLess(fp_rate, 5.0,
                        f'误报率 {fp_rate:.1f}% 应 <5%（假阳 {false_positives}/{total}）')


if __name__ == '__main__':
    unittest.main(verbosity=2)
