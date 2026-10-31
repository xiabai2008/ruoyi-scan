# API 前缀探测（前后端分离版只反代 /prod-api/）回归测试
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.basepath import detect_api_base  # noqa: E402


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "application/json"}


class FakeSession:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, url, **kw):
        return self.mapping.get(url, FakeResp("<html><title>SPA</title></html>", 200, {"Content-Type": "text/html"}))


CAPTCHA_JSON = '{"msg":"操作成功","code":200,"captchaEnabled":false}'


def test_basepath_detected_for_spa_frontend():
    """根路径是 SPA 兜底页、/prod-api/captchaImage 是后端 JSON → 识别 /prod-api"""
    sess = FakeSession({"http://target/prod-api/captchaImage": FakeResp(CAPTCHA_JSON, 200)})
    assert detect_api_base("http://target/", sess) == "/prod-api"


def test_basepath_empty_when_root_is_backend():
    """根路径就能拿到验证码 JSON（单机版 / 根反代）→ 不加前缀，行为不变"""
    sess = FakeSession({"http://target/captchaImage": FakeResp(CAPTCHA_JSON, 200)})
    assert detect_api_base("http://target/", sess) == ""


def test_basepath_detects_dev_api_variant():
    """改过前缀的部署（/dev-api）也能识别"""
    sess = FakeSession({"http://target/dev-api/captchaImage": FakeResp(CAPTCHA_JSON, 200)})
    assert detect_api_base("http://target/", sess) == "/dev-api"


# JeecgBoot 3.6.3 的真实响应（2026-10-31 从 R10 实测）：result 是 data URI 字符串，code 是 0。
# 旧用例用的是 {"code":200,"result":{"img":"..."}}，与线上实现不符，导致探测函数按错误
# 结构写、单测还全绿——R10 因此始终探不到 /jeecg-boot。
JEECG_JSON_REAL = (
    '{"success":true,"message":"","code":0,'
    '"result":"data:image/jpg;base64,/9j/4AAQSkZJRgABAgAA"}'
)
# 兼容老版本 / 其它 Jeecg 分支返回的嵌套形态
JEECG_JSON_NESTED = '{"success":true,"code":200,"result":{"img":"data:image/png;base64,iVBORw0KGgo="}}'


def test_basepath_detected_for_jeecg_boot():
    """真实 Jeecg 验证码 /sys/randomImage/{key}：result 为 data URI 字符串 → 识别 /jeecg-boot"""
    sess = FakeSession(
        {"http://target/jeecg-boot/sys/randomImage/ruoyi_scan_probe": FakeResp(JEECG_JSON_REAL)}
    )
    assert detect_api_base("http://target/", sess) == "/jeecg-boot"


def test_basepath_detected_for_jeecg_boot_nested_result():
    """兼容 result 为 {'img': ...} 的嵌套形态"""
    sess = FakeSession(
        {"http://target/jeecg-boot/sys/randomImage/ruoyi_scan_probe": FakeResp(JEECG_JSON_NESTED)}
    )
    assert detect_api_base("http://target/", sess) == "/jeecg-boot"


def test_basepath_jeecg_requires_real_image_payload():
    """只有 success 没有图片数据 → 不认"""
    sess = FakeSession({"http://target/jeecg-boot/sys/randomImage/ruoyi_scan_probe": FakeResp('{"success":true}')})
    assert detect_api_base("http://target/", sess) == ""


def test_basepath_jeecg_rejects_non_image_result_string():
    """result 是非图片字符串（如错误文案）→ 不认"""
    sess = FakeSession(
        {
            "http://target/jeecg-boot/sys/randomImage/ruoyi_scan_probe": FakeResp(
                '{"success":true,"code":0,"result":"Token失效"}'
            )
        }
    )
    assert detect_api_base("http://target/", sess) == ""


def test_basepath_jeecg_captcha_path_does_not_exist():
    """/jeecg-boot/captchaImage 是错误假设，不能作为判据"""
    sess = FakeSession({"http://target/jeecg-boot/captchaImage": FakeResp(CAPTCHA_JSON)})
    assert detect_api_base("http://target/", sess) == ""


def test_basepath_jeecg_spa_root_not_used_as_evidence():
    """/jeecg-boot/ 根路径 SPA 兜底 200 HTML 不能作为前缀判据"""
    sess = FakeSession(
        {
            "http://target/jeecg-boot/": FakeResp(
                "<html><title>JeecgBoot</title></html>", 200, {"Content-Type": "text/html"}
            )
        }
    )
    assert detect_api_base("http://target/", sess) == ""


def test_basepath_none_for_non_ruoyi():
    """全站只有静态页 → 不臆造前缀"""
    sess = FakeSession({})
    assert detect_api_base("http://target/", sess) == ""


def test_basepath_ignores_spa_200_html():
    """SPA 对任意路径返回 200 HTML，不能被当成『串到后端』"""
    sess = FakeSession(
        {
            "http://target/prod-api/captchaImage": FakeResp(
                "<html><title>若依管理系统</title></html>", 200, {"Content-Type": "text/html"}
            )
        }
    )
    assert detect_api_base("http://target/", sess) == ""


def test_basepath_detects_cloud_code_endpoint():
    """RuoYi-Cloud 网关的验证码是 /code（没有 /captchaImage）→ 仍能识别 /prod-api

    2026-10-29 R8 实测：Cloud v3.6.8 的 /prod-api/captchaImage 是 404，
    只有 /prod-api/code 返回 {"code":200,"captchaEnabled":false}。
    """
    sess = FakeSession({"http://target/prod-api/code": FakeResp(CAPTCHA_JSON, 200)})
    assert detect_api_base("http://target/", sess) == "/prod-api"


def test_basepath_cloud_code_not_confused_with_generic_json():
    """普通 JSON（无 captchaEnabled/img/uuid）不算验证码接口"""
    sess = FakeSession(
        {
            "http://target/code": FakeResp('{"code":200,"msg":"ok"}', 200),
            "http://target/prod-api/code": FakeResp('{"code":200,"msg":"ok"}', 200),
        }
    )
    assert detect_api_base("http://target/", sess) == ""
