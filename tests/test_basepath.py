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
JEECG_JSON_REAL = '{"success":true,"message":"","code":0,"result":"data:image/jpg;base64,/9j/4AAQSkZJRgABAgAA"}'
# 兼容老版本 / 其它 Jeecg 分支返回的嵌套形态
JEECG_JSON_NESTED = '{"success":true,"code":200,"result":{"img":"data:image/png;base64,iVBORw0KGgo="}}'


def test_basepath_detected_for_jeecg_boot():
    """真实 Jeecg 验证码 /sys/randomImage/{key}：result 为 data URI 字符串 → 识别 /jeecg-boot"""
    sess = FakeSession({"http://target/jeecg-boot/sys/randomImage/ruoyi_scan_probe": FakeResp(JEECG_JSON_REAL)})
    assert detect_api_base("http://target/", sess) == "/jeecg-boot"


def test_basepath_detected_for_jeecg_boot_nested_result():
    """兼容 result 为 {'img': ...} 的嵌套形态"""
    sess = FakeSession({"http://target/jeecg-boot/sys/randomImage/ruoyi_scan_probe": FakeResp(JEECG_JSON_NESTED)})
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


# ── F11: plugin_target 提升（Jeecg 双前缀回归） ─────────────────────────


def test_plugin_target_for_empty_base_returns_target():
    from core.basepath import plugin_target_for

    assert plugin_target_for("http://target/", "") == "http://target/"


def test_plugin_target_for_appends_api_base():
    from core.basepath import plugin_target_for

    assert plugin_target_for("http://target/", "/prod-api") == "http://target/prod-api/"


def test_plugin_target_for_jeecg_does_not_double_prefix():
    """JeecgBoot 插件路径自带 /jeecg-boot，不能再把 base 追加到 target。

    2026-11-02 R10 实测：追加后 5 个插件 URL 变成 /jeecg-boot/jeecg-boot/...，
    真实 Jeecg 目标会整包漏报。
    """
    from core.basepath import plugin_target_for

    assert plugin_target_for("http://target/", "/jeecg-boot") == "http://target/"
    assert plugin_target_for("http://target/", "/jeecg") == "http://target/"


# ── v1.5.6 WP1：自定义 context-path 识别 ────────────────────────────────
# 背景：候选表写死时，二开站点把后端挂在 /portal 这类自定义前缀下，
# 一个判据都对不上 → 路径类插件整类探错基准（D1 实测：/jeecg-boot/doc.html
# 未授权 200 却报「不存在 Swagger 文档泄露」）。


class ImageResp(FakeResp):
    """图片型验证码响应替身（RuoYi 4.x 单机版形态）"""

    def __init__(self, size=3102, status_code=200):
        super().__init__("", status_code, {"Content-Type": "image/jpeg"})
        self.content = b"\xff\xd8\xff\xe0" + b"\x00" * size


def test_basepath_detects_image_captcha_for_ruoyi4():
    """RuoYi 4.x 单机版验证码是图片而非 JSON → 仍能识别前缀

    实测 D1（4.6.2 二开，context-path=/portal）：
        GET / -> 302 Location: http://host/portal/
        GET /portal/captcha/captchaImage?type=char -> 200 image/jpeg 3092 字节
    这里同时模拟根路径的 302，因为被动提取靠它拿到 /portal 线索。
    """
    sess = FakeSession(
        {
            "http://target/": FakeResp("", 302, {"Location": "http://target/portal/"}),
            "http://target/portal/captcha/captchaImage?type=char": ImageResp(3092),
        }
    )
    assert detect_api_base("http://target/", sess) == "/portal"


def test_basepath_detects_image_captcha_without_hints():
    """没有任何被动线索时，写死候选表里的前缀仍靠图片判据识别（兜底路径）"""
    sess = FakeSession({"http://target/prod-api/captcha/captchaImage?type=char": ImageResp(3102)})
    assert detect_api_base("http://target/", sess) == "/prod-api"


def test_basepath_rejects_zero_byte_captcha_image():
    """0 字节图片不算命中——这是缺 type 参数时的经典失败形态

    实测 R1：不带 type 时返回 200 + image/jpeg + **0 字节**（BufferedImage 为 null、
    异常被框架吞掉）。只看 Content-Type 会把「探测失败」当成「接口存在」。
    """
    sess = FakeSession({"http://target/portal/captcha/captchaImage?type=char": ImageResp(0)})
    assert detect_api_base("http://target/", sess) == ""


def test_basepath_rejects_tiny_fake_image():
    """几十字节的「图片」多半是 WAF/兜底页错误声明 Content-Type"""
    sess = FakeSession({"http://target/portal/captcha/captchaImage?type=char": ImageResp(50)})
    assert detect_api_base("http://target/", sess) == ""


def test_basepath_hint_from_absolute_location():
    """nginx return 302 http://host/portal/ —— 绝对 Location 也要能提取

    实测 D1：GET / -> 302 Location: http://127.0.0.1:19321/portal/
    """
    from core.basepath import extract_base_hints

    class LocSession:
        def get(self, url, **kw):
            return FakeResp("", 302, {"Location": "http://host/portal/", "Content-Type": "text/html"})

    assert extract_base_hints("http://host/", LocSession()) == ["/portal"]


def test_basepath_hint_from_set_cookie_path():
    """Set-Cookie: Path=/portal —— 后端自己声明的 cookie 作用域最可靠"""
    from core.basepath import extract_base_hints

    class CookieSession:
        def get(self, url, **kw):
            return FakeResp("", 200, {"Set-Cookie": "JSESSIONID=abc; Path=/portal; HttpOnly"})

    assert extract_base_hints("http://host/", CookieSession()) == ["/portal"]


def test_basepath_hint_from_js_baseurl():
    """前端 JS 里写死的 baseURL 也能当前缀线索"""
    from core.basepath import extract_base_hints

    html = "<script>window.__CONFIG__={baseURL:'/portal'}</script>"
    class HtmlSession:
        def get(self, url, **kw):
            return FakeResp(html, 200, {"Content-Type": "text/html"})

    assert extract_base_hints("http://host/", HtmlSession()) == ["/portal"]


def test_basepath_hint_rejects_business_module_paths():
    """业务模块路径（/system、/monitor）不是 context-path，不能当候选

    误当前缀会把「业务接口可达」当成「前缀存在」，进而把整站插件基准推错位置。
    """
    from core.basepath import _accept_candidate

    for bad in ("/system", "/monitor", "/login", "/actuator", "/v3", "/druid"):
        assert _accept_candidate(bad) == "", bad
    assert _accept_candidate("/portal") == "/portal"
    assert _accept_candidate("/portal/") == "/portal"


def test_basepath_hint_rejects_absolute_urls():
    """绝对地址是跨域 CDN/网关，不是 context-path"""
    from core.basepath import _accept_candidate

    assert _accept_candidate("http://evil.test/x") == ""
    assert _accept_candidate("//cdn.test/x") == ""


def test_explicit_base_path_takes_priority():
    """--base-path 显式指定优先于自动探测（运维知道真实前缀时不该赌探测）"""
    sess = FakeSession({"http://target/portal/captcha/captchaImage?type=char": ImageResp(3092)})
    assert detect_api_base("http://target/", sess, extra_hints=["/portal"]) == "/portal"


def test_explicit_base_path_still_requires_evidence():
    """显式指定也要过判据：写错的前缀不能被采纳（否则整站探错基准）"""
    sess = FakeSession({})
    assert detect_api_base("http://target/", sess, extra_hints=["/wrong"]) == ""


def test_plugin_target_skips_when_plugin_carries_same_prefix():
    """插件路径自带 /prod-api 时不能再追加同名前缀（否则 /prod-api/prod-api/...）

    实测 D1：plus_job_unauth 探 /prod-api/monitor/job/list，基准是 /portal 时
    拼成 /portal/prod-api/... → 302 登录墙 → 判 SAFE（假阴性）。
    """
    from core.basepath import plugin_target_for

    assert plugin_target_for("http://t/", "/prod-api", plugin_prefixes=("/prod-api",)) == "http://t/"
    # 前缀不同则不豁免：插件自带的 /prod-api 与站点真实的 /portal 不是一回事，
    # 此时仍应把基准推进到真实 context-path
    assert plugin_target_for("http://t/", "/portal") == "http://t/portal/"


# ── v1.6 WP-F0：探针数据表 + 芋道 ──────────────────────────────────────


def test_probe_table_is_data_driven():
    """探针表结构：加框架应只需加一行，不改控制流"""
    from core.basepath import _PROBES

    assert isinstance(_PROBES, list) and len(_PROBES) >= 5
    for item in _PROBES:
        assert len(item) == 4, f"探针项应为 4 元组: {item}"


def test_yudao_candidate_prefixes_present():
    """芋道的固定前缀必须在候选表里（缺了会整类漏报）"""
    from core.basepath import CANDIDATES

    assert "/admin-api" in CANDIDATES
    assert "/app-api" in CANDIDATES


def test_looks_like_yudao_api():
    """芋道免鉴权探针判据：code 必须是 0，data 必须是非空数组

    真实响应（2026-11-03 Y1 实测）：
      {"code":0,"msg":"","data":[{"id":1,"name":"芋道源码",...}]}
    注意 code 是 **0** 而不是 200——这是它与若依最明显的区别。
    """
    from core.basepath import _looks_like_yudao_api

    class R:
        def __init__(self, body, code=200, ct="application/json"):
            self.text = body
            self.status_code = code
            self.headers = {"Content-Type": ct}

    assert _looks_like_yudao_api(R('{"code":0,"msg":"","data":[{"id":1,"name":"x"}]}')) is True
    # code 不是 0 → 不是芋道成功响应
    assert _looks_like_yudao_api(R('{"code":200,"data":[{"id":1}]}')) is False
    # 空数组 → 可能只是错误包装，不算
    assert _looks_like_yudao_api(R('{"code":0,"data":[]}')) is False
    # data 不是数组
    assert _looks_like_yudao_api(R('{"code":0,"data":null}')) is False
    # 非 200
    assert _looks_like_yudao_api(R('{"code":0,"data":[{"id":1}]}', code=401)) is False
