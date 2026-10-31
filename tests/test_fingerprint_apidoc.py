# P1-1：API 文档取证（base-path 感知的指纹与版本识别）
#
# 背景：前后端分离版把后端挂在 context-path（/prod-api、/jeecg-boot）后面，前端 SPA 对
# 根路径任意 path 都返回 index.html；品牌化之后根页面连框架名都没有。这类站点靠
# 「页面文字 + favicon」必然探不到（实测 R9 完全未识别），但 SpringDoc/knife4j 文档
# 默认公开，info.title/info.version 直接写着框架名与版本。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fingerprint import detect_cms  # noqa: E402


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.content = text.encode("utf-8", "ignore")

    def json(self):
        import json as _json

        return _json.loads(self.text)


class FakeSession:
    """按 URL 精确映射；未命中的 URL 一律 404（等价于该路径不存在）"""

    def __init__(self, responses, default=None):
        self.responses = responses
        self.default = default

    def get(self, url, **kw):
        if url in self.responses:
            return self.responses[url]
        return self.default or FakeResp("", 404)

    def post(self, url, **kw):
        return self.get(url, **kw)


SPA_HTML = "<html><head><title>某某业务系统</title></head><body><div id=app></div></body></html>"

RUOYI_DOC = """{
  "openapi": "3.1.0",
  "info": {"title": "标题：若依管理系统_接口文档", "version": "版本号:3.9.2"},
  "paths": {"/tool/gen": {}}
}"""

PLUS_DOC = """{
  "openapi": "3.1.0",
  "info": {"title": "标题：RuoYi-Vue-Plus多租户管理系统_接口文档", "version": "版本号: 5.6.2"},
  "paths": {"/tool/gen": {}}
}"""

JEECG_DOC = """{
  "swagger": "2.0",
  "info": {"title": "JeecgBoot 后台服务API接口文档", "version": "1.0"},
  "paths": {}
}"""

UNRELATED_DOC = """{
  "openapi": "3.0.1",
  "info": {"title": "My Internal API", "version": "2.3.4"},
  "paths": {}
}"""


def _json_resp(text):
    return FakeResp(text, 200, {"Content-Type": "application/json"})


def _html_resp(text):
    return FakeResp(text, 200, {"Content-Type": "text/html"})


def test_apidoc_establishes_cms_and_exact_version():
    """根路径是 SPA 壳、/prod-api/v3/api-docs 公开 → 识别 ruoyi 并取到精确版本"""
    sess = FakeSession(
        {
            "http://target/": _html_resp(SPA_HTML),
            "http://target/prod-api/v3/api-docs": _json_resp(RUOYI_DOC),
        }
    )
    res = detect_cms("http://target/", sess)
    assert res.cms == "ruoyi"
    assert res.version == "3.9.2"
    assert any("apidoc" in m for m in res.matched)


def test_apidoc_variant_plus_from_title():
    """文档标题含 RuoYi-Vue-Plus → 变体细分，版本取 5.6.2"""
    sess = FakeSession(
        {
            "http://target/": _html_resp(SPA_HTML),
            "http://target/prod-api/v3/api-docs": _json_resp(PLUS_DOC),
        }
    )
    res = detect_cms("http://target/", sess)
    assert res.cms == "ruoyi"
    assert res.variant == "ruoyi-plus"
    assert res.version == "5.6.2"


def test_apidoc_unrelated_doc_does_not_claim_cms():
    """无关的 OpenAPI 文档（标题无框架名）不能把站点判成若依"""
    sess = FakeSession(
        {
            "http://target/": _html_resp(SPA_HTML),
            "http://target/v3/api-docs": _json_resp(UNRELATED_DOC),
        }
    )
    res = detect_cms("http://target/", sess)
    assert res.cms == ""


def test_apidoc_absent_keeps_negative_sample_clean():
    """负样本：任何路径都没有文档、也没有框架特征 → cms 必须为空

    对应 R11（自建 Spring Boot internal-api）：它是这套靶场里唯一"不是若依"的站点，
    指纹改动一旦把它判成若依，整个负样本校验就失效了。
    """
    sess = FakeSession({"http://target/": _html_resp(SPA_HTML)})
    res = detect_cms("http://target/", sess)
    assert res.cms == ""
    assert res.version == ""
    assert res.confidence == 0.0


def test_jeecg_version_comes_from_asset_query_not_info_version():
    """JeecgBoot：info.version 是业务应用版本（1.0），框架版本在 _app.config.js?v= 里

    实测 R10（JeecgBoot 3.6.3）：/jeecg-boot/v2/api-docs 的 info.version 为 "1.0"，
    真正的框架版本写在根页面 <script src="/_app.config.js?v=3.6.3-179...">
    """
    root = (
        '<html lang="zh_CN"><head>'
        '<script src="/_app.config.js?v=3.6.3-1793355312425"></script>'
        "</head><body></body></html>"
    )
    sess = FakeSession(
        {
            "http://target/": _html_resp(root),
            # 强特征：/jeecg-boot/ 返回与根不同的内容
            "http://target/jeecg-boot/": FakeResp("ok", 200, {"Content-Type": "text/plain"}),
            "http://target/jeecg-boot/v2/api-docs": _json_resp(JEECG_DOC),
        }
    )
    res = detect_cms("http://target/", sess)
    assert res.cms == "jeecgboot"
    assert res.version == "3.6.3", "不能把文档里的业务应用版本 1.0 当成框架版本"


def test_apidoc_non_json_200_page_is_ignored():
    """文档路径返回 200 的 HTML（SPA 兜底）不能当文档"""
    sess = FakeSession(
        {
            "http://target/": _html_resp(SPA_HTML),
            "http://target/v3/api-docs": _html_resp(SPA_HTML),
            "http://target/prod-api/v3/api-docs": _html_resp(SPA_HTML),
        }
    )
    res = detect_cms("http://target/", sess)
    assert res.cms == ""
