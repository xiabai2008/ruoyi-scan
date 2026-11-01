# F7-3：ruoyi-cloud 指纹不得把「路径 200 + 空 body」当强特征。
#
# 背景：C2-3（Spring Cloud Function）的 /nacos/、/gateway/ 都是 200 + 0 字节，
# 旧指纹 matched=["path:/nacos/(any,200)","path:/gateway/(any,200)"]，confidence 1.0。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fingerprint import FeatureBasedFingerprint  # noqa: E402
from core.fingerprint_features import get_feature  # noqa: E402


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None, content=b""):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.content = content


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))


def test_empty_200_paths_not_cloud():
    """根页面正常、/nacos/ 与 /gateway/ 均 200+空 body → 不识别为 ruoyi-cloud。"""
    session = FakeSession(
        {
            "http://target/": FakeResp("<html><body>welcome to app</body></html>", 200),
            "http://target/nacos/": FakeResp("", 200),
            "http://target/gateway/": FakeResp("", 200),
        }
    )

    result = FeatureBasedFingerprint("ruoyi-cloud").detect("http://target/", session)

    assert result.cms == "", f"空 200 不应成为强特征，matched={result.matched}"
    assert not any("nacos" in m or "gateway" in m for m in result.matched)


def test_nacos_body_over_20_bytes_hits():
    """20 字节以上且含 nacos 的控制台响应 → 仍命中 ruoyi-cloud。"""
    nacos_page = "<html><title>nacos</title><body>Nacos Console</body></html>"
    session = FakeSession(
        {
            "http://target/": FakeResp("<html><body>welcome to app</body></html>", 200),
            "http://target/nacos/": FakeResp(nacos_page, 200),
        }
    )

    result = FeatureBasedFingerprint("ruoyi-cloud").detect("http://target/", session)

    assert result.cms == "ruoyi-cloud", result.matched
    assert any("path:/nacos/" in m for m in result.matched)


def test_r8_cloud_features_not_degraded():
    """R8 形态：Nacos 控制台 + Gateway 均为有内容 200 → 两条路径都命中。"""
    nacos_page = "<html><head><title>Nacos</title></head><body>nacos console 3.6.8</body></html>"
    gateway_json = '{"routes":[{"route_id":"ruoyi-auth","uri":"lb://ruoyi-auth"}],"count":1}'
    session = FakeSession(
        {
            "http://target/": FakeResp("<html><body>ruoyi cloud portal</body></html>", 200),
            "http://target/nacos/": FakeResp(nacos_page, 200),
            "http://target/gateway/": FakeResp(gateway_json, 200, {"Content-Type": "application/json"}),
        }
    )

    result = FeatureBasedFingerprint("ruoyi-cloud").detect("http://target/", session)

    assert result.cms == "ruoyi-cloud", result.matched
    assert any("path:/nacos/" in m for m in result.matched)
    assert any("path:/gateway/" in m for m in result.matched)


def test_cloud_feature_config_keeps_any_expect_with_min_length():
    """两条强特征仍为 expect=any，只增加 min_length=20（不能改成 JSON 判定）。"""
    feature = get_feature("ruoyi-cloud")
    assert feature is not None
    by_path = {item["path"]: item for item in feature["strong_paths"]}
    assert by_path["/nacos/"]["expect"] == "any"
    assert by_path["/gateway/"]["expect"] == "any"
    assert by_path["/nacos/"]["min_length"] == 20
    assert by_path["/gateway/"]["min_length"] == 20
