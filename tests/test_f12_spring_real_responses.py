"""F12：Spring 插件对「真实响应形态」的判定（2026-11-02 C2 真实靶场实测）。

旧实现只认内置签名靶场的响应：env 要 propertySources、gateway 要响应体含
filters/predicate、cloud function 要 200+49。真实组件分别返回：
  - env POST → {"ruoyi.scan.env_probe":"true"}（或 204 无正文）
  - gateway POST → 201 + 空 body + Location: /routes/{id}
  - cloud function 受影响版 → 500（默认不暴露 message），需时序差分
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN  # noqa: E402
from plugins.spring.actuator_env_rce import SpringActuatorEnvRcePlugin  # noqa: E402
from plugins.spring.cloud_function_rce import SpringCloudFunctionRcePlugin  # noqa: E402
from plugins.spring.gateway_rce import SpringGatewayRcePlugin  # noqa: E402

TARGET = "http://target/"


class FakeResp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}
        self.content = text.encode()

    def json(self):
        import json

        return json.loads(self.text)


class FakeSession:
    """按 (method, 路径后缀) 返回预设响应，并记录 DELETE 调用。"""

    def __init__(self, routes):
        self.routes = routes
        self.deleted = []
        self.requests = []

    def _resp(self, method, url):
        self.requests.append((method, url))
        for (m, suffix), resp in self.routes.items():
            if m == method and url.endswith(suffix):
                return resp
        return FakeResp("", 404)

    def get(self, url, **kwargs):
        return self._resp("get", url)

    def post(self, url, **kwargs):
        return self._resp("post", url)

    def delete(self, url, **kwargs):
        self.deleted.append(url)
        return self._resp("delete", url)


def test_env_probe_echo_is_confirmed_with_readback():
    sess = FakeSession(
        {
            ("post", "/actuator/env"): FakeResp('{"ruoyi.scan.env_probe":"true"}', 200),
            ("get", "/actuator/env"): FakeResp(
                '{"propertySources":[{"name":"manager","properties":{"ruoyi.scan.env_probe":{"value":"true"}}}]}',
                200,
            ),
        }
    )
    r = SpringActuatorEnvRcePlugin().verify(TARGET, sess)
    assert r.status == STATUS_CONFIRMED, r.evidence
    assert "回读" in r.evidence


def test_env_204_with_readable_endpoint_is_confirmed():
    sess = FakeSession(
        {
            ("post", "/actuator/env"): FakeResp("", 204),
            ("get", "/actuator/env"): FakeResp('{"propertySources":[]}', 200),
        }
    )
    r = SpringActuatorEnvRcePlugin().verify(TARGET, sess)
    assert r.status == STATUS_CONFIRMED, r.evidence


def test_env_200_without_evidence_still_unknown():
    sess = FakeSession({("post", "/actuator/env"): FakeResp('{"hello":"world"}', 200)})
    r = SpringActuatorEnvRcePlugin().verify(TARGET, sess)
    assert r.status == STATUS_UNKNOWN, r.evidence


def test_gateway_201_location_only_is_confirmed_and_cleaned():
    class LocSession(FakeSession):
        def post(self, url, **kwargs):
            route_id = url.rsplit("/", 1)[-1]
            return FakeResp("", 201, {"Location": "/routes/" + route_id})

    sess = LocSession({})
    r = SpringGatewayRcePlugin().verify(TARGET, sess)
    assert r.status == STATUS_CONFIRMED, r.evidence
    assert "Location" in r.evidence
    assert sess.deleted, "创建探针路由后必须尝试 DELETE 清理"


def test_gateway_201_unrelated_location_is_safe():
    sess = FakeSession({("post", "/actuator/gateway/routes/"): FakeResp("", 201, {"Location": "/routes/other"})})
    r = SpringGatewayRcePlugin().verify(TARGET, sess)
    assert r.status == STATUS_SAFE, r.evidence
    assert sess.deleted, "无论判定如何都应清理本次创建的路由"


def test_cloud_function_timing_differential_confirmed(monkeypatch):
    import time

    import plugins.spring.cloud_function_rce as mod

    monkeypatch.setattr(mod, "SLEEP_MIN_DELAY_SECONDS", 0.2)

    class DelaySession(FakeSession):
        def post(self, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if headers.get("spring.cloud.function.routing-expression"):
                time.sleep(0.35)
            return FakeResp('{"timestamp":1700000000000,"status":500,"error":"Internal Server Error"}', 500)

    sess = DelaySession({})
    r = SpringCloudFunctionRcePlugin().verify(TARGET, sess)
    assert r.status == STATUS_CONFIRMED, r.evidence
    assert "时序" in r.evidence or "延迟" in r.evidence


def test_cloud_function_timing_fast_is_safe(monkeypatch):
    class FastSession(FakeSession):
        def post(self, url, **kwargs):
            return FakeResp('{"timestamp":1700000000000,"status":500,"error":"Internal Server Error"}', 500)

    sess = FastSession({})
    r = SpringCloudFunctionRcePlugin().verify(TARGET, sess)
    assert r.status == STATUS_SAFE, r.evidence
