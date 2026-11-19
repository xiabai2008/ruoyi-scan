"""Cloud 能力包：Gateway 路由表、Nacos 默认口令、Cloud 路由别名。

测试不连外网；R8 真实形态的 routes JSON 用 fixture 复制自 2026-11-19 实测。
"""

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.cloud_routes import (
    build_cloud_profile,
    cloud_alias_paths,
    cloud_candidate_paths,
    parse_gateway_routes,
)

ROUTES = [
    {
        "route_id": "ReactiveCompositeDiscoveryClient_ruoyi-gen",
        "uri": "lb://ruoyi-gen",
        "predicate": "(RouteDefinitionRouteLocator$$Lambda$1793 && Paths: [/ruoyi-gen/**], match trailing slash: true)",
        "filters": ["[[RewritePath /ruoyi-gen/?(?<remaining>.*) = '/${remaining}'], order = 1]"],
        "metadata": None,
    },
    {
        "route_id": "ReactiveCompositeDiscoveryClient_ruoyi-job",
        "uri": "lb://ruoyi-job",
        "predicate": "(RouteDefinitionRouteLocator$$Lambda$1793 && Paths: [/ruoyi-job/**], match trailing slash: true)",
        "filters": ["[[RewritePath /ruoyi-job/?(?<remaining>.*) = '/${remaining}'], order = 1]"],
        "metadata": None,
    },
    {
        "route_id": "ruoyi-auth",
        "uri": "lb://ruoyi-auth",
        "predicate": "(RouteDefinitionRouteLocator$$Lambda$1793 && Paths: [/auth/**], match trailing slash: true)",
        "filters": ["[[StripPrefix parts = 1], order = 3]"],
        "metadata": None,
    },
    {
        "route_id": "ruoyi-gen",
        "uri": "lb://ruoyi-gen",
        "predicate": "(RouteDefinitionRouteLocator$$Lambda$1793 && Paths: [/code/**], match trailing slash: true)",
        "filters": ["[[StripPrefix parts = 1], order = 1]"],
        "metadata": None,
    },
    {
        "route_id": "ruoyi-job",
        "uri": "lb://ruoyi-job",
        "predicate": "(RouteDefinitionRouteLocator$$Lambda$1793 && Paths: [/schedule/**], match trailing slash: true)",
        "filters": ["[[StripPrefix parts = 1], order = 1]"],
        "metadata": None,
    },
    {
        "route_id": "ruoyi-system",
        "uri": "lb://ruoyi-system",
        "predicate": "(RouteDefinitionRouteLocator$$Lambda$1793 && Paths: [/system/**], match trailing slash: true)",
        "filters": ["[[StripPrefix parts = 1], order = 1]"],
        "metadata": None,
    },
]


class _Resp:
    def __init__(self, status_code=200, text="", payload=None, headers=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload
        self.headers = headers or {"Content-Type": "application/json"}

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def _profile():
    profile = build_cloud_profile(ROUTES)
    assert profile is not None
    return profile


class _GatewaySession:
    timeout = 3

    def __init__(self, response):
        self.response = response
        self.cloud_profile = None
        self.requested = []

    def get(self, url, **kwargs):
        self.requested.append(url)
        return self.response

    def anonymous(self):
        return self

    def close(self):
        pass


def test_parse_gateway_routes_and_aliases():
    routes = parse_gateway_routes(ROUTES)
    assert len(routes) == 6
    profile = _profile()
    assert profile["route_count"] == 6
    assert "/code" in profile["prefixes"] and "/schedule" in profile["prefixes"]
    assert cloud_alias_paths("/tool/gen/preview/1") == ["/code/gen/preview/1"]
    gen_paths = cloud_candidate_paths("/tool/gen", profile)
    assert "/code/gen" in gen_paths and "/ruoyi-gen/gen" in gen_paths
    job_paths = cloud_candidate_paths("/monitor/job", profile)
    assert "/schedule/job" in job_paths and "/ruoyi-job/job" in job_paths


def test_gateway_routes_plugin_confirms_real_shape():
    from plugins.ruoyi.cloud_gateway_routes import CloudGatewayRoutesPlugin

    session = _GatewaySession(_Resp(payload=ROUTES))
    result = CloudGatewayRoutesPlugin().verify("http://target/prod-api", session)
    assert result.status == STATUS_CONFIRMED, result.evidence
    assert result.extra["route_count"] == 6
    assert session.cloud_profile is not None


def test_gateway_routes_plugin_safe_on_html_and_empty():
    from plugins.ruoyi.cloud_gateway_routes import CloudGatewayRoutesPlugin

    html = CloudGatewayRoutesPlugin().verify(
        "http://target/prod-api", _GatewaySession(_Resp(text="<html>SPA</html>", headers={"Content-Type": "text/html"}))
    )
    assert html.status == STATUS_SAFE
    empty = CloudGatewayRoutesPlugin().verify("http://target/prod-api", _GatewaySession(_Resp(payload=[])))
    assert empty.status == STATUS_SAFE


class _NacosSession:
    timeout = 3

    def __init__(self, mode="hit"):
        self.mode = mode
        self.cloud_profile = _profile()
        self.requested = []

    def anonymous(self):
        return self

    def close(self):
        pass

    def post(self, url, data=None, **kwargs):
        self.requested.append(url)
        if self.mode == "hit" and ":8080/v3/auth/user/login" in url:
            return _Resp(payload={"accessToken": "x" * 40, "globalAdmin": True, "username": "nacos"})
        if self.mode == "wrong":
            return _Resp(status_code=403, text="User not found! Please check user exist or password is right!")
        return _Resp(status_code=404, text="Not Found")


def test_nacos_default_password_hit():
    from plugins.ruoyi.cloud_nacos_default_password import CloudNacosDefaultPasswordPlugin

    session = _NacosSession("hit")
    result = CloudNacosDefaultPasswordPlugin().verify("http://10.0.0.5:19108/prod-api", session)
    assert result.status == STATUS_CONFIRMED, result.evidence
    assert result.extra["global_admin"] is True
    assert ":8080/v3/auth/user/login" in result.url


def test_nacos_default_password_wrong_is_safe():
    from plugins.ruoyi.cloud_nacos_default_password import CloudNacosDefaultPasswordPlugin

    result = CloudNacosDefaultPasswordPlugin().verify("http://10.0.0.5:19108/prod-api", _NacosSession("wrong"))
    assert result.status == STATUS_SAFE


def test_nacos_default_password_no_console_is_unknown():
    from plugins.ruoyi.cloud_nacos_default_password import CloudNacosDefaultPasswordPlugin

    result = CloudNacosDefaultPasswordPlugin().verify("http://10.0.0.5:19108/prod-api", _NacosSession("none"))
    assert result.status == STATUS_UNKNOWN
    assert result.unknown_reason == "insufficient_evidence"


class _JobAliasSession:
    timeout = 3

    def __init__(self, alias_payload):
        self.cloud_profile = _profile()
        self.alias_payload = alias_payload
        self.requested = []

    def anonymous(self):
        return self

    def close(self):
        pass

    def post(self, url, **kwargs):
        self.requested.append(("POST", url))
        return _Resp(status_code=405, text="<html><title>405 Not Allowed</title></html>")

    def request(self, method, url, **kwargs):
        self.requested.append((method, url))
        return _Resp(payload=self.alias_payload)


def test_job_rce_cloud_alias_denied_is_unknown_not_safe():
    from plugins.ruoyi.job_rce import JobRcePlugin

    session = _JobAliasSession({"code": 401, "msg": "认证参数为空"})
    result = JobRcePlugin().verify("http://target/prod-api", session)
    assert result.status == STATUS_UNKNOWN
    assert result.unknown_reason == "denied"
    assert "/schedule/job" in result.evidence
    assert any(method == "PUT" for method, _url in session.requested)


def test_job_rce_cloud_alias_business_layer_confirms():
    from plugins.ruoyi.job_rce import JobRcePlugin

    session = _JobAliasSession({"code": 500, "msg": "定时任务不存在", "jobId": 99999})
    result = JobRcePlugin().verify("http://target/prod-api", session)
    assert result.status == STATUS_CONFIRMED, result.evidence
    assert "/schedule/job" in result.evidence


class _GenAliasSession:
    timeout = 3

    def __init__(self):
        self.cloud_profile = _profile()
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        if "/code/gen/preview/" in url:
            if "7*7" in url or "%24%7B" in url:
                return _Resp(
                    text='<mapper namespace="com.ruoyi.sys_user_49Mapper"/>',
                    headers={"Content-Type": "application/xml"},
                )
            return _Resp(
                text='<mapper namespace="com.ruoyi.sys_userMapper"/>',
                headers={"Content-Type": "application/xml"},
            )
        if "/code/gen/list" in url:
            return _Resp(payload={"code": 403, "msg": "没有权限"})
        if "/tool/gen/edit" in url:
            return _Resp(
                text='{"code":500,"msg":"404 NOT_FOUND "No static resource tool/gen/edit""}',
                payload={"code": 500, "msg": '404 NOT_FOUND "No static resource tool/gen/edit"'},
            )
        return _Resp(status_code=404, text="Not Found")


def test_gen_rce_cloud_alias_differential_confirms():
    from plugins.ruoyi.ruoyi_gen_rce import RuoyiGenRcePlugin

    session = _GenAliasSession()
    result = RuoyiGenRcePlugin().verify("http://target/prod-api", session)
    assert result.status == STATUS_CONFIRMED, result.evidence
    assert "/code/gen/preview/1" in result.url
    assert any("/code/gen/preview/" in url for url in session.urls)
