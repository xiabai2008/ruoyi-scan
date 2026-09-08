# E2 组件版本检测测试：fastjson/SpringBoot/Shiro/Nacos/Log4j 探测 + CVE 映射 + 转换
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from lib.component_detect import (
    ComponentDetector,
    detect_fastjson,
    detect_log4j,
    detect_nacos,
    detect_shiro,
    detect_spring_boot,
    match_cve,
    to_scan_result,
)


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None, content=b""):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.content = content


class FakeSession:
    """按 URL 映射返回固定响应的 mock session"""

    def __init__(self, responses):
        self.responses = responses
        self.request_count = 0

    def get(self, url, **kw):
        self.request_count += 1
        return self.responses.get(url, FakeResp("", 404))

    def post(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))


def test_cve_map_loaded():
    """CVE 映射数据加载 + 版本区间匹配"""
    m = match_cve("fastjson", "1.2.60")
    assert m and m["cve"] == "CVE-2022-25845", m
    m2 = match_cve("nacos", "1.4.0")
    assert m2 and m2["cve"] == "CVE-2021-29441", m2
    # 安全版本 → 空
    m3 = match_cve("fastjson", "2.0.64")
    assert m3 == {}, m3
    # 未识别版本 → 空
    assert match_cve("fastjson", "") == {}
    print("PASS test_cve_map_loaded")


def test_detect_fastjson_keyword_unknown():
    """fastjson 关键字命中但版本未知 → UNKNOWN（不判 SAFE）"""
    sess = FakeSession(
        {
            "http://target/prod-api/": FakeResp(
                '{"code":500,"msg":"com.alibaba.fastjson.JSONException..."}',
                200,
                {"Content-Type": "application/json"},
            ),
        }
    )
    res = detect_fastjson("http://target/", sess)
    assert res.component == "fastjson"
    assert res.status == STATUS_UNKNOWN, res.status
    print("PASS test_detect_fastjson_keyword_unknown: %s" % res.status)


def test_detect_fastjson_ruoyi_infer():
    """fastjson 无泄漏但若依版本已知 → 推断版本 + CVE 命中"""
    sess = FakeSession({})
    res = detect_fastjson("http://target/", sess, ruoyi_version="4.7.8")
    assert res.status == STATUS_CONFIRMED, res.status
    assert res.cve == "CVE-2022-25845", res.cve
    assert res.detected_version == "1.2.80", res.detected_version
    print("PASS test_detect_fastjson_ruoyi_infer: %s %s" % (res.detected_version, res.cve))


def test_detect_spring_actuator():
    """/actuator 200 → Spring Boot 存在但无版本 → UNKNOWN"""
    sess = FakeSession(
        {
            "http://target/actuator": FakeResp(
                '{"_links":{"env":{"href":"/actuator/env"}}}',
                200,
                {"Content-Type": "application/json"},
            ),
        }
    )
    res = detect_spring_boot("http://target/", sess)
    assert res.component == "spring-boot"
    assert res.status == STATUS_UNKNOWN, res.status  # 无版本 → UNKNOWN
    print("PASS test_detect_spring_actuator: %s" % res.status)


def test_detect_spring_whitelabel_with_version():
    """Whitelabel + 版本泄漏 → CVE 命中"""
    sess = FakeSession(
        {
            "http://target/": FakeResp(
                '<html><body><h1>Whitelabel Error Page</h1><div>"spring-boot": "2.5.15"</div></body></html>',
                200,
                {"Content-Type": "text/html"},
            ),
        }
    )
    res = detect_spring_boot("http://target/", sess)
    assert res.status == STATUS_CONFIRMED, res.status
    assert res.cve == "CVE-2022-22965", res.cve
    print("PASS test_detect_spring_whitelabel_with_version: %s %s" % (res.detected_version, res.cve))


def test_detect_spring_none():
    """无 Spring 特征 → UNKNOWN（不判 SAFE，避免漏报）"""
    sess = FakeSession({})
    res = detect_spring_boot("http://target/", sess)
    assert res.status == STATUS_UNKNOWN, res.status
    print("PASS test_detect_spring_none: %s" % res.status)


def test_detect_shiro_delete_me():
    """rememberMe=deleteMe → Shiro 存在但版本未知 → UNKNOWN"""
    sess = FakeSession(
        {
            "http://target/login": FakeResp("", 200, {"Set-Cookie": "rememberMe=deleteMe; Path=/"}),
        }
    )
    res = detect_shiro("http://target/", sess)
    assert res.component == "shiro"
    assert res.status == STATUS_UNKNOWN, res.status
    assert "rememberMe" in res.evidence
    print("PASS test_detect_shiro_delete_me: %s" % res.status)


def test_detect_shiro_none():
    """无 Shiro 特征 → SAFE"""
    sess = FakeSession({})
    res = detect_shiro("http://target/", sess)
    assert res.status == STATUS_SAFE, res.status
    print("PASS test_detect_shiro_none: %s" % res.status)


def test_detect_nacos_versioned():
    """Nacos state 接口带版本 → CVE 命中"""
    sess = FakeSession(
        {
            "http://target/nacos/v1/console/server/state": FakeResp(
                '{"version":"1.4.0","Nacos":"1.4.0"}',
                200,
                {"Content-Type": "application/json"},
            ),
        }
    )
    res = detect_nacos("http://target/", sess)
    assert res.status == STATUS_CONFIRMED, res.status
    assert res.cve == "CVE-2021-29441", res.cve
    print("PASS test_detect_nacos_versioned: %s %s" % (res.detected_version, res.cve))


def test_detect_nacos_none():
    """无 Nacos → SAFE"""
    sess = FakeSession({})
    res = detect_nacos("http://target/", sess)
    assert res.status == STATUS_SAFE, res.status
    print("PASS test_detect_nacos_none: %s" % res.status)


def test_detect_log4j_requires_oast():
    """Log4j 未启用 OAST → UNKNOWN + 提示（不自动探测）"""
    sess = FakeSession({})
    res = detect_log4j("http://target/", sess)
    assert res.status == STATUS_UNKNOWN, res.status
    assert "--oast" in res.evidence
    print("PASS test_detect_log4j_requires_oast")


class FakeOastClient:
    """mock OAST 客户端（不真实请求）"""

    def __init__(self, hit=False):
        self.hit = hit

    def get_payload(self, vuln_type):
        return "interact.example.com/abc123"

    def wait_callback(self, interaction_id=None, timeout=0):
        return self.hit


def test_detect_log4j_with_oast_hit():
    """OAST 回调命中 → UNKNOWN + 人工复核提示（不自动 CONFIRMED）"""
    sess = FakeSession({})
    res = detect_log4j("http://target/", sess, oast_client=FakeOastClient(hit=True))
    assert res.status == STATUS_UNKNOWN, res.status
    assert res.cve == "CVE-2021-44228"
    assert "人工复核" in res.evidence
    print("PASS test_detect_log4j_with_oast_hit")


def test_detect_all_aggregates():
    """ComponentDetector.detect_all 聚合全部组件（G1 扩展后 20 个，前 5 手写保持原顺序）"""
    from lib.component_detect import DETECTORS

    sess = FakeSession(
        {
            "http://target/nacos/v1/console/server/state": FakeResp(
                '{"version":"1.4.0","Nacos":"1.4.0"}', 200, {"Content-Type": "application/json"}
            ),
            "http://target/login": FakeResp("", 200, {"Set-Cookie": "rememberMe=deleteMe; Path=/"}),
        }
    )
    detector = ComponentDetector()
    results = detector.detect_all("http://target/", sess, ruoyi_version="")
    names = [r.component for r in results]
    assert len(names) == len(DETECTORS) == 20, names
    assert names[:5] == ["fastjson", "spring-boot", "shiro", "nacos", "log4j"], names
    # nacos 命中 CVE
    nacos = [r for r in results if r.component == "nacos"][0]
    assert nacos.status == STATUS_CONFIRMED and nacos.cve == "CVE-2021-29441"
    print("PASS test_detect_all_aggregates: %s" % names)


def test_to_scan_result():
    """ComponentVersionResult → ScanResult 转换（vuln 类型 + CVSS 严重度）"""
    from common.models import ComponentVersionResult

    res = ComponentVersionResult(
        component="nacos",
        detected_version="1.4.0",
        status=STATUS_CONFIRMED,
        cve="CVE-2021-29441",
        fix_version="1.4.2+",
        cvss_score=10.0,
    )
    sr = to_scan_result(res)
    assert sr.kind == "vuln", sr.kind
    assert sr.severity == "high", sr.severity
    assert sr.cve == "CVE-2021-29441"
    assert "nacos" in sr.name
    d = sr.to_dict()
    assert d["cve"] == "CVE-2021-29441"
    # SAFE → info
    res2 = ComponentVersionResult(component="nacos", status=STATUS_SAFE)
    assert to_scan_result(res2).kind == "info"
    print("PASS test_to_scan_result")


if __name__ == "__main__":
    test_cve_map_loaded()
    test_detect_fastjson_keyword_unknown()
    test_detect_fastjson_ruoyi_infer()
    test_detect_spring_actuator()
    test_detect_spring_whitelabel_with_version()
    test_detect_spring_none()
    test_detect_shiro_delete_me()
    test_detect_shiro_none()
    test_detect_nacos_versioned()
    test_detect_nacos_none()
    test_detect_log4j_requires_oast()
    test_detect_log4j_with_oast_hit()
    test_detect_all_aggregates()
    test_to_scan_result()
    print("ALL_E2_TESTS_PASS")


# ── G1 通用组件探测器（spec 驱动，15 个新组件）测试 ──────────────────────
def test_spec_registry_covers_all_components():
    """注册表覆盖 5 手写 + 15 spec 探测器，且 spec 表每个组件都已注册"""
    from lib.component_detect import _COMPONENT_SPECS, DETECTORS

    assert len(DETECTORS) == 20, len(DETECTORS)
    for name in _COMPONENT_SPECS:
        assert name in DETECTORS, name


def test_cve_map_new_components():
    """新增组件的 CVE 区间数据加载与匹配"""
    m = match_cve("grafana", "8.3.0")
    assert m and m["cve"] == "CVE-2021-43798", m
    assert match_cve("grafana", "8.3.1") == {}
    m2 = match_cve("tomcat", "9.0.30")
    assert m2 and m2["cve"] == "CVE-2020-1938", m2
    # 7.x 老版本命中 PUT RCE
    m3 = match_cve("tomcat", "7.0.79")
    assert m3 and m3["cve"] == "CVE-2020-1938", m3
    # xxl-job 无 CVE 编号但有版本风险区间（accessToken）
    m4 = match_cve("xxl-job", "2.3.1")
    assert m4 and m4["cve"] == "" and "accessToken" in m4.get("note", ""), m4
    assert match_cve("xxl-job", "2.4.1") == {}
    print("PASS test_cve_map_new_components")


def test_detect_jenkins_header_version_confirmed():
    """Jenkins X-Jenkins 头命中 → 版本比对 CONFIRMED CVE-2024-23897"""
    from lib.component_detect import detect_jenkins

    sess = FakeSession(
        {
            "http://t/jenkins/login": FakeResp("", 200, headers={"X-Jenkins": "2.440.3"}),
            "http://t/jenkins/": FakeResp("", 200, headers={"X-Jenkins": "2.440.3"}),
        }
    )
    res = detect_jenkins("http://t/jenkins", sess)
    assert res.status == STATUS_CONFIRMED, res
    assert res.cve == "CVE-2024-23897", res
    assert res.detected_version == "2.440.3"
    print("PASS test_detect_jenkins_header_version_confirmed")


def test_detect_tomcat_error_page_ghostcat():
    """Tomcat 错误页版本命中 Ghostcat 区间 → CONFIRMED；已修复版本 → SAFE"""
    from lib.component_detect import detect_tomcat

    sess = FakeSession(
        {
            "http://t/tomcat/": FakeResp("<html>Apache Tomcat/9.0.30</html>", 200),
        }
    )
    res = detect_tomcat("http://t/tomcat", sess)
    assert res.status == STATUS_CONFIRMED and res.cve == "CVE-2020-1938", res

    sess2 = FakeSession(
        {
            "http://t/tomcat/": FakeResp("<html>Apache Tomcat/9.0.58</html>", 200),
        }
    )
    res2 = detect_tomcat("http://t/tomcat", sess2)
    assert res2.status == STATUS_SAFE, res2
    print("PASS test_detect_tomcat_error_page_ghostcat")


def test_detect_kibana_grafana_version_confirmed():
    """Kibana /api/status 与 Grafana /api/health 的 JSON 版本提取 → CONFIRMED"""
    from lib.component_detect import detect_grafana, detect_kibana

    sess = FakeSession(
        {
            "http://t/kb/api/status": FakeResp('{"version":{"number":"6.4.2"},"status":{"level":"available"}}', 200),
        }
    )
    res = detect_kibana("http://t/kb", sess)
    assert res.status == STATUS_CONFIRMED and res.cve == "CVE-2019-7600", res

    sess2 = FakeSession(
        {
            "http://t/gf/api/health": FakeResp('{"commit":"abc","database":"ok","version":"8.2.0"}', 200),
        }
    )
    res2 = detect_grafana("http://t/gf", sess2)
    assert res2.status == STATUS_CONFIRMED and res2.cve == "CVE-2021-43798", res2
    print("PASS test_detect_kibana_grafana_version_confirmed")


def test_detect_minio_status_signal_unknown():
    """MinIO 健康探测 200 无 body → 存在但版本未知 → UNKNOWN（不判 SAFE）"""
    from lib.component_detect import detect_minio

    sess = FakeSession(
        {
            "http://t/mio/minio/health/live": FakeResp("", 200),
        }
    )
    res = detect_minio("http://t/mio", sess)
    assert res.status == STATUS_UNKNOWN, res
    assert "版本无法识别" in res.evidence, res
    print("PASS test_detect_minio_status_signal_unknown")


def test_detect_spec_absent_safe():
    """全部探测路径未命中特征 → SAFE（与 shiro/nacos 判定惯例一致）"""
    from lib.component_detect import detect_solr

    sess = FakeSession({})  # 所有路径 404
    res = detect_solr("http://t/x", sess)
    assert res.status == STATUS_SAFE, res
    print("PASS test_detect_spec_absent_safe")


def test_detect_spec_network_error_unknown():
    """网络异常 → UNKNOWN（三态纪律：异常绝不判 SAFE）"""
    from lib.component_detect import detect_druid

    class BoomSession:
        def get(self, url, **kw):
            raise ConnectionError("refused")

    res = detect_druid("http://t/x", BoomSession())
    assert res.status == STATUS_UNKNOWN, res
    print("PASS test_detect_spec_network_error_unknown")


def test_detector_aggregate_includes_new_components():
    """聚合器 detect_all 输出 20 个组件结果"""
    sess = FakeSession({})
    detector = ComponentDetector()
    results = detector.detect_all("http://t/x", sess)
    names = {r.component for r in results}
    assert len(results) == 20, len(results)
    for expect in ("druid", "xxl-job", "jenkins", "tomcat", "grafana", "consul"):
        assert expect in names, expect
    print("PASS test_detector_aggregate_includes_new_components")
