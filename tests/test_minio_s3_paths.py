"""MinIO 未授权：匿名列举走 S3 根路径 `/`，不在 `/minio/`。

背景（2026-11-01 C4-2 实测）
============================
旧实现只探 `/minio/` —— 那是 **MinIO 控制台入口**，永远返回登录页 HTML，
不含 bucket 列表。真实 MinIO 的匿名列举走 **S3 协议根路径 `GET /`**，
返回 `<ListAllMyBucketsResult>` XML。

用真实 S3 协议响应复刻的靶场实测：

    GET /            → 200 + <ListAllMyBucketsResult><Bucket>hospital-reports...
    GET /minio/      → 200 + 控制台 SPA HTML（登录页，无 bucket）
    → 旧实现探 /minio/ 判 SAFE **漏报**

与 `rocketmq_unauth` 是同一类缺陷：照着自己想象的路径写，没按真实产品形态验证。

关于靶场的诚实说明
==================
MinIO 2025 年把社区版二进制彻底下架（所有 dl.min.io/server/... 返回 410 Gone），
唯一在发的 AIStor 版需要商业 license，实测无 license 时连 ListBuckets 都拒绝，
做不了「匿名可读」场景。因此 C4-2 靶场是按真实 S3 协议**复刻**的响应
（响应头、XML 结构、健康检查端点都照抄），不是 marker 桩 ——
扫描器必须真的按 S3 语义读 XML 才可能命中。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.common.minio_unauth import MinioUnauthPlugin  # noqa: E402

TARGET = "http://minio.test/"

HEALTH_OK = ""
LIST_BUCKETS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner><Buckets><Bucket><Name>hospital-reports</Name><CreationDate>2021-04-15T08:12:33.000Z</CreationDate></Bucket><Bucket><Name>patient-uploads</Name><CreationDate>2021-06-02T11:35:10.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>"""

ACCESS_DENIED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied.</Message><Resource>/</Resource><RequestId>18E3E57898DFEA88</RequestId><HostId>470a0afc</HostId></Error>"""

CONSOLE_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>MinIO Console</title></head><body><div id="root"></div></body></html>"""


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Server": "MinIO", "Content-Type": "application/xml"}


class _Session:
    """按路径返回预设响应。"""

    def __init__(self, mapping):
        self.mapping = mapping
        self.requested = []

    def get(self, url, **kw):
        self.requested.append(url)
        # 按后缀匹配（"/" 是空前缀，放最后兜底，避免吞掉其它路径）
        for suffix in sorted(self.mapping, key=len, reverse=True):
            if url.endswith(suffix):
                return self.mapping[suffix]
        return _Resp("not found", 404)


def _lab_mapping(root_resp, minio_resp=None):
    """构造一个「健康检查 200 + 根路径 X + /minio/ Y」的响应表。"""
    return {
        "/minio/health/live": _Resp(HEALTH_OK, 200, {"Server": "MinIO"}),
        "/minio/": minio_resp or _Resp(CONSOLE_HTML, 200, {"Server": "MinIO", "Content-Type": "text/html"}),
        "/": root_resp,
    }


# ── 核心修复：根路径匿名可列举 ──────────────────────────


def test_anonymous_listbuckets_on_root_is_confirmed():
    """S3 根路径匿名返回 bucket 列表 → CONFIRMED（旧实现在这里漏报）。"""
    sess = _Session(_lab_mapping(_Resp(LIST_BUCKETS_XML, 200)))
    result = MinioUnauthPlugin().verify(TARGET, sess)
    assert result.status == "CONFIRMED", f"S3 根路径匿名列举漏报：{result.evidence}"
    assert result.url == TARGET, f"证据 URL 应是根路径，实际 {result.url}"


def test_root_path_is_probed():
    """必须真的探根路径，而不只探 /minio/。"""
    sess = _Session(_lab_mapping(_Resp(LIST_BUCKETS_XML, 200)))
    MinioUnauthPlugin().verify(TARGET, sess)
    assert any(u.rstrip("/") == TARGET.rstrip("/") for u in sess.requested), (
        f"未探测 S3 根路径，实际请求：{sess.requested}"
    )


# ── 负样本：安全配置不能误报 ────────────────────────────


def test_access_denied_on_root_is_safe():
    """根路径返回 AccessDenied（MinIO 默认安全配置）→ SAFE。"""
    sess = _Session(_lab_mapping(_Resp(ACCESS_DENIED_XML, 403)))
    result = MinioUnauthPlugin().verify(TARGET, sess)
    assert result.status == "SAFE", f"安全配置判成 {result.status}"


def test_console_login_page_is_not_confirmed():
    """/minio/ 与控制台登录页即使含 bucket 字样也不算未授权。"""
    console_with_bucket_word = CONSOLE_HTML.replace("</body>", "<!-- bucket manager --></body>")
    sess = _Session(
        _lab_mapping(
            _Resp(ACCESS_DENIED_XML, 403),
            _Resp(console_with_bucket_word, 200, {"Server": "MinIO", "Content-Type": "text/html"}),
        )
    )
    result = MinioUnauthPlugin().verify(TARGET, sess)
    assert result.status != "CONFIRMED", "控制台登录页被误判为未授权"


def test_no_minio_service_is_safe():
    """健康检查失败且无 MinIO 特征 → SAFE（不是 MinIO 服务）。"""
    sess = _Session({"/minio/health/live": _Resp("", 404, {"Server": "nginx"})})
    result = MinioUnauthPlugin().verify(TARGET, sess)
    assert result.status == "SAFE"


# ── 兼容：少数部署把列表挂在前缀下 ──────────────────────


def test_prefix_deployment_still_works():
    """/minio/ 真返回 bucket 列表时也能命中（不因新增根路径而丢旧行为）。"""
    sess = _Session(
        _lab_mapping(
            _Resp(ACCESS_DENIED_XML, 403),
            _Resp(LIST_BUCKETS_XML, 200, {"Server": "MinIO", "Content-Type": "application/xml"}),
        )
    )
    result = MinioUnauthPlugin().verify(TARGET, sess)
    assert result.status == "CONFIRMED", f"前缀部署漏报：{result.evidence}"


# ── 网络异常不能判 SAFE ────────────────────────────────


def test_network_error_is_unknown_not_safe():
    """两个路径都请求失败 → UNKNOWN（测不到 ≠ 安全）。"""

    class _Boom:
        def get(self, url, **kw):
            if url.endswith("/minio/health/live"):
                return _Resp("", 200, {"Server": "MinIO"})  # 健康检查通过
            raise ConnectionError("connection refused")

    result = MinioUnauthPlugin().verify(TARGET, _Boom())
    assert result.status == "UNKNOWN", f"网络异常判成 {result.status}，应为 UNKNOWN"
