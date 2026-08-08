# F7 中间件未授权检测测试：Redis/MinIO/RocketMQ（mock 网络）
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **kw):
        return self.responses.get(url, FakeResp("", 404))

    def post(self, url, data=None, headers=None, **kw):
        return self.responses.get(url, FakeResp("", 404))


# === Redis ===


class FakeSocket:
    """mock socket：记录发送数据，返回预设响应"""

    def __init__(self, recv_data=b"$...\r\n# Server\r\nredis_version:7.0.0\r\n"):
        self.recv_data = recv_data
        self.sent = b""

    def sendall(self, data):
        self.sent += data

    def settimeout(self, t):
        pass

    def recv(self, n):
        data, self.recv_data = self.recv_data[:n], self.recv_data[n:]
        return data

    def close(self):
        pass


def test_redis_unauth_confirm():
    """Redis：INFO 返回 redis_version（无 NOAUTH）→ CONFIRMED"""
    from plugins.common.redis_unauth import RedisUnauthPlugin

    with patch("socket.create_connection", return_value=FakeSocket()):
        res = RedisUnauthPlugin().verify("http://target/", FakeSession({}))
    assert res.status == STATUS_CONFIRMED, res.status
    assert "redis_version" in res.evidence
    print("PASS test_redis_unauth_confirm")


def test_redis_unauth_safe():
    """Redis：响应含 -NOAUTH → SAFE（已启用认证）"""
    from plugins.common.redis_unauth import RedisUnauthPlugin

    with patch("socket.create_connection", return_value=FakeSocket(b"-NOAUTH Authentication required.\r\n")):
        res = RedisUnauthPlugin().verify("http://target/", FakeSession({}))
    assert res.status == STATUS_SAFE, res.status
    print("PASS test_redis_unauth_safe")


def test_redis_unauth_unknown():
    """Redis：连接失败 → UNKNOWN（绝不判 SAFE）"""
    from plugins.common.redis_unauth import RedisUnauthPlugin

    def _raise(*a, **kw):
        raise OSError("connection refused")

    with patch("socket.create_connection", side_effect=_raise):
        res = RedisUnauthPlugin().verify("http://target/", FakeSession({}))
    assert res.status == STATUS_UNKNOWN, res.status
    print("PASS test_redis_unauth_unknown")


# === MinIO ===


def test_minio_unauth_confirm():
    """MinIO：health/live 200 + bucket 列表 → CONFIRMED"""
    from plugins.common.minio_unauth import MinioUnauthPlugin

    sess = FakeSession(
        {
            "http://target/minio/health/live": FakeResp("ok", 200),
            "http://target/minio/": FakeResp('{"buckets":[{"name":"data"}]}', 200, {"Content-Type": "application/json"}),
        }
    )
    res = MinioUnauthPlugin().verify("http://target/", sess)
    assert res.status == STATUS_CONFIRMED, res.status
    print("PASS test_minio_unauth_confirm")


def test_minio_unauth_safe():
    """MinIO：无服务 → SAFE"""
    from plugins.common.minio_unauth import MinioUnauthPlugin

    res = MinioUnauthPlugin().verify("http://target/", FakeSession({}))
    assert res.status == STATUS_SAFE, res.status
    print("PASS test_minio_unauth_safe")


# === RocketMQ ===


def test_rocketmq_unauth_confirm():
    """RocketMQ：/rocketmq/ 返回 Dashboard → CONFIRMED"""
    from plugins.common.rocketmq_unauth import RocketmqUnauthPlugin

    sess = FakeSession(
        {
            "http://target/rocketmq/": FakeResp("<html><title>RocketMQ Dashboard</title></html>", 200),
        }
    )
    res = RocketmqUnauthPlugin().verify("http://target/", sess)
    assert res.status == STATUS_CONFIRMED, res.status
    print("PASS test_rocketmq_unauth_confirm")


def test_rocketmq_unauth_safe():
    """RocketMQ：无 Dashboard（404）→ SAFE"""
    from plugins.common.rocketmq_unauth import RocketmqUnauthPlugin

    res = RocketmqUnauthPlugin().verify("http://target/", FakeSession({}))
    assert res.status == STATUS_SAFE, res.status
    print("PASS test_rocketmq_unauth_safe")


def test_f7_plugins_registered():
    """F7: 3 个中间件插件已注册到 common 包"""
    from core.loader import load_plugins

    names = [getattr(p, "name", "") for p in load_plugins("plugins.common")]
    assert "Redis 未授权访问" in names
    assert "MinIO 未授权访问" in names
    assert "RocketMQ Dashboard 未授权" in names
    print("PASS test_f7_plugins_registered: %d 个 common 插件" % len(names))


def test_f7_meta_complete():
    """F7: 3 个插件元信息完整"""
    for cls_name in ("RedisUnauthPlugin", "MinioUnauthPlugin", "RocketmqUnauthPlugin"):
        import importlib

        mod = importlib.import_module("plugins.common.%s" % {
            "RedisUnauthPlugin": "redis_unauth",
            "MinioUnauthPlugin": "minio_unauth",
            "RocketmqUnauthPlugin": "rocketmq_unauth",
        }[cls_name])
        cls = getattr(mod, cls_name)
        inst = cls()
        assert inst.cve and inst.fix_detail and inst.reproduce and inst.cvss_vector and inst.compliance
    print("PASS test_f7_meta_complete")


if __name__ == "__main__":
    test_redis_unauth_confirm()
    test_redis_unauth_safe()
    test_redis_unauth_unknown()
    test_minio_unauth_confirm()
    test_minio_unauth_safe()
    test_rocketmq_unauth_confirm()
    test_rocketmq_unauth_safe()
    test_f7_plugins_registered()
    test_f7_meta_complete()
    print("ALL_F7_TESTS_PASS")
