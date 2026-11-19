"""OAST 扫描侧接线测试：HTTP/TCP 回调、Log4j、盲 SSRF/XXE 三态。

测试用真实 OASTServer/TCP 监听 + 假的易受攻击目标（触发回调），
不依赖外部网络与靶场。
"""

import re
import socket
import urllib.request

from common.models import STATUS_CONFIRMED, STATUS_UNKNOWN


def _http_server():
    from lib.oast import OASTServer

    server = OASTServer("127.0.0.1", 0)
    assert server.start()
    return server


def test_http_interaction_receives_callback():
    from lib.oast import OASTClient

    server = _http_server()
    client = OASTClient(server=server, timeout=2)
    try:
        interaction = client.new_http_interaction()
        urllib.request.urlopen(interaction.url, timeout=2).read()
        assert interaction.wait(2)
        callbacks = interaction.callbacks()
        assert callbacks and callbacks[0]["protocol"] == "http"
    finally:
        client.close()
        server.stop()


def test_tcp_interaction_receives_connection():
    from lib.oast import OASTClient

    server = _http_server()
    client = OASTClient(server=server, timeout=2)
    try:
        interaction = client.new_tcp_interaction()
        with socket.create_connection((interaction.host, interaction.port), timeout=2) as sock:
            sock.sendall(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00")
        assert interaction.wait(2)
        callbacks = interaction.callbacks()
        assert callbacks and callbacks[0]["protocol"] == "tcp"
    finally:
        client.close()
        server.stop()


class _CallbackSession:
    """按 payload 触发对应回调的假目标会话。"""

    timeout = 2

    def __init__(self, kind):
        self.kind = kind

    def get(self, url, headers=None, **kwargs):
        if self.kind == "log4j":
            match = re.search(r"ldap://([^:/]+):(\d+)/", (headers or {}).get("User-Agent", ""))
            if match:
                with socket.create_connection((match.group(1), int(match.group(2))), timeout=1):
                    pass
        return object()

    def post(self, url, data="", headers=None, **kwargs):
        if self.kind != "xxe":
            return object()
        match = re.search(r'SYSTEM "([^"]+)"', data or "")
        if match:
            try:
                urllib.request.urlopen(match.group(1), timeout=1).read()
            except Exception:
                pass
        return object()


def test_detect_log4j_confirmed_by_tcp_callback():
    from lib.component_detect import detect_log4j
    from lib.oast import OASTClient

    server = _http_server()
    client = OASTClient(server=server, timeout=2)
    try:
        res = detect_log4j("http://target/", _CallbackSession("log4j"), oast_client=client)
        assert res.status == STATUS_CONFIRMED, res.evidence
        assert res.cve == "CVE-2021-44228"
        assert "TCP 回调" in res.evidence
    finally:
        client.close()
        server.stop()


def test_log4j_without_callback_is_unknown():
    from lib.component_detect import detect_log4j
    from lib.oast import OASTClient

    server = _http_server()
    client = OASTClient(server=server, timeout=0.5)
    try:
        res = detect_log4j("http://target/", _CallbackSession("none"), oast_client=client)
        assert res.status == STATUS_UNKNOWN
        assert res.unknown_reason == "oast_no_callback"
    finally:
        client.close()
        server.stop()


def test_blind_ssrf_confirmed_by_http_callback():
    from lib.oast import OASTClient
    from plugins.common.blind_ssrf import BlindSsrfPlugin

    class SsrfSession(_CallbackSession):
        timeout = 2

        def get(self, url, headers=None, **kwargs):
            match = re.search(r"[?&]url=([^&]+)", url)
            if match:
                target = urllib.parse.unquote(match.group(1))
                try:
                    urllib.request.urlopen(target, timeout=1).read()
                except Exception:
                    pass
            return object()

    server = _http_server()
    client = OASTClient(server=server, timeout=2)
    try:

        class Sess(SsrfSession):
            oast_client = client

        res = BlindSsrfPlugin().verify("http://target/", Sess("ssrf"))
        assert res.status == STATUS_CONFIRMED, res.evidence
        assert "参数" in res.evidence
    finally:
        client.close()
        server.stop()


def test_blind_xxe_confirmed_by_http_callback():
    from lib.oast import OASTClient
    from plugins.common.blind_xxe import BlindXxePlugin

    server = _http_server()
    client = OASTClient(server=server, timeout=2)
    try:

        class Sess(_CallbackSession):
            timeout = 2
            oast_client = client

        res = BlindXxePlugin().verify("http://target/", Sess("xxe"))
        assert res.status == STATUS_CONFIRMED, res.evidence
        assert "外部实体" in res.evidence
    finally:
        client.close()
        server.stop()


def test_blind_ssrf_without_callback_is_unknown():
    from lib.oast import OASTClient
    from plugins.common.blind_ssrf import BlindSsrfPlugin

    server = _http_server()
    client = OASTClient(server=server, timeout=0.5)
    try:

        class Sess(_CallbackSession):
            timeout = 1
            oast_client = client

        res = BlindSsrfPlugin().verify("http://target/", Sess("none"))
        assert res.status == STATUS_UNKNOWN
        assert res.unknown_reason == "oast_no_callback"
    finally:
        client.close()
        server.stop()


def test_blind_xxe_without_callback_is_unknown():
    from lib.oast import OASTClient
    from plugins.common.blind_xxe import BlindXxePlugin

    server = _http_server()
    client = OASTClient(server=server, timeout=0.5)
    try:

        class Sess(_CallbackSession):
            timeout = 1
            oast_client = client

        res = BlindXxePlugin().verify("http://target/", Sess("none"))
        assert res.status == STATUS_UNKNOWN
        assert res.unknown_reason == "oast_no_callback"
    finally:
        client.close()
        server.stop()


def test_tcp_interaction_can_use_fixed_port():
    import socket as _socket

    from lib.oast import OASTClient

    probe = _socket.socket()
    probe.bind(("127.0.0.1", 0))
    fixed_port = probe.getsockname()[1]
    probe.close()

    server = _http_server()
    client = OASTClient(server=server, timeout=1, tcp_port=fixed_port)
    try:
        interaction = client.new_tcp_interaction()
        assert interaction.port == fixed_port
        with _socket.create_connection(("127.0.0.1", fixed_port), timeout=2):
            pass
        assert interaction.wait(2)
    finally:
        client.close()
        server.stop()
