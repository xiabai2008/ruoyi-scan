"""前端 sourcemap 泄露：必须严格校验 map JSON，不把 SPA 兜底页判成泄露。"""

import json

import requests_mock

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from core.session import SessionManager
from plugins.common.sourcemap_leak import SourceMapLeakPlugin


def _run(root_text, js_text="", map_text=None):
    session = SessionManager()
    try:
        with requests_mock.Mocker() as mocker:
            mocker.get("http://target/", text=root_text, headers={"Content-Type": "text/html"})
            if root_text and "app.js" in root_text:
                mocker.get("http://target/static/js/app.js", text=js_text)
            if map_text is not None:
                mocker.get("http://target/static/js/app.js.map", text=map_text)
            return SourceMapLeakPlugin().verify("http://target/", session)
    finally:
        session.close()


def test_sourcemap_confirmed_when_map_is_valid_json():
    result = _run(
        '<html><script src="/static/js/app.js"></script></html>',
        "//# sourceMappingURL=app.js.map",
        json.dumps({"version": 3, "sources": ["src/main.ts"], "mappings": "AAAA"}),
    )
    assert result.status == STATUS_CONFIRMED
    assert "app.js.map" in result.url


def test_sourcemap_uses_script_plus_map_without_comment():
    result = _run(
        '<html><script src="/static/js/app.js"></script></html>',
        "console.log(1)",
        json.dumps({"version": 3, "sources": ["a.ts"], "mappings": "BBBB"}),
    )
    assert result.status == STATUS_CONFIRMED


def test_spa_fallback_html_is_not_sourcemap():
    result = _run(
        '<html><script src="/static/js/app.js"></script></html>',
        "console.log(1)",
        "<!doctype html><html><body>index fallback</body></html>",
    )
    assert result.status == STATUS_SAFE


def test_no_script_returns_safe():
    result = _run("<html><body>no frontend</body></html>")
    assert result.status == STATUS_SAFE


def test_network_error_returns_unknown():
    session = SessionManager()
    try:
        with requests_mock.Mocker() as mocker:
            mocker.get("http://target/", exc=ConnectionError("down"))
            result = SourceMapLeakPlugin().verify("http://target/", session)
        assert result.status == STATUS_UNKNOWN
        assert result.unknown_reason == "unreachable"
    finally:
        session.close()
