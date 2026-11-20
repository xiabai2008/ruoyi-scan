# 在线更新服务：版本比较 / 清单校验 / 资产校验 / 冻结版资产选择
import hashlib

import pytest

from lib import updater


class FakeResponse:
    def __init__(self, *, status=200, payload=None, content=b"", chunks=None):
        self.status_code = status
        self._payload = payload
        self.content = content
        self._chunks = chunks or []

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def iter_content(self, chunk_size=256 * 1024):
        yield from self._chunks

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_compare_versions_semver():
    assert updater.compare_versions("2.0.0", "1.9.9") == 1
    assert updater.compare_versions("2.0.0", "2.0.0") == 0
    assert updater.compare_versions("2.0.0-rc.1", "2.0.0") == -1
    assert updater.compare_versions("2.0.0", "2.0.0-rc.1") == 1
    assert updater.compare_versions("v2.0.1", "2.0.0") == 1
    assert updater.compare_versions("2.0.0-alpha.2", "2.0.0-alpha.10") == -1


def test_fetch_manifest_rejects_non_https(monkeypatch):
    with pytest.raises(updater.UpdateError, match="HTTPS"):
        updater.fetch_manifest("http://example.com/version.json")


def test_fetch_manifest_validates_schema(monkeypatch):
    payload = {"schema": 2, "version": "2.0.1"}
    monkeypatch.setattr(updater.requests, "get", lambda *a, **k: FakeResponse(payload=payload))
    with pytest.raises(updater.UpdateError, match="schema"):
        updater.fetch_manifest("https://example.com/version.json")


def test_fetch_manifest_http_error(monkeypatch):
    monkeypatch.setattr(updater.requests, "get", lambda *a, **k: FakeResponse(status=404))
    with pytest.raises(updater.UpdateError, match="HTTP 404"):
        updater.fetch_manifest("https://example.com/version.json")


def test_check_for_update_available(monkeypatch):
    payload = {"schema": 1, "version": "2.0.1", "pub_date": "2026-11-20", "notes": "fix"}
    monkeypatch.setattr(updater.requests, "get", lambda *a, **k: FakeResponse(payload=payload))
    info = updater.check_for_update(current="2.0.0", url="https://example.com/version.json")
    assert info.available is True
    assert info.latest == "2.0.1"
    assert info.notes == "fix"


def test_check_for_update_current_is_latest(monkeypatch):
    payload = {"schema": 1, "version": "2.0.0"}
    monkeypatch.setattr(updater.requests, "get", lambda *a, **k: FakeResponse(payload=payload))
    info = updater.check_for_update(current="2.0.0", url="https://example.com/version.json")
    assert info.available is False


def test_get_cli_asset_only_for_frozen(monkeypatch):
    monkeypatch.delattr(updater.sys, "frozen", raising=False)
    assert updater.get_cli_asset({"assets": {"cli": {}}}) == {}


def test_get_cli_asset_for_frozen(monkeypatch):
    monkeypatch.setattr(updater.sys, "frozen", True, raising=False)
    monkeypatch.setattr(updater.sys, "platform", "win32")
    manifest = {"assets": {"cli": {"windows-x86_64": {"url": "https://example.com/a.exe"}}}}
    assert updater.get_cli_asset(manifest)["url"].endswith("a.exe")


def test_download_asset_sha256_and_size(monkeypatch, tmp_path):
    data = b"binary-update"
    digest = hashlib.sha256(data).hexdigest()
    payload = {"sha256": digest, "size": len(data), "url": "https://example.com/u.exe"}
    monkeypatch.setattr(
        updater.requests,
        "get",
        lambda *a, **k: FakeResponse(chunks=[data[:4], data[4:]]),
    )
    dest = tmp_path / "u.exe"
    updater._download_asset(payload, dest)
    assert dest.read_bytes() == data


def test_download_asset_rejects_bad_sha256(monkeypatch, tmp_path):
    payload = {"sha256": "0" * 64, "size": 3, "url": "https://example.com/u.exe"}
    monkeypatch.setattr(updater.requests, "get", lambda *a, **k: FakeResponse(chunks=[b"abc"]))
    with pytest.raises(updater.UpdateError, match="sha256"):
        updater._download_asset(payload, tmp_path / "u.exe")
    assert not (tmp_path / "u.exe").exists()


def test_download_asset_rejects_missing_sha256(monkeypatch, tmp_path):
    monkeypatch.setattr(updater.requests, "get", lambda *a, **k: FakeResponse(chunks=[b"abc"]))
    with pytest.raises(updater.UpdateError, match="sha256"):
        updater._download_asset({"url": "https://example.com/u.exe"}, tmp_path / "u.exe")
