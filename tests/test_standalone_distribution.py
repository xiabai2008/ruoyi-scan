"""独立分发模式（--distributed standalone）的失败语义回归。

StandaloneDistributor 被删除后，本机分发改为 cli/distributed_runner._run_standalone。
它必须保证：单目标异常进入 failed_targets、退出码为 1、聚合报告字段完整，
不能因为并发异常静默丢目标。
"""

import json

import pytest

from cli import distributed_runner


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr(distributed_runner, "emit", lambda *args, **kwargs: None)


def _report(tmp_path):
    path = tmp_path / "reports" / "distributed_report.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_standalone_all_success(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        distributed_runner,
        "_scan_one",
        lambda target, config, mode: [{"status": "CONFIRMED", "name": target}, {"status": "SAFE"}],
    )

    rc = distributed_runner._run_standalone(None, ["http://a/", "http://b/"], {}, "full")

    assert rc == 0
    data = _report(tmp_path)
    assert data["successful"] == 2
    assert data["failed"] == 0
    assert data["total_vulns"] == 2
    assert {v["name"] for v in data["all_vulns"]} == {"http://a/", "http://b/"}


def test_standalone_partial_failure_is_reported(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def fake_scan(target, config, mode):
        if "bad" in target:
            raise RuntimeError("boom")
        return [{"status": "CONFIRMED", "name": target}]

    monkeypatch.setattr(distributed_runner, "_scan_one", fake_scan)

    rc = distributed_runner._run_standalone(None, ["http://ok/", "http://bad/"], {}, "full")

    assert rc == 1
    data = _report(tmp_path)
    assert data["successful"] == 1
    assert data["failed"] == 1
    assert data["failed_targets"][0]["target"] == "http://bad/"
    assert "RuntimeError: boom" in data["failed_targets"][0]["error"]


def test_standalone_all_failed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(distributed_runner, "_scan_one", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))

    rc = distributed_runner._run_standalone(None, ["http://a/", "http://b/"], {}, "full")

    assert rc == 1
    data = _report(tmp_path)
    assert data["successful"] == 0
    assert data["failed"] == 2
