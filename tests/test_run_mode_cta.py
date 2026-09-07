# run_mode 收尾引导调用链集成测试
# 验证：单目标扫描默认输出引导；--no-cta 关闭；CI 模式跳过
import types
from argparse import Namespace
from unittest import mock

from cli import runner


def _args(**kw):
    """构造 run_mode 所需的 args 命名空间（覆盖 run_mode 全程访问的字段）"""
    base = dict(
        threads=1,
        timeout=1,
        rate=0,
        pass_level="full",
        proxy=None,
        debug=False,
        cms=None,
        no_components=False,
        components=False,
        template=None,
        config=None,
        report=None,
        report_format="all",
        no_dedup=False,
        ci=False,
        no_cta=False,
        logic_scan=False,
        logic_endpoints=None,
        logic_concurrency=10,
        siem_export=None,
        siem_output=None,
        siem_syslog=None,
        siem_protocol="udp",
        notify=None,
        ai_report=None,
        save_baseline=False,
        diff=None,
        async_mode=False,
        async_workers=10,
        api_key=None,
        auth=None,
        auth_file=None,
        auth_login=None,
        lang="zh",
        crawl=False,
        subdomain=False,
        js_extract=False,
        portscan=False,
    )
    base.update(kw)
    return Namespace(**base)


def _patch_scan(monkeypatch):
    """mock 掉真实扫描与请求构造，使 run_mode 不触网即可跑完整流程"""
    monkeypatch.setattr(runner, "_build_scan_request", lambda *a, **k: types.SimpleNamespace(cms="", template=None))
    monkeypatch.setattr("core.orchestrator.ScanOrchestrator.run_sync", lambda self, req, on_event=None: [])


def test_run_mode_prints_cta_by_default(monkeypatch):
    """单目标扫描结尾默认输出引导"""
    monkeypatch.setattr(runner, "print_star_cta", mock.Mock(return_value=True))
    _patch_scan(monkeypatch)
    runner.run_mode("p", "http://127.0.0.1:1/", _args())
    assert runner.print_star_cta.called
    assert runner.print_star_cta.call_args.kwargs.get("explicit_off") is False


def test_run_mode_respects_no_cta(monkeypatch):
    """--no-cta 时显式关闭"""
    monkeypatch.setattr(runner, "print_star_cta", mock.Mock(return_value=False))
    _patch_scan(monkeypatch)
    runner.run_mode("p", "http://127.0.0.1:1/", _args(no_cta=True))
    assert runner.print_star_cta.called
    assert runner.print_star_cta.call_args.kwargs.get("explicit_off") is True


def test_run_mode_skips_cta_in_ci(monkeypatch):
    """CI 模式需干净输出，跳过引导（且 run_ci_mode 返回 0 不 exit）"""
    monkeypatch.setattr(runner, "print_star_cta", mock.Mock(return_value=False))
    _patch_scan(monkeypatch)
    monkeypatch.setattr("lib.ci_runner.run_ci_mode", lambda *a, **k: 0)
    runner.run_mode("p", "http://127.0.0.1:1/", _args(ci=True))
    assert not runner.print_star_cta.called
