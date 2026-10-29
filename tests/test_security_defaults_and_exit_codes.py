# 安全默认值与退出码语义护栏：--host 默认绑定 / 批量退出码 / 批量 + --ci 不中断
#
# 背景（2026-10-29 陌生用户实测反馈 + 内部盲测）：
#   1. --serve 默认 0.0.0.0 —— 安全工具的 Web API 默认暴露整个网段是不安全默认值，
#      与 lab/ 靶场 v1.2.0 已做的「默认绑 127.0.0.1」收口不一致。
#   2. 批量模式全部目标不可达时退出码为 0 —— 脚本里会被当成「扫描完成」。
#   3. 批量 + --ci 会在第一个超阈值目标上 sys.exit() —— 后续目标根本没扫，
#      用户拿到的是「只覆盖 1/N 目标」的报告却以为整批都扫过（假覆盖）。
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.preflight import EXIT_PARTIAL, EXIT_UNREACHABLE  # noqa: E402

# ── 1. --host 默认绑定 ────────────────────────────────────────────────────────


def test_host_defaults_to_loopback():
    """--host 默认 127.0.0.1（此前 0.0.0.0：Web API 默认暴露整个网段）"""
    from main import build_parser

    args = build_parser().parse_args(["--serve"])
    assert args.host == "127.0.0.1", "安全默认值必须只绑本机回环"


def test_host_env_override_allows_container_binding():
    """RUOYI_SCAN_HOST 可覆盖默认值（容器 / 反向代理场景用）"""
    from main import build_parser

    os.environ["RUOYI_SCAN_HOST"] = "0.0.0.0"
    try:
        args = build_parser().parse_args(["--serve"])
        assert args.host == "0.0.0.0"
    finally:
        os.environ.pop("RUOYI_SCAN_HOST", None)


def test_host_explicit_flag_wins_over_env(monkeypatch):
    """显式 --host 优先于环境变量"""
    from main import build_parser

    monkeypatch.setenv("RUOYI_SCAN_HOST", "0.0.0.0")
    args = build_parser().parse_args(["--serve", "--host", "127.0.0.1"])
    assert args.host == "127.0.0.1"


# ── 2. 批量退出码语义 ────────────────────────────────────────────────────────


def _write_targets(tmp_path, lines):
    f = tmp_path / "targets.txt"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(f)


def _make_args(**overrides):
    from argparse import Namespace

    base = {
        "file": None,
        "report": None,
        "report_format": "html",
        "no_dedup": False,
        "no_cta": True,
        "ci": False,
        "severity_threshold": "high",
        "skip_preflight": False,
        "proxy": None,
        "proxy_file": None,
        "async_mode": False,
        "async_workers": 10,
    }
    base.update(overrides)
    return Namespace(**base)


def test_batch_all_unreachable_exits_unreachable(tmp_path, monkeypatch, capsys):
    """批量全部目标不可达 → 退出码 3（此前 0：脚本误判为扫描完成）"""
    from cli import runner

    targets_file = _write_targets(tmp_path, ["http://127.0.0.1:59999/", "http://127.0.0.1:59998/"])
    monkeypatch.setattr(runner, "preflight_target", lambda t, a: False)

    with pytest.raises(SystemExit) as exc:
        runner.run_mode_batch(targets_file, "p", _make_args())
    assert exc.value.code == EXIT_UNREACHABLE


def test_batch_partial_unreachable_exits_partial(tmp_path, monkeypatch, capsys):
    """批量部分目标不可达 → 退出码 4（表示「扫到了但覆盖面不全」）"""
    from cli import runner

    targets_file = _write_targets(tmp_path, ["http://example.com/", "http://127.0.0.1:59999/"])
    # 第一个可达、第二个不可达
    monkeypatch.setattr(runner, "preflight_target", lambda t, a: "59999" not in t)
    monkeypatch.setattr(runner, "run_mode", lambda *a, **k: [])
    monkeypatch.setattr(runner, "_render_batch_target_reports", lambda *a, **k: [])
    monkeypatch.setattr(runner.BatchReport, "render_all", lambda self, *a, **k: [])

    with pytest.raises(SystemExit) as exc:
        runner.run_mode_batch(targets_file, "p", _make_args())
    assert exc.value.code == EXIT_PARTIAL


def test_batch_all_reachable_exits_zero(tmp_path, monkeypatch):
    """批量全部目标扫到 → 退出码 0"""
    from cli import runner

    targets_file = _write_targets(tmp_path, ["http://example.com/"])
    monkeypatch.setattr(runner, "preflight_target", lambda t, a: True)
    monkeypatch.setattr(runner, "run_mode", lambda *a, **k: [])
    monkeypatch.setattr(runner, "_render_batch_target_reports", lambda *a, **k: [])
    monkeypatch.setattr(runner.BatchReport, "render_all", lambda self, *a, **k: [])

    result = runner.run_mode_batch(targets_file, "p", _make_args())
    assert result is not None


# ── 3. 批量 + --ci 不得中断后续目标 ──────────────────────────────────────────


def test_batch_ci_does_not_exit_after_first_target(tmp_path, monkeypatch):
    """批量 + --ci：第一个目标命中高危也不得 sys.exit()，必须扫完全部目标

    回归场景：run_mode 里的 CI 分支会 sys.exit(exit_code)，而批量对每个目标调
    run_mode —— 修复前第一个目标就整批中断，后续目标根本没扫。
    """
    from cli import runner

    targets_file = _write_targets(tmp_path, ["http://a.example.com/", "http://b.example.com/", "http://c.example.com/"])
    scanned = []

    def _fake_run_mode(mode, target, args, show_cta=True):
        scanned.append(target)
        # 断言单目标 CI 退出码已被禁用：args.ci 必须为 False
        assert not getattr(args, "ci", False), "批量内必须禁用单目标 CI 退出码逻辑"
        return []

    monkeypatch.setattr(runner, "preflight_target", lambda t, a: True)
    monkeypatch.setattr(runner, "run_mode", _fake_run_mode)
    monkeypatch.setattr(runner, "_render_batch_target_reports", lambda *a, **k: [])
    monkeypatch.setattr(runner.BatchReport, "render_all", lambda self, *a, **k: [])

    result = runner.run_mode_batch(targets_file, "p", _make_args(ci=True))
    assert len(scanned) == 3, f"批量 + --ci 必须扫完全部目标，实际只扫了 {len(scanned)} 个"
    assert result is not None


def test_batch_async_disables_per_target_ci_exit(monkeypatch):
    """异步批量路径同样必须禁用单目标 CI 退出码"""
    from cli import runner
    from common.models import STATUS_SAFE, ScanResult

    scanned = []
    captured_args = {}

    def _fake_run_mode(mode, target, args, show_cta=True):
        scanned.append(target)
        captured_args["ci"] = getattr(args, "ci", False)
        # 返回一条真实结果，避免空结果触发 EXIT_UNREACHABLE 分支
        return [
            ScanResult(
                kind="vuln",
                name="测试",
                severity="low",
                status=STATUS_SAFE,
                url=target,
                evidence="mock",
            )
        ]

    class _FakeEngine:
        @staticmethod
        def scan_batch_targets(scan_fn, targets, max_workers, progress_callback=None):
            for t in targets:
                scan_fn(t)

    import lib.async_engine as async_engine

    monkeypatch.setattr(async_engine, "scan_batch_targets", _FakeEngine.scan_batch_targets)
    monkeypatch.setattr(runner, "run_mode", _fake_run_mode)

    runner._run_batch_async(["http://a.example.com/", "http://b.example.com/"], "p", _make_args(ci=True), "漏洞", 4)
    assert len(scanned) == 2
    assert captured_args.get("ci") is False


# ── 4. -f 缺模式 → 参数错误退出码 2 ──────────────────────────────────────────


def test_batch_without_mode_flag_exits_two(tmp_path, capsys):
    """-f 不带 -u/-m/-p/-l → 退出码 2（此前 return：退出码 0，脚本误判为完成）"""
    from main import main

    f = tmp_path / "targets.txt"
    f.write_text("http://example.com/\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["-f", str(f)])
    assert exc.value.code == 2
    assert "批量扫描需配合" in capsys.readouterr().out
