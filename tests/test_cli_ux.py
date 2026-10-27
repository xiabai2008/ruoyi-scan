# 陌生用户首次使用体验护栏：版本号 / 缺目标 / 结尾暂停 / 结论行重复 / 报告同名
# 背景：README 主推「pip install 完就能扫」，但 --version 报错、裸 -p 静默退出、
# 每条结论在终端打两遍、role/dept 两个注入点在报告里同名——这些都是首次接触即踩的坑。
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings  # noqa: E402
from lib import reporter  # noqa: E402
from lib.colors import ok  # noqa: E402


def test_version_flag_prints_version(capsys):
    """--version / -V 直接输出版本号并 exit 0（此前是 unrecognized arguments + 60 行 usage）"""
    from main import main

    for flag in ("--version", "-V"):
        with pytest.raises(SystemExit) as exc:
            main([flag])
        assert exc.value.code == 0
        assert settings.VERSION in capsys.readouterr().out


def test_bare_mode_requires_target(capsys):
    """裸 -p/-u/-m/-l 缺目标 → 明确报错 + 退出码 2（此前只打 banner 就 exit 0）"""
    from main import main

    for flag in ("-p", "-u", "-m", "-l"):
        with pytest.raises(SystemExit) as exc:
            main([flag])
        assert exc.value.code == 2
        out = capsys.readouterr().out
        assert "缺少扫描目标" in out
        assert f"-{flag[1:]}" in out


def test_final_prompt_skips_with_no_pause(monkeypatch):
    """--no-pause 时不调用 input（CI / 脚本场景）"""
    from cli.runner import final_prompt

    def _boom(*_a, **_kw):  # pragma: no cover - 只用于断言未被调用
        raise AssertionError("no_pause=True 时不应等待回车")

    monkeypatch.setattr("builtins.input", _boom)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    final_prompt(no_pause=True)


def test_final_prompt_skips_in_ci(monkeypatch):
    """CI 环境变量存在时不等待（docker -t 之类仍分配 tty 的场景）"""
    from cli.runner import final_prompt

    def _boom(*_a, **_kw):  # pragma: no cover
        raise AssertionError("CI 环境不应等待回车")

    monkeypatch.setattr("builtins.input", _boom)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("CI", "true")
    final_prompt()


def test_findings_muted_suppresses_plugin_conclusion(capsys):
    """结论行静音只压制 ok()/no() 产出的整行结论，进度类文案照常输出"""
    was_muted = reporter.is_findings_muted()
    was_quiet = reporter.is_quiet()  # 测试环境默认静默，本用例需要真实 stdout 才能断言
    reporter.set_quiet(False)
    reporter.set_findings_muted(True)
    try:
        reporter.emit(ok("存在任意文件读取"))
        reporter.emit("[*]指纹识别：cms=ruoyi")
    finally:
        reporter.set_findings_muted(was_muted)
        reporter.set_quiet(was_quiet)

    out = capsys.readouterr().out
    assert "存在任意文件读取" not in out
    assert "指纹识别" in out


def test_resolve_name_keeps_suffix_for_single_result():
    """单条结果的聚合组沿用插件原名：role / dept 不再合并成同名两行"""
    from types import SimpleNamespace

    from core.dedup import _resolve_name

    assert _resolve_name([SimpleNamespace(name="POST型报错注入（role）", extra={})]) == "POST型报错注入（role）"
    assert _resolve_name([SimpleNamespace(name="POST型报错注入（dept）", extra={})]) == "POST型报错注入（dept）"
    # 真正发生合并时仍收敛措辞
    merged = _resolve_name(
        [
            SimpleNamespace(name="任意文件读取（路径穿越）", extra={}),
            SimpleNamespace(name="任意文件读取", extra={}),
        ]
    )
    assert merged == "任意文件读取"
