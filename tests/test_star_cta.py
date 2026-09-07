# 收尾仓库引导（lib/star_cta.py）单元测试
import io

from lib.star_cta import REPO_URL, cta_enabled, print_star_cta


def test_cta_enabled_by_default(monkeypatch):
    """默认允许输出"""
    monkeypatch.delenv("RUOYI_SCAN_NO_CTA", raising=False)
    assert cta_enabled() is True


def test_cta_disabled_by_env(monkeypatch):
    """环境变量 RUOYI_SCAN_NO_CTA=1 全局关闭"""
    monkeypatch.setenv("RUOYI_SCAN_NO_CTA", "1")
    assert cta_enabled() is False


def test_cta_disabled_by_env_variants(monkeypatch):
    """环境变量多种真值写法均生效"""
    for val in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("RUOYI_SCAN_NO_CTA", val)
        assert cta_enabled() is False, val


def test_cta_disabled_explicitly(monkeypatch):
    """显式关闭（对应 --no-cta）"""
    monkeypatch.delenv("RUOYI_SCAN_NO_CTA", raising=False)
    assert cta_enabled(explicit_off=True) is False


def test_print_contains_repo_url():
    """强制输出时必须包含仓库地址"""
    buf = io.StringIO()
    assert print_star_cta(force=True, stream=buf) is True
    assert REPO_URL in buf.getvalue()


def test_print_respects_explicit_off():
    """--no-cta 时完全不输出，不产生任何字节"""
    buf = io.StringIO()
    assert print_star_cta(explicit_off=True, force=True, stream=buf) is False
    assert buf.getvalue() == ""


def test_print_respects_env_off(monkeypatch):
    """环境变量关闭时完全不输出"""
    monkeypatch.setenv("RUOYI_SCAN_NO_CTA", "1")
    buf = io.StringIO()
    assert print_star_cta(force=True, stream=buf) is False
    assert buf.getvalue() == ""


def test_print_skipped_when_not_tty():
    """非终端（管道/重定向/CI）自动静默，避免污染机器可读输出"""
    buf = io.StringIO()  # StringIO.isatty() 恒为 False
    assert print_star_cta(stream=buf) is False
    assert buf.getvalue() == ""
