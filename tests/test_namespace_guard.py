# 顶层包名冲突检测护栏
#
# 背景：本项目以非 src-layout 分发，site-packages 下会出现 core / common / lib / cli
# 等 9 个顶层名。用户项目里若有同名包且排在 sys.path 前面，扫描器内部的
# `from core.http import join_url` 会导入到**用户的**模块——实测轻则报难以定位的
# TypeError，重则静默调用到错误实现（签名恰好兼容时）。
#
# 不做「收进 ruoyi_scan/ 单包」重构的原因见 lib/namespace_guard.py 顶部注释。
# 本测试守护检测逻辑本身的正确性：必须精准命中真实劫持，且对正常场景零误报。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.namespace_guard import (  # noqa: E402
    PROJECT_TOP_LEVEL,
    Conflict,
    _is_project_copy,
    detect_conflicts,
    format_conflict_warning,
)


def _make_user_package(tmp_path, name):
    """在 tmp_path 下造一个「用户自己的同名包」"""
    pkg = tmp_path / name
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text(f"# user package: {name}\nMARKER = 'USER'\n", encoding="utf-8")
    return pkg


def test_no_conflict_in_normal_environment():
    """正常环境（源码运行 / 纯净 venv）不得误报"""
    assert detect_conflicts() == []


def test_detects_hijacked_top_level_package(tmp_path, monkeypatch):
    """用户同名包排在 sys.path 前面时必须被检出"""
    _make_user_package(tmp_path, "core")
    _make_user_package(tmp_path, "lib")
    # 把用户目录插到最前（模拟 pip 安装后 site-packages 在后、用户 cwd 在前）
    monkeypatch.syspath_prepend(str(tmp_path))

    conflicts = detect_conflicts()
    names = {c.name for c in conflicts}
    assert "core" in names, "被劫持的 core 必须被检出"
    assert "lib" in names, "被劫持的 lib 必须被检出"

    for c in conflicts:
        assert isinstance(c, Conflict)
        assert str(tmp_path) in c.actual, "冲突项必须指向用户的包路径"
        assert "expected" in c._fields and "actual" in c._fields


def test_shadowed_package_not_reported(tmp_path, monkeypatch):
    """用户同名包排在 sys.path **后面**（不会被导入）时不得误报"""
    _make_user_package(tmp_path, "core")
    # 追加到末尾：真实 import 不会解析到它
    monkeypatch.setattr(sys, "path", list(sys.path) + [str(tmp_path)])

    conflicts = detect_conflicts()
    assert not [c for c in conflicts if c.name == "core"], "排在后面不会被导入的包不算冲突"


def test_installed_copy_is_not_conflict(tmp_path):
    """site-packages 里本项目的安装副本不算冲突（用户装的可能是旧版本）"""
    # 造一个「本项目安装副本」：含 5 个标志性顶层包
    for sig in ("core", "lib", "plugins", "common", "cli"):
        pkg = tmp_path / sig
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "__init__.py").write_text(f"# {sig}\n", encoding="utf-8")

    # 含 5 个标志性包 → 判为本项目副本 → 不是冲突
    assert _is_project_copy(str(tmp_path / "core" / "__init__.py"), "core", "/nonexistent/root")


def test_single_user_package_is_conflict(tmp_path):
    """只有一个同名包的目录不是「本项目安装副本」"""
    _make_user_package(tmp_path, "core")
    assert not _is_project_copy(str(tmp_path / "core" / "__init__.py"), "core", "/nonexistent/root")


def test_warning_text_contains_actionable_guidance():
    """告警文本必须给出可操作的解决办法，而不只是说「有冲突」"""
    c = Conflict(name="core", expected="/proj/core", actual="/user/core/__init__.py")
    text = format_conflict_warning([c])
    assert "core" in text
    assert "venv" in text.lower(), "必须提示使用虚拟环境"
    assert "/user/core" in text, "必须指出实际解析到的路径"


def test_warning_text_empty_for_no_conflict():
    """无冲突时不产出告警文本"""
    assert format_conflict_warning([]) == ""


def test_project_top_level_covers_all_exposed_names():
    """检测范围必须覆盖 pyproject packages.find.include 暴露的全部顶层名"""
    for name in ("common", "cli", "core", "lib", "api", "plugins", "config", "chains", "main"):
        assert name in PROJECT_TOP_LEVEL


def test_frozen_environment_skips_check(monkeypatch):
    """PyInstaller 冻结环境（桌面端 exe）不做检查——模块已内嵌，无冲突可能"""
    from lib import namespace_guard

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert namespace_guard.check_early() == []
