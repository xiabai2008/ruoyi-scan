# G2：控制台编码兜底测试（Windows ANSI 代码页可移植性）
import io
import os
import sys
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.console import force_utf8_stdio


def test_force_utf8_stdio_reconfigures():
    """TextIO 流被 reconfigure 为 utf-8 + replace（初始 cp1252 模拟英文 Windows）"""
    out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    err = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
        force_utf8_stdio()
    assert out.encoding == "utf-8", out.encoding
    assert out.errors == "replace", out.errors
    assert err.encoding == "utf-8"


def test_force_utf8_stdio_tolerates_unreconfigurable():
    """无 reconfigure 属性的流（测试捕获管道/旧包装）静默跳过不抛异常"""

    class Legacy:
        pass

    legacy_out, legacy_err = Legacy(), Legacy()
    with mock.patch("sys.stdout", legacy_out), mock.patch("sys.stderr", legacy_err):
        force_utf8_stdio()  # 不应抛 AttributeError


def test_force_utf8_stdio_tolerates_closed_stream():
    """已关闭流抛 ValueError 时静默跳过"""

    class Closed(io.StringIO):
        def reconfigure(self, **kw):
            raise ValueError("I/O operation on closed file")

    with mock.patch("sys.stdout", Closed()), mock.patch("sys.stderr", io.StringIO()):
        force_utf8_stdio()  # 不应抛 ValueError


def test_force_utf8_stdio_none_stream():
    """stdout/stderr 为 None（pythonw 场景）不抛异常"""
    with mock.patch("sys.stdout", None), mock.patch("sys.stderr", None):
        force_utf8_stdio()


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v", "--tb=short"])
