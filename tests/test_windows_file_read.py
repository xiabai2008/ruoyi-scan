# Windows 任意文件读取特征判定（v1.5.6 WP2）
#
# 背景：盲测 v3 的两个「任意文件读取」插件零产出，记录的原因是「Windows 靶场
# 无法提供 /etc/passwd 型证据」。核实后发现不是靶场问题——是 lib/matcher 只有
# Linux 特征（外加一条 boot.ini 的 [boot loader]，而 boot.ini 是另一个文件）。
# plugins/ruoyi/file_read.py 的 reproduce 里早就写了 win.ini 的 curl，
# 判据却不支持：文档承诺了、代码没实现。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN  # noqa: E402
from lib.matcher import is_windows_ini  # noqa: E402

# Windows 10/11 的真实 win.ini（C:\Windows\win.ini，92 字节）
REAL_WIN_INI = """; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
"""


class _Resp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {"Content-Type": "text/plain"}


class _Session:
    """按 URL 后缀返回不同载荷内容，模拟目标平台差异"""

    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, url, **_kw):
        for key, value in self.mapping.items():
            if key in url:
                return value
        return _Resp("<html>404 not found</html>", 404)


# ============================================================
# 1. 判据本身
# ============================================================


def test_real_win_ini_is_detected():
    hit, evidence = is_windows_ini(REAL_WIN_INI)
    assert hit is True
    assert "win.ini" in evidence


def test_marker_line_alone_is_enough():
    """`for 16-bit app support` 是 win.ini 独有的注释行，单条即可判真"""
    hit, _ = is_windows_ini("; for 16-bit app support\n")
    assert hit is True


def test_three_sections_without_marker_is_enough():
    """用户可能删了注释行，但段头是骨架——≥3 个段头也判真"""
    hit, evidence = is_windows_ini("[fonts]\n[extensions]\n[files]\n")
    assert hit is True
    assert "3" in evidence


def test_single_section_is_not_enough():
    """单个段名太泛（[files]、[Mail] 在任意 INI/HTML 里都可能出现）"""
    hit, evidence = is_windows_ini("[fonts]\nArial=1\n")
    assert hit is False
    assert "不足以确认" in evidence


def test_html_with_section_word_is_not_win_ini():
    """HTML 里出现 [files] 字样不能判成 win.ini（防误报）"""
    assert is_windows_ini("<html><a href='/files'>[files] download</a></html>")[0] is False


def test_empty_response_is_not_win_ini():
    assert is_windows_ini("")[0] is False


def test_boot_loader_is_not_win_ini():
    """[boot loader] 是 boot.ini 的段，与 win.ini 是不同文件，不能混用

    boot.ini 是 XP 引导配置，Win10/11 早已不存在；用它当 win.ini 特征
    会让判定在现代 Windows 上恒为假（假阴性）。
    """
    assert is_windows_ini("[boot loader]\ntimeout=30\n")[0] is False


# ============================================================
# 2. 插件双载荷
# ============================================================


def test_file_read_confirms_on_windows_target():
    """Windows 目标读不到 /etc/passwd 是正常的；win.ini 命中即 CONFIRMED"""
    from plugins.ruoyi.file_read import FileReadPlugin

    sess = _Session({"win.ini": _Resp(REAL_WIN_INI)})
    res = FileReadPlugin().verify("http://t/", sess)
    assert res.status == STATUS_CONFIRMED
    assert "win.ini" in res.evidence
    # payload_class 按平台区分，避免与 Linux 命中被去重合并
    assert res.extra["payload_class"] == "traversal_windows_winini"


def test_file_read_still_confirms_on_linux_target():
    """Linux 目标行为不变（回归）"""
    from plugins.ruoyi.file_read import FileReadPlugin

    sess = _Session({"etc/passwd": _Resp("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\n")})
    res = FileReadPlugin().verify("http://t/", sess)
    assert res.status == STATUS_CONFIRMED
    assert res.extra["payload_class"] == "traversal_etc_passwd"


def test_file_read_safe_mentions_both_platforms():
    """全都不命中时判 SAFE，但证据要写明试过两个平台（可审计）"""
    from plugins.ruoyi.file_read import FileReadPlugin

    sess = _Session({"download": _Resp("<html>no such file</html>")})
    res = FileReadPlugin().verify("http://t/", sess)
    assert res.status == STATUS_SAFE
    assert "Linux" in res.evidence and "Windows" in res.evidence


def test_file_read_path_confirms_on_windows_target():
    """file_read_path 同样支持 win.ini"""
    from plugins.ruoyi.file_read_path import RuoyiFileReadPathPlugin

    sess = _Session({"win.ini": _Resp(REAL_WIN_INI)})
    res = RuoyiFileReadPathPlugin().verify("http://t/", sess)
    assert res.status == STATUS_CONFIRMED
    assert res.extra["payload_class"] == "traversal_windows_winini"


def test_file_read_all_network_errors_is_unknown():
    """全部载荷网络异常 → UNKNOWN（测不到 ≠ 安全，三态纪律）"""
    from plugins.ruoyi.file_read import FileReadPlugin

    class _Raising:
        def get(self, url, **_kw):
            raise OSError("connection refused")

    res = FileReadPlugin().verify("http://t/", _Raising())
    assert res.status == STATUS_UNKNOWN


def test_file_read_partial_network_error_still_checks_other_payload():
    """一个载荷异常、另一个正常 → 仍按正常载荷判定（不能因单点失败放弃）"""
    from plugins.ruoyi.file_read import FileReadPlugin

    class _Partial:
        def get(self, url, **_kw):
            if "win.ini" in url:
                return _Resp(REAL_WIN_INI)
            raise OSError("boom")

    res = FileReadPlugin().verify("http://t/", _Partial())
    assert res.status == STATUS_CONFIRMED


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)
