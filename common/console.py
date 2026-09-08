# 控制台输出编码兜底（Windows ANSI 代码页环境可移植性，G2）
#
# 问题：Windows 控制台默认走 ANSI 代码页（英文系统 cp1252 / 中文系统 GBK），
# CLI / 回归脚本输出中的中文与框线字符会触发 UnicodeEncodeError 使进程崩溃
# 退出码 1（Windows CI matrix 首跑暴露；中文系统 GBK 碰巧能编码所以此前未发现）。
#
# 方案：所有可直接运行的入口（main.py / tests/regression_*.py）启动时调用
# force_utf8_stdio()，把 stdout/stderr 重配置为 UTF-8 + errors=replace——
# 极旧终端上最多乱码显示，绝不中断程序。
import sys


def force_utf8_stdio() -> None:
    """强制 stdout/stderr 为 UTF-8（幂等，可在 argparse/打印前任意时机调用）

    必须在任何中文输出之前调用（argparse -h 的帮助文本同样经过 stdout）。
    对不可重配置的流（如测试捕获管道、已关闭流）静默跳过，不抛异常。
    """
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass
