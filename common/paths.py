# 路径与文件名安全工具：集中处理外部可控的 stem / 文件名，避免路径穿越。
import os
import re

# Windows 文件名非法字符 + 控制字符；同时覆盖 POSIX 分隔符
_UNSAFE_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

# Windows 保留设备名（不含扩展名时同样不可用）
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def safe_filename(name: str, default: str = "output", max_length: int = 120) -> str:
    """把外部可控字符串收敛为安全的单段文件名。

    - 只保留最后一段，丢弃目录部分（同时处理 / 和 \\）
    - 替换非法字符与 ..，去掉首尾空格/点
    - 规避 Windows 保留设备名
    - 空值/超长值分别回退 default / 截断
    """
    raw = str(name or "").replace("\\", "/").rsplit("/", 1)[-1]
    raw = _UNSAFE_FILENAME_CHARS.sub("_", raw)
    raw = raw.replace("..", "_").strip(" .")
    if not raw:
        raw = default
    if raw.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
        raw = "_" + raw
    return raw[:max_length].rstrip(" .") or default


def safe_join(base: str, *parts: str) -> str:
    """在 base 内拼接路径；任何越出 base 的结果都直接拒绝。"""
    base_abs = os.path.abspath(base)
    target = os.path.abspath(os.path.join(base_abs, *parts))
    if target != base_abs and not target.startswith(base_abs + os.sep):
        raise ValueError("路径越出目标目录: %s" % target)
    return target
