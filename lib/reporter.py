# lib/reporter.py — 扫描进度输出桥（CLI 走 stdout，库/服务模式走 logger）
"""插件与 core 模块的统一进度输出通道。

存在意义
========
插件在 verify() 内需要向用户报告「正在检测什么、结果如何」。原先直接使用 `print()`：
在 CLI 下体验良好，但在库/服务模式下造成两个实际问题：

  1. **污染服务日志**：API sidecar（FastAPI）与桌面端嵌入扫描引擎时，插件输出
     会直接写进服务进程的 stdout，与访问日志、错误日志混在一起无法分离。
  2. **污染测试输出**：误报基线测试会执行 51 插件 × 多条语料，向 stdout 倾倒
     约 2 MB 文本，淹没真正的测试失败信息。

本模块提供单一出口，按运行模式分流：

  - **CLI 模式（默认）**：原样写 stdout，保留 ANSI 颜色与 `[*]` / `[/]` 前缀，
    CLI 观感与迁移前完全一致。
  - **静默模式**：不写 stdout；内容去除 ANSI 后以 DEBUG 级别交给 logging。
    由于 loguru 配置默认为 WARNING 级别，静默模式下默认完全无输出；
    需要排查时用 `--debug` 或环境变量 `RUOYI_SCAN_DEBUG=1` 打开。

用法
====
    from lib.reporter import emit
    emit(ok("存在 Thymeleaf/SpEL 模板注入漏洞"))

服务入口显式切换模式：

    from lib.reporter import set_quiet
    set_quiet(True)     # API 服务 / 库调用 / 测试

函数名为什么是 emit 而不是 report
=================================
`report` 在本项目里是高频**局部变量名**（扫描结果字典）：`ai_generator`、
`ai_triage`、`ai_validate`、`cve_sync`、`distributed`、`diff_scan`、`core/dedup`
共 7 个文件存在 `report = ...` 绑定。若把桥函数命名为 `report`，这些文件里
`report = master.aggregate_results(...)` 之后的 `report(...)` 会立刻抛
`TypeError: 'dict' object is not callable`。`emit` 经 AST 全量排查确认
在 `plugins/` `lib/` `core/` 中零绑定冲突。

约定
====
- `plugins/**`、`lib/**`、`core/**` **不得直接 `print()`**，必须走 `emit()`。
  该约定由 `tests/test_logging_hygiene.py` 的 AST 门禁强制。
- `cli/**` 是 stdout 呈现层（banner、扫描结果表格、帮助信息），允许直接 print；
  `lib/reporter.py` 自身是桥的实现，同样在门禁白名单内。
"""

import logging
import re
from typing import Any

from common.logger import get_logger

logger = get_logger(__name__)

# ANSI 转义序列（\033[32m 等），日志中必须剥离，否则日志文件会混入控制字符
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

_quiet = False


def set_quiet(quiet: bool = True) -> None:
    """切换静默模式

    Args:
        quiet: True 则不再写 stdout，进度内容改走 logging（DEBUG 级别）
    """
    global _quiet
    _quiet = bool(quiet)


def is_quiet() -> bool:
    """当前是否处于静默模式"""
    return _quiet


def strip_ansi(text: str) -> str:
    """去除字符串中的 ANSI 颜色转义序列"""
    return _ANSI_RE.sub("", text)


def emit(*args: Any, sep: str = " ", end: str = "\n") -> None:
    """输出一行扫描进度（plugins / lib / core 的唯一输出出口）

    签名与 `print()` 兼容，便于从 `print(...)` 直接改名为 `emit(...)`。

    行为：
      - CLI 模式：等价于 `print(*args, sep=sep, end=end)`
      - 静默模式：不写 stdout；DEBUG 级别开启时把去 ANSI 的文本交给 logging

    Args:
        *args: 待输出内容（通常为单个已由 lib.colors 着色/加前缀的字符串）
        sep: 多参数分隔符，同 print
        end: 行尾，同 print
    """
    if not _quiet:
        print(*args, sep=sep, end=end)
        return
    # 静默模式下先判断级别，避免为丢弃的日志做字符串拼接与正则替换
    if not logger.isEnabledFor(logging.DEBUG):
        return
    logger.debug(strip_ansi(sep.join(str(a) for a in args)))
