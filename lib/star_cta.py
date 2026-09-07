# 扫描结束后的仓库引导（降低点星摩擦）
"""扫描收尾时输出仓库地址，把「用完了就走」的用户引导回仓库。

设计取舍：
1. 只在真实终端（isatty）输出 —— 管道/重定向/CI 场景下自动静默，
   避免污染 `python main.py -p ... | tee log`、`--ci` 等机器可读输出。
2. 支持两级关闭：CLI `--no-cta` 一次性关闭；环境变量 `RUOYI_SCAN_NO_CTA=1`
   长期关闭（适合写进 Dockerfile / CI 配置）。
3. 不依赖任何扫描上下文，API 服务与报告渲染可直接复用本模块的常量。
"""

from __future__ import annotations

import os
import sys
from typing import IO, Optional

from lib.colors import GREEN, RESET, SEPARATOR, YELLOW

# 仓库地址（star / issue / 文档 同址，统一出口，便于后续改域名只改一处）
REPO_URL = "https://github.com/xiabai2008/ruoyi-scan"

# 环境变量开关：任一命中即全局静默
_DISABLE_ENV_VARS = ("RUOYI_SCAN_NO_CTA",)
_TRUTHY = ("1", "true", "yes", "on")


def cta_enabled(explicit_off: bool = False) -> bool:
    """是否允许输出引导

    Args:
        explicit_off: 显式关闭（对应 CLI `--no-cta`）

    Returns:
        True 表示允许输出
    """
    if explicit_off:
        return False
    for name in _DISABLE_ENV_VARS:
        if os.environ.get(name, "").strip().lower() in _TRUTHY:
            return False
    return True


def print_star_cta(
    explicit_off: bool = False,
    force: bool = False,
    stream: Optional[IO[str]] = None,
) -> bool:
    """打印仓库引导

    Args:
        explicit_off: 显式关闭（CLI `--no-cta`）
        force: 忽略 isatty 判断强制输出（批量汇总、测试使用）
        stream: 输出流，默认 sys.stdout

    Returns:
        是否实际输出（便于测试断言）
    """
    if not cta_enabled(explicit_off):
        return False

    out = stream if stream is not None else sys.stdout
    if not force:
        try:
            if not out.isatty():
                return False
        except (AttributeError, ValueError):
            # 某些包装流（StringIO 的部分实现）无 isatty，按非终端处理
            return False

    print(SEPARATOR, file=out)
    print(f"{GREEN}[*]Ruoyi-Scan 是开源免费工具，如果它帮到了你，欢迎点个 Star ★ 支持一下{RESET}", file=out)
    print(f"    {GREEN}{REPO_URL}{RESET}", file=out)
    print(f"{YELLOW}[*]不想看到这行提示？运行时加 --no-cta，或设置环境变量 RUOYI_SCAN_NO_CTA=1{RESET}", file=out)
    return True
