"""扫描前目标可用性预检（单目标 / 批量 / 利用链三种入口共用）。

独立成模块的原因：dispatcher、runner、chain_runner 三者都需要它，而
chain_runner 由 runner 导入——若把实现放在 dispatcher 会形成循环导入。

两级探测，因为两级各自会漏掉一类目标：

1. TCP 层：目标未启动 / 地址写错 / 端口不通 —— 秒级判定。
2. HTTP 层：端口可连接但服务无响应（防火墙接受 SYN 后丢包、服务假死）——
   TCP 探测会放行，而每个插件都要等满超时，实测这类目标 120 秒仅完成数个插件。

唯一例外：配置了代理时跳过直连探测，否则经代理可达的目标会被误判为不可达。
"""

from __future__ import annotations

from argparse import Namespace

# 目标不可用的退出码：与 CI 模式（0 通过 / 1 超阈值 / 2 异常）区分开，
# 使脚本能辨别「扫描未完成」与「扫出漏洞」两种失败
EXIT_UNREACHABLE = 3

# 批量模式下「部分目标未扫到」的退出码：整批已完成且有结果，但有目标因不可用被跳过。
# 与 EXIT_UNREACHABLE 区分：前者是「扫到了但不全」，后者是「一个都没扫到」。
EXIT_PARTIAL = 4


def preflight_target(target: str, args: Namespace) -> bool:
    """确认目标可扫描：TCP 可连且 HTTP 有响应。

    Args:
        target: 待扫描目标 URL
        args: CLI 参数命名空间（读取 skip_preflight / proxy / proxy_file）

    Returns:
        True 允许继续扫描；False 目标不可用（原因与建议已打印）
    """
    if getattr(args, "skip_preflight", False):
        return True
    # 配置代理时目标由代理侧访问，直连探测会把可达目标误判为不可达
    if getattr(args, "proxy", None) or getattr(args, "proxy_file", None):
        return True

    from core.http import probe_http_responsive, probe_reachable
    from lib.colors import RED, RESET, YELLOW

    hints = f"{YELLOW}[*]经代理访问请加 --proxy；确需跳过本检查用 --skip-preflight{RESET}"

    # 探测自身可能抛出非 OSError 异常（如 URL 端口非法时 split_target 抛 ValueError）：
    # 本函数契约是返回 False + 可读提示，不能把 CLI 输入错误升级为整段扫描崩溃
    try:
        ok, reason = probe_reachable(target)
        if not ok:
            print(f"{RED}[!]目标不可达：{reason}{RESET}")
            print(f"{YELLOW}[*]已跳过该目标。请确认地址与端口是否正确、目标是否已启动。{RESET}")
            print(hints)
            return False

        ok, reason = probe_http_responsive(target)
    except Exception as e:
        print(f"{RED}[!]目标预检失败：{e}{RESET}")
        print(f"{YELLOW}[*]已跳过该目标。请检查目标地址格式是否正确。{RESET}")
        print(hints)
        return False

    if not ok:
        print(f"{RED}[!]目标无 HTTP 响应：{reason}{RESET}")
        print(f"{YELLOW}[*]已跳过该目标：端口可连接但服务不返回数据，继续扫描只会白等超时。{RESET}")
        print(hints)
        return False

    return True
