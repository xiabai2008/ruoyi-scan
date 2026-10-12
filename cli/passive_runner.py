"""CLI submodule — 被动代理模式"""

from __future__ import annotations

import time
from argparse import Namespace

from common.logger import get_logger
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW

logger = get_logger(__name__)


def run_passive_mode(args: Namespace) -> None:
    """被动代理模式：启动 HTTP/HTTPS 代理，捕获流量 URL 自动扫描"""
    from core.proxy_server import ProxyServer, ScanQueue

    queue = ScanQueue()
    host = args.passive_host
    port = args.passive_port
    proxy = ProxyServer(host=host, port=port, queue=queue)
    proxy.start()

    print(f"{SEPARATOR}")
    print(f"{GREEN}[*]被动扫描模式启动{RESET}")
    print(f"{YELLOW}[*]代理监听: http://{host}:{port}")
    print(f"{YELLOW}[*]请将浏览器/工具代理设为 http://{host}:{port}")
    print(f"{YELLOW}[*]所有经过代理的 HTTP/HTTPS 请求目标会自动加入扫描队列")
    print(f"{YELLOW}[*]按 Ctrl+C 停止被动扫描{RESET}")
    print(f"{SEPARATOR}")

    # 去重由 ScanQueue 全权负责：add() 时的 _seen 永久去重（drain 不清除），
    # 同一 URL 不可能再次入队；此处只需计数供退出时展示（避免无界的本地集合）
    scanned_count = 0
    # 延迟导入必须在函数内：cli.runner 反向导入本模块，模块级导入会形成循环
    from cli.runner import run_mode

    try:
        # 代理主循环：常驻轮询采集队列，直到用户 Ctrl+C 退出
        while True:
            # 每 3 秒轮询一次队列：批量 drain 合并突发流量，避免逐请求即时扫描的开销
            time.sleep(3)
            urls = queue.drain()
            if not urls:
                continue
            for url in urls:
                scanned_count += 1
                print(f"\n{SEPARATOR}")
                print(f"{YELLOW}[*]被动捕获: {url}{RESET}")
                # 单 URL 扫描隔离：个别目标异常仅提示，不中断代理与后续流量采集
                try:
                    # 被动代理每捕获一个 URL 就扫一次，此处必须关闭引导避免逐条刷屏
                    run_mode("p", url, args, show_cta=False)
                except Exception as e:
                    # 保留 traceback（debug 档可查），对用户仍只给一行提示
                    logger.debug("被动扫描异常 url=%s", url, exc_info=True)
                    print(f"{RED}[!]扫描异常 ({url}): {e}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*]被动扫描已停止，共扫描 {scanned_count} 个目标{RESET}")
    finally:
        proxy.stop()
