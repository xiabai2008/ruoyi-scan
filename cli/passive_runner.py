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

    scanned = set()
    try:
        while True:
            time.sleep(3)
            urls = queue.drain()
            if not urls:
                continue
            for url in urls:
                if url in scanned:
                    continue
                scanned.add(url)
                print(f"\n{SEPARATOR}")
                print(f"{YELLOW}[*]被动捕获: {url}{RESET}")
                try:
                    from cli.runner import run_mode
                    run_mode("p", url, args)
                except Exception as e:
                    print(f"{RED}[!]扫描异常 ({url}): {e}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*]被动扫描已停止，共扫描 {len(scanned)} 个目标{RESET}")
    finally:
        proxy.stop()
