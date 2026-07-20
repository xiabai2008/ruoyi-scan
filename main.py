# Ruoyi-Scan CLI 入口（-h/-u/-m/-p/-l 向后兼容 + 新长参数）
"""Ruoyi-Scan — 若依专项漏洞扫描工具 CLI 入口

P0 重构：main.py 仅保留 CLI 参数解析与模式分发，业务编排逻辑全部迁移至 core/runner.py。
"""

import argparse

from config import settings
from core.runner import (
    final_prompt,
    run_chain_mode,
    run_ci_init_mode,
    run_diff_only_mode,
    run_mode,
    run_mode_batch,
    run_passive_mode,
    run_plugin_check_mode,
    run_plugin_init_mode,
    run_plugin_list_mode,
    run_serve_mode,
    run_template_list_mode,
    run_wiki_mode,
)
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW


def print_banner():
    """打印 banner（沿用现有 ASCII Art + 绿(art)/黄(信息) 配色）"""
    print(f"""{GREEN}
  ____                            _     ____
 |  _ \\   _   _    ___    _   _  (_)   / ___|    ___    __ _   _ __
 | |_) | | | | |  / _ \\  | | | | | |   \\___ \\   / __|  / _` | | '_ \\
 |  _ <  | |_| | | (_) | | |_| | | |    ___) | | (__  | (_| | | | | |
 |_| \\_\\  \\__,_|  \\___/   \\__, | |_|   |____/   \\___|  \\__,_| |_| |_|
                          |___/

---Ruoyi-Scan&Version:{settings.VERSION}{YELLOW}
[*]By.{settings.AUTHOR}
[*]一款用于针对Ruoyi系统框架的综合漏洞扫描工具
[*]Github:{settings.GITHUB}
[*]联系方式:{settings.CONTACT}{RESET}""")


def build_parser():
    """构建参数解析（-h/-u/-m/-p/-l 向后兼容，新增能力用长参数）"""
    parser = argparse.ArgumentParser(add_help=False)
    # 核心短参数（向后兼容）
    parser.add_argument("-h", dest="help", nargs="?", const="flag", default=None, help="帮助")
    parser.add_argument("-u", metavar="target", nargs="?", const="__flag__", default=None, help="综合扫描")
    parser.add_argument("-m", metavar="target", nargs="?", const="__flag__", default=None, help="目录扫描")
    parser.add_argument("-p", metavar="target", nargs="?", const="__flag__", default=None, help="漏洞检测")
    parser.add_argument("-l", metavar="target", nargs="?", const="__flag__", default=None, help="登录爆破")
    parser.add_argument("-f", metavar="file", dest="file", default=None, help="批量扫描：从文件读取目标列表")
    # 通用参数
    parser.add_argument("--proxy", default=None, help="代理地址（如 http://127.0.0.1:8080）")
    parser.add_argument("--proxy-file", default=None, help="代理池文件")
    parser.add_argument(
        "--proxy-rotate", choices=["round-robin", "random", "least-fail"], default="round-robin", help="代理轮换策略"
    )
    parser.add_argument("--threads", type=int, default=settings.THREADS, help="并发线程数")
    parser.add_argument("--rate", type=int, default=settings.RATE, help="每秒请求数（0 不限速）")
    parser.add_argument("--report", default=None, help="报告输出目录")
    parser.add_argument("--debug", action="store_true", default=False, help="调试模式")
    parser.add_argument(
        "--timeout", type=int, default=settings.TIMEOUT, help=f"请求超时秒数（默认 {settings.TIMEOUT}s）"
    )
    parser.add_argument("--cms", default=None, choices=["ruoyi", "spring"], help="手动指定 CMS")
    parser.add_argument("--pass-level", default="full", choices=["top100", "top1000", "full"], help="口令字典级别")
    # 扫描模式
    parser.add_argument("--portscan", action="store_true", default=False, help="端口扫描")
    parser.add_argument("--ports", default=None, help="自定义端口（逗号分隔）")
    parser.add_argument("--passive", action="store_true", default=False, help="被动代理模式")
    parser.add_argument("--passive-host", default="127.0.0.1", help="代理监听地址")
    parser.add_argument("--passive-port", type=int, default=8080, help="代理监听端口")
    # 报告
    parser.add_argument("--report-format", default="all", help="报告格式 html/json/csv/pdf/docx/xlsx/sarif")
    parser.add_argument("--no-dedup", action="store_true", default=False, help="关闭结果去重")
    # D6 利用链
    parser.add_argument("--chain", default=None, metavar="NAME", help="执行漏洞利用链")
    parser.add_argument("--chain-list", action="store_true", default=False, help="列出可用链")
    # D7 WAF
    parser.add_argument("--bypass-waf", choices=["auto", "on", "off"], default="auto", help="WAF 绕过策略")
    # D9 Web API
    parser.add_argument("--serve", action="store_true", default=False, help="启动 Web API 服务")
    parser.add_argument("--host", default="0.0.0.0", help="API 监听地址")
    parser.add_argument("--port", type=int, default=8000, help="API 监听端口")
    # D11 API 鉴权
    parser.add_argument("--api-key", default=None, help="API Key 鉴权")
    parser.add_argument("--cors-origins", default=None, help="CORS 源（逗号分隔）")
    parser.add_argument("--db-path", default=None, help="SQLite 数据库路径")
    # D14 信息收集
    parser.add_argument("--crawl", action="store_true", default=False, help="主动爬虫")
    parser.add_argument("--crawl-depth", type=int, default=2, help="爬虫深度")
    parser.add_argument("--crawl-max-pages", type=int, default=50, help="爬虫最大页面数")
    parser.add_argument("--subdomain", action="store_true", default=False, help="子域名枚举")
    parser.add_argument("--js-extract", action="store_true", default=False, help="JS 端点提取")
    # D19 扫描模板
    parser.add_argument("--template", default=None, choices=["quick", "deep", "compliance", "dengbao"], help="扫描模板")
    parser.add_argument("--template-list", action="store_true", default=False, help="列出模板")
    # D27 YAML 配置
    parser.add_argument("--config", default=None, metavar="PATH", help="YAML 配置文件")
    # D20 差异对比
    parser.add_argument("--diff", default=None, metavar="OLD_REPORT", help="与历史报告对比")
    parser.add_argument("--diff-only", nargs=2, metavar=("OLD", "NEW"), help="仅对比两个 JSON 报告")
    parser.add_argument("--save-baseline", action="store_true", default=False, help="保存基线")
    # D21 通知
    parser.add_argument("--notify", action="append", default=None, metavar="TYPE=TARGET", help="扫描完成通知")
    # D26 认证
    parser.add_argument("--auth", action="append", default=None, metavar="TYPE=VALUE", help="认证信息注入")
    parser.add_argument("--auth-file", default=None, metavar="PATH", help="从文件加载认证")
    parser.add_argument("--auth-login", default=None, metavar="USER:PASS", help="自动登录")
    # D23 国际化
    parser.add_argument("--lang", default="zh", choices=["zh", "en"], help="报告语言")
    # D25 插件 SDK
    parser.add_argument("--plugin-init", default=None, metavar="NAME", help="生成插件模板")
    parser.add_argument("--plugin-check", default=None, metavar="PATH", help="验证插件")
    parser.add_argument("--plugin-list", action="store_true", default=False, help="列出插件")
    parser.add_argument("--category", default="common", choices=["ruoyi", "spring", "common"], help="插件类别")
    # D28 CI/CD
    parser.add_argument("--ci", action="store_true", default=False, help="CI 模式")
    parser.add_argument("--severity-threshold", default="high", choices=["low", "medium", "high"], help="CI 阈值")
    parser.add_argument(
        "--ci-init", default=None, metavar="PLATFORM", choices=["github", "gitlab", "jenkins"], help="生成 CI 配置"
    )
    # D29 知识库
    parser.add_argument("--wiki", action="store_true", default=False, help="生成漏洞知识库")
    parser.add_argument("--wiki-output", default=None, metavar="PATH", help="知识库输出路径")
    # D30 OAST
    parser.add_argument("--oast", action="store_true", default=False, help="OAST 带外检测")
    parser.add_argument("--oast-server", action="store_true", default=False, help="OAST 回调服务器")
    parser.add_argument("--oast-host", default="127.0.0.1", help="OAST 监听地址")
    parser.add_argument("--oast-port", type=int, default=5555, help="OAST 监听端口")
    # D31 业务逻辑
    parser.add_argument("--logic-scan", action="store_true", default=False, help="业务逻辑漏洞检测")
    parser.add_argument("--logic-endpoints", default=None, metavar="FILE", help="端点列表文件")
    parser.add_argument("--logic-concurrency", type=int, default=10, help="竞争条件并发数")
    # D32 CVE
    parser.add_argument("--cve-sync", action="store_true", default=False, help="同步 NVD CVE")
    parser.add_argument("--cve-id", default=None, metavar="CVE-ID", help="查询 CVE 信息")
    parser.add_argument("--nvd-api-key", default=None, help="NVD API Key")
    # D33 SIEM
    parser.add_argument("--siem-export", default=None, metavar="FORMAT", help="SIEM 格式导出")
    parser.add_argument("--siem-output", default=None, metavar="PATH", help="SIEM 输出路径")
    parser.add_argument("--siem-syslog", default=None, metavar="HOST[:PORT]", help="Syslog 服务器")
    parser.add_argument("--siem-protocol", default="udp", choices=["udp", "tcp"], help="Syslog 协议")
    # D34 异步
    parser.add_argument("--async", dest="async_mode", action="store_true", default=False, help="异步引擎")
    parser.add_argument("--async-workers", type=int, default=10, help="异步线程数")
    # D35 Web UI
    parser.add_argument("--web-ui", action="store_true", default=False, help="生成 Web UI")
    parser.add_argument("--web-ui-output", default=None, metavar="PATH", help="Web UI 输出路径")
    parser.add_argument("--web-ui-api", default=None, metavar="URL", help="Web UI API 地址")
    # D36 分布式
    parser.add_argument(
        "--distributed", default=None, metavar="MODE", choices=["master", "worker", "standalone"], help="分布式模式"
    )
    parser.add_argument("--redis-url", default="redis://127.0.0.1:6379", help="Redis URL")
    parser.add_argument("--distributed-rate", type=int, default=0, help="P3: 分布式全局限速（每秒请求数，0 不限速）")
    parser.add_argument("--worker-max-tasks", type=int, default=0, help="Worker 最大任务数")
    parser.add_argument("--distributed-timeout", type=int, default=600, help="分布式超时")
    # D37 缓存
    parser.add_argument("--cache", action="store_true", default=False, help="启用缓存")
    parser.add_argument("--cache-ttl", type=int, default=3600, help="缓存 TTL")
    parser.add_argument("--cache-db", default="data/scan_cache.db", help="缓存数据库路径")
    parser.add_argument("--cache-stats", action="store_true", default=False, help="缓存统计")
    parser.add_argument("--cache-clear", action="store_true", default=False, help="清除过期缓存")
    parser.add_argument("--cache-clear-all", action="store_true", default=False, help="清除全部缓存")
    return parser


def print_help():
    """打印帮助（对齐原 -h 输出）"""
    print(SEPARATOR)
    print("-u : 综合扫描")
    print("-m : 目录扫描")
    print("-p : 漏洞检测")
    print("-l : 登录爆破")
    print("-f : 批量扫描（从文件读取目标列表）")
    print(SEPARATOR)
    print("可选长参数：")
    long_params = [
        ("--proxy <url>", "代理（如 http://127.0.0.1:8080）"),
        ("--proxy-file <f>", "代理池文件（每行一个代理 URL）"),
        ("--proxy-rotate <s>", "代理轮换策略 round-robin/random/least-fail"),
        ("--threads <n>", "并发线程数（默认 1 同步顺序执行）"),
        ("--rate <n>", "每秒请求数（0 不限速）"),
        ("--report <dir>", "报告输出目录（生成 HTML/JSON/CSV）"),
        ("--debug", "调试模式（请求日志输出到 stderr）"),
        ("--timeout <n>", "请求超时秒数（默认 10s）"),
        ("--cms <cms>", "手动指定 CMS（跳过指纹识别）"),
        ("--pass-level <lvl>", "口令字典级别 top100/top1000/full"),
        ("--portscan", "扫描前执行端口扫描 + 服务识别"),
        ("--ports <p1,p2>", "自定义端口列表（逗号分隔）"),
        ("--passive", "启动被动代理模式（监听 HTTP/HTTPS 流量）"),
        ("--passive-host", "代理监听地址（默认 127.0.0.1）"),
        ("--passive-port", "代理监听端口（默认 8080）"),
        ("--report-format <f>", "报告格式 html/json/csv/pdf/docx/xlsx/sarif"),
        ("--no-dedup", "关闭结果去重聚合"),
        ("--chain <name>", "执行漏洞利用链"),
        ("--chain-list", "列出所有可用的漏洞利用链"),
        ("--bypass-waf <m>", "WAF 绕过策略：auto/on/off（默认 auto）"),
        ("--serve", "启动 Web API 服务（FastAPI + WebSocket + Web 控制台）"),
        ("--host <addr>", "API 服务监听地址（默认 0.0.0.0）"),
        ("--port <n>", "API 服务监听端口（默认 8000）"),
        ("--api-key <key>", "API Key 鉴权"),
        ("--cors-origins <o>", "允许的 CORS 源（逗号分隔）"),
        ("--db-path <path>", "SQLite 数据库路径"),
        ("--crawl", "启用主动爬虫"),
        ("--crawl-depth <n>", "爬虫最大深度（默认 2）"),
        ("--crawl-max-pages <n>", "爬虫最大页面数（默认 50）"),
        ("--subdomain", "启用被动子域名枚举"),
        ("--js-extract", "启用 JS 端点提取"),
        ("--template <name>", "扫描模板：quick/deep/compliance/dengbao"),
        ("--template-list", "列出所有可用的扫描模板"),
        ("--config <path>", "YAML 配置文件"),
        ("--diff <old.json>", "与历史扫描报告对比"),
        ("--diff-only <old> <new>", "仅对比两个 JSON 报告"),
        ("--save-baseline", "保存本次扫描结果为基线"),
        ("--notify <type=target>", "扫描完成通知"),
        ("--auth <type=value>", "认证注入"),
        ("--auth-file <path>", "从文件加载认证信息"),
        ("--auth-login <user:pass>", "自动登录获取认证"),
        ("--lang <zh|en>", "报告语言（默认 zh）"),
        ("--plugin-init <name>", "生成插件模板"),
        ("--plugin-check <path>", "验证插件文件完整性"),
        ("--plugin-list", "列出所有已加载插件"),
        ("--ci", "CI 模式"),
        ("--severity-threshold <level>", "CI 失败阈值（默认 high）"),
        ("--ci-init <platform>", "生成 CI 配置（github/gitlab/jenkins）"),
        ("--wiki", "生成漏洞知识库"),
        ("--wiki-output <path>", "知识库输出路径"),
        ("--oast", "启用 OAST 带外检测"),
        ("--oast-server", "启动 OAST 回调服务器"),
        ("--oast-host <addr>", "OAST 服务器监听地址"),
        ("--oast-port <n>", "OAST 服务器监听端口"),
        ("--logic-scan", "业务逻辑漏洞检测"),
        ("--logic-endpoints <file>", "业务扫描端点列表文件"),
        ("--logic-concurrency <n>", "竞争条件检测并发数"),
        ("--cve-sync", "同步 NVD CVE 信息"),
        ("--cve-id <CVE-ID>", "查询单个 CVE 信息"),
        ("--nvd-api-key <key>", "NVD API Key"),
        ("--siem-export <fmt>", "导出 SIEM 格式"),
        ("--siem-output <path>", "SIEM 导出路径"),
        ("--siem-syslog <host:port>", "发送到 Syslog 服务器"),
        ("--siem-protocol <p>", "Syslog 协议 udp/tcp"),
        ("--async", "启用异步扫描引擎"),
        ("--async-workers <n>", "异步并发线程数"),
        ("--web-ui", "生成 Web UI 控制台"),
        ("--web-ui-output <path>", "Web UI 输出路径"),
        ("--web-ui-api <url>", "Web UI 连接的 API 地址"),
        ("--distributed <mode>", "分布式模式（master/worker/standalone）"),
        ("--redis-url <url>", "Redis 连接 URL"),
        ("--worker-max-tasks <n>", "Worker 最大任务数"),
        ("--cache", "启用扫描结果缓存"),
        ("--cache-ttl <n>", "缓存有效期秒数"),
        ("--cache-db <path>", "缓存数据库路径"),
        ("--cache-stats", "查看缓存统计"),
        ("--cache-clear", "清除过期缓存"),
        ("--cache-clear-all", "清除全部缓存"),
    ]
    for param, desc in long_params:
        print(f"  {param:<28} {desc}")
    print(SEPARATOR)


# ── 主入口 ──
def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    print_banner()

    # D27：加载 YAML 配置文件
    config_data = {}
    if getattr(args, "config", None):
        from lib.config_loader import apply_config_to_args, load_yaml_config, normalize_config_keys

        try:
            config_data = load_yaml_config(args.config)
            config_data = normalize_config_keys(config_data)
            args, _overridden = apply_config_to_args(args, args.config, verbose=True)
        except FileNotFoundError as e:
            print(f"{RED}[!]{e}{RESET}")
            return
        except ValueError as e:
            print(f"{RED}[!]配置文件解析失败: {e}{RESET}")
            return
        cli_has_mode = any([args.u, args.m, args.p, args.l])
        if not cli_has_mode:
            cfg_mode = config_data.get("mode", "u")
            cfg_target = config_data.get("target", config_data.get("u", ""))
            if cfg_target and cfg_target != "__flag__":
                if cfg_mode in ("u", "m", "p", "l"):
                    setattr(args, cfg_mode, cfg_target)
                else:
                    args.u = cfg_target

    # D19：应用扫描模板
    if getattr(args, "template", None):
        from lib.scan_templates import apply_template

        print(f"{YELLOW}[*]应用扫描模板: {args.template}{RESET}")
        apply_template(args, args.template, verbose=True)

    # 检查是否有任何模式被指定
    has_mode = any(
        [
            args.u,
            args.m,
            args.p,
            args.l,
            args.file,
            args.passive,
            args.chain,
            args.chain_list,
            args.serve,
            args.template_list,
            args.diff_only,
            args.plugin_init,
            args.plugin_check,
            args.plugin_list,
            args.ci_init,
            args.wiki,
            args.oast_server,
            args.cve_sync,
            args.cve_id,
            args.web_ui,
            args.distributed,
            args.cache_stats,
            args.cache_clear,
        ]
    )
    if args.help is not None or not has_mode:
        print_help()
        return

    # ── 纯工具模式（不涉及扫描）──
    if args.diff_only:
        run_diff_only_mode(args.diff_only[0], args.diff_only[1])
        return
    if args.template_list:
        run_template_list_mode()
        return
    if args.plugin_init:
        run_plugin_init_mode(args)
        return
    if args.plugin_check:
        run_plugin_check_mode(args)
        return
    if args.plugin_list:
        run_plugin_list_mode()
        return
    if args.ci_init:
        run_ci_init_mode(args)
        return
    if args.wiki:
        run_wiki_mode(args)
        return
    if args.oast_server:
        from lib.oast import run_oast_mode

        run_oast_mode(args)
        return
    if args.cve_sync or args.cve_id:
        from lib.cve_sync import run_cve_sync_mode

        run_cve_sync_mode(args)
        return
    if args.web_ui:
        from lib.web_ui import run_web_ui_mode

        run_web_ui_mode(args)
        return
    if args.cache_stats:
        from lib.cache import run_cache_stats_mode

        run_cache_stats_mode(args)
        return
    if args.cache_clear:
        from lib.cache import run_cache_clear_mode

        run_cache_clear_mode(args)
        return

    # ── 服务/链/代理模式（独立进程）──
    if args.serve:
        run_serve_mode(args)
        return
    if args.chain_list or (args.chain == "list"):
        run_chain_mode("list", args)
        return
    if args.chain:
        run_chain_mode(args.chain, args)
        return
    if args.passive:
        run_passive_mode(args)
        return

    # ── 标准扫描模式 ──
    def _mode_flag(val):
        return val is not None and val != "__flag__"

    target_for = {}
    flag_for = {}
    for k in ("u", "m", "p", "l"):
        val = getattr(args, k, None)
        if val is not None:
            if val == "__flag__":
                flag_for[k] = True
            else:
                target_for[k] = val

    if args.file:
        mode = None
        for k in ("u", "m", "p", "l"):
            if k in flag_for:
                mode = k
                break
        if not mode:
            print(f"{RED}[!]-f 批量扫描需配合 -u/-m/-p/-l 指定扫描模式，如：main.py -f targets.txt -p{RESET}")
            return
        run_mode_batch(args.file, mode, args)
    elif target_for:
        for k in ("u", "m", "p", "l"):
            if k in target_for:
                run_mode(k, target_for[k], args)
                break

    final_prompt()


if __name__ == "__main__":
    main()
