# Ruoyi-Scan CLI 入口（-h/-u/-m/-p/-l 向后兼容 + 新长参数）
import argparse
import datetime
import sys
import time

from lib.colors import GREEN, RED, YELLOW, RESET, SEPARATOR
from lib.http import normalize_target
from config import settings
from core.session import SessionManager
from core.engine import ScanEngine
from core.loader import load_plugins
from core.fingerprint import RuoyiFingerprint
from core.router import Router
from core.report import ReportBuilder


def print_banner():
    """打印 banner（沿用现有 ASCII Art + 绿(art)/黄(信息) 配色）"""
    print(f'''{GREEN}
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
[*]联系方式:{settings.CONTACT}{RESET}''')


def build_parser():
    """构建参数解析（-h/-u/-m/-p/-l 向后兼容，新增能力用长参数）"""
    parser = argparse.ArgumentParser(add_help=False)
    # -h 兼容原 `python Ruoyi-Scan.py -h` 及 `-h <target>`（target 被忽略，仅显示帮助）
    parser.add_argument('-h', dest='help', nargs='?', const='flag', default=None, help='帮助')
    parser.add_argument('-u', metavar='target', help='综合扫描')
    parser.add_argument('-m', metavar='target', help='目录扫描')
    parser.add_argument('-p', metavar='target', help='漏洞检测')
    parser.add_argument('-l', metavar='target', help='登录爆破')
    # 新增长参数（不破坏旧短参数语义）
    parser.add_argument('--proxy', default=None, help='代理地址（如 http://127.0.0.1:8080）')
    parser.add_argument('--threads', type=int, default=settings.THREADS, help='并发线程数')
    parser.add_argument('--rate', type=int, default=settings.RATE, help='每秒请求数（0 不限速）')
    parser.add_argument('--report', default=None, help='报告输出目录')
    return parser


def print_help():
    """打印帮助（对齐原 -h 输出）"""
    print(SEPARATOR)
    print('-u : 综合扫描')
    print('-m : 目录扫描')
    print('-p : 漏洞检测')
    print('-l : 登录爆破')
    print(SEPARATOR)


# 模式 → 需要执行的插件 category 顺序（对齐原脚本 -u 综合扫描：path_scan → poc_scan → web_login）
MODE_CATEGORIES = {
    'u': ['recon', 'vuln', 'brute'],
    'm': ['recon'],
    'p': ['vuln'],
    'l': ['brute'],
}

# 模式中文标签（综合扫描高亮红色，其余绿色，对齐原脚本）
MODE_LABELS = {
    'u': ('综合扫描', RED),
    'm': ('目录扫描', GREEN),
    'p': ('漏洞扫描', GREEN),
    'l': ('登录爆破', GREEN),
}


def run_mode(mode, target, args):
    """分发到各扫描模式：指纹→路由→插件 主流程，按 category 分组执行，每组开头打印 SEPARATOR"""
    label, color = MODE_LABELS[mode]
    print(f'{YELLOW}[*]当前扫描模式:[{color}{label}{YELLOW}]{RESET}')

    # 目标归一化（确保以 / 结尾，对齐原 self.url += '/'）
    target = normalize_target(target)

    # 会话与引擎
    session = SessionManager(proxy=args.proxy)
    engine = ScanEngine(threads=args.threads, rate=args.rate)

    # 计时起点（用于报告摘要）
    started_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    t0 = time.time()

    # 指纹识别 → 路由 → 插件包（开发方案 §三 Step 3 主流程链路）
    fp = RuoyiFingerprint()
    fp_result = fp.detect(target, session)
    if fp_result.cms:
        print(f'{YELLOW}[*]指纹识别：cms={fp_result.cms} 置信度={fp_result.confidence:.2f} '
              f'命中={fp_result.matched}{RESET}')
    else:
        print(f'{YELLOW}[*]指纹识别：未识别到已知 CMS 特征{RESET}')

    # 路由到插件包
    router = Router()
    all_plugins = router.resolve(fp_result)
    if not all_plugins:
        # 阶段一回退：本工具为若依专用，未识别时默认走 ruoyi 插件包
        print(f'{YELLOW}[*]未匹配插件包，回退默认 ruoyi 插件包（阶段一兼容）{RESET}')
        all_plugins = load_plugins('plugins.ruoyi')

    # 按 category 分组
    plugins_by_cat = {}
    for cls in all_plugins:
        cat = getattr(cls, 'category', '')
        plugins_by_cat.setdefault(cat, []).append(cls)

    all_results = []
    for cat in MODE_CATEGORIES[mode]:
        print(SEPARATOR)
        classes = plugins_by_cat.get(cat, [])
        if not classes:
            continue
        results = engine.run(classes, target, session)
        all_results.extend(results)

    duration = time.time() - t0
    session.close()

    # 报告生成（--report 指定目录时输出 HTML/JSON/CSV 三格式）
    if args.report:
        summary = {
            'started_at': started_at,
            'duration': duration,
            'request_count': session.request_count,
            'mode': label,
            'fingerprint': {
                'cms': fp_result.cms,
                'confidence': fp_result.confidence,
                'matched': fp_result.matched,
            },
        }
        builder = ReportBuilder(results=all_results, target=target, summary=summary)
        paths = builder.render_all(args.report)
        dist = builder.risk_distribution()
        print(SEPARATOR)
        print(f'{YELLOW}[*]扫描摘要：耗时 {duration:.2f}s 请求数 {session.request_count} '
              f'风险分布 高{dist["high"]}/中{dist["medium"]}/低{dist["low"]} '
              f'合计 {dist["total"]} 个漏洞{RESET}')
        for p in paths:
            print(f'{GREEN}[*]报告已生成：{p}{RESET}')

    return all_results


def final_prompt():
    """结尾交互（保留原 input 习惯；非 tty 时自动跳过，便于自动化验收）"""
    if not sys.stdin.isatty():
        return
    try:
        input('[*]工作完毕,感谢你的使用,回车退出.../')
    except EOFError:
        pass


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    print_banner()

    # -h 或无任何模式参数：显示帮助并退出
    if args.help is not None or not any([args.u, args.m, args.p, args.l]):
        print_help()
        return

    if args.u:
        run_mode('u', args.u, args)
    elif args.m:
        run_mode('m', args.m, args)
    elif args.p:
        run_mode('p', args.p, args)
    elif args.l:
        run_mode('l', args.l, args)

    final_prompt()


if __name__ == '__main__':
    main()
