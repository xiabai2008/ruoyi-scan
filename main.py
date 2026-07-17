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
from core.fingerprint import detect_cms
from core.router import Router
from core.report import ReportBuilder, BatchReport


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
    parser.add_argument('-u', metavar='target', nargs='?', const='__flag__',
                        default=None, help='综合扫描')
    parser.add_argument('-m', metavar='target', nargs='?', const='__flag__',
                        default=None, help='目录扫描')
    parser.add_argument('-p', metavar='target', nargs='?', const='__flag__',
                        default=None, help='漏洞检测')
    parser.add_argument('-l', metavar='target', nargs='?', const='__flag__',
                        default=None, help='登录爆破')
    parser.add_argument('-f', metavar='file', dest='file', default=None,
                        help='批量扫描：从文件读取目标列表，每行一个 URL')
    # 新增长参数（不破坏旧短参数语义）
    parser.add_argument('--proxy', default=None, help='代理地址（如 http://127.0.0.1:8080）')
    parser.add_argument('--threads', type=int, default=settings.THREADS, help='并发线程数')
    parser.add_argument('--rate', type=int, default=settings.RATE, help='每秒请求数（0 不限速）')
    parser.add_argument('--report', default=None, help='报告输出目录')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='调试模式：打印每个请求的方法/URL/状态/响应字节到 stderr')
    return parser


def print_help():
    """打印帮助（对齐原 -h 输出）"""
    print(SEPARATOR)
    print('-u : 综合扫描')
    print('-m : 目录扫描')
    print('-p : 漏洞检测')
    print('-l : 登录爆破')
    print('-f : 批量扫描（从文件读取目标列表）')
    print(SEPARATOR)
    print('可选长参数：')
    print('  --proxy <url>      代理（如 http://127.0.0.1:8080）')
    print('  --threads <n>      并发线程数（默认 1 同步顺序执行）')
    print('  --rate <n>         每秒请求数（0 不限速）')
    print('  --report <dir>      报告输出目录（生成 HTML/JSON/CSV）')
    print('  --debug            调试模式（请求日志输出到 stderr）')
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
    session = SessionManager(proxy=args.proxy, debug=args.debug)
    engine = ScanEngine(threads=args.threads, rate=args.rate)

    # 计时起点（用于报告摘要）
    started_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    t0 = time.time()

    # 指纹识别 → 路由 → 插件包（开发方案 §三 Step 3 主流程链路；阶段二多 CMS 自动识别）
    fp_result = detect_cms(target, session)
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


def run_mode_batch(filepath, mode, args):
    """批量扫描：从文件读目标，逐目标扫描并生成单报告 + 批量汇总报告

    Args:
        filepath: 目标列表文件路径（每行一个 URL）
        mode: 扫描模式 'u'/'m'/'p'/'l'（单模式应用到所有目标）
        args: 命令行参数
    """
    import os as _os

    if not _os.path.isfile(filepath):
        print(f'{RED}[!]目标文件不存在：{filepath}{RESET}')
        return

    label, color = MODE_LABELS[mode]
    print(f'{YELLOW}[*]批量扫描模式：[{color}{label}{YELLOW}]{RESET}')
    print(f'{YELLOW}[*]目标文件：{filepath}{RESET}')

    # 读取目标（去空白行 + 去前后空白）
    with open(filepath, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f if line.strip()]
    if not targets:
        print(f'{RED}[!]目标文件为空{RESET}')
        return
    print(f'{YELLOW}[*]共 {len(targets)} 个目标待扫描{RESET}')

    batch = BatchReport()
    out_dir = args.report or settings.REPORT_DIR

    for i, target in enumerate(targets, 1):
        print(f'\n{SEPARATOR}')
        print(f'{YELLOW}[*]进度 [{i}/{len(targets)}] 目标：{target}{RESET}')
        try:
            results = run_mode(mode, target, args)
        except Exception as e:
            print(f'{RED}[!]扫描异常 ({target})：{e}{RESET}')
            continue

        # 构建单目标报告
        t0 = time.time()  # 用 run_mode 内部的计时，但这里用 0 表示(已在 run_mode 中计时)
        started_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 重新获取 session 信息（run_mode 已 close，这里从结果反推）
        builder = ReportBuilder(results=results, target=target,
                                summary={
                                    'started_at': started_at,
                                    'duration': 0,  # 在 run_mode 内部已由各自计时确定
                                    'request_count': len(results),
                                    'mode': label,
                                    'fingerprint': {'cms': '', 'confidence': 0},
                                })
        batch.add(builder)

    # 输出批量汇总报告
    if batch.builders:
        bpaths = batch.render_all(out_dir)
        print(SEPARATOR)
        print(f'{YELLOW}[*]批量汇总：{batch.total_targets} 个目标 共 {batch.total_confirmed()} 个确认漏洞{RESET}')
        for p in bpaths:
            print(f'{GREEN}[*]批量报告：{p}{RESET}')

    return batch


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
    has_mode = any([args.u, args.m, args.p, args.l, args.file])
    if args.help is not None or not has_mode:
        print_help()
        return

    # 检查哪种模式被指定（值为 __flag__ 表示 flag 模式/批量，否则为 target URL）
    def _mode_flag(val):
        return val is not None and val != '__flag__'

    target_for = {}
    flag_for = {}
    for k in ('u', 'm', 'p', 'l'):
        val = getattr(args, k, None)
        if val is not None:
            if val == '__flag__':
                flag_for[k] = True
            else:
                target_for[k] = val

    # -f 批量扫描：从文件读目标，配合 -u/-m/-p/-l flag 指定模式
    if args.file:
        mode = None
        for k in ('u', 'm', 'p', 'l'):
            if k in flag_for:
                mode = k
                break
        if not mode:
            print(f'{RED}[!]-f 批量扫描需配合 -u/-m/-p/-l 指定扫描模式，如：main.py -f targets.txt -p{RESET}')
            return
        run_mode_batch(args.file, mode, args)
    elif target_for:
        for k in ('u', 'm', 'p', 'l'):
            if k in target_for:
                run_mode(k, target_for[k], args)
                break

    final_prompt()


if __name__ == '__main__':
    main()
