# Ruoyi-Scan CLI 入口（-h/-u/-m/-p/-l 向后兼容 + 新长参数）
import argparse
import sys

from lib.colors import GREEN, RED, YELLOW, RESET, SEPARATOR
from config import settings


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


def run_mode(mode, target, args):
    """分发到各扫描模式（Step 2 起接入指纹→路由→插件链路）"""
    if mode == 'u':
        # 综合扫描高亮沿用红色（对齐原脚本）
        print(f'{YELLOW}[*]当前扫描模式:[{RED}综合扫描{YELLOW}]{RESET}')
    else:
        labels = {'m': '目录扫描', 'p': '漏洞扫描', 'l': '登录爆破'}
        print(f'{YELLOW}[*]当前扫描模式:[{GREEN}{labels[mode]}{YELLOW}]{RESET}')
    print(SEPARATOR)
    # Step 2 起接入插件链路
    print(f'{YELLOW}[*]骨架就绪：插件能力将在 Step 2 迁移接入（target={target}）{RESET}')


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
