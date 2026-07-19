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
from core.fingerprint import detect_cms, detect_waf
from core.router import Router
from core.report import ReportBuilder, BatchReport
from core.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
from core.models import FingerprintResult


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
    # D13 代理池：从文件加载多代理轮换
    parser.add_argument('--proxy-file', default=None,
                        help='代理池文件（每行一个代理 URL，# 注释；与 --proxy 互斥）')
    parser.add_argument('--proxy-rotate', choices=['round-robin', 'random', 'least-fail'],
                        default='round-robin',
                        help='代理轮换策略（round-robin/random/least-fail，默认 round-robin）')
    parser.add_argument('--threads', type=int, default=settings.THREADS, help='并发线程数')
    parser.add_argument('--rate', type=int, default=settings.RATE, help='每秒请求数（0 不限速）')
    parser.add_argument('--report', default=None, help='报告输出目录')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='调试模式：打印每个请求的方法/URL/状态/响应字节到 stderr')
    parser.add_argument('--timeout', type=int, default=settings.TIMEOUT,
                        help=f'请求超时秒数（默认 {settings.TIMEOUT}s）')
    parser.add_argument('--cms', default=None, choices=['ruoyi','spring'],
                        help='手动指定 CMS 跳过指纹识别（ruoyi/spring）')
    parser.add_argument('--pass-level', default='full', choices=['top100','top1000','full'],
                        help='口令字典级别（top100/top1000/full，默认 full）')
    parser.add_argument('--portscan', action='store_true', default=False,
                        help='扫描前执行端口扫描 + 服务识别')
    parser.add_argument('--ports', default=None,
                        help='自定义扫描端口（逗号分隔，如 80,443,8080）')
    parser.add_argument('--passive', action='store_true', default=False,
                        help='启动被动代理模式（监听 HTTP/HTTPS 流量）')
    parser.add_argument('--passive-host', default='127.0.0.1',
                        help='被动代理监听地址（默认 127.0.0.1）')
    parser.add_argument('--passive-port', type=int, default=8080,
                        help='被动代理监听端口（默认 8080）')
    # D8 报告增强：报告格式 + 去重开关
    parser.add_argument('--report-format', default='all',
                        help='报告格式：html/json/csv/pdf/docx/xlsx，逗号分隔；all=全部 6 种（默认 all，未装依赖自动降级）')
    parser.add_argument('--no-dedup', action='store_true', default=False,
                        help='关闭结果去重聚合（默认开启，合并同指纹漏洞）')
    # D6 漏洞利用链编排：--chain <name> 触发链执行
    parser.add_argument('--chain', default=None, metavar='NAME',
                        help='执行漏洞利用链（如 ruoyi_sql_to_rce）；--chain list 列出可用链')
    parser.add_argument('--chain-list', action='store_true', default=False,
                        help='列出所有可用的漏洞利用链')
    # D7 WAF 绕过：--bypass-waf 启用自动绕过
    parser.add_argument('--bypass-waf', choices=['auto', 'on', 'off'], default='auto',
                        help='WAF 绕过策略：auto=检测到 WAF 才启用（默认）/on=强制启用/off=禁用')
    # D9 Web API：--serve 启动 HTTP API 服务
    parser.add_argument('--serve', action='store_true', default=False,
                        help='启动 Web API 服务（FastAPI + WebSocket + Web 控制台）')
    parser.add_argument('--host', default='0.0.0.0',
                        help='API 服务监听地址（默认 0.0.0.0）')
    parser.add_argument('--port', type=int, default=8000,
                        help='API 服务监听端口（默认 8000）')
    # D11 API 鉴权 + CORS 收紧
    parser.add_argument('--api-key', default=None,
                        help='API Key 鉴权（未设置则仅允许 127.0.0.1 访问；也可通过环境变量 RUOYI_SCAN_API_KEY 设置）')
    parser.add_argument('--cors-origins', default=None,
                        help='允许的 CORS 源（逗号分隔，如 https://example.com,http://localhost:3000）')
    parser.add_argument('--db-path', default=None,
                        help='SQLite 数据库路径（默认 data/tasks.db，存任务历史与事件）')
    # D14 主动信息收集：爬虫 + 子域名 + JS 端点提取
    parser.add_argument('--crawl', action='store_true', default=False,
                        help='启用主动爬虫（BFS 抓取目标站点页面，发现更多扫描入口）')
    parser.add_argument('--crawl-depth', type=int, default=2,
                        help='爬虫最大深度（默认 2，1=仅起始页）')
    parser.add_argument('--crawl-max-pages', type=int, default=50,
                        help='爬虫最大页面数（默认 50，防止失控）')
    parser.add_argument('--subdomain', action='store_true', default=False,
                        help='启用被动子域名枚举（crt.sh 证书透明日志 + 字典）')
    parser.add_argument('--js-extract', action='store_true', default=False,
                        help='启用 JS 端点提取（从抓取到的 JS 文件提取 API 端点）')
    # D19 扫描模板：--template <name> 选择预设策略
    parser.add_argument('--template', default=None,
                        choices=['quick', 'deep', 'compliance', 'dengbao'],
                        help='扫描模板：quick=快速/deep=深度/compliance=OWASP合规/dengbao=等保合规')
    parser.add_argument('--template-list', action='store_true', default=False,
                        help='列出所有可用的扫描模板')
    # D27 YAML 配置文件：--config <path> 加载预设参数
    parser.add_argument('--config', default=None, metavar='PATH',
                        help='YAML 配置文件路径（预设扫描参数，CLI 参数优先级更高）')
    # D20 增量扫描与差异对比
    parser.add_argument('--diff', default=None, metavar='OLD_REPORT',
                        help='与历史扫描报告对比（JSON 文件路径），输出新增/修复/未变漏洞差异报告')
    parser.add_argument('--diff-only', nargs=2, metavar=('OLD', 'NEW'),
                        help='仅对比两个 JSON 报告（不执行扫描），输出差异报告')
    parser.add_argument('--save-baseline', action='store_true', default=False,
                        help='保存本次扫描结果为基线（用于后续 --diff 对比）')
    # D21 告警通知
    parser.add_argument('--notify', action='append', default=None, metavar='TYPE=TARGET',
                        help='扫描完成后发送通知（可多次指定）：webhook=<url> / dingtalk=<url> / wechat=<url> / feishu=<url> / email=<addr>')
    # D22 SARIF 报告格式（集成到 --report-format）
    # SARIF 格式在 _parse_report_formats 中处理，无需单独参数
    # D26 认证扫描增强
    parser.add_argument('--auth', action='append', default=None, metavar='TYPE=VALUE',
                        help='认证信息注入（可多次指定）：cookie=<string> / bearer=<token> / header=<name:value> / basic=<user:pass>')
    parser.add_argument('--auth-file', default=None, metavar='PATH',
                        help='从文件加载认证信息（Cookie/Token）')
    parser.add_argument('--auth-login', default=None, metavar='USER:PASS',
                        help='自动登录获取认证信息（用户名:密码）')
    # D23 国际化
    parser.add_argument('--lang', default='zh', choices=['zh', 'en'],
                        help='报告语言：zh=中文（默认）/en=英文')
    # D25 插件 SDK
    parser.add_argument('--plugin-init', default=None, metavar='NAME',
                        help='生成插件模板（如 --plugin-init my_plugin --category common）')
    parser.add_argument('--plugin-check', default=None, metavar='PATH',
                        help='验证插件文件完整性（检查必需字段和方法）')
    parser.add_argument('--plugin-list', action='store_true', default=False,
                        help='列出所有已加载插件的元数据')
    parser.add_argument('--category', default='common', choices=['ruoyi', 'spring', 'common'],
                        help='插件类别（--plugin-init 时指定）')
    # D28 CI/CD 集成
    parser.add_argument('--ci', action='store_true', default=False,
                        help='CI 模式（发现高危漏洞时退出码 1，适合流水线）')
    parser.add_argument('--severity-threshold', default='high', choices=['low', 'medium', 'high'],
                        help='CI 模式严重度阈值（达到此级别则 CI 失败，默认 high）')
    parser.add_argument('--ci-init', default=None, metavar='PLATFORM',
                        choices=['github', 'gitlab', 'jenkins'],
                        help='生成 CI 配置文件（github/gitlab/jenkins）')
    # D29 漏洞知识库
    parser.add_argument('--wiki', action='store_true', default=False,
                        help='生成漏洞知识库（离线 HTML Wiki）')
    parser.add_argument('--wiki-output', default=None, metavar='PATH',
                        help='知识库输出路径（默认 vuln_wiki.html）')
    # D30 OAST 带外检测
    parser.add_argument('--oast', action='store_true', default=False,
                        help='启用 OAST 带外检测（无回显漏洞验证）')
    parser.add_argument('--oast-server', action='store_true', default=False,
                        help='启动 OAST 回调服务器模式（独立运行）')
    parser.add_argument('--oast-host', default='127.0.0.1',
                        help='OAST 回调服务器监听地址（默认 127.0.0.1）')
    parser.add_argument('--oast-port', type=int, default=5555,
                        help='OAST 回调服务器监听端口（默认 5555）')
    # D31 业务逻辑漏洞检测
    parser.add_argument('--logic-scan', action='store_true', default=False,
                        help='启用业务逻辑漏洞检测（IDOR/越权/参数篡改/竞争条件）')
    parser.add_argument('--logic-endpoints', default=None, metavar='FILE',
                        help='业务逻辑扫描端点列表文件（每行一个 URL）')
    parser.add_argument('--logic-concurrency', type=int, default=10,
                        help='竞争条件检测并发数（默认 10）')
    # D32 CVE/NVD 自动同步
    parser.add_argument('--cve-sync', action='store_true', default=False,
                        help='同步 NVD CVE 信息到插件库')
    parser.add_argument('--cve-id', default=None, metavar='CVE-ID',
                        help='查询单个 CVE 信息（如 --cve-id CVE-2024-1234）')
    parser.add_argument('--nvd-api-key', default=None,
                        help='NVD API Key（可选，提升速率限制）')
    # D33 SIEM 集成
    parser.add_argument('--siem-export', default=None, metavar='FORMAT',
                        help='导出 SIEM 格式（ecs/cef/leef/json，逗号分隔）')
    parser.add_argument('--siem-output', default=None, metavar='PATH',
                        help='SIEM 导出文件路径或目录（默认 reports/siem/）')
    parser.add_argument('--siem-syslog', default=None, metavar='HOST[:PORT]',
                        help='发送到 Syslog 服务器（如 10.0.0.1:514）')
    parser.add_argument('--siem-protocol', default='udp', choices=['udp', 'tcp'],
                        help='Syslog 协议（udp/tcp，默认 udp）')
    # D34 异步扫描引擎
    parser.add_argument('--async', dest='async_mode', action='store_true', default=False,
                        help='启用异步扫描引擎（ThreadPoolExecutor 并发）')
    parser.add_argument('--async-workers', type=int, default=10,
                        help='异步扫描并发线程数（默认 10）')
    # D35 Web UI 控制台
    parser.add_argument('--web-ui', action='store_true', default=False,
                        help='生成 Web UI 控制台 HTML 文件')
    parser.add_argument('--web-ui-output', default=None, metavar='PATH',
                        help='Web UI 输出路径（默认 webui/index.html）')
    parser.add_argument('--web-ui-api', default=None, metavar='URL',
                        help='Web UI 连接的 API 地址（留空则使用相对路径）')
    # D36 分布式任务队列
    parser.add_argument('--distributed', default=None, metavar='MODE',
                        choices=['master', 'worker', 'standalone'],
                        help='分布式模式：master=分发任务/worker=执行扫描/standalone=本机多线程')
    parser.add_argument('--redis-url', default='redis://127.0.0.1:6379',
                        help='Redis 连接 URL（分布式模式）')
    parser.add_argument('--worker-max-tasks', type=int, default=0,
                        help='Worker 最大处理任务数（0=无限）')
    parser.add_argument('--distributed-timeout', type=int, default=600,
                        help='Master 等待结果超时秒数（默认 600）')
    # D37 结果缓存
    parser.add_argument('--cache', action='store_true', default=False,
                        help='启用扫描结果缓存（避免重复扫描）')
    parser.add_argument('--cache-ttl', type=int, default=3600,
                        help='缓存有效期秒数（默认 3600）')
    parser.add_argument('--cache-db', default='data/scan_cache.db',
                        help='缓存数据库路径（默认 data/scan_cache.db）')
    parser.add_argument('--cache-stats', action='store_true', default=False,
                        help='查看缓存统计')
    parser.add_argument('--cache-clear', action='store_true', default=False,
                        help='清除过期缓存（配合 --cache-clear-all 清除全部）')
    parser.add_argument('--cache-clear-all', action='store_true', default=False,
                        help='清除全部缓存')
    # 注：--nuclei-dir / --nuclei-autoload 已随 plugins/nuclei 迁移至 cms-scan-extras/
    return parser


def _parse_report_formats(fmt_str):
    """解析 --report-format 参数为 render_all 可接受的 formats 值

    'all' → 'all'（render_all 内部展开为 6 种）
    'html,json,csv' → ['html', 'json', 'csv']
    'pdf' → ['pdf']
    无效格式会被过滤掉（仅打印警告，不报错）
    """
    if not fmt_str:
        return None
    fmt_str = fmt_str.strip().lower()
    if fmt_str == 'all':
        return 'all'
    valid = {'html', 'json', 'csv', 'pdf', 'docx', 'xlsx', 'sarif'}
    parts = [f.strip() for f in fmt_str.split(',') if f.strip()]
    # 过滤无效格式
    invalid = [p for p in parts if p not in valid]
    if invalid:
        print(f'{YELLOW}[!]未知报告格式: {invalid}（支持: {sorted(valid)}）{RESET}')
    parts = [p for p in parts if p in valid]
    return parts or None


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
    print('  --proxy-file <f>   代理池文件（每行一个代理 URL，与 --proxy 互斥）')
    print('  --proxy-rotate <s> 代理轮换策略 round-robin/random/least-fail（默认 round-robin）')
    print('  --threads <n>      并发线程数（默认 1 同步顺序执行）')
    print('  --rate <n>         每秒请求数（0 不限速）')
    print('  --report <dir>      报告输出目录（生成 HTML/JSON/CSV）')
    print('  --debug            调试模式（请求日志输出到 stderr）')
    print('  --timeout <n>      请求超时秒数（默认 10s）')
    print('  --cms <cms>        手动指定 CMS（跳过指纹识别）')
    print('  --pass-level <lvl> 口令字典级别 top100/top1000/full')
    print('  --portscan         扫描前执行端口扫描 + 服务识别')
    print('  --ports <p1,p2>    自定义端口列表（逗号分隔）')
    print('  --passive          启动被动代理模式（监听 HTTP/HTTPS 流量）')
    print('  --passive-host     代理监听地址（默认 127.0.0.1）')
    print('  --passive-port     代理监听端口（默认 8080）')
    print('  --report-format <f> 报告格式 html/json/csv/pdf/docx/xlsx/sarif，逗号分隔；all=全部（默认 all）')
    print('  --no-dedup         关闭结果去重聚合（默认开启，合并同指纹漏洞）')
    print('  --chain <name>     执行漏洞利用链（如 ruoyi_sql_to_rce）；--chain list 列出可用链')
    print('  --chain-list       列出所有可用的漏洞利用链')
    print('  --bypass-waf <m>   WAF 绕过策略：auto=检测到才启用（默认）/on=强制/off=禁用')
    print('  --serve            启动 Web API 服务（FastAPI + WebSocket + Web 控制台）')
    print('  --host <addr>      API 服务监听地址（默认 0.0.0.0）')
    print('  --port <n>         API 服务监听端口（默认 8000）')
    print('  --api-key <key>    API Key 鉴权（未设置则仅允许 127.0.0.1 访问）')
    print('  --cors-origins <o> 允许的 CORS 源（逗号分隔）')
    print('  --db-path <path>   SQLite 数据库路径（默认 data/tasks.db）')
    print('  --crawl            启用主动爬虫（BFS 抓取目标站点页面）')
    print('  --crawl-depth <n>  爬虫最大深度（默认 2，1=仅起始页）')
    print('  --crawl-max-pages <n> 爬虫最大页面数（默认 50）')
    print('  --subdomain        启用被动子域名枚举（crt.sh + 字典）')
    print('  --js-extract       启用 JS 端点提取（从 JS 文件提取 API 端点）')
    print('  --template <name>  扫描模板：quick/deep/compliance/dengbao')
    print('  --template-list    列出所有可用的扫描模板')
    print('  --config <path>    YAML 配置文件（预设扫描参数，CLI 参数优先）')
    print('  --diff <old.json>  与历史扫描报告对比，输出差异报告')
    print('  --diff-only <old> <new>  仅对比两个 JSON 报告（不执行扫描）')
    print('  --save-baseline    保存本次扫描结果为基线（用于后续 --diff 对比）')
    print('  --notify <type=target>  扫描完成通知（webhook/dingtalk/wechat/feishu/email，可多次指定）')
    print('  --auth <type=value>  认证注入（cookie/bearer/header/basic，可多次指定）')
    print('  --auth-file <path> 从文件加载认证信息')
    print('  --auth-login <user:pass>  自动登录获取认证信息')
    print('  --lang <zh|en>     报告语言：zh=中文（默认）/en=英文')
    print('  --plugin-init <name>  生成插件模板（配合 --category）')
    print('  --plugin-check <path>  验证插件文件完整性')
    print('  --plugin-list      列出所有已加载插件的元数据')
    print('  --ci               CI 模式（发现高危漏洞时退出码 1）')
    print('  --severity-threshold <level>  CI 失败阈值（low/medium/high，默认 high）')
    print('  --ci-init <platform>  生成 CI 配置（github/gitlab/jenkins）')
    print('  --wiki             生成漏洞知识库（离线 HTML Wiki）')
    print('  --wiki-output <path>  知识库输出路径')
    print('  --oast             启用 OAST 带外检测（无回显漏洞验证）')
    print('  --oast-server      启动 OAST 回调服务器（独立模式）')
    print('  --oast-host <addr> OAST 服务器监听地址（默认 127.0.0.1）')
    print('  --oast-port <n>    OAST 服务器监听端口（默认 5555）')
    print('  --logic-scan       业务逻辑漏洞检测（IDOR/越权/参数篡改/竞争条件）')
    print('  --logic-endpoints <file>  业务扫描端点列表文件')
    print('  --logic-concurrency <n>  竞争条件检测并发数（默认 10）')
    print('  --cve-sync         同步 NVD CVE 信息到插件库')
    print('  --cve-id <CVE-ID>  查询单个 CVE 信息')
    print('  --nvd-api-key <key>  NVD API Key（可选）')
    print('  --siem-export <fmt>  导出 SIEM 格式（ecs/cef/leef/json）')
    print('  --siem-output <path>  SIEM 导出路径（默认 reports/siem/）')
    print('  --siem-syslog <host:port>  发送到 Syslog 服务器')
    print('  --siem-protocol <p>  Syslog 协议 udp/tcp（默认 udp）')
    print('  --async            启用异步扫描引擎（并发线程池）')
    print('  --async-workers <n>  异步并发线程数（默认 10）')
    print('  --web-ui           生成 Web UI 控制台 HTML 文件')
    print('  --web-ui-output <path>  Web UI 输出路径')
    print('  --web-ui-api <url> Web UI 连接的 API 地址')
    print('  --distributed <mode>  分布式模式（master/worker/standalone）')
    print('  --redis-url <url>  Redis 连接 URL（分布式模式）')
    print('  --worker-max-tasks <n>  Worker 最大任务数（0=无限）')
    print('  --cache            启用扫描结果缓存')
    print('  --cache-ttl <n>    缓存有效期秒数（默认 3600）')
    print('  --cache-db <path>  缓存数据库路径')
    print('  --cache-stats      查看缓存统计')
    print('  --cache-clear      清除过期缓存')
    print('  --cache-clear-all  清除全部缓存')
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


def _print_scan_result(res):
    """实时输出扫描结果（作为 engine.run 的 on_result 回调）

    配色语义遵循 agents.md §3.1：
    - CONFIRMED → 绿色 [*]（命中/成功）
    - SAFE → 红色 [/]（未命中）
    - UNKNOWN → 黄色 [?]（无法判定）
    """
    if res.status == STATUS_CONFIRMED:
        print(f'{GREEN}[*]存在{res.name}{RESET}')
    elif res.status == STATUS_SAFE:
        print(f'{RED}[/]不存在{res.name}{RESET}')
    else:
        print(f'{YELLOW}[?]无法判定{res.name}: {res.evidence}{RESET}')


def run_mode(mode, target, args):
    """分发到各扫描模式：指纹→路由→插件 主流程，按 category 分组执行，每组开头打印 SEPARATOR"""
    label, color = MODE_LABELS[mode]
    print(f'{YELLOW}[*]当前扫描模式:[{color}{label}{YELLOW}]{RESET}')

    # 口令字典分级（P1-B）：按 --pass-level 切换字典文件
    if args.pass_level != 'full' and args.pass_level in settings.PASSWORD_DICT_BY_LEVEL:
        settings.PASSWORD_DICT = settings.PASSWORD_DICT_BY_LEVEL[args.pass_level]
        print(f'{YELLOW}[*]口令字典级别: {args.pass_level}{RESET}')

    # 目标归一化（确保以 / 结尾，对齐原 self.url += '/'）
    target = normalize_target(target)

    # 端口扫描（P2-A）：--portscan 开启，在指纹识别之前执行
    if args.portscan:
        from core.portscan import PortScanner, DEFAULT_PORTS
        host = host_of(target)
        ports = DEFAULT_PORTS
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]
        scanner = PortScanner(timeout=args.timeout, threads=args.threads)
        print(f'{YELLOW}[*]端口扫描：{host} ({len(ports)} 个端口)...{RESET}')
        port_results = scanner.scan(host, ports)
        open_count = len(port_results)
        print(f'{YELLOW}[*]端口扫描完成：开放 {open_count}/{len(ports)}{RESET}')
        for pr in port_results:
            detail = f'{pr.port}/tcp {pr.service}'
            if pr.banner:
                detail += f' — {pr.banner[:80]}'
            print(f'{GREEN}  [*] {detail}{RESET}')

    # D14：主动信息收集（爬虫 + 子域名 + JS 端点提取）
    if getattr(args, 'crawl', False) or getattr(args, 'subdomain', False) \
            or getattr(args, 'js_extract', False):
        from lib.crawler import Crawler
        from lib.subdomain import SubdomainEnumerator
        from lib.js_extractor import JSExtractor

        # 子域名枚举（独立于爬虫）
        if args.subdomain:
            host = host_of(target)
            if host:
                print(f'{YELLOW}[*]子域名枚举：{host}（crt.sh + 字典）...{RESET}')
                enum = SubdomainEnumerator(verify_dns=False)
                subs = enum.enumerate(host, session=None)
                print(f'{YELLOW}[*]子域名枚举完成：发现 {len(subs)} 个（含主域）{RESET}')
                for s in subs[:20]:  # 只打印前 20 个，避免刷屏
                    print(f'{GREEN}  [*] {s}{RESET}')
                if len(subs) > 20:
                    print(f'{YELLOW}  ...（共 {len(subs)} 个，已省略 {len(subs) - 20} 个）{RESET}')

        # 主动爬虫 + JS 端点提取
        if args.crawl or args.js_extract:
            print(f'{YELLOW}[*]主动爬虫：target={target} depth={args.crawl_depth} '
                  f'max_pages={args.crawl_max_pages}...{RESET}')
            recon_session = SessionManager(proxy=args.proxy, debug=args.debug,
                                           timeout=args.timeout)
            crawler = Crawler(
                max_depth=args.crawl_depth,
                max_pages=args.crawl_max_pages,
                same_host_only=True,
                include_static=False,
            )
            crawl_result = crawler.crawl_with_js_urls(target, recon_session)
            pages = crawl_result['pages']
            js_urls = crawl_result['js']
            all_crawled = crawl_result['all']
            print(f'{YELLOW}[*]爬虫完成：抓取 {len(pages)} 个页面，{len(js_urls)} 个 JS 文件{RESET}')
            for u in pages[:10]:
                print(f'{GREEN}  [*] {u}{RESET}')
            if len(pages) > 10:
                print(f'{YELLOW}  ...（共 {len(pages)} 个页面，已省略 {len(pages) - 10} 个）{RESET}')

            # JS 端点提取
            if args.js_extract and js_urls:
                print(f'{YELLOW}[*]JS 端点提取：{len(js_urls)} 个 JS 文件...{RESET}')
                extractor = JSExtractor()
                endpoints = extractor.extract_from_urls(js_urls, session=recon_session)
                endpoint_urls = []
                seen = set()
                for ep in endpoints:
                    if ep.url not in seen:
                        seen.add(ep.url)
                        endpoint_urls.append(ep.url)
                print(f'{YELLOW}[*]JS 端点提取完成：发现 {len(endpoint_urls)} 个端点{RESET}')
                for u in endpoint_urls[:20]:
                    print(f'{GREEN}  [*] {u}{RESET}')
                if len(endpoint_urls) > 20:
                    print(f'{YELLOW}  ...（共 {len(endpoint_urls)} 个端点，已省略 {len(endpoint_urls) - 20} 个）{RESET}')

            recon_session.close()

    # 会话与引擎
    session = SessionManager(proxy=args.proxy, debug=args.debug, timeout=args.timeout)
    engine = ScanEngine(threads=args.threads, rate=args.rate)

    # D26：认证扫描增强（Cookie/Token/Bearer 注入）
    auth_config = None
    if getattr(args, 'auth', None) or getattr(args, 'auth_file', None) or getattr(args, 'auth_login', None):
        from lib.auth_scan import parse_auth_arg, load_auth_file, auto_login, apply_auth_to_session, parse_login_arg
        auth_config = {'cookies': {}, 'headers': {}, 'type': None}
        if args.auth:
            parsed = parse_auth_arg(args.auth)
            auth_config['cookies'].update(parsed['cookies'])
            auth_config['headers'].update(parsed['headers'])
            if parsed['type']:
                auth_config['type'] = parsed['type']
        if args.auth_file:
            try:
                file_config = load_auth_file(args.auth_file)
                auth_config['cookies'].update(file_config['cookies'])
                auth_config['headers'].update(file_config['headers'])
                if file_config['type']:
                    auth_config['type'] = file_config['type']
                print(f'{YELLOW}[*]已加载认证文件: {args.auth_file}{RESET}')
            except FileNotFoundError as e:
                print(f'{RED}[!]{e}{RESET}')
        if args.auth_login:
            try:
                username, password = parse_login_arg(args.auth_login)
                login_config = auto_login(target, username, password, verbose=True)
                if login_config['cookies'] or login_config['headers']:
                    auth_config['cookies'].update(login_config['cookies'])
                    auth_config['headers'].update(login_config['headers'])
                    if login_config['type']:
                        auth_config['type'] = login_config['type']
            except ValueError as e:
                print(f'{RED}[!]{e}{RESET}')
        # 应用认证信息到 session
        if auth_config['cookies'] or auth_config['headers']:
            apply_auth_to_session(session, auth_config)
            auth_summary = []
            if auth_config['cookies']:
                auth_summary.append(f'{len(auth_config["cookies"])} 个 Cookie')
            if auth_config['headers']:
                auth_summary.append(f'{len(auth_config["headers"])} 个自定义头')
            print(f'{YELLOW}[*]认证扫描: {" + ".join(auth_summary)} 已注入{RESET}')

    # 计时起点（用于报告摘要）
    started_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    t0 = time.time()

    # 指纹识别 → 路由 → 插件包（--cms 手动指定时跳过指纹识别）
    router = Router()
    if args.cms:
        print(f'{YELLOW}[*]手动指定 CMS: {args.cms}（跳过指纹识别）{RESET}')
        fp_result = FingerprintResult(cms=args.cms, version='', confidence=1.0, matched=['manual'])
        all_plugins = router.resolve_by_name(args.cms)
    else:
        fp_result = detect_cms(target, session)
        if fp_result.cms:
            print(f'{YELLOW}[*]指纹识别：cms={fp_result.cms} 置信度={fp_result.confidence:.2f} '
                  f'命中={fp_result.matched}{RESET}')
        else:
            print(f'{YELLOW}[*]指纹识别：未识别到已知 CMS 特征{RESET}')
        all_plugins = router.resolve(fp_result)

    # WAF 探测（P1-C）：检测目标是否部署了 WAF
    waf_result = detect_waf(target, session)
    waf_bypass_coordinator = None  # D7: WAF 绕过协调器
    if waf_result['waf']:
        print(f'{RED}[!]检测到 WAF: {waf_result["display"]} — {waf_result["bypass_hint"]}{RESET}')
        # D7: 根据 --bypass-waf 参数决定是否启用绕过
        bypass_mode = getattr(args, 'bypass_waf', 'auto')
        if bypass_mode in ('auto', 'on'):
            from lib.waf_bypass import WafBypassCoordinator, BypassStatsTracker
            from lib.origin_finder import OriginIPFinder
            # D7.4: 策略成功率追踪器（动态调整策略优先级）
            stats_tracker = BypassStatsTracker()
            # 预探测源站 IP（L4 策略需要）
            origin_ip = ''
            try:
                from urllib.parse import urlparse
                domain = urlparse(target).hostname or ''
                if domain:
                    finder = OriginIPFinder(timeout=5)
                    ips = finder.find_origin_ip(domain, session)
                    if ips:
                        origin_ip = ips[0]
                        print(f'{YELLOW}[*]源站 IP 探测: {origin_ip}{RESET}')
            except Exception:
                pass
            waf_bypass_coordinator = WafBypassCoordinator(
                waf_type=waf_result['waf'], origin_ip=origin_ip,
                stats_tracker=stats_tracker)
            print(f'{YELLOW}[*]WAF 绕过已启用（{bypass_mode} 模式）{RESET}')
    else:
        print(f'{YELLOW}[*]未检测到已知 WAF 特征{RESET}')
        # D7: --bypass-waf=on 时即使无 WAF 也启用（强制模式）
        if getattr(args, 'bypass_waf', 'auto') == 'on':
            from lib.waf_bypass import WafBypassCoordinator, BypassStatsTracker
            stats_tracker = BypassStatsTracker()
            waf_bypass_coordinator = WafBypassCoordinator(
                waf_type='', stats_tracker=stats_tracker)
            print(f'{YELLOW}[*]WAF 绕过强制启用（on 模式，未检测到 WAF）{RESET}')
    if not all_plugins:
        print(f'{YELLOW}[*]未匹配插件包，回退默认 ruoyi 插件包（阶段一兼容）{RESET}')
        all_plugins = load_plugins('plugins.ruoyi')

    # 通用漏洞检测包始终加载（不依赖 CMS 指纹，与 CMS 插件并行执行）
    try:
        common_plugins = load_plugins('plugins.common')
        all_plugins = all_plugins + common_plugins
        print(f'{YELLOW}[*]通用漏洞检测：已加载 {len(common_plugins)} 个通用插件{RESET}')
    except Exception:
        pass

    # 注：Nuclei 模板加载已随 plugins/nuclei 迁移至 cms-scan-extras/

    # D19：扫描模板过滤插件
    template_obj = None
    if getattr(args, 'template', None):
        from lib.scan_templates import get_template, filter_plugins
        template_obj = get_template(args.template)
        if template_obj:
            before_count = len(all_plugins)
            all_plugins = filter_plugins(all_plugins, template_obj)
            after_count = len(all_plugins)
            print(f'{YELLOW}[*]模板过滤: {template_obj.display_name} '
                  f'({before_count} → {after_count} 个插件){RESET}')

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
        results = engine.run(classes, target, session, on_result=_print_scan_result,
                             waf_bypass_coordinator=waf_bypass_coordinator)
        all_results.extend(results)

    duration = time.time() - t0
    session.close()

    # 报告生成（--report 指定目录时输出 HTML/JSON/CSV 三格式）
    if args.report:
        # D19：模板报告标签覆盖
        report_label = label
        if template_obj and template_obj.report_label:
            report_label = template_obj.report_label
        summary = {
            'started_at': started_at,
            'duration': duration,
            'request_count': session.request_count,
            'mode': report_label,
            'fingerprint': {
                'cms': fp_result.cms,
                'confidence': fp_result.confidence,
                'matched': fp_result.matched,
            },
        }
        builder = ReportBuilder(results=all_results, target=target, summary=summary,
                                dedup=not args.no_dedup)
        paths = builder.render_all(args.report, formats=_parse_report_formats(args.report_format))
        dist = builder.risk_distribution()
        print(SEPARATOR)
        print(f'{YELLOW}[*]扫描摘要：耗时 {duration:.2f}s 请求数 {session.request_count} '
              f'风险分布 高{dist["high"]}/中{dist["medium"]}/低{dist["low"]} '
              f'合计 {dist["total"]} 个漏洞{RESET}')
        # 去重统计输出
        dr = builder.dedup_report()
        if dr and not args.no_dedup and dr.merged_groups > 0:
            print(f'{YELLOW}[*]去重统计：原始 {dr.original_count} 条 → 聚合后 {dr.aggregated_count} 条'
                  f'（{dr.merged_groups} 组合并）{RESET}')
        for p in paths:
            print(f'{GREEN}[*]报告已生成：{p}{RESET}')

        # D20：保存基线 / 差异对比
        report_json_path = os.path.join(args.report, 'report.json')
        if getattr(args, 'save_baseline', False):
            from lib.diff_scan import save_baseline
            baseline_path = os.path.join(args.report, 'baseline.json')
            save_baseline(builder.to_dict(), baseline_path)
            print(f'{GREEN}[*]基线已保存：{baseline_path}{RESET}')
        if getattr(args, 'diff', None):
            from lib.diff_scan import diff_reports, load_report, render_diff_report
            try:
                old_report = load_report(args.diff)
                diff = diff_reports(old_report, builder.to_dict())
                print(f'{SEPARATOR}')
                print(f'{YELLOW}[*]差异对比结果（vs {args.diff}）{RESET}')
                print(f'    {GREEN}🆕 新增: {diff.total_new} 个{RESET}')
                print(f'    {GREEN}✅ 已修复: {diff.total_fixed} 个{RESET}')
                print(f'    {YELLOW}⚠️ 状态变化: {diff.total_changed} 个{RESET}')
                print(f'    {YELLOW}⏳ 未变: {diff.total_persisted} 个{RESET}')
                diff_paths = render_diff_report(diff, os.path.join(args.report, 'diff'))
                for dp in diff_paths:
                    print(f'{GREEN}[*]差异报告：{dp}{RESET}')
            except FileNotFoundError as e:
                print(f'{RED}[!]差异对比失败: {e}{RESET}')
            except Exception as e:
                print(f'{RED}[!]差异对比异常: {e}{RESET}')

        # D21：告警通知
        if getattr(args, 'notify', None):
            from lib.notifier import parse_notify_arg, send_notifications
            notifications = parse_notify_arg(args.notify)
            if notifications:
                send_notifications(notifications, builder, verbose=True)

    # D31：业务逻辑漏洞扫描（在主扫描完成后追加）
    if getattr(args, 'logic_scan', False):
        from lib.logic_scan import LogicScanner, parse_endpoints_from_urls
        print(f'{YELLOW}[*]业务逻辑漏洞扫描...{RESET}')
        # 从文件加载端点列表
        endpoints = []
        if getattr(args, 'logic_endpoints', None):
            import os as _os
            if _os.path.isfile(args.logic_endpoints):
                with open(args.logic_endpoints, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
                endpoints = parse_endpoints_from_urls(urls)
        # 创建已认证 session（复用主扫描的认证信息）
        from core.session import SessionManager
        logic_session = SessionManager(proxy=args.proxy, debug=args.debug,
                                        timeout=args.timeout)
        # 注入认证信息（如有）
        if getattr(args, '_auth_headers', None):
            for k, v in args._auth_headers.items():
                logic_session.session.headers[k] = v
        scanner = LogicScanner(session=logic_session)
        logic_vulns = scanner.scan(target, endpoints)
        # 转换 LogicVuln → ScanResult 并追加到结果
        from core.models import ScanResult
        for lv in logic_vulns:
            all_results.append(ScanResult(
                kind='vuln', name=lv.name, severity=lv.severity,
                status=STATUS_CONFIRMED, url=lv.url, evidence=lv.evidence,
                fix=lv.fix, fix_detail=lv.fix_detail, reproduce=lv.reproduce,
            ))
        print(f'{YELLOW}[*]业务逻辑扫描完成：发现 {len(logic_vulns)} 个漏洞{RESET}')
        logic_session.close()

    # D33：SIEM 导出（在报告生成后）
    if getattr(args, 'siem_export', None):
        from lib.siem_export import run_siem_export_mode
        started_at = summary.get('started_at', '') if summary else ''
        run_siem_export_mode(args, all_results, target, started_at)

    # D28：CI 模式退出码
    if getattr(args, 'ci', False):
        from lib.ci_runner import run_ci_mode
        exit_code = run_ci_mode(args, all_results, target, duration, has_error=False)
        if exit_code != 0:
            import sys
            sys.exit(exit_code)

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
                                },
                                dedup=not args.no_dedup)
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


def run_chain_mode(chain_name, args):
    """漏洞利用链执行模式（D6）：按链定义编排多插件，端到端攻击链

    用法：
        python main.py --chain ruoyi_sql_to_rce -u http://target/
        python main.py --chain list  # 列出可用链
        python main.py --chain-list  # 同上

    Args:
        chain_name: 链名称，或 'list' 列出可用链
        args: 命令行参数（需包含 -u <target> 指定目标）
    """
    from chains.registry import list_chains, get_chain
    from core.chain import ChainEngine

    # --chain list 或 --chain-list：列出可用链
    if chain_name == 'list' or getattr(args, 'chain_list', False):
        print(f'{SEPARATOR}')
        print(f'{YELLOW}[*]可用漏洞利用链{RESET}')
        print(f'{SEPARATOR}')
        for c in list_chains():
            print(f'{GREEN}  {c["name"]}{RESET}')
            print(f'    名称：{c["display_name"]}')
            print(f'    描述：{c["description"]}')
            print(f'    严重度：{c["severity"]}')
            print()
        return

    # 获取目标 URL（复用 -u 参数）
    target = args.u
    if not target or target == '__flag__':
        print(f'{RED}[!]--chain 需配合 -u <target> 指定目标，如：main.py --chain ruoyi_sql_to_rce -u http://target/{RESET}')
        return

    # 查找链定义
    chain_def = get_chain(chain_name)
    if chain_def is None:
        print(f'{RED}[!]未找到链: {chain_name}（用 --chain list 查看可用链）{RESET}')
        return

    print(f'{YELLOW}[*]执行漏洞利用链: {chain_def.display_name}{RESET}')
    print(f'{YELLOW}[*]链描述: {chain_def.description}{RESET}')
    print(f'{YELLOW}[*]影响版本: {chain_def.affected_versions or "全版本"}{RESET}')
    print(f'{SEPARATOR}')

    # 校验链定义
    errors = chain_def.validate()
    if errors:
        print(f'{RED}[!]链定义校验失败:{RESET}')
        for e in errors:
            print(f'{RED}  - {e}{RESET}')
        return

    # 会话与指纹
    target = normalize_target(target)
    session = SessionManager(proxy=args.proxy, debug=args.debug, timeout=args.timeout)

    # 指纹识别（链可能依赖 CMS 信息）
    if args.cms:
        fp_result = FingerprintResult(cms=args.cms, version='', confidence=1.0, matched=['manual'])
        print(f'{YELLOW}[*]手动指定 CMS: {args.cms}（跳过指纹识别）{RESET}')
    else:
        fp_result = detect_cms(target, session)
        if fp_result.cms:
            print(f'{YELLOW}[*]指纹识别：cms={fp_result.cms} 置信度={fp_result.confidence:.2f}{RESET}')
        else:
            print(f'{YELLOW}[*]指纹识别：未识别到已知 CMS{RESET}')

    # 执行链
    engine = ChainEngine()
    started_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    t0 = time.time()

    def _on_result(res):
        """节点结果实时输出"""
        if res.status == STATUS_CONFIRMED:
            print(f'{GREEN}[*]节点成功: {res.name}{RESET}')
        elif res.status == STATUS_SAFE:
            print(f'{RED}[/]节点失败: {res.name}{RESET}')
        else:
            print(f'{YELLOW}[?]节点未知: {res.name} - {res.evidence}{RESET}')

    chain_result = engine.run(chain_def, target, session, fp_result, on_result=_on_result)
    duration = time.time() - t0
    session.close()

    # 输出链执行结果
    print(f'{SEPARATOR}')
    status_color = GREEN if chain_result.status == 'CONFIRMED' else (YELLOW if chain_result.status == 'UNKNOWN' else RED)
    print(f'{YELLOW}[*]链执行状态: {status_color}{chain_result.status}{YELLOW}{RESET}')
    print(f'{YELLOW}[*]耗时: {duration:.2f}s{RESET}')

    # 节点状态明细
    for step_id, status in chain_result.node_status.items():
        color = GREEN if status == 'success' else (YELLOW if status == 'skipped' else RED)
        print(f'  {color}{step_id}: {status}{RESET}')

    # facts 输出（非敏感）
    if chain_result.facts:
        print(f'{YELLOW}[*]提取事实:{RESET}')
        for k, v in chain_result.facts.items():
            print(f'  {k} = {v}')

    # 转为 ScanResult 并生成报告
    chain_scan_result = chain_result.to_scan_result(chain_def)
    all_results = [chain_scan_result]

    if args.report:
        summary = {
            'started_at': started_at,
            'duration': duration,
            'request_count': session.request_count,
            'mode': f'链执行: {chain_def.display_name}',
            'fingerprint': {
                'cms': fp_result.cms,
                'confidence': fp_result.confidence,
                'matched': fp_result.matched,
            },
        }
        builder = ReportBuilder(results=all_results, target=target, summary=summary,
                                dedup=not args.no_dedup)
        paths = builder.render_all(args.report, formats=_parse_report_formats(args.report_format))
        print(f'{SEPARATOR}')
        for p in paths:
            print(f'{GREEN}[*]报告已生成：{p}{RESET}')


def run_serve_mode(args):
    """Web API 服务模式（D9 + D11）：启动 FastAPI + WebSocket + Web 控制台

    用法：
        python main.py --serve                                    # 仅本地访问
        python main.py --serve --host 0.0.0.0 --api-key <key>     # 开放远程 + 鉴权
        python main.py --serve --host 127.0.0.1 --port 9000

    启动后可访问：
        http://host:port/         Web 控制台（Alpine.js 单页）
        http://host:port/docs     OpenAPI 交互文档
        http://host:port/api/*    REST API 端点（需 X-API-Key 头）
        ws://host:port/ws/scan/{task_id}  WebSocket 实时事件
    """
    print(f'{YELLOW}[*]启动 Web API 服务模式（D9 + D11）{RESET}')
    print(f'{YELLOW}[*]监听地址: {args.host}:{args.port}{RESET}')
    print(f'{YELLOW}[*]API 文档: http://{args.host}:{args.port}/docs{RESET}')
    print(f'{YELLOW}[*]Web 控制台: http://{args.host}:{args.port}/{RESET}')
    # D11 鉴权提示
    api_key = args.api_key or ''
    if not api_key:
        import os
        api_key = os.environ.get('RUOYI_SCAN_API_KEY', '')
    if api_key:
        print(f'{GREEN}[*]API 鉴权: 已启用（X-API-Key 头）{RESET}')
    else:
        print(f'{YELLOW}[*]API 鉴权: 未设置 API Key，仅允许 127.0.0.1 访问{RESET}')
    # D11 持久化提示
    db_path = args.db_path or 'data/tasks.db'
    print(f'{YELLOW}[*]任务持久化: {db_path}{RESET}')
    print(f'{SEPARATOR}')

    try:
        import uvicorn
        from api.app import create_app
        # D11：解析 CORS 源
        cors_origins = None
        if args.cors_origins:
            cors_origins = [o.strip() for o in args.cors_origins.split(',') if o.strip()]
        app = create_app(
            api_key=api_key,
            cors_origins=cors_origins,
            db_path=args.db_path or '',
        )
        uvicorn.run(app, host=args.host, port=args.port, log_level='info')
    except ImportError as e:
        print(f'{RED}[!]启动 API 服务需要 fastapi + uvicorn，请安装：pip install fastapi uvicorn[standard]{RESET}')
        print(f'{RED}[!]缺失模块: {e}{RESET}')


def run_passive_mode(args):
    """被动代理模式（P2-B）：启动 HTTP/HTTPS 代理，捕获流量 URL 自动扫描

    工作流程：
    1. 启动代理服务器监听指定地址/端口
    2. 每 5 秒从队列取出新捕获的 URL
    3. 对每个 URL 执行 -p 漏洞检测（自动指纹识别 + 插件扫描）
    4. Ctrl+C 停止
    """
    from core.proxy_server import ProxyServer, ScanQueue

    queue = ScanQueue()
    host = args.passive_host
    port = args.passive_port
    proxy = ProxyServer(host=host, port=port, queue=queue)
    proxy.start()

    print(f'{SEPARATOR}')
    print(f'{GREEN}[*]被动扫描模式启动{RESET}')
    print(f'{YELLOW}[*]代理监听: http://{host}:{port}')
    print(f'{YELLOW}[*]请将浏览器/工具代理设为 http://{host}:{port}')
    print(f'{YELLOW}[*]所有经过代理的 HTTP/HTTPS 请求目标会自动加入扫描队列')
    print(f'{YELLOW}[*]按 Ctrl+C 停止被动扫描{RESET}')
    print(f'{SEPARATOR}')

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
                print(f'\n{SEPARATOR}')
                print(f'{YELLOW}[*]被动捕获: {url}{RESET}')
                try:
                    run_mode('p', url, args)
                except Exception as e:
                    print(f'{RED}[!]扫描异常 ({url}): {e}{RESET}')
    except KeyboardInterrupt:
        print(f'\n{YELLOW}[*]被动扫描已停止，共扫描 {len(scanned)} 个目标{RESET}')
    finally:
        proxy.stop()


def run_template_list_mode():
    """列出所有可用的扫描模板（D19）"""
    from lib.scan_templates import list_templates
    print(f'{SEPARATOR}')
    print(f'{YELLOW}[*]可用扫描模板{RESET}')
    print(f'{SEPARATOR}')
    for t in list_templates():
        print(f'{GREEN}  {t.name}{RESET}')
        print(f'    名称：{t.display_name}')
        print(f'    描述：{t.description}')
        print(f'    预估耗时：{t.estimated_time}')
        if t.severity_filter:
            print(f'    严重度过滤：{", ".join(sorted(t.severity_filter))}')
        if t.category_filter:
            print(f'    类别过滤：{", ".join(sorted(t.category_filter))}')
        if t.compliance_filter:
            print(f'    合规过滤：{", ".join(sorted(t.compliance_filter))}')
        if t.default_args:
            defaults_str = ', '.join(f'{k}={v}' for k, v in t.default_args.items())
            print(f'    默认参数：{defaults_str}')
        print()
    print(f'{YELLOW}用法：python main.py --template <name> -u <target>{RESET}')
    print(f'{SEPARATOR}')


def run_diff_only_mode(old_path: str, new_path: str):
    """仅对比两个 JSON 报告（D20）"""
    from lib.diff_scan import diff_reports, load_report, render_diff_report
    print(f'{YELLOW}[*]差异对比模式{RESET}')
    print(f'    旧报告: {old_path}')
    print(f'    新报告: {new_path}')
    try:
        old_report = load_report(old_path)
        new_report = load_report(new_path)
    except FileNotFoundError as e:
        print(f'{RED}[!]{e}{RESET}')
        return
    except json.JSONDecodeError as e:
        print(f'{RED}[!]JSON 解析失败: {e}{RESET}')
        return

    diff = diff_reports(old_report, new_report)
    print(f'{SEPARATOR}')
    print(f'{YELLOW}[*]差异结果{RESET}')
    print(f'    旧扫描: {diff.old_scan_time}（{diff.old_total} 个漏洞）')
    print(f'    新扫描: {diff.new_scan_time}（{diff.new_total} 个漏洞）')
    print(f'    {GREEN}🆕 新增: {diff.total_new} 个{RESET}')
    print(f'    {GREEN}✅ 已修复: {diff.total_fixed} 个{RESET}')
    print(f'    {YELLOW}⚠️ 状态变化: {diff.total_changed} 个{RESET}')
    print(f'    {YELLOW}⏳ 未变: {diff.total_persisted} 个{RESET}')

    # 输出差异报告
    out_dir = os.path.dirname(new_path) or '.'
    paths = render_diff_report(diff, os.path.join(out_dir, 'diff'))
    print(f'{SEPARATOR}')
    print(f'{GREEN}[+]差异报告已生成:{RESET}')
    for p in paths:
        print(f'    {p}')
    print(f'{SEPARATOR}')


def run_plugin_init_mode(args):
    """生成插件模板（D25）"""
    from lib.plugin_sdk import init_plugin_file
    name = args.plugin_init
    category = args.category
    print(f'{YELLOW}[*]生成插件模板{RESET}')
    print(f'    名称: {name}')
    print(f'    类别: {category}')
    try:
        filepath = init_plugin_file(name, category=category)
        print(f'{GREEN}[+]插件已生成: {filepath}{RESET}')
        print(f'{YELLOW}[*]下一步:{RESET}')
        print(f'    1. 编辑 {filepath} 完善检测逻辑')
        print(f'    2. 运行 python main.py --plugin-check {filepath} 验证')
        print(f'    3. 运行 python main.py -u http://target/ 扫描')
    except FileExistsError as e:
        print(f'{RED}[!]{e}{RESET}')


def run_plugin_check_mode(args):
    """验证插件文件（D25）"""
    from lib.plugin_sdk import check_plugin, check_plugin_by_import
    filepath = args.plugin_check
    print(f'{YELLOW}[*]验证插件: {filepath}{RESET}')

    # 静态检查
    ok1, errors1, warnings1 = check_plugin(filepath)
    print(f'{SEPARATOR}')
    print(f'静态检查:')
    if ok1:
        print(f'  {GREEN}✓ 通过{RESET}')
    else:
        print(f'  {RED}✗ 失败{RESET}')
    for e in errors1:
        print(f'  {RED}错误: {e}{RESET}')
    for w in warnings1:
        print(f'  {YELLOW}警告: {w}{RESET}')

    # 导入检查
    ok2, errors2, warnings2 = check_plugin_by_import(filepath)
    print(f'导入检查:')
    if ok2:
        print(f'  {GREEN}✓ 通过{RESET}')
    else:
        print(f'  {RED}✗ 失败{RESET}')
    for e in errors2:
        print(f'  {RED}错误: {e}{RESET}')
    for w in warnings2:
        print(f'  {YELLOW}警告: {w}{RESET}')

    print(f'{SEPARATOR}')
    if ok1 and ok2:
        print(f'{GREEN}[+]插件验证通过{RESET}')
    else:
        print(f'{RED}[!]插件验证失败{RESET}')


def run_plugin_list_mode(args):
    """列出所有插件元数据（D25）"""
    from lib.plugin_sdk import list_all_plugins
    plugins = list_all_plugins()
    print(f'{SEPARATOR}')
    print(f'{YELLOW}[*]已加载插件列表（{len(plugins)} 个）{RESET}')
    print(f'{SEPARATOR}')
    print(f'{"#":<3} {"漏洞名称":<25} {"类别":<10} {"严重度":<8} {"CVE":<18} {"修复":<4} {"复现":<4}')
    print(f'{"-" * 80}')
    for i, p in enumerate(plugins, 1):
        has_fix = '✓' if p['has_fix_detail'] else '✗'
        has_reproduce = '✓' if p['has_reproduce'] else '✗'
        print(f'{i:<3} {p["name"][:25]:<25} {p["category"]:<10} '
              f'{p["severity"]:<8} {(p["cve"] or "N/A")[:18]:<18} '
              f'{has_fix:<4} {has_reproduce:<4}')
    print(f'{SEPARATOR}')


def run_ci_init_mode(args):
    """生成 CI 配置文件（D28）"""
    from lib.ci_runner import generate_ci_config
    platform = args.ci_init
    output_paths = {
        'github': '.github/workflows/security-scan.yml',
        'gitlab': '.gitlab-ci-security.yml',
        'jenkins': 'Jenkinsfile.security',
    }
    output_path = output_paths.get(platform, f'ci-{platform}.yml')
    print(f'{YELLOW}[*]生成 CI 配置: {platform}{RESET}')
    try:
        generate_ci_config(platform, output_path)
        print(f'{GREEN}[+]CI 配置已生成: {output_path}{RESET}')
        if platform == 'github':
            print(f'{YELLOW}[*]使用方法:{RESET}')
            print(f'    1. 将文件提交到仓库')
            print(f'    2. 在 GitHub Secrets 中设置 SCAN_TARGET')
            print(f'    3. 推送代码触发扫描')
            print(f'    4. 在 GitHub → Security → Code scanning 查看结果')
    except ValueError as e:
        print(f'{RED}[!]{e}{RESET}')


def run_wiki_mode(args):
    """生成漏洞知识库（D29）"""
    from lib.vuln_wiki import generate_wiki
    output_path = args.wiki_output or 'vuln_wiki.html'
    print(f'{YELLOW}[*]生成漏洞知识库{RESET}')
    paths = generate_wiki(output_path, formats=['html', 'json'])
    print(f'{GREEN}[+]知识库已生成:{RESET}')
    for p in paths:
        print(f'    {p}')
    print(f'{YELLOW}[*]用浏览器打开 HTML 文件查看{RESET}')


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    print_banner()

    # D27：加载 YAML 配置文件（--config）
    # 优先级：CLI 参数 > 配置文件 > 默认值
    # 配置文件中的 mode/target 需要特殊处理（映射到 -u/-m/-p/-l）
    config_data = {}
    if getattr(args, 'config', None):
        from lib.config_loader import apply_config_to_args, normalize_config_keys, load_yaml_config
        try:
            config_data = load_yaml_config(args.config)
            config_data = normalize_config_keys(config_data)
            args, _overridden = apply_config_to_args(args, args.config, verbose=True)
        except FileNotFoundError as e:
            print(f'{RED}[!]{e}{RESET}')
            return
        except ValueError as e:
            print(f'{RED}[!]配置文件解析失败: {e}{RESET}')
            return

        # 从配置文件设置 mode 和 target（如果 CLI 未指定）
        cli_has_mode = any([args.u, args.m, args.p, args.l])
        if not cli_has_mode:
            cfg_mode = config_data.get('mode', 'u')
            cfg_target = config_data.get('target', config_data.get('u', ''))
            if cfg_target and cfg_target != '__flag__':
                # 设置对应的 -u/-m/-p/-l 参数
                if cfg_mode in ('u', 'm', 'p', 'l'):
                    setattr(args, cfg_mode, cfg_target)
                else:
                    args.u = cfg_target  # 默认综合扫描

    # D19：应用扫描模板（--template）
    # 模板默认参数在配置文件之后应用，优先级：CLI > 模板 > 配置文件 > 默认
    # 但模板仅填充"未显式指定"的参数（与 CLI 默认值比较）
    if getattr(args, 'template', None):
        from lib.scan_templates import apply_template
        print(f'{YELLOW}[*]应用扫描模板: {args.template}{RESET}')
        apply_template(args, args.template, verbose=True)

    # -h 或无任何模式参数：显示帮助并退出
    has_mode = any([args.u, args.m, args.p, args.l, args.file, args.passive,
                    args.chain, args.chain_list, args.serve, args.template_list,
                    args.diff_only, args.plugin_init, args.plugin_check,
                    args.plugin_list, args.ci_init, args.wiki,
                    args.oast_server, args.cve_sync, args.cve_id,
                    args.web_ui, args.distributed, args.cache_stats, args.cache_clear])
    if args.help is not None or not has_mode:
        print_help()
        return

    # --diff-only：仅对比两个 JSON 报告（D20）
    if args.diff_only:
        run_diff_only_mode(args.diff_only[0], args.diff_only[1])
        return

    # --template-list：列出可用模板并退出
    if args.template_list:
        run_template_list_mode()
        return

    # --plugin-init：生成插件模板（D25）
    if args.plugin_init:
        run_plugin_init_mode(args)
        return

    # --plugin-check：验证插件文件（D25）
    if args.plugin_check:
        run_plugin_check_mode(args)
        return

    # --plugin-list：列出所有插件（D25）
    if args.plugin_list:
        run_plugin_list_mode(args)
        return

    # --ci-init：生成 CI 配置文件（D28）
    if args.ci_init:
        run_ci_init_mode(args)
        return

    # --wiki：生成漏洞知识库（D29）
    if args.wiki:
        run_wiki_mode(args)
        return

    # --oast-server：启动 OAST 回调服务器（D30）
    if args.oast_server:
        from lib.oast import run_oast_mode
        run_oast_mode(args)
        return

    # --cve-sync / --cve-id：CVE 同步模式（D32）
    if args.cve_sync or args.cve_id:
        from lib.cve_sync import run_cve_sync_mode
        run_cve_sync_mode(args)
        return

    # --web-ui：生成 Web UI 控制台（D35）
    if args.web_ui:
        from lib.web_ui import run_web_ui_mode
        run_web_ui_mode(args)
        return

    # --cache-stats / --cache-clear：缓存管理（D37）
    if args.cache_stats:
        from lib.cache import run_cache_stats_mode
        run_cache_stats_mode(args)
        return
    if args.cache_clear:
        from lib.cache import run_cache_clear_mode
        run_cache_clear_mode(args)
        return

    # --serve Web API 服务模式（D9）：优先于其他模式
    if args.serve:
        run_serve_mode(args)
        return

    # --chain / --chain-list 链执行模式（D6）：优先于其他模式
    if args.chain_list or (args.chain == 'list'):
        run_chain_mode('list', args)
        return
    if args.chain:
        run_chain_mode(args.chain, args)
        return

    # --passive 被动代理模式（P2-B）：优先于其他模式
    if args.passive:
        run_passive_mode(args)
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
