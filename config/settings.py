# 全局配置：线程 / 限速 / 代理 / 超时 / 字典路径
import os

# 项目根目录（config/ 的上一级）
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _dict_path(name):
    """字典路径：优先 data/，回退根目录

    字典内容原样保留（ruoyi.txt 保留 %20 前缀；password.txt 保留空行口令，勿 strip）。
    """
    data_path = os.path.join(BASE_DIR, "data", name)
    root_path = os.path.join(BASE_DIR, name)
    return data_path if os.path.exists(data_path) else root_path


# 默认 User-Agent（沿用原脚本）
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"

# 请求超时（秒）
TIMEOUT = 10

# 并发线程数（默认 1 = 同步顺序执行，对齐原脚本行为；Step 5 通过 --threads N 启用并发）
THREADS = 1

# 限速（每秒请求数，0 表示不限速）
RATE = 0

# 代理（如 http://127.0.0.1:8080，None 表示不使用）
PROXY = None

# 字典路径
RUOYI_DICT = _dict_path("ruoyi.txt")
PASSWORD_DICT = _dict_path("password.txt")

# 口令字典分级（P1-B）：top100 / top1000 / full
PASSWORD_DICT_BY_LEVEL = {
    "top100": os.path.join(BASE_DIR, "data", "pass_top100.txt"),
    "top1000": os.path.join(BASE_DIR, "data", "pass_top1000.txt"),
    "full": _dict_path("password.txt"),
}

# 报告输出目录
REPORT_DIR = os.path.join(BASE_DIR, "reports")

# Druid 爆破用户名清单（沿用原 web_login，6 个）
DRUID_USERS = ["ruoyi", "druid", "admin", "admin123", "auth", "123456"]

# 定时任务任意文件读取：固定 JSESSIONID（沿用原脚本）
# D1 后：file_read_time 已改用 RuoYiAuthChain 登录链，此值仅保留兼容
JOB_JSESSIONID = "6db3d8ea-2d5c-490e-9863-6ef864b99828"


# 若依登录链配置（D1 阶段）
class RuoYiAuth:
    """若依登录链配置：为需鉴权 POC 提供会话凭证"""

    # 默认口令（若依官方默认 admin/admin123）
    USERNAME = "admin"
    PASSWORD = "admin123"
    # 记住我（RuoYi v4 Shiro rememberMe，部分环境可延长会话）
    REMEMBER_ME = False
    # 登录超时（秒，None 用 SessionManager 默认）
    TIMEOUT = None
    # 验证码模式：auto（自动探测）/ ocr（D3 接 OCR）/ skip（跳过登录链）
    CAPTCHA_MODE = "auto"


# WAF 绕过配置（D7 阶段）
class WafBypass:
    """WAF 绕过配置：控制绕过行为开关和参数"""

    # 是否启用 WAF 绕过（None=自动：检测到 WAF 才启用，True=强制启用，False=禁用）
    ENABLED = None
    # 最大绕过尝试次数（每种策略算一次）
    MAX_ATTEMPTS = 3
    # 是否启用源站 IP 探测（L4 策略需要，需联网查询 crt.sh）
    ORIGIN_IP_PROBE = True
    # 源站 IP 探测超时（秒）
    ORIGIN_IP_TIMEOUT = 5
    # 参与绕过的漏洞类型（逗号分隔，空=全部支持类型）
    BYPASS_VULN_TYPES = "sqli,xss,rce,file_read"
    # 绕过失败后是否标记到结果 extra（便于审计）
    MARK_FAILED_ATTEMPTS = True


# 工具版本与作者（同步 banner）
VERSION = "1.1.0"
AUTHOR = "XIABAI"
GITHUB = "https://github.com/xiabai2008/Ruoyi-Scan"
CONTACT = "https://github.com/xiabai2008"

# E5：插件模板仓库地址（--plugin-update 默认拉取源，占位待官方仓库建立）
PLUGIN_REPO_URL = ""
