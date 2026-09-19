# 全局配置：线程 / 限速 / 代理 / 超时 / 字典路径
"""settings 模块：线程/限速/代理/超时/字典路径等全局常量（模块导入时即求值）。

供 core/lib/api/cli/plugins 共享；--threads/--rate 等 CLI 参数可覆盖部分默认值。
"""

import os

# 项目根目录（config/ 的上一级）
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _dict_path(name: str) -> str:
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

# TLS 证书校验（默认关闭，可用 --verify-tls 打开）
#
# 默认不校验的理由：内网若依部署普遍使用自签名证书或私有 CA，开启校验时每个请求都会抛
# SSLError，插件按三态纪律一律降级为 UNKNOWN——工具对这类目标完全失效且没有任何提示。
# 扫描器行业惯例亦如此（被测目标是分析对象，不是需要防篡改的信道）。
VERIFY_TLS = False

# 连续超时熔断阈值（core/session.py）：连续 N 个请求超时即判定目标无响应，
# 后续请求立即失败，避免「接受连接但永不响应」的目标把扫描拖成数分钟无效重试
TIMEOUT_BREAKER_THRESHOLD = 5

# 字典路径
RUOYI_DICT = _dict_path("ruoyi.txt")
PASSWORD_DICT = _dict_path("password.txt")

# 口令字典分级（P1-B）：top100 / top1000 / full
PASSWORD_DICT_BY_LEVEL = {
    "top100": os.path.join(BASE_DIR, "data", "pass_top100.txt"),
    "top1000": os.path.join(BASE_DIR, "data", "pass_top1000.txt"),
    # full 级复用 _dict_path（兼容老字典放项目根的情况）；分级词典固定 data/
    "full": _dict_path("password.txt"),
}

# 报告输出目录（RUOYI_SCAN_REPORT_DIR 可覆盖：PyInstaller 冻结环境重定向到用户目录，
# 避免 Program Files 只读导致报告写入失败；源码运行保持默认 reports/）
REPORT_DIR = os.environ.get("RUOYI_SCAN_REPORT_DIR") or os.path.join(BASE_DIR, "reports")

# Druid 爆破用户名清单（沿用原 web_login，6 个）
DRUID_USERS = ["ruoyi", "druid", "admin", "admin123", "auth", "123456"]

# 定时任务任意文件读取：固定 JSESSIONID（沿用原脚本）
# D1 后：定时任务类插件已改用 RuoYiAuthChain 登录链，此值仅保留兼容
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


class RuoYiLowPriv:
    """低权限账号配置：用于验证「需普通用户权限才可触发」的越权类漏洞

    为什么需要单独一个账号：RuoYi 的 `checkUserDataScope` 对超级管理员**直接跳过**：

        if (!SysUser.isAdmin(ShiroUtils.getUserId())) { ...校验数据范围... }

    因此拿 admin 去探测，无论目标版本有没有该校验，行为完全一致——**区分不出来**。
    必须用「持有所需功能权限、但数据范围不含目标用户」的普通账号才能复现。

    该账号由 `lab/version_matrix/run_matrix.py seed` 在各版本库里自动创建
    （角色：普通角色 role_id=2，data_scope=2 自定义且不含目标部门；
    额外授予 `system:user:resetPwd` 菜单权限）。
    """

    USERNAME = os.environ.get("RUOYI_SCAN_LOWPRIV_USER", "scanner_low")
    PASSWORD = os.environ.get("RUOYI_SCAN_LOWPRIV_PASS", "LowPriv_2026")
    # 越权探测的目标用户（默认超管自身：普通账号的数据范围必然不含它）
    TARGET_USER_ID = int(os.environ.get("RUOYI_SCAN_LOWPRIV_TARGET", "1"))


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
VERSION = "1.4.3"
AUTHOR = "XIABAI"
GITHUB = "https://github.com/xiabai2008/Ruoyi-Scan"
CONTACT = "https://github.com/xiabai2008"

# E5：插件模板仓库地址（--plugin-update 默认拉取源）
PLUGIN_REPO_URL = "https://github.com/xiabai2008/ruoyi-scan-templates/archive/refs/heads/main.zip"
