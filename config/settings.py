# 全局配置：线程 / 限速 / 代理 / 超时 / 字典路径
"""settings 模块：线程/限速/代理/超时/字典路径等全局常量（模块导入时即求值）。

供 core/lib/api/cli/plugins 共享；--threads/--rate 等 CLI 参数可覆盖部分默认值。
"""

import os
from typing import Any, Optional

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
#
# 关于默认值为何仍为 1（2026-10 评估，结论：保持 1）：
#   曾被提议改为 10 以加速 `l` 模式 Druid 爆破（6 用户 × 1052 口令 = 6312 个串行 POST）。
#   但核实后发现：本值只喂给 core/engine.py 的**插件级**线程池（并行跑不同插件），
#   而 plugins/ruoyi/druid_brute.py 的口令循环是插件**内部**的串行 for 循环，
#   engine.threads 根本不参与——改大本值并不能加速 Druid 爆破，反而会让「原本顺序
#   执行的多个插件」在所有模式下并发，改变目标负载/账号锁定时序等行为，且无测试守护。
#   故此保持 1；如需加速爆破应在插件内部做受控并发（另议）。
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


# 中间件（Redis 等）的探测端口。None = 用插件内的官方默认端口。
#
# 为什么需要它：Redis 未授权插件走 socket 直连，历史上把 6379 写死在插件里。
# 真实客户现场几乎不会用默认端口（云厂商安全组也优先封 6379），靶场/攻防演练
# 同样常把 Redis 挪到高端口；写死端口时这些目标恒判「连接失败 → UNKNOWN」，
# 而插件本身完全有能力在任意端口验证。属「端口可配」而非「改判定」，
# 不触碰三态纪律（连不上仍是 UNKNOWN）。
#
# 形式：环境变量 RUOYI_SCAN_REDIS_PORT，或 CLI --redis-port。
# 非数字/越界值忽略并回退 None（与 settings 其余项一致的容错策略：解析发生在
# import 期，抛异常会让整个工具无法启动）。


def _parse_port_override(raw: Any) -> Optional[int]:
    """把 CLI/环境变量里的端口文本收敛成合法的 int 或 None。

    非法输入不抛异常：端口是可选增强项，用户手滑写错不该让整次扫描崩掉。
    范围校验到 1..65535，避免 socket 抛 OverflowError 而不是预期的连接失败。
    """
    if raw is None or raw == "":
        return None
    try:
        port = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    return port


REDIS_PORT: Optional[int] = _parse_port_override(os.environ.get("RUOYI_SCAN_REDIS_PORT"))


REDIS_PORT = _parse_port_override(os.environ.get("RUOYI_SCAN_REDIS_PORT"))

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
    """低权限账号配置（越权对照用）。

    账号必须由调用方显式提供：命令行 `--surface-account user:pass`（可多次），
    或 API 请求里的 surface_account。工具不再内置任何默认账号——内置账号只在
    特定靶场成立，会把「未登录扫描」变成「偷偷用测试账号登录」，也会让产品在
    真实客户环境里带着一个无效凭据。

    未提供账号时，相关插件必须返回 UNKNOWN（测不了），不得返回 SAFE。

    TARGET_USER_ID 只是探测对象（默认超管），不是凭据，可用
    RUOYI_SCAN_LOWPRIV_TARGET 覆盖。
    """

    USERNAME = None
    PASSWORD = None
    # 越权探测的目标用户（默认超管自身：普通账号的数据范围必然不含它）
    try:
        # 空/非数字的环境变量回退默认值：解析发生在 import 期，抛 ValueError 会让整个工具无法启动
        TARGET_USER_ID = int(os.environ.get("RUOYI_SCAN_LOWPRIV_TARGET", "1") or "1")
    except ValueError:
        TARGET_USER_ID = 1


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
VERSION = "1.6.0"
AUTHOR = "XIABAI"
GITHUB = "https://github.com/xiabai2008/Ruoyi-Scan"
CONTACT = "https://github.com/xiabai2008"

# E5：插件模板仓库地址（--plugin-update 默认拉取源）
PLUGIN_REPO_URL = "https://github.com/xiabai2008/ruoyi-scan-templates/archive/refs/heads/main.zip"
