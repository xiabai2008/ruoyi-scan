# ANSI 颜色常量（沿用现有配色语义，见 agents.md §3.1）
# 绿=正向/命中/成功；红=负向/未命中/失败；黄=提示/标签/分隔；\033[0m 收尾

GREEN = "\033[32m"  # 正向 / 命中 / 成功 / 存在
RED = "\033[31m"  # 负向 / 未命中 / 失败 / 不存在
YELLOW = "\033[33m"  # 过程提示 / 字段标签 / 分隔语境
RESET = "\033[0m"  # 颜色重置（每段彩色输出必须以此收尾）

# 89 字符分隔线（对齐现有 '-'*89 视觉宽度）
SEPARATOR = "-" * 89

# 消息前缀（严格保留，见 agents.md §3.2）
PREFIX_OK = "[*]"  # 正向结果条目
PREFIX_NO = "[/]"  # 负向结果条目


class Finding(str):
    """「单条漏洞结论」文案标记类型

    ok() / no() 返回的是带颜色的整行结论文案（[*]存在xxx / [/]不存在xxx）。
    插件在 verify() 里自行 emit 一次，扫描引擎又会按 ScanResult 统一打印一次，
    同一结论在终端出现两遍。lib.reporter.emit 依据该类型识别结论行，
    在 CLI 已统一打印结论时（见 reporter.set_findings_muted）跳过插件侧输出，
    其它进度类文案不受影响。

    继承 str：对既有的拼接 / 打印 / 正则逻辑完全透明。
    """

    __slots__ = ()


def ok(msg):
    """正向结果整行绿色包裹：[*]xxx"""
    return Finding(f"{GREEN}{PREFIX_OK}{msg}{RESET}")


def no(msg):
    """负向结果整行红色包裹：[/]xxx"""
    return Finding(f"{RED}{PREFIX_NO}{msg}{RESET}")
