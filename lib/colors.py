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


def ok(msg):
    """正向结果整行绿色包裹：[*]xxx"""
    return f"{GREEN}{PREFIX_OK}{msg}{RESET}"


def no(msg):
    """负向结果整行红色包裹：[/]xxx"""
    return f"{RED}{PREFIX_NO}{msg}{RESET}"
