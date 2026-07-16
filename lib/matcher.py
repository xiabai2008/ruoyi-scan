# 降误报判定工具：正向关键字 + 负向排除联合判定（见 agents.md §5）


def match_positive(text, positives, negatives=None):
    """正向命中：text 含任一 positives 且不含任何 negatives

    Args:
        text: 响应文本
        positives: 正向关键字列表（命中任一即为正向特征存在）
        negatives: 负向排除关键字列表（命中任一即判为噪声/WAF/错误页）
    """
    if text is None:
        return False
    if not any(p in text for p in positives):
        return False
    if negatives and any(n in text for n in negatives):
        return False
    return True


def match_all(text, keywords):
    """联合命中：text 必须同时包含所有 keywords（如 root + :/）"""
    if text is None:
        return False
    return all(k in text for k in keywords)
