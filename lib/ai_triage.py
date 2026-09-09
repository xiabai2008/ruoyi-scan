# G3 AI 闭环 v2：UNKNOWN 智能降噪（证据聚类 + LLM 辅助归类）
#
# 定位（ROADMAP G3）：扫描结果中的 UNKNOWN（无法判定）案例量大且杂，
# LLM 辅助归类帮助测试人员分流处理优先级。
#
# 三态纪律（红线）：
#   AI 的输出只能是分流标签（固定枚举），**不得输出 CONFIRMED/SAFE**——
#   AI 结论仅供分流参考，最终判定权在人工与三态引擎。
#
# 分类标签（固定枚举）：
#   suspected_waf       疑似 WAF/防护拦截（响应被篡改，特征无法命中）
#   network_error       网络异常/超时（目标不可达或响应中断）
#   captcha_or_auth     疑似验证码/鉴权拦截（登录墙导致探测被挡）
#   needs_manual_review 需人工复核（证据不足或形态未知）
#
# LLM 不可用时降级规则分类（evidence 关键字匹配），闭环不依赖外网。
import json
import os
import re
from typing import Any, Callable, Dict, List, Optional

from common.logger import get_logger

logger = get_logger(__name__)

# 分流标签固定枚举（AI 只能从中选择，不得给出三态判定）
TRIAGE_LABELS = ("suspected_waf", "network_error", "captcha_or_auth", "needs_manual_review")

# 降级规则：evidence/url 关键字 → 标签（按优先级顺序匹配）
_RULES = [
    ("network_error", ("timeout", "timed out", "connection", "connect", "refused", "unreachable", "reset")),
    ("suspected_waf", ("waf", "forbidden", "403", "拦截", "防火墙", "blocked", "incapsula", "cloudflare", "安全狗")),
    ("captcha_or_auth", ("验证码", "captcha", "请先登录", "unauthorized", "401", "login")),
]

DISCLAIMER = "AI 结论仅供漏洞分流参考，不构成三态判定（CONFIRMED/SAFE/UNKNOWN），最终判定权在人工复核与三态引擎。"


def _rule_classify(evidence: str) -> str:
    """规则降级分类（无 LLM 时的确定性兜底）"""
    text = (evidence or "").lower()
    for label, keywords in _RULES:
        if any(kw in text for kw in keywords):
            return label
    return "needs_manual_review"


def cluster_unknowns(results: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    """UNKNOWN 案例聚类：按插件名分组（同插件同特征 → 同因归类的概率最高）

    Returns:
        {插件名: [{name/url/evidence/severity}, ...]}
    """
    from common.models import STATUS_UNKNOWN

    groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        if getattr(r, "status", "") != STATUS_UNKNOWN:
            continue
        plugin = getattr(r, "name", "unknown") or "unknown"
        groups.setdefault(plugin, []).append(
            {
                "name": getattr(r, "name", ""),
                "url": getattr(r, "url", ""),
                "evidence": (getattr(r, "evidence", "") or "")[:400],
                "severity": getattr(r, "severity", ""),
            }
        )
    return groups


def triage_unknowns(
    results: List[Any],
    llm_fn: Optional[Callable[[str], str]] = None,
) -> Dict[str, Any]:
    """UNKNOWN 降噪主入口

    Args:
        results: ScanResult 列表（引擎原始输出，三态未改写）
        llm_fn: LLM 调用函数（接受 prompt 返回文本；None 则规则降级）

    Returns:
        {
            'disclaimer': 免责说明（三态纪律）,
            'summary': {'total_unknown': n, 'labels': {label: count}},
            'groups': [
                {'plugin': 插件名, 'label': 分流标签, 'count': n,
                 'items': [...], 'reason': LLM/规则给出的归类理由},
            ],
        }
    """
    groups_raw = cluster_unknowns(results)
    out_groups: List[Dict[str, Any]] = []
    label_counts: Dict[str, int] = {label: 0 for label in TRIAGE_LABELS}

    for plugin, items in groups_raw.items():
        label: Optional[str] = None
        reason = ""
        if llm_fn is not None:
            label, reason = _llm_classify_group(plugin, items, llm_fn)
        if label is None:
            # 规则降级：组内逐条规则分类，取多数
            labels = [_rule_classify(it["evidence"]) for it in items]
            label = max(set(labels), key=labels.count)
            reason = "规则匹配（LLM 不可用）"
        if label not in TRIAGE_LABELS:
            label = "needs_manual_review"
        label_counts[label] += len(items)
        out_groups.append({"plugin": plugin, "label": label, "count": len(items), "items": items, "reason": reason})

    # 排序：数量多的组在前（分流优先级）
    out_groups.sort(key=lambda g: -g["count"])
    return {
        "disclaimer": DISCLAIMER,
        "summary": {"total_unknown": sum(g["count"] for g in out_groups), "labels": label_counts},
        "groups": out_groups,
    }


def _llm_classify_group(plugin: str, items: List[Dict[str, Any]], llm_fn: Callable[[str], str]) -> tuple:
    """LLM 归类单组 UNKNOWN（失败返回 (None, "") 由调用方降级规则）

    提示词约束 AI 只能输出固定枚举标签，禁止输出三态判定。
    """
    sample = "\n".join(f"- url: {it['url']}\n  evidence: {it['evidence'][:200]}" for it in items[:5])
    prompt = (
        "你是漏洞扫描结果的分流助手。以下是插件 %s 产生的 UNKNOWN（无法判定）结果样例：\n%s\n"
        '请从以下标签中选择最匹配的一个（只能输出 JSON，格式 {"label": "...", "reason": "一句话理由"}）：\n'
        "%s\n"
        "注意：禁止输出 CONFIRMED 或 SAFE——你的任务是分流建议，不是漏洞判定。"
        % (plugin, sample, "、".join(TRIAGE_LABELS))
    )
    try:
        raw = llm_fn(prompt)
        # 容错解析：提取首个 JSON 对象
        m = re.search(r"\{[^{}]+\}", raw, re.S)
        if not m:
            return None, ""
        data = json.loads(m.group(0))
        label = str(data.get("label", ""))
        if label not in TRIAGE_LABELS:
            return None, ""
        return label, str(data.get("reason", ""))[:200]
    except Exception as e:
        logger.debug("LLM 归类失败，降级规则: %s", e)
        return None, ""


def run_ai_triage_mode(args, builder: Any = None) -> Optional[str]:
    """--ai-triage 模式入口：对本次扫描的 UNKNOWN 结果归类

    Args:
        args: CLI 参数（ai_api_key/ai_model/ai_base_url，--report 输出目录）
        builder: ReportBuilder（None 时无法取结果，提示先扫描）

    Returns:
        输出文件路径；无 UNKNOWN 时返回 None
    """
    from lib.colors import GREEN, RESET, YELLOW

    if builder is None:
        print(f"{YELLOW}[!]--ai-triage 需在扫描完成后使用（配合 -u/-p 等）{RESET}")
        return None

    results = builder._effective_results()
    llm_fn = None
    api_key = getattr(args, "ai_api_key", "") or os.environ.get("RUOYI_AI_API_KEY", "")
    base_url = getattr(args, "ai_base_url", "") or os.environ.get("RUOYI_AI_BASE_URL", "https://api.openai.com/v1")
    model = getattr(args, "ai_model", "") or os.environ.get("RUOYI_AI_MODEL", "gpt-4o-mini")
    if api_key or base_url != "https://api.openai.com/v1":
        from lib.ai_generator import _llm_complete

        llm_fn = lambda prompt: _llm_complete(  # noqa: E731
            [{"role": "user", "content": prompt}], model=model, api_key=api_key, base_url=base_url
        )

    report = triage_unknowns(results, llm_fn=llm_fn)
    if report["summary"]["total_unknown"] == 0:
        print(f"{GREEN}[*]本次扫描无 UNKNOWN 结果，无需分流{RESET}")
        return None

    out_dir = getattr(args, "report", None) or "reports"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "unknown_triage.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"{YELLOW}[*]UNKNOWN 降噪：共 {report['summary']['total_unknown']} 条，分流如下{RESET}")
    for g in report["groups"]:
        print(f"    [{g['label']}] {g['plugin']} × {g['count']}")
    print(f"{GREEN}[*]分流报告已生成: {out_path}{RESET}")
    print(f"{YELLOW}[!]{report['disclaimer']}{RESET}")
    return out_path
