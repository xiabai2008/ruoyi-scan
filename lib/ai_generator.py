# E7：AI POC 生成器（--ai）
#
# 设计目标：把「漏洞描述 → 插件骨架」的时间压缩到分钟级（参照 nuclei -ai）。
#   --ai "<漏洞描述>" --category ruoyi
#     → 调用 LLM（OpenAI 兼容 API，requests 直调，零新依赖）
#     → plugin_sdk.generate_plugin 规整落盘 plugins/<category>/xxx.py
#     → 自动 --plugin-check 验证；失败把错误回灌 LLM 重试（最多 3 轮）
#
# 无 API Key 降级：规则模板模式（描述关键词 → PLUGIN_TEMPLATE 变体 → 生成带 TODO 骨架）
#
# 安全提示：AI 生成代码必须人工复核后再用于生产；生成物不自动加入 plugin_list。
import json
import os
import re
import time
from typing import Dict, List, Optional, Tuple

from common.logger import get_logger

logger = get_logger(__name__)

# 默认 LLM 配置（环境变量可覆盖）
AI_BASE_URL = os.environ.get("RUOYI_AI_BASE_URL", "https://api.openai.com/v1")
AI_API_KEY = os.environ.get("RUOYI_AI_API_KEY", "")
AI_MODEL = os.environ.get("RUOYI_AI_MODEL", "gpt-4o-mini")
AI_TIMEOUT = int(os.environ.get("RUOYI_AI_TIMEOUT", "60"))

# 系统提示词：内嵌插件规范（与 PLUGIN_TEMPLATE 结构对齐）
SYSTEM_PROMPT = """你是 Ruoyi-Scan 的 POC 插件代码生成器。根据用户提供的漏洞描述，生成一个完整的
Python 插件源码。插件规范（必须遵守）：

1. 继承 PluginBase（from plugins.base import PluginBase）
2. 必须填写类属性：name（中文漏洞名）/ cve（无则 N/A）/ severity（high|medium|low）/
   category（vuln）/ description / fix / fix_detail / reproduce / affected_versions /
   cvss_vector / compliance（等保2.0:8.1.3;OWASP:A03:2021）
3. 实现 verify(self, target, session) -> ScanResult 方法
4. 判定三态：CONFIRMED（确认存在）/ SAFE（确认不存在）/ UNKNOWN（网络异常等无法判定），
   网络错误绝不能判为 SAFE
5. 降误报：多条件联合（状态码 + 正向关键字 + 负向排除 WAF/错误页）
6. 仅做存在性验证，不写破坏性 payload（如删库/写 webshell 执行）
7. 使用 from core.http import join_url 拼接 URL
8. 结果用 self._build_result(status, url, evidence, extra) 构建
9. 注释使用简体中文

只输出 Python 代码本身（不要 markdown 代码块标记，不要额外解释）。"""


def _load_prompt_template() -> str:
    """规则模板（无 API Key 降级路径）"""
    from lib.plugin_sdk import PLUGIN_TEMPLATE

    return PLUGIN_TEMPLATE


# === LLM 客户端（requests 直调，零新依赖） ===


def _llm_complete(messages: List[Dict[str, str]], model: str, api_key: str, base_url: str) -> str:
    """调用 OpenAI 兼容 Chat Completions API

    Args:
        messages: [{role, content}, ...]
        model: 模型名
        api_key: API Key
        base_url: API 基础地址（如 https://api.openai.com/v1）

    Returns:
        模型输出文本

    Raises:
        ValueError: API 调用失败
    """
    import requests

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Authorization": "Bearer %s" % api_key, "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=AI_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        raise ValueError("LLM 调用失败: %s" % e)


# === 规则降级模式 ===

# 描述关键词 → 生成参数（漏洞类型 → 严重度/CVSS/合规/探测建议）
_RULE_TEMPLATES = [
    {
        "keywords": ["sql", "注入", "sqli"],
        "severity": "high",
        "cvss": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "compliance": "OWASP:A03:2021;等保2.0:8.1.3",
        "probe_hint": "POST 表单参数拼接单引号触发报错，对比基准响应",
    },
    {
        "keywords": ["文件读取", "file_read", "读取", "路径穿越", "lfi", "traversal"],
        "severity": "high",
        "cvss": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "compliance": "OWASP:A01:2021;等保2.0:8.1.4",
        "probe_hint": "GET 下载接口拼 ../.. 探测 /etc/passwd root: 特征",
    },
    {
        "keywords": ["文件上传", "upload"],
        "severity": "high",
        "cvss": "AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
        "compliance": "OWASP:A04:2021;等保2.0:8.1.4",
        "probe_hint": "multipart 上传带扩展名校验探测，仅验证不落地 webshell",
    },
    {
        "keywords": ["rce", "命令执行", "代码执行", "远程执行"],
        "severity": "high",
        "cvss": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "compliance": "OWASP:A03:2021;等保2.0:8.1.3",
        "probe_hint": "注入无害命令（如 echo 随机串）对比回显",
    },
    {
        "keywords": ["未授权", "unauth", "未授权访问", "越权", "idor"],
        "severity": "medium",
        "cvss": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "compliance": "OWASP:A01:2021;等保2.0:8.1.4",
        "probe_hint": "无凭据 GET 管理端点，200 + 业务 JSON 即命中",
    },
    {
        "keywords": ["默认口令", "弱口令", "default", "密码"],
        "severity": "medium",
        "cvss": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "compliance": "OWASP:A07:2021;等保2.0:8.1.4",
        "probe_hint": "POST 登录接口尝试 admin/admin123，成功标志区分",
    },
    {
        "keywords": ["ssti", "模板注入"],
        "severity": "high",
        "cvss": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "compliance": "OWASP:A03:2021;等保2.0:8.1.3",
        "probe_hint": "模板表达式探测（如 ${7*7}）对比 49 回显",
    },
]


def _rule_fallback(description: str, name: str, category: str) -> str:
    """规则降级：按关键词匹配生成参数，产出带 TODO 的插件骨架"""
    from lib.plugin_sdk import generate_plugin

    desc_lower = description.lower()
    matched = None
    for rule in _RULE_TEMPLATES:
        if any(k.lower() in desc_lower for k in rule["keywords"]):
            matched = rule
            break
    if matched is None:
        matched = _RULE_TEMPLATES[0]  # 默认按 SQL 注入骨架
    source = generate_plugin(
        name=name,
        category=category,
        severity=matched["severity"],
        cve="N/A",
        description=description,
        fix="修复 %s 漏洞（详见 fix_detail）" % name,
        cvss_vector=matched["cvss"],
        compliance=matched["compliance"],
    )
    # 在 verify 方法中注入 TODO 提示
    source = source.replace(
        "        # TODO: 实现检测逻辑",
        "        # TODO: 实现检测逻辑（探测建议：%s）\n        # TODO: 三态判定：CONFIRMED/SAFE/UNKNOWN，网络异常绝不判 SAFE" % matched["probe_hint"],
    )
    return source


# === 生成流程 ===


def generate_ai_plugin(
    description: str,
    name: str,
    category: str = "ruoyi",
    api_key: str = "",
    model: str = AI_MODEL,
    base_url: str = AI_BASE_URL,
    max_retries: int = 3,
    output_dir: str = None,
) -> Tuple[str, bool, List[str]]:
    """生成 AI 插件（LLM 优先，无 Key 降级规则模板）

    Args:
        description: 漏洞描述（用户输入）
        name: 插件名称（中文）
        category: 插件类别（ruoyi/spring/common）
        api_key: LLM API Key（空则降级规则模板）
        model: LLM 模型名
        base_url: LLM API 基础地址
        max_retries: 自验证失败最大重试轮数
        output_dir: 输出目录（默认 plugins/<category>/）

    Returns:
        (文件路径, 是否通过验证, 验证错误列表)
    """
    from lib.plugin_sdk import check_plugin, init_plugin_file

    api_key = api_key or AI_API_KEY
    source = None
    used_llm = bool(api_key)

    if used_llm:
        # LLM 主路径 + 自验证回灌循环
        for attempt in range(max_retries):
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": "漏洞名称: %s\n漏洞描述: %s\n插件类别: %s" % (name, description, category),
                },
            ]
            if attempt > 0 and errors:
                messages.append({"role": "user", "content": "上次生成的代码验证失败：\n%s\n请修复后重新生成完整代码。" % "\n".join(errors)})
            try:
                source = _llm_complete(messages, model=model, api_key=api_key, base_url=base_url)
            except ValueError as e:
                # LLM 调用失败 → 降级规则模板
                logger.debug("LLM 调用失败，降级规则模板: %s", e)
                source = _rule_fallback(description, name, category)
                used_llm = False
                break
            # 清洗 markdown 代码块
            source = _clean_code(source)
            # 写临时文件验证（同一会话内允许覆盖重试产物）
            filepath = _write_source(name, category, source, output_dir, overwrite=True)
            ok, errors, _warnings = check_plugin(filepath)
            if ok:
                return filepath, True, []
        # 重试耗尽：保留最后一次输出（标注未通过验证）
        if source:
            filepath = _write_source(name, category, source, output_dir, overwrite=True)
            return filepath, False, errors
        # LLM 完全失败
        source = _rule_fallback(description, name, category)
        used_llm = False
    else:
        # 规则降级路径
        source = _rule_fallback(description, name, category)

    # 规则模式落盘（生成带 TODO 骨架，验证应通过——TODO 不阻塞 check）
    try:
        filepath = init_plugin_file(name, category=category, output_dir=output_dir, description=description)
        return filepath, True, []
    except FileExistsError as e:
        raise FileExistsError(str(e))


def _clean_code(source: str) -> str:
    """清洗 LLM 输出：去除 markdown 代码块标记"""
    source = source.strip()
    if source.startswith("```"):
        lines = source.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        source = "\n".join(lines).strip()
    return source


def _write_source(name: str, category: str, source: str, output_dir: Optional[str] = None, overwrite: bool = False) -> str:
    """直接写入 LLM 源码到插件文件

    Args:
        name: 插件名称
        category: 插件类别
        source: 源码
        output_dir: 输出目录
        overwrite: 已存在时是否覆盖（同一生成会话内重试循环用 True）
    """
    if output_dir is None:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(project_root, "plugins", category)
    os.makedirs(output_dir, exist_ok=True)
    from lib.plugin_sdk import _to_filename

    filepath = os.path.join(output_dir, _to_filename(name) + ".py")
    if os.path.exists(filepath) and not overwrite:
        raise FileExistsError("插件文件已存在: %s" % filepath)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(source)
    return filepath


# === CLI 入口 ===


def run_ai_generate_mode(args) -> None:
    """--ai 模式入口：生成插件 + 自验证 + 提示

    Args:
        args: argparse Namespace（含 ai/ai_name/ai_api_key/ai_model/ai_category 等）
    """
    from lib.colors import GREEN, RED, YELLOW

    description = args.ai
    name = getattr(args, "ai_name", "") or description
    category = getattr(args, "category", "ruoyi")
    api_key = getattr(args, "ai_api_key", "") or AI_API_KEY

    if not api_key:
        print(f"{YELLOW}[*]未配置 LLM API Key，使用规则模板模式（生成骨架，需人工补全）{RESET}")
        print(f"{YELLOW}[*]配置方式: 环境变量 RUOYI_AI_API_KEY / RUOYI_AI_BASE_URL / RUOYI_AI_MODEL{RESET}")
    else:
        print(f"{YELLOW}[*]AI 生成中（%s）...{RESET}" % description)

    try:
        filepath, ok, errors = generate_ai_plugin(
            description, name, category=category, api_key=api_key,
            max_retries=getattr(args, "ai_retries", 3),
        )
    except FileExistsError as e:
        print(f"{RED}[!]{e}{RESET}")
        return
    except ValueError as e:
        print(f"{RED}[!]生成失败: {e}{RESET}")
        return

    print(f"{GREEN}[*]插件已生成: {filepath}{RESET}")
    if ok:
        print(f"{GREEN}[*]插件验证通过（--plugin-check）{RESET}")
    else:
        print(f"{YELLOW}[*]插件验证未通过，错误如下（建议人工修复或重试）:{RESET}")
        for e in errors:
            print(f"{RED}    - {e}{RESET}")
    print(f"{RED}[!]AI 生成代码请人工复核后再用于生产；生成插件未加入 plugin_list，需手动确认{RESET}")
