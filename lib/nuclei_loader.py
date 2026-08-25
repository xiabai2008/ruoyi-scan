# E4：nuclei YAML 模板兼容层（--nuclei）
#
# 设计目标：nuclei-templates 是全球最大 POC 模板库（7000+ 贡献者），
# 本模块解析 nuclei http 协议模板子集，运行时适配为 PluginBase 插件，
# 复用现有引擎/三态判定/报告管线，直接获得全世界最新 POC。
#
# 安全红线（重要）：
#   1. 仅支持 http 协议；tcp/dns/ssl/file/code/javascript/websocket/headless
#      协议模板一律跳过（禁止任意代码执行类模板）
#   2. matchers 仅支持 status/word/regex/dsl（dsl 白名单函数，不做任意表达式求值）
#   3. 模板为外部输入，加载前须经过 validate_template 校验
#
# 判定三态：matcher 命中 → CONFIRMED；明确未命中 → SAFE；网络异常 → UNKNOWN
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url

logger = get_logger(__name__)

# 支持的协议白名单（其他协议一律跳过）
SUPPORTED_PROTOCOLS = {"http"}

# 严重度映射：nuclei critical → high（本工具无 critical 级）
SEVERITY_MAP = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}

# 支持变量
_VAR_PATTERN = re.compile(r"\{\{([A-Za-z0-9_-]+)\}\}")


def _try_import_yaml():
    """尝试导入 PyYAML，不可用时返回 None"""
    try:
        import yaml

        return yaml
    except ImportError:
        return None


# === 数据模型 ===


@dataclass
class NucleiHttpRequest:
    """nuclei http 请求块（子集）"""

    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""


@dataclass
class NucleiMatcher:
    """nuclei matcher（子集：status/word/regex/dsl）"""

    mtype: str = "word"  # status/word/regex/dsl
    values: List[str] = field(default_factory=list)
    negative: bool = False
    part: str = "body"  # body/header/all（简化：all=body+header）


@dataclass
class NucleiExtractor:
    """nuclei extractor（子集：regex/name）"""

    name: str = ""
    regex: List[str] = field(default_factory=list)


@dataclass
class NucleiTemplate:
    """解析后的 nuclei 模板（http 子集）"""

    id: str = ""
    name: str = ""
    severity: str = "info"
    tags: List[str] = field(default_factory=list)
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    requests: List[NucleiHttpRequest] = field(default_factory=list)
    matchers: List[NucleiMatcher] = field(default_factory=list)
    extractors: List[NucleiExtractor] = field(default_factory=list)
    matchers_condition: str = "and"  # and/or
    raw: str = ""  # 原始 YAML（校验/调试用）


# === 解析 ===


def _parse_simple_yaml(content: str) -> dict:
    """简易 YAML 解析器（无 PyYAML 时回退，支持缩进嵌套的扁平子集）

    支持：顶层 key: value；列表项 '- key: value'；
    不支持：复杂锚点/多行块。回退失败时抛出 ValueError。
    """
    result: dict = {}
    stack: List[tuple] = []  # (indent, dict_ref)
    for line_num, line in enumerate(content.splitlines(), 1):
        if not line.strip() or line.strip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if stripped.startswith("- "):
            # 列表项：仅支持标量值（收集到父列表）
            item = stripped[2:].strip()
            if not stack:
                raise ValueError(f"第 {line_num} 行列表项缺少父级")
            parent = stack[-1][1]
            if isinstance(parent, list):
                parent.append(_infer_scalar(item))
            continue
        if ":" not in stripped:
            raise ValueError(f"第 {line_num} 行格式错误: {line}")
        key, _, value = stripped.partition(":")
        key = key.strip().strip('"').strip("'")
        value = value.strip()
        # 维护缩进栈
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            parent = result
        else:
            parent = stack[-1][1]
        if value:
            parent[key] = _infer_scalar(value)
        else:
            # 嵌套：先建 dict（若是列表上下文则特殊处理）
            if isinstance(parent, list) and parent and isinstance(parent[-1], dict):
                # 列表项下的嵌套字典
                pass
            new_dict: dict = {}
            parent[key] = new_dict
            stack.append((indent, new_dict))
    return result


def _infer_scalar(value: str):
    """类型推断（与 config_loader._infer_type 语义一致）"""
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    low = value.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    # YAML 列表内联 [a, b]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [v.strip().strip('"').strip("'") for v in inner.split(",")]
    return value


def parse_nuclei_template(filepath: str) -> NucleiTemplate:
    """解析 nuclei 模板文件为 NucleiTemplate

    Args:
        filepath: .yaml/.yml 模板文件路径

    Returns:
        NucleiTemplate（协议不支持时 requests 为空，调用方跳过）

    Raises:
        FileNotFoundError: 文件不存在
        ValueError: 解析失败或缺少必需字段
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"模板文件不存在: {filepath}")
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    yaml = _try_import_yaml()
    if yaml is not None:
        try:
            data = yaml.safe_load(content)
        except Exception as e:
            raise ValueError(f"YAML 解析失败: {e}")
    else:
        data = _parse_simple_yaml(content)
    if not isinstance(data, dict):
        raise ValueError("模板顶层应为字典")

    tpl = NucleiTemplate(raw=content)
    tpl.id = str(data.get("id", "") or "")
    info = data.get("info") or {}
    if isinstance(info, dict):
        tpl.name = str(info.get("name", "") or "")
        tpl.severity = str(info.get("severity", "info") or "info")
        tags = info.get("tags", "")
        if isinstance(tags, str):
            tpl.tags = [t.strip() for t in tags.split(",") if t.strip()]
        elif isinstance(tags, list):
            tpl.tags = [str(t) for t in tags]
        tpl.description = str(info.get("description", "") or "")
        meta = info.get("metadata") or {}
        if isinstance(meta, dict):
            tpl.metadata = meta

    # 协议白名单校验（不支持的协议 → 返回空 requests）
    if (
        data.get("tcp")
        or data.get("dns")
        or data.get("ssl")
        or data.get("file")
        or data.get("code")
        or data.get("javascript")
        or data.get("websocket")
        or data.get("headless")
    ):
        logger.debug("模板 %s 含不支持协议，跳过: %s", filepath, list(data.keys()))
        return tpl

    http_block = data.get("http") or []
    if isinstance(http_block, dict):
        http_block = [http_block]
    if not http_block:
        return tpl
    first = http_block[0]
    if not isinstance(first, dict):
        return tpl

    method = str(first.get("method", "GET") or "GET").upper()
    paths = first.get("path") or ["/"]
    if isinstance(paths, str):
        paths = [paths]
    path = str(paths[0]) if paths else "/"
    headers = first.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    headers = {str(k): str(v) for k, v in headers.items()}
    body = first.get("body", "") or ""
    tpl.requests.append(NucleiHttpRequest(method=method, path=path, headers=headers, body=body))

    # matchers（可位于 http 块或顶层）
    raw_matchers = first.get("matchers") or data.get("matchers") or []
    if not isinstance(raw_matchers, list):
        raw_matchers = [raw_matchers]
    for m in raw_matchers:
        if not isinstance(m, dict):
            continue
        mtype = str(m.get("type", "word") or "word")
        if mtype not in ("status", "word", "regex", "dsl"):
            continue
        values = m.get("status") or m.get("words") or m.get("regex") or m.get("dsl") or []
        if isinstance(values, str):
            values = [values]
        tpl.matchers.append(
            NucleiMatcher(
                mtype=mtype,
                values=[str(v) for v in values],
                negative=bool(m.get("negative", False)),
                part=str(m.get("part", "body") or "body"),
            )
        )
    tpl.matchers_condition = str(first.get("matchers-condition", "and") or "and")

    # extractors（提取证据）
    raw_extractors = first.get("extractors") or []
    if not isinstance(raw_extractors, list):
        raw_extractors = [raw_extractors]
    for e in raw_extractors:
        if not isinstance(e, dict):
            continue
        if e.get("type") in ("regex", "json"):
            tpl.extractors.append(
                NucleiExtractor(
                    name=str(e.get("name", "") or ""),
                    regex=[str(r) for r in (e.get("regex") or e.get("json") or [])],
                )
            )
    return tpl


# === 变量替换 ===


def _resolve_vars(tpl: NucleiTemplate, target: str, session=None) -> NucleiTemplate:
    """替换模板变量：{{BaseURL}} / {{Hostname}} / {{interactsh-url}}

    不支持的变量（如 {{interactsh-url}} 未启用 OAST）→ 抛 ValueError 由调用方跳过该模板。
    """
    from urllib.parse import urlparse

    base = target.rstrip("/")
    hostname = urlparse(target).hostname or ""
    oast_client = getattr(session, "_oast_client", None)

    resolved = NucleiTemplate(
        id=tpl.id,
        name=tpl.name,
        severity=tpl.severity,
        tags=list(tpl.tags),
        description=tpl.description,
        metadata=dict(tpl.metadata),
        matchers=list(tpl.matchers),
        extractors=list(tpl.extractors),
        matchers_condition=tpl.matchers_condition,
        raw=tpl.raw,
    )

    def _sub(value: str) -> str:
        def repl(m):
            var = m.group(1)
            if var == "BaseURL":
                return base
            if var == "Hostname":
                return hostname
            if var == "interactsh-url":
                if oast_client is None:
                    raise ValueError("模板含 {{interactsh-url}} 但未启用 OAST")
                return oast_client.get_payload("oob")
            raise ValueError("不支持模板变量 {{%s}}" % var)

        return _VAR_PATTERN.sub(repl, value)

    for req in tpl.requests:
        resolved.requests.append(
            NucleiHttpRequest(
                method=req.method,
                path=_sub(req.path),
                headers={k: _sub(v) for k, v in req.headers.items()},
                body=_sub(req.body),
            )
        )
    return resolved


# === matcher 判定 ===

# dsl 白名单：数字/比较/逻辑运算符/空白/括号/字母（and/or/not/True/False）
# 安全防线：不含下划线（拒绝 __import__ 等 dunder）、不含点号（拒绝属性访问）、
# eval 使用空 builtins（任何名字解析失败 → False）
_DSL_SAFE_RE = re.compile(r"^[0-9<>=!&\s|()a-zA-Z]+$")


def _eval_dsl(expr: str, status_code: int, body: str, headers_str: str) -> bool:
    """dsl matcher 白名单求值：仅支持 status_code 数字比较 + contains(body/header, 'x')"""
    expr = expr.replace("status_code", str(status_code))
    # 逐个替换 contains 调用（白名单：仅 body/header 两个参数名）
    expr2 = expr
    for m in re.finditer(r"contains\(\s*(\w+)\s*,\s*['\"]([^'\"]*)['\"]\s*\)", expr):
        part, needle = m.group(1), m.group(2)
        if part not in ("body", "header"):
            return False
        hay = body if part == "body" else headers_str
        expr2 = expr2.replace(m.group(0), "True" if needle in hay else "False", 1)
    # nuclei DSL 逻辑运算符 → Python 语法（! 仅替换非 != 的否定符）
    expr2 = expr2.replace("&&", " and ").replace("||", " or ")
    expr2 = re.sub(r"(?<![=!])!(?!=)", " not ", expr2)
    if not _DSL_SAFE_RE.fullmatch(expr2):
        return False
    try:
        return bool(eval(expr2, {"__builtins__": {}}, {}))
    except Exception:
        return False


def _matcher_match(m: NucleiMatcher, status_code: int, body: str, headers_str: str) -> bool:
    """单个 matcher 是否匹配（negative 取反）"""
    hit = False
    if m.mtype == "status":
        hit = any(int(v) == status_code for v in m.values if str(v).isdigit())
    elif m.mtype == "word":
        hay = body
        if m.part in ("header", "all"):
            hay += "\n" + headers_str
        hit = any(w in hay for w in m.values)
    elif m.mtype == "regex":
        hay = body
        if m.part in ("header", "all"):
            hay += "\n" + headers_str
        hit = any(re.search(p, hay) for p in m.values if p)
    elif m.mtype == "dsl":
        hit = any(_eval_dsl(expr, status_code, body, headers_str) for expr in m.values)
    return (not hit) if m.negative else hit


def _extract_evidence(tpl: NucleiTemplate, body: str) -> str:
    """extractor 提取证据（regex 第一组匹配）"""
    for e in tpl.extractors:
        for pat in e.regex:
            try:
                m = re.search(pat, body)
                if m:
                    val = m.group(1) if m.lastindex else m.group(0)
                    if e.name:
                        return "%s: %s" % (e.name, val)
                    return val
            except Exception:
                continue
    return ""


# === 适配器（PluginBase 子类，运行时生成） ===


class NucleiTemplatePlugin:
    """nuclei 模板适配器：鸭子类型兼容 PluginBase（无需继承基类，避免抽象方法约束）

    由 build_template_plugin() 工厂生成类，元信息来自模板 info 段。
    """

    name = ""
    cve = ""
    severity = "low"
    category = "vuln"
    description = ""
    fix = "参考模板描述与 CVE 修复建议"
    affected_versions = ""
    variant = ""
    cvss_vector = ""
    compliance = ""

    def __init__(self, tpl: NucleiTemplate, source: str = ""):
        """初始化模板插件实例

        Args:
            tpl: 解析后的 nuclei 模板对象
            source: 模板来源文件路径（调试/溯源用）
        """
        self.tpl = tpl
        self.source = source

    def verify(self, target: str, session) -> ScanResult:
        """执行模板请求 + 三态判定"""
        # 变量替换（不支持变量 → UNKNOWN 而非崩溃）
        try:
            tpl = _resolve_vars(self.tpl, target, session=session)
        except ValueError as e:
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=target,
                evidence="模板变量解析失败: %s" % e,
            )
        if not tpl.requests:
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=target,
                evidence="模板协议不支持（仅支持 http）",
            )

        last_exc = ""
        for req in tpl.requests:
            try:
                # {{BaseURL}} 替换后 path 可能是绝对 URL，此时直接使用
                if req.path.startswith(("http://", "https://")):
                    req_url = req.path
                else:
                    req_url = join_url(target, req.path.lstrip("/"))
                resp = session.request(
                    req.method,
                    req_url,
                    headers=req.headers or None,
                    data=req.body or None,
                )
            except Exception as e:
                last_exc = str(e)
                continue
            body = resp.text or ""
            headers_str = str(resp.headers)

            # matcher 判定（默认 and：全部满足 → 命中；or：任一满足）
            if not tpl.matchers:
                # 无 matcher：默认 200 即命中（nuclei 行为）
                matched = resp.status_code == 200
            elif tpl.matchers_condition == "or":
                matched = any(_matcher_match(m, resp.status_code, body, headers_str) for m in tpl.matchers)
            else:
                matched = all(_matcher_match(m, resp.status_code, body, headers_str) for m in tpl.matchers)

            if matched:
                evidence = _extract_evidence(tpl, body)
                url = req.path
                extra = {"nuclei_template": tpl.id, "tags": ",".join(tpl.tags)}
                if evidence:
                    extra["extracted"] = evidence
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=SEVERITY_MAP.get(tpl.severity, "low"),
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence=evidence or "nuclei 模板匹配（%s）" % tpl.id,
                    cve=str(tpl.metadata.get("cve", "") or ""),
                    fix=self.fix,
                    extra=extra,
                )
        if last_exc:
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=target,
                evidence="请求异常: %s" % last_exc,
            )
        return ScanResult(
            kind="info",
            name=self.name,
            status=STATUS_SAFE,
            url=target,
            evidence="nuclei 模板未匹配（%s）" % tpl.id,
        )


def build_template_plugin(tpl: NucleiTemplate, source: str = "") -> type:
    """由模板构建插件类（工厂：元信息写入类属性，匹配 meta() 契约）"""
    name = tpl.name or tpl.id or "nuclei_template"
    severity = SEVERITY_MAP.get(tpl.severity, "low")
    cve = str(tpl.metadata.get("cve", "") or "")
    cvss_vector = str(tpl.metadata.get("cvss", "") or "")
    description = tpl.description or "nuclei 模板: %s" % tpl.id

    class _Tpl(NucleiTemplatePlugin):
        def meta(self):
            """返回插件元信息（含 CVSS 评分，匹配 PluginBase.meta 契约）"""
            from plugins.base import cvss_score

            return {
                "name": self.name,
                "cve": self.cve,
                "severity": self.severity,
                "category": self.category,
                "description": self.description,
                "fix": self.fix,
                "fix_detail": "",
                "reproduce": "",
                "cvss_vector": self.cvss_vector,
                "cvss_score": cvss_score(self.cvss_vector) if self.cvss_vector else 0.0,
                "compliance": {},
                "affected_versions": "",
                "variant": "",
            }

    _Tpl.name = name
    _Tpl.severity = severity
    _Tpl.category = "vuln"
    _Tpl.description = description
    _Tpl.cve = cve
    _Tpl.cvss_vector = cvss_vector
    _Tpl.fix = "参考模板描述与官方修复公告" + ("（%s）" % cve if cve else "")
    _Tpl.source = source
    return _Tpl


# === 加载与过滤 ===


def discover_nuclei_files(path: str) -> List[str]:
    """发现目录/文件下的 .yaml/.yml 模板文件"""
    files = []
    if os.path.isfile(path):
        if path.endswith((".yaml", ".yml")):
            files.append(path)
        return files
    if os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for n in names:
                if n.endswith((".yaml", ".yml")):
                    files.append(os.path.join(root, n))
    return files


def validate_template(filepath: str) -> List[str]:
    """模板校验：返回错误列表（空列表 = 通过）"""
    errors = []
    try:
        tpl = parse_nuclei_template(filepath)
    except (FileNotFoundError, ValueError) as e:
        return [str(e)]
    if not tpl.id:
        errors.append("缺少必需字段 id")
    if not tpl.requests:
        errors.append("无 http 请求块或协议不支持（仅支持 http）")
    for i, m in enumerate(tpl.matchers):
        if m.mtype == "dsl":
            for expr in m.values:
                if not _DSL_SAFE_RE.fullmatch(expr.replace("status_code", "200")) and "contains(" not in expr:
                    errors.append("matcher[%d] dsl 表达式超出白名单: %s" % (i, expr))
    return errors


def load_nuclei_templates(
    paths: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    exclude_tags: Optional[List[str]] = None,
) -> List[type]:
    """加载 nuclei 模板为插件类列表

    Args:
        paths: 文件或目录列表（递归发现 .yaml/.yml）
        tags: 仅加载含任一指定 tag 的模板
        severities: 仅加载指定严重度（critical→high 映射后比较）
        exclude_tags: 排除含任一指定 tag 的模板

    Returns:
        插件类列表（无效/不支持模板跳过，不抛异常）
    """
    results = []
    seen_ids = set()
    for path in paths or []:
        for f in discover_nuclei_files(path):
            try:
                tpl = parse_nuclei_template(f)
            except Exception as e:
                logger.warning("nuclei 模板解析失败 %s: %s", f, e)
                continue
            if not tpl.requests:
                continue
            if tags and not any(t in tpl.tags for t in tags):
                continue
            if severities and SEVERITY_MAP.get(tpl.severity) not in severities:
                continue
            if exclude_tags and any(t in tpl.tags for t in exclude_tags):
                continue
            if tpl.id in seen_ids:
                continue
            seen_ids.add(tpl.id)
            results.append(build_template_plugin(tpl, source=f))
    return results
