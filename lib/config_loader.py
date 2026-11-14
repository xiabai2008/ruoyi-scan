# D27：YAML 配置文件加载
#
# 允许用户通过 YAML 文件预设扫描参数，避免每次输入冗长命令行：
#
#   python main.py --config scan.yml
#
# 配置文件示例（scan.yml）：
#   target: http://example.com/
#   mode: u                          # u/m/p/l
#   template: deep                   # quick/deep/compliance/dengbao
#   proxy: http://127.0.0.1:8080
#   threads: 5
#   rate: 10
#   timeout: 15
#   report: ./reports
#   report_format: html,json
#   cms: ruoyi
#   bypass_waf: auto
#   crawl: true
#   crawl_depth: 3
#   subdomain: true
#   js_extract: true
#
# 优先级：CLI 参数 > 配置文件 > 默认值
#   - CLI 显式指定的参数不会被配置文件覆盖
#   - 配置文件中未指定的参数使用 CLI 默认值
#
# YAML 解析：优先使用 PyYAML，未安装时回退简易解析器（支持 key: value 格式）
import os
from typing import Any, Dict, Optional, Tuple

from common.logger import get_logger
from lib.reporter import emit

logger = get_logger(__name__)


def _try_import_yaml():
    """尝试导入 PyYAML，不可用时返回 None"""
    try:
        import yaml

        return yaml
    except ImportError:
        return None


def load_yaml_config(filepath: str) -> Dict[str, Any]:
    """加载 YAML 配置文件为字典

    Args:
        filepath: YAML 文件路径
    Returns:
        配置字典（key 为参数名，value 为参数值）
    Raises:
        FileNotFoundError: 文件不存在
        ValueError: 文件格式错误
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"配置文件不存在: {filepath}")

    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    yaml = _try_import_yaml()
    if yaml is not None:
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"YAML 解析失败: {e}")
        # 空 YAML（仅注释/空白）safe_load 返回 None，按空配置处理
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise ValueError(f"YAML 顶层应为字典，实际为 {type(data).__name__}")
        return data
    else:
        # 回退：简易解析器（支持 key: value 格式，不支持嵌套）
        return _simple_yaml_parse(content)


def _strip_inline_comment(value: str) -> str:
    """去除值尾部的行内注释（# 前有空白，且不在引号内）

    示例：'http://example.com/        # 目标 URL' → 'http://example.com/'
    URL 片段（如 http://x/#/path）中的 # 前无空白，不受影响。
    """
    quote = ""
    for i, ch in enumerate(value):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or value[i - 1] in " \t"):
            return value[:i].rstrip()
    return value


def _simple_yaml_parse(content: str) -> Dict[str, Any]:
    """简易 YAML 解析器（无 PyYAML 时回退）

    支持格式：
        # 注释
        key: value
        key: true / false
        key: 123
        key: "string"

    不支持：嵌套字典、列表、多行字符串
    """
    result = {}
    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"第 {line_num} 行格式错误（应为 key: value）: {line}")
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        # 去行内注释：create_example_config 等文件在值后带 "  # 注释"，
        # 不剥离会把注释并进值（如 target 变成 "http://x/  # 目标 URL"）
        value = _strip_inline_comment(value)
        # 去引号
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        # 类型推断
        value = _infer_type(value)
        result[key] = value
    return result


def _infer_type(value: str) -> Any:
    """推断字符串值的类型

    true/false → bool
    纯数字 → int
    其他 → str
    """
    if not value:
        return ""
    lower = value.lower()
    # 兼容 YAML 布尔语义：yes/no/on/off 均视为布尔值
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False
    # 尝试 int
    try:
        return int(value)
    except ValueError:
        logger.debug("解析配置整数值失败，尝试浮点数", exc_info=True)
    # 尝试 float
    try:
        return float(value)
    except ValueError:
        logger.debug("解析配置浮点数值失败，使用原始字符串", exc_info=True)
    return value


# CLI 参数名 → argparse 属性名映射
# YAML 中的 key 可以用横线或下划线，统一映射到 argparse 属性名
_KEY_ALIASES = {
    # 短参数
    "target": "u",
    "mode": None,  # mode 不直接映射到 args，由 main() 处理
    # 长参数（YAML key → argparse dest）
    "proxy": "proxy",
    "proxy-file": "proxy_file",
    "proxy_file": "proxy_file",
    "proxy-rotate": "proxy_rotate",
    "proxy_rotate": "proxy_rotate",
    "threads": "threads",
    "rate": "rate",
    "report": "report",
    "debug": "debug",
    "timeout": "timeout",
    "cms": "cms",
    # v1.5.6：显式 API 前缀 + Redis 端口（YAML 里写 base_path: /portal、redis_port: 16379）
    "base-path": "base_path",
    "base_path": "base_path",
    "redis-port": "redis_port",
    "redis_port": "redis_port",
    "pass-level": "pass_level",
    "pass_level": "pass_level",
    "portscan": "portscan",
    "ports": "ports",
    "passive": "passive",
    "passive-host": "passive_host",
    "passive_host": "passive_host",
    "passive-port": "passive_port",
    "passive_port": "passive_port",
    "report-format": "report_format",
    "report_format": "report_format",
    "no-dedup": "no_dedup",
    "no_dedup": "no_dedup",
    "chain": "chain",
    "chain-list": "chain_list",
    "chain_list": "chain_list",
    "bypass-waf": "bypass_waf",
    "bypass_waf": "bypass_waf",
    "serve": "serve",
    "host": "host",
    "port": "port",
    "api-key": "api_key",
    "api_key": "api_key",
    "cors-origins": "cors_origins",
    "cors_origins": "cors_origins",
    "db-path": "db_path",
    "db_path": "db_path",
    "crawl": "crawl",
    "crawl-depth": "crawl_depth",
    "crawl_depth": "crawl_depth",
    "crawl-max-pages": "crawl_max_pages",
    "crawl_max_pages": "crawl_max_pages",
    "subdomain": "subdomain",
    "js-extract": "js_extract",
    "js_extract": "js_extract",
    # D19
    "template": "template",
    # D27
    "config": "config",
    # 文件批量
    "file": "file",
}


def normalize_config_keys(config: Dict[str, Any]) -> Dict[str, Any]:
    """将配置文件的 key 标准化为 argparse 属性名

    YAML 中的 key 可以用横线或下划线，统一映射到 argparse dest。
    未识别的 key 保留原值（可能是自定义参数）。

    Args:
        config: 原始配置字典
    Returns:
        标准化后的配置字典（key 为 argparse dest）
    """
    normalized = {}
    for key, value in config.items():
        mapped = _KEY_ALIASES.get(key, key)
        if mapped is not None:
            normalized[mapped] = value
    return normalized


def explicit_keys_from_argv(argv: Optional[list] = None) -> set:
    """从命令行参数列表算出「用户显式指定了哪些 dest」

    为什么要有这个函数（改自 2026-11-04 评审报告 §4.4 的实测缺陷）：
        旧实现让 merge_config_with_args / apply_template 自己去扫全局 sys.argv
        判断「用户是否显式指定」。这很脆弱——**任何**往 sys.argv 里塞参数的
        东西都会被误认成「用户指定」：pytest 的 --timeout=30、以及任何宿主进程
        的参数都是。实测：`pytest tests/test_d19_d27_template_config.py
        --timeout=30` 会让 timeout 被误判为显式指定，配置文件的 timeout=12
        不再生效，2 个用例稳定失败（无参时全绿）。

        注意 addopts 不会进 sys.argv，所以 CI 未受影响——但这个耦合本身
        是定时炸弹：谁在命令行手写一次 --timeout=N 就会踩到。

    做法：解析动作只在 main() 做一次，把结果作为集合传下去。判定依据不再
    依赖全局状态，测试里也不会有外部参数混进来。

    Args:
        argv: 待解析的参数列表；None 表示取 sys.argv[1:]
    Returns:
        被显式指定的 argparse dest 名集合
    """
    import sys as _sys

    tokens = _sys.argv[1:] if argv is None else list(argv)
    keys = set()
    for token in tokens:
        if not token.startswith("--"):
            continue
        name = token[2:].split("=", 1)[0].strip()
        if not name:
            continue
        keys.add(name.replace("-", "_"))
    return keys


def merge_config_with_args(
    args,
    config: Dict[str, Any],
    explicit_keys: Optional[set] = None,
) -> Tuple[Any, Dict[str, Any]]:
    """将配置文件值合并到 argparse args

    优先级：CLI 显式参数 > 配置文件 > 默认值

    判定"CLI 是否显式指定"的方法：
        - 获取 argparse 默认值
        - 当前 args 值与默认值不同 → CLI 显式指定 → 不覆盖
        - 当前 args 值与默认值相同 → 看 explicit_keys 是否含该键
          （含 → 用户显式传了同值参数，不覆盖；不含 → 未指定，用配置文件覆盖）

    Args:
        args: argparse.Namespace 对象
        config: 标准化后的配置字典
        explicit_keys: 用户在命令行显式指定的 dest 集合（见 explicit_keys_from_argv）。
            None 表示「没有 CLI 上下文」（库调用 / 测试），此时一律视为未指定，
            与旧行为一致，但不再去扫全局 sys.argv。
    Returns:
        (合并后的 args 对象, 被配置文件覆盖的参数名列表)
    """
    defaults = _get_parser_defaults()
    if explicit_keys is None:
        explicit_keys = set()

    overridden = []
    for key, config_value in config.items():
        if key in ("mode", "target"):
            # mode 和 target 由 main() 单独处理，不直接设到 args
            continue
        current_value = getattr(args, key, None)
        default_value = defaults.get(key)
        # 当前值与默认值相同且 CLI 未显式指定 → 用配置文件值覆盖
        # （explicit_keys 保证 --threads 5（等于默认值）这类显式参数不被配置文件覆盖）
        if current_value == default_value and key not in explicit_keys:
            setattr(args, key, config_value)
            overridden.append(key)

    return args, overridden


# 缓存 argparse 默认值（测试时可注入）
_parser_defaults_cache: Optional[Dict[str, Any]] = None


def _get_parser_defaults() -> Dict[str, Any]:
    """获取 main.py build_parser() 的默认值映射

    优先使用注入的缓存（测试用），否则从 main.build_parser() 获取。
    """
    global _parser_defaults_cache
    if _parser_defaults_cache is not None:
        return _parser_defaults_cache

    try:
        import main as _main

        parser = _main.build_parser()
        # 空参数解析得到各参数默认值，作为"CLI 是否显式指定"的参照
        _parser_defaults_cache = dict(vars(parser.parse_args([])))
    except Exception:
        # 获取失败不缓存降级结果：一次瞬时失败不应在进程内永久禁用配置合并；
        # 返回空映射时无法判定"显式指定"，保守跳过覆盖而非误盖 CLI 参数
        logger.warning("获取 argparse 默认值失败，本次跳过配置文件合并", exc_info=True)
        return {}

    return _parser_defaults_cache


def set_parser_defaults(defaults: Dict[str, Any]):
    """注入 argparse 默认值（测试用）

    测试时可不依赖 main.py 直接注入默认值映射。
    """
    global _parser_defaults_cache
    _parser_defaults_cache = dict(defaults)


def apply_config_to_args(
    args,
    filepath: str,
    verbose: bool = True,
    explicit_keys: Optional[set] = None,
) -> Tuple[Any, Dict[str, Any]]:
    """加载 YAML 配置文件并合并到 args

    Args:
        args: argparse.Namespace 对象
        filepath: YAML 配置文件路径
        verbose: 是否打印应用日志
        explicit_keys: 用户在命令行显式指定的 dest 集合，透传给 merge_config_with_args
    Returns:
        (合并后的 args 对象, 原始配置字典)
    Raises:
        FileNotFoundError: 文件不存在
        ValueError: 格式错误
    """
    config = load_yaml_config(filepath)
    config = normalize_config_keys(config)

    if verbose and config:
        emit(f"  [*]加载配置文件: {filepath}")
        emit(f"      参数数: {len(config)}")

    args, overridden = merge_config_with_args(args, config, explicit_keys=explicit_keys)

    if verbose and overridden:
        emit(f"      覆盖参数: {', '.join(overridden)}")

    return args, config


def create_example_config(filepath: str):
    """生成示例配置文件

    Args:
        filepath: 输出文件路径
    """
    example = """# Ruoyi-Scan 配置文件示例
# 用法: python main.py --config scan.yml
# 优先级: CLI 参数 > 配置文件 > 默认值

# 目标设置
target: http://example.com/        # 目标 URL（与 -u 等效）
mode: u                            # 扫描模式: u=综合/m=目录/p=漏洞/l=爆破
template: deep                     # 扫描模板: quick/deep/compliance/dengbao

# 网络设置
proxy: http://127.0.0.1:8080       # 代理地址（留空不使用）
threads: 5                         # 并发线程数
rate: 0                            # 每秒请求数（0=不限速）
timeout: 15                        # 请求超时秒数

# 指纹与 CMS
cms: ruoyi                         # 手动指定 CMS（留空自动识别）

# 信息收集
crawl: true                        # 主动爬虫
crawl_depth: 3                     # 爬虫深度
crawl_max_pages: 100               # 爬虫最大页面数
subdomain: true                    # 子域名枚举
js_extract: true                   # JS 端点提取

# WAF 绕过
bypass_waf: auto                   # auto/on/off

# 报告
report: ./reports                  # 报告输出目录
report_format: all                 # html/json/csv/pdf/docx/xlsx，逗号分隔
no_dedup: false                    # 关闭去重

# 端口扫描
portscan: false                    # 扫描前执行端口扫描
ports: 80,443,8080                 # 自定义端口
redis_port: 6379                   # Redis 未授权检测端口（现场常改）

# API 前缀（前后端分离 / 自定义 context-path）
base_path: /portal                 # 显式指定，留空自动探测

# 口令字典
pass_level: full                   # top100/top1000/full
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(example)
