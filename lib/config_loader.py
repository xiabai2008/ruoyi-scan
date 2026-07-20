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
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise ValueError(f"YAML 顶层应为字典，实际为 {type(data).__name__}")
        return data
    else:
        # 回退：简易解析器（支持 key: value 格式，不支持嵌套）
        return _simple_yaml_parse(content)


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


def merge_config_with_args(args, config: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
    """将配置文件值合并到 argparse args

    优先级：CLI 显式参数 > 配置文件 > 默认值

    判定"CLI 是否显式指定"的方法：
        - 获取 argparse 默认值
        - 当前 args 值与默认值不同 → CLI 显式指定 → 不覆盖
        - 当前 args 值与默认值相同 → CLI 未指定 → 用配置文件值覆盖

    Args:
        args: argparse.Namespace 对象
        config: 标准化后的配置字典
    Returns:
        (合并后的 args 对象, 被配置文件覆盖的参数名列表)
    """
    defaults = _get_parser_defaults()

    overridden = []
    for key, config_value in config.items():
        if key in ("mode", "target"):
            # mode 和 target 由 main() 单独处理，不直接设到 args
            continue
        current_value = getattr(args, key, None)
        default_value = defaults.get(key)
        # 当前值与默认值相同 → CLI 未指定 → 用配置文件值覆盖
        if current_value == default_value:
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
        _parser_defaults_cache = dict(vars(parser.parse_args([])))
    except Exception:
        _parser_defaults_cache = {}

    return _parser_defaults_cache


def set_parser_defaults(defaults: Dict[str, Any]):
    """注入 argparse 默认值（测试用）

    测试时可不依赖 main.py 直接注入默认值映射。
    """
    global _parser_defaults_cache
    _parser_defaults_cache = dict(defaults)


def apply_config_to_args(args, filepath: str, verbose: bool = True) -> Tuple[Any, Dict[str, Any]]:
    """加载 YAML 配置文件并合并到 args

    Args:
        args: argparse.Namespace 对象
        filepath: YAML 配置文件路径
        verbose: 是否打印应用日志
    Returns:
        (合并后的 args 对象, 原始配置字典)
    Raises:
        FileNotFoundError: 文件不存在
        ValueError: 格式错误
    """
    config = load_yaml_config(filepath)
    config = normalize_config_keys(config)

    if verbose and config:
        print(f"  [*]加载配置文件: {filepath}")
        print(f"      参数数: {len(config)}")

    args, overridden = merge_config_with_args(args, config)

    if verbose and overridden:
        print(f"      覆盖参数: {', '.join(overridden)}")

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

# 口令字典
pass_level: full                   # top100/top1000/full
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(example)
