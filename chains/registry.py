# 链注册表（D6 阶段）
#
# 提供 list_chains() / get_chain(name) 接口，供 main.py --chain 使用。
# 链定义采用惰性导入（用到时才 import），避免无 --chain 时的额外开销。
from typing import Dict, List, Optional, Tuple

from common.logger import get_logger
from core.chain import ChainDef

logger = get_logger(__name__)

# 链注册表：name → (模块路径, 链定义变量名)
# 惰性导入：仅在 get_chain() 时才 import 对应模块
_CHAIN_REGISTRY: Dict[str, Tuple[str, str]] = {
    "ruoyi_sql_to_rce": ("chains.ruoyi_sql_to_rce", "CHAIN"),
    "ruoyi_defaultpw_to_webshell": ("chains.ruoyi_defaultpw_to_webshell", "CHAIN"),
    "ruoyi_nacos_to_dbcreds": ("chains.ruoyi_nacos_to_dbcreds", "CHAIN"),
}

# 内置链的展示元信息（仅用于 list_chains()，不参与链解析）。
# 列表以 _CHAIN_REGISTRY 为唯一权威来源，本字典只是附加元数据，缺失时回退占位值，
# 避免出现「列表里有、get_chain() 却取不到」或反之的不一致。
_CHAIN_META: Dict[str, Dict[str, str]] = {
    "ruoyi_sql_to_rce": {
        "display_name": "SQL注入 → 文件读取配置 → 定时任务 RCE",
        "description": "通过 SQL 注入提取数据库名，任意文件读取获取配置凭证，验证定时任务 RCE 接口未授权",
        "severity": "high",
    },
    "ruoyi_defaultpw_to_webshell": {
        "display_name": "默认口令 → 登录链 → 任意文件上传 → webshell",
        "description": "利用默认口令登录，上传 JSP 探针文件验证可执行性（非真实 webshell）",
        "severity": "high",
    },
    "ruoyi_nacos_to_dbcreds": {
        "display_name": "Nacos 未授权 → 配置泄露 → 数据库凭证",
        "description": "利用 Nacos 未授权访问拉取配置，正则提取数据库凭证",
        "severity": "high",
    },
}

# 动态注册链（register_chain）无内置元信息时的占位展示信息
_DEFAULT_META = {"description": "动态注册链（无内置元信息）", "severity": "medium"}


def list_chains() -> List[Dict[str, str]]:
    """列出所有已注册的链（不触发导入，仅返回元信息）

    以 _CHAIN_REGISTRY 为唯一权威来源：列出的每个 name 都保证可被 get_chain() 解析，
    动态注册的链也会一并列出（元信息缺失时用占位值）。

    Returns:
        [{'name': ..., 'display_name': ..., 'description': ..., 'severity': ...}, ...]
    """
    result = []
    # 依赖字典插入序：迭代顺序即链展示顺序（与注册表/报告顺序一致，排序稳定）
    for name in _CHAIN_REGISTRY:
        meta = _CHAIN_META.get(name)
        if meta is None:
            meta = dict(_DEFAULT_META, display_name=name)
        result.append(
            {
                "name": name,
                "display_name": meta["display_name"],
                "description": meta["description"],
                "severity": meta["severity"],
            }
        )
    return result


def get_chain(name: str) -> Optional[ChainDef]:
    """按名称获取链定义（惰性导入）

    Args:
        name: 链标识（如 'ruoyi_sql_to_rce'）

    Returns:
        ChainDef 实例，未注册或注册条目导入失败返回 None
    """
    if name not in _CHAIN_REGISTRY:
        return None
    module_path, var_name = _CHAIN_REGISTRY[name]
    # import 置于函数体内：未命中注册表时零导入开销；importlib 由解释器缓存，重复调用无额外成本
    import importlib

    try:
        module = importlib.import_module(module_path)
        return getattr(module, var_name)
    except (ImportError, AttributeError) as e:
        # 注册条目损坏（模块路径错误 / var_name 缺失）：保持 Optional[ChainDef] 契约返回 None，
        # 但必须可观测——否则会被上层当成「未注册」，掩盖真正的配置/导入错误
        logger.error("链 %s 导入失败（%s.%s）: %s", name, module_path, var_name, e)
        return None


def register_chain(name: str, module_path: str, var_name: str = "CHAIN"):
    """动态注册链（供插件扩展用）

    Args:
        name: 链标识
        module_path: 模块路径（如 'chains.ruoyi_sql_to_rce'）
        var_name: 链定义变量名（默认 'CHAIN'）
    """
    # 同名注册直接覆盖：允许插件用新实现替换内置链（不报重复注册错误），
    # 但覆盖已有链必须留痕，便于排查「内置链被意外替换」类问题
    if name in _CHAIN_REGISTRY:
        logger.warning("链 %s 已被覆盖：%s.%s", name, module_path, var_name)
    _CHAIN_REGISTRY[name] = (module_path, var_name)
