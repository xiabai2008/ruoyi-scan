# 链注册表（D6 阶段）
#
# 提供 list_chains() / get_chain(name) 接口，供 main.py --chain 使用。
# 链定义采用惰性导入（用到时才 import），避免无 --chain 时的额外开销。
from typing import Dict, List, Optional, Tuple

from core.chain import ChainDef

# 链注册表：name → (模块路径, 链定义变量名)
# 惰性导入：仅在 get_chain() 时才 import 对应模块
_CHAIN_REGISTRY: Dict[str, Tuple[str, str]] = {
    "ruoyi_sql_to_rce": ("chains.ruoyi_sql_to_rce", "CHAIN"),
    "ruoyi_defaultpw_to_webshell": ("chains.ruoyi_defaultpw_to_webshell", "CHAIN"),
    "ruoyi_nacos_to_dbcreds": ("chains.ruoyi_nacos_to_dbcreds", "CHAIN"),
}


def list_chains() -> List[Dict[str, str]]:
    """列出所有已注册的链（不触发导入，仅返回元信息）

    Returns:
        [{'name': ..., 'display_name': ..., 'description': ..., 'severity': ...}, ...]
    """
    # 预定义的元信息（避免导入链模块）
    _META = {
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
    # 依赖字典插入序：迭代顺序即链展示顺序（与注册表/报告顺序一致，排序稳定）
    result = []
    for name, meta in _META.items():
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
        ChainDef 实例，未注册返回 None
    """
    if name not in _CHAIN_REGISTRY:
        return None
    module_path, var_name = _CHAIN_REGISTRY[name]
    # import 置于函数体内：未命中注册表时零导入开销；importlib 由解释器缓存，重复调用无额外成本
    import importlib

    module = importlib.import_module(module_path)
    return getattr(module, var_name)


def register_chain(name: str, module_path: str, var_name: str = "CHAIN"):
    """动态注册链（供插件扩展用）

    Args:
        name: 链标识
        module_path: 模块路径（如 'chains.ruoyi_sql_to_rce'）
        var_name: 链定义变量名（默认 'CHAIN'）
    """
    # 同名注册直接覆盖：允许插件用新实现替换内置链（不报重复注册错误）
    _CHAIN_REGISTRY[name] = (module_path, var_name)
