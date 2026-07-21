# 插件动态发现与加载
import importlib
import os
import sys
from typing import List, Optional


def load_plugins(package_name: str = "plugins.ruoyi") -> List[type]:
    """加载插件包内 plugin_list 显式声明的插件类（保持执行顺序）

    各插件包需在 __init__.py 中定义 plugin_list = [PluginClass1, ...]（元素为插件类对象）。
    兼容字符串形式（类名），自动 getattr 取回类对象。
    """
    package = importlib.import_module(package_name)
    result = []
    plugin_list = getattr(package, "plugin_list", [])
    for item in plugin_list:
        if isinstance(item, str):
            cls = getattr(package, item, None)
        else:
            # 直接是类对象（推荐写法）
            cls = item
        if cls is not None:
            result.append(cls)
    return result


def load_external_plugins(plugin_paths: Optional[List[str]] = None) -> List[type]:
    """从外部目录加载插件（P0: 插件生态扩展）

    支持两种外部插件格式：
    1. 目录形式：/path/to/my_plugins/  含 __init__.py + plugin_list
    2. 单文件形式：/path/to/my_plugin.py  含 PluginBase 子类

    用法：
        # CLI: --plugin-path /path/to/plugins --plugin-path /path/to/extra.py
        plugins = load_external_plugins(["/path/to/my_plugins", "/path/to/extra.py"])

    Args:
        plugin_paths: 外部插件目录/文件路径列表

    Returns:
        插件类列表
    """
    if not plugin_paths:
        return []

    from common.logger import get_logger

    logger = get_logger(__name__)
    result = []

    for path in plugin_paths:
        path = os.path.abspath(path)
        if not os.path.exists(path):
            logger.debug("外部插件路径不存在: %s", path)
            continue

        if os.path.isdir(path):
            # 目录形式：尝试作为包导入
            result.extend(_load_external_dir(path, logger))
        elif path.endswith(".py"):
            # 单文件形式
            result.extend(_load_external_file(path, logger))

    return result


def _load_external_dir(dir_path: str, logger) -> List[type]:
    """从目录加载插件包"""
    init_file = os.path.join(dir_path, "__init__.py")
    if not os.path.isfile(init_file):
        # 无 __init__.py，扫描目录下所有 .py 文件
        result = []
        for fname in sorted(os.listdir(dir_path)):
            if fname.endswith(".py") and not fname.startswith("_"):
                fpath = os.path.join(dir_path, fname)
                result.extend(_load_external_file(fpath, logger))
        return result

    # 有 __init__.py，作为包导入
    pkg_name = os.path.basename(dir_path)
    parent = os.path.dirname(dir_path)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    try:
        return load_plugins(pkg_name)
    except Exception as e:
        logger.debug("加载外部插件目录失败 %s: %s", dir_path, e)
        return []


def _load_external_file(file_path: str, logger) -> List[type]:
    """从单个 .py 文件加载插件"""
    from plugins.base import PluginBase

    module_name = "_external_plugin_" + os.path.splitext(os.path.basename(file_path))[0]

    # 使用 importlib 加载
    import importlib.util

    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        return []
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        logger.debug("加载外部插件文件失败 %s: %s", file_path, e)
        return []

    # 方式1：文件中定义了 plugin_list
    plugin_list = getattr(module, "plugin_list", [])
    if plugin_list:
        result = []
        for item in plugin_list:
            if isinstance(item, str):
                cls = getattr(module, item, None)
            else:
                cls = item
            if cls is not None:
                result.append(cls)
        return result

    # 方式2：自动发现 PluginBase 子类
    result = []
    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if (
            isinstance(attr, type)
            and issubclass(attr, PluginBase)
            and attr is not PluginBase
            and attr.__module__ == module_name
        ):
            result.append(attr)
    return result


def discover_plugin_packages() -> List[str]:
    """自动发现所有插件包（消除硬编码，P1: 插件自动发现）

    扫描 plugins/ 目录下所有含 __init__.py 的子目录，
    返回包名列表（如 ['plugins.common', 'plugins.ruoyi', 'plugins.spring']）。

    排除 plugins.chain（链专用步骤插件，不参与主扫描引擎路由）。
    新增 CMS 框架时只需在 plugins/ 下建包，无需修改任何代码。
    """
    # chain 包是链专用步骤插件，不注册到主扫描引擎
    _EXCLUDED = {"chain"}
    plugins_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "plugins")
    packages = []
    if not os.path.isdir(plugins_dir):
        return packages
    for name in sorted(os.listdir(plugins_dir)):
        if name in _EXCLUDED:
            continue
        pkg_path = os.path.join(plugins_dir, name)
        if os.path.isdir(pkg_path) and os.path.isfile(os.path.join(pkg_path, "__init__.py")):
            packages.append(f"plugins.{name}")
    return packages
