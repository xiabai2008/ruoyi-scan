# 插件动态发现与加载
import hashlib
import importlib
import os
import sys
from typing import Any, List, Optional


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


def _load_external_dir(dir_path: str, logger: Any) -> List[type]:
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
    # 临时把父目录加入 sys.path 以便按包名导入，导入结束必须还原：
    # 永久留在 sys.path 首位会遮蔽已安装包（同名包被外部目录抢先解析）
    inserted = parent not in sys.path
    if inserted:
        sys.path.insert(0, parent)
    try:
        return load_plugins(pkg_name)
    except Exception as e:
        logger.debug("加载外部插件目录失败 %s: %s", dir_path, e)
        return []
    finally:
        if inserted:
            try:
                sys.path.remove(parent)
            except ValueError:  # pragma: no cover - 其他线程已移除
                pass


def _load_external_file(file_path: str, logger: Any) -> List[type]:
    """从单个 .py 文件加载插件"""
    from plugins.base import PluginBase

    # 模块名加前缀隔离命名空间，并用绝对路径哈希去重：不同目录下的同名文件
    # （如两个 util.py）若沿用 basename 会在 sys.modules 中互相覆盖
    _stem = os.path.splitext(os.path.basename(file_path))[0]
    _digest = hashlib.md5(os.path.abspath(file_path).encode("utf-8")).hexdigest()[:8]
    module_name = "_external_plugin_%s_%s" % (_stem, _digest)

    # 使用 importlib 加载
    import importlib.util

    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        return []
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        # 导入失败时不把半初始化模块留在 sys.modules（否则后续加载会拿到坏模块，
        # 而不是重新执行本文件）
        sys.modules.pop(module_name, None)
        logger.debug("加载外部插件文件失败 %s: %s", file_path, e)
        return []
    sys.modules[module_name] = module

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
            # __module__ 限定本文件定义的类，排除 import 进模块的第三方插件类
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
    packages: List[str] = []
    if not os.path.isdir(plugins_dir):
        return packages
    for name in sorted(os.listdir(plugins_dir)):
        if name in _EXCLUDED:
            continue
        pkg_path = os.path.join(plugins_dir, name)
        if os.path.isdir(pkg_path) and os.path.isfile(os.path.join(pkg_path, "__init__.py")):
            packages.append(f"plugins.{name}")
    return packages


def load_entry_point_plugins() -> List[type]:
    """通过 entry_points 加载第三方注册的插件（P1: pip install 插件包）

    第三方插件包在自身 pyproject.toml 中声明：
        [project.entry-points."ruoyi_scan.plugins"]
        my-plugin = "my_plugin_pkg:plugin_list"

    安装后 ruoyi-scan 自动发现，无需 --plugin-path。

    Returns:
        插件类列表
    """
    from common.logger import get_logger

    logger = get_logger(__name__)
    result = []

    try:
        # Python 3.8+ 使用 importlib.metadata
        try:
            from importlib.metadata import entry_points
        except ImportError:
            from importlib_metadata import entry_points  # type: ignore[no-redef]

        # Python 3.10+ entry_points 返回SelectableGroups，3.8/3.9 返回 dict
        try:
            eps = entry_points(group="ruoyi_scan.plugins")
        except TypeError:
            eps = entry_points().get("ruoyi_scan.plugins", [])  # type: ignore[arg-type]

        for ep in eps:
            try:
                loaded = ep.load()
                if not isinstance(loaded, list):
                    # 加载的是模块，尝试取 plugin_list 属性
                    loaded = getattr(loaded, "plugin_list", [])
                if isinstance(loaded, list):
                    before = len(result)
                    result.extend(loaded)
                    # 计数用本次 entry_point 新增的插件数，而非累计总数（后者会误导排查）
                    logger.debug("entry_point 插件加载成功: %s (%d 个)", ep.name, len(result) - before)
            except Exception as e:
                # 第三方插件导入失败会被静默丢弃，debug 默认不可见：升为 warning 并带堆栈
                logger.warning("entry_point 插件加载失败 %s: %s", ep.name, e, exc_info=True)
    except Exception as e:
        logger.debug("entry_points 发现失败: %s", e)

    return result
