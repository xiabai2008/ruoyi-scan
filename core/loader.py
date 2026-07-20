# 插件动态发现与加载
import importlib
from typing import List


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
