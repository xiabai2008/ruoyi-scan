# 插件动态发现与加载
import importlib


def load_plugins(package_name='plugins.ruoyi'):
    """加载插件包内 plugin_list 显式声明的插件类（保持执行顺序）

    各插件包需在 __init__.py 中定义 plugin_list = [PluginClass1, ...]。
    """
    package = importlib.import_module(package_name)
    result = []
    plugin_list = getattr(package, 'plugin_list', [])
    for cls_name in plugin_list:
        cls = getattr(package, cls_name, None)
        if cls is not None:
            result.append(cls)
    return result
