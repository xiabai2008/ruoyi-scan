# 指纹→插件包路由（阶段一硬编码 ruoyi，阶段二加映射即可，引擎零改动）
from core.loader import load_plugins


class Router:
    """按指纹结果选择对应 CMS 的插件包"""

    # cms -> 插件包名（阶段二新增 CMS 在此注册即可）
    mapping = {
        'ruoyi': 'plugins.ruoyi',
    }

    def resolve(self, fingerprint_result):
        """根据指纹结果返回插件类列表

        Args:
            fingerprint_result: FingerprintResult 实例
        Returns:
            插件类列表（未匹配返回空列表）
        """
        cms = fingerprint_result.cms
        package = self.mapping.get(cms)
        if not package:
            return []
        return load_plugins(package)
