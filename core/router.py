# 指纹→插件包路由（自动同步特征库 cms，新增 CMS 零改动）
from core.loader import load_plugins


class Router:
    """按指纹结果选择对应 CMS 的插件包"""

    # 显式映射兜底（优先于动态推导）
    mapping = {
        'ruoyi': 'plugins.ruoyi',
        'thinkphp': 'plugins.thinkphp',
        'spring': 'plugins.spring',
        'weaver': 'plugins.weaver',
    }

    def resolve(self, fingerprint_result):
        """根据指纹结果返回插件类列表

        Args:
            fingerprint_result: FingerprintResult 实例
        Returns:
            插件类列表（未匹配返回空列表）
        """
        cms = fingerprint_result.cms
        if not cms:
            return []
        package = self.mapping.get(cms)
        if not package:
            # 动态尝试 plugins.<cms>（特征库已注册的 CMS 自动可用）
            candidate = 'plugins.%s' % cms
            try:
                load_plugins(candidate)
                package = candidate
            except Exception:
                return []
        return load_plugins(package)
