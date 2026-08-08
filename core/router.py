# 指纹→插件包路由（自动同步特征库 cms，新增 CMS 零改动）
from typing import List

from common.models import FingerprintResult
from core.loader import load_plugins


class Router:
    """按指纹结果选择对应 CMS 的插件包"""

    # 显式映射兜底（优先于动态推导）
    # 注：thinkphp / weaver / shiro / struts2 已迁移至 cms-scan-extras/，本项目专注若依做深
    # P0：ruoyi-cloud 也路由到 plugins.ruoyi（共享若依插件包）
    # E1：若依全部变体（vue3/app/plus/cloud-plus/magic）共享 plugins.ruoyi 插件包
    # F5：JeecgBoot 独立插件包（第一个拓展框架，证明基建通用）
    mapping = {
        "ruoyi": "plugins.ruoyi",
        "ruoyi-cloud": "plugins.ruoyi",
        "ruoyi-vue3": "plugins.ruoyi",
        "ruoyi-app": "plugins.ruoyi",
        "ruoyi-plus": "plugins.ruoyi",
        "ruoyi-cloud-plus": "plugins.ruoyi",
        "ruoyi-magic": "plugins.ruoyi",
        "spring": "plugins.spring",
        "jeecgboot": "plugins.jeecgboot",
    }

    def resolve(self, fingerprint_result: FingerprintResult) -> List[type]:
        """根据指纹结果返回插件类列表（D2：按 affected_versions 过滤；E1：按 variant 过滤）

        D2 阶段：若指纹识别出版本号，则过滤掉 affected_versions 不匹配的插件。
        版本未识别（空串）时不过滤，保守策略：跑全部 POC。
        E1 阶段：若识别出变体，则过滤掉 variant 不匹配的插件（插件 variant='' 表示全变体适用）。

        Args:
            fingerprint_result: FingerprintResult 实例（含 cms / version / confidence）
        Returns:
            插件类列表（未匹配返回空列表）
        """
        cms = fingerprint_result.cms
        if not cms:
            return []
        plugins = self.resolve_by_name(cms)
        # E1：按 variant 过滤（插件 variant='' 全变体适用）
        variant = getattr(fingerprint_result, "variant", "") or ""
        if variant:
            plugins = [
                cls for cls in plugins if not (getattr(cls, "variant", "") or "") or getattr(cls, "variant") == variant
            ]
        # D2：按 affected_versions 过滤
        version = getattr(fingerprint_result, "version", "") or ""
        if version:
            from core.ruoyi_versions import version_in_range

            filtered = []
            for cls in plugins:
                spec = getattr(cls, "affected_versions", "") or ""
                if version_in_range(version, spec):
                    filtered.append(cls)
            return filtered
        return plugins

    def resolve_by_name(self, cms: str) -> List[type]:
        """按 CMS 名称直接加载插件包（跳过指纹识别，供 --cms 手动指定）

        Args:
            cms: CMS 标识字符串（如 'ruoyi'）
        Returns:
            插件类列表（未匹配返回空列表）
        """
        package = self.mapping.get(cms)
        if not package:
            # 动态尝试 plugins.<cms>（特征库已注册的 CMS 自动可用）
            candidate = "plugins.%s" % cms
            try:
                load_plugins(candidate)
                package = candidate
            except Exception:
                return []
        return load_plugins(package)
