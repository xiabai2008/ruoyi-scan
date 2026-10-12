# 指纹→插件包路由（自动同步特征库 cms，新增 CMS 零改动）
import re
from typing import List

from common.logger import get_logger
from common.models import FingerprintResult
from core.loader import load_plugins

logger = get_logger(__name__)


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

    def candidates(self, fingerprint_result: FingerprintResult) -> List[type]:
        """返回「按 CMS + 变体收窄、但**未按版本过滤**」的候选插件集

        供版本对照矩阵使用：矩阵的意义在于展示「哪些插件因版本不匹配被跳过」，
        因此必须拿过滤前的候选集。若用 `resolve()`（已过滤）构造矩阵，
        所有条目都会是 applicable=True，对照表失去意义
        （2026-09-19 实测发现：CLI 报告里的 version_matrix 恒为空/全适用）。
        """
        cms = fingerprint_result.cms
        if not cms:
            return []
        plugins = self.resolve_by_name(cms)
        # E1/F6：按 variant 过滤（插件 variant='' 表示全变体适用）
        variant = getattr(fingerprint_result, "variant", "") or ""
        return [cls for cls in plugins if not (getattr(cls, "variant", "") or "") or getattr(cls, "variant") == variant]

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
        # 取包后依次收窄：先按 CMS/变体过滤（candidates），再按版本范围过滤
        plugins = self.candidates(fingerprint_result)
        version = getattr(fingerprint_result, "version", "") or ""
        if not version:
            return plugins
        from core.ruoyi_versions import version_in_range

        return [cls for cls in plugins if version_in_range(version, getattr(cls, "affected_versions", "") or "")]

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
            # 先校验标识符合法性：--cms 传入 None/空串/含点号等畸形值时，
            # 直接拼模块名（如 plugins.None）只会经异常静默返回空结果，难以排查
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cms or ""):
                logger.warning("无效的 CMS 标识: %r（应为字母/数字/下划线组成的模块名）", cms)
                return []
            candidate = "plugins.%s" % cms
            # 动态加载失败视为该 CMS 未注册，返回空列表（与显式映射缺失同语义）；
            # 但要记录异常：插件包存在却 import 失败（ImportError/AttributeError）
            # 与「未注册」在返回值上不可区分，若不记日志将极难排查
            try:
                # 复用本次加载结果：原实现先 load 探测、随后又 load 一次，插件包被导入两遍
                return load_plugins(candidate)
            except Exception:
                logger.debug("动态加载插件包 %s 失败，按未注册 CMS 处理", candidate, exc_info=True)
                return []
        return load_plugins(package)
