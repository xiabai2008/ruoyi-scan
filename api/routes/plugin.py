# D9 插件路由：列出/查询插件
from fastapi import APIRouter, HTTPException

from api.models.schemas import PluginDTO
from common.logger import get_logger
from core.loader import discover_plugin_packages, load_plugins

logger = get_logger(__name__)
router = APIRouter(tags=["插件"])


def _load_all_plugins():
    """加载所有已注册插件类（自动发现，无硬编码）"""
    plugins = []
    for pkg in discover_plugin_packages():
        try:
            plugins.extend(load_plugins(pkg))
        except Exception:
            logger.debug("加载插件包 %s 失败", pkg, exc_info=True)
    return plugins


@router.get("/plugins", response_model=list, summary="列出所有已加载插件")
async def list_plugins():
    """列出所有已加载的扫描插件"""
    result = []
    # 按类名去重：多个插件包可能注册同一个插件类，避免重复列出
    seen = set()
    for cls in _load_all_plugins():
        key = cls.__name__
        if key in seen:
            continue
        seen.add(key)
        result.append(
            PluginDTO(
                name=getattr(cls, "name", ""),
                # 扫描器面向若依框架，CMS 固定标记为 ruoyi
                cms="ruoyi",
                category=getattr(cls, "category", ""),
                severity=getattr(cls, "severity", "low"),
                description=getattr(cls, "description", ""),
                cve=getattr(cls, "cve", ""),
                affected_versions=getattr(cls, "affected_versions", ""),
                vuln_type=getattr(cls, "vuln_type", ""),
                supports_waf_bypass=getattr(cls, "supports_waf_bypass", False),
            )
        )
    return result


@router.get("/plugins/{name}", response_model=PluginDTO, summary="查询单个插件元数据")
async def get_plugin(name: str):
    """查询单个插件的元数据"""
    for cls in _load_all_plugins():
        plugin_name = getattr(cls, "name", "")
        # 支持按插件的 name 属性或类名两种方式精确查询
        if plugin_name == name or cls.__name__ == name:
            return PluginDTO(
                name=plugin_name,
                cms="ruoyi",
                category=getattr(cls, "category", ""),
                severity=getattr(cls, "severity", "low"),
                description=getattr(cls, "description", ""),
                cve=getattr(cls, "cve", ""),
                affected_versions=getattr(cls, "affected_versions", ""),
                vuln_type=getattr(cls, "vuln_type", ""),
                supports_waf_bypass=getattr(cls, "supports_waf_bypass", False),
            )
    raise HTTPException(status_code=404, detail=f"插件不存在: {name}")
