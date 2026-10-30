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
            # 插件包系统性损坏（导入错误/缺 plugin_list）不能静默：升级为 warning 以便发现
            logger.warning("加载插件包 %s 失败", pkg, exc_info=True)
    return plugins


# 插件元数据占位符：插件模板默认 cve="N/A"，前端 `p.cve` 真值判断会把
# “没有 CVE”当成“有 CVE”，导致 CVE 计数/筛选全量命中（测评 P1-11）。
# 归一化在后端完成，所有消费方（桌面端/Web/第三方）看到同一契约。
_META_PLACEHOLDERS = {"", "n/a", "na", "none", "null", "-", "—"}


def _clean_meta(value) -> str:
    """清理插件元数据占位符，空值统一返回空串"""
    text = str(value or "").strip()
    return "" if text.lower() in _META_PLACEHOLDERS else text


def _to_dto(cls) -> PluginDTO:
    """插件类 → PluginDTO（list/get 两个端点共用，字段构造只保留一处）"""
    return PluginDTO(
        name=getattr(cls, "name", ""),
        # 扫描器面向若依框架，CMS 固定标记为 ruoyi
        cms="ruoyi",
        category=getattr(cls, "category", ""),
        severity=getattr(cls, "severity", "low"),
        description=getattr(cls, "description", ""),
        cve=_clean_meta(getattr(cls, "cve", "")),
        affected_versions=_clean_meta(getattr(cls, "affected_versions", "")),
        vuln_type=getattr(cls, "vuln_type", ""),
        supports_waf_bypass=getattr(cls, "supports_waf_bypass", False),
    )


def _iter_unique_plugins():
    """按类名去重的插件类迭代器（多个插件包可能注册同一个插件类）

    list_plugins 与 get_plugin 共用，保证两个端点对"存在哪些插件"的判断一致。
    """
    seen = set()
    for cls in _load_all_plugins():
        key = cls.__name__
        if key in seen:
            continue
        seen.add(key)
        yield cls


@router.get("/plugins", response_model=list[PluginDTO], summary="列出所有已加载插件")
def list_plugins():
    """列出所有已加载的扫描插件

    同步 def：_load_all_plugins 含阻塞式文件系统发现与模块导入，
    FastAPI 在线程池执行，避免阻塞事件循环。
    """
    return [_to_dto(cls) for cls in _iter_unique_plugins()]


@router.get("/plugins/{name}", response_model=PluginDTO, summary="查询单个插件元数据")
def get_plugin(name: str):
    """查询单个插件的元数据（同步 def：同上，阻塞式加载走线程池）"""
    for cls in _iter_unique_plugins():
        plugin_name = getattr(cls, "name", "")
        # 支持按插件的 name 属性或类名两种方式精确查询
        if plugin_name == name or cls.__name__ == name:
            return _to_dto(cls)
    raise HTTPException(status_code=404, detail=f"插件不存在: {name}")
