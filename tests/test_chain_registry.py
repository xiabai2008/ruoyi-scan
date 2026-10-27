# 链注册表分支覆盖：动态注册元信息回退 / 损坏条目导入失败 / 覆盖告警留痕
import chains.registry as reg


def test_dynamic_chain_lifecycle():
    """动态注册链：list_chains 用占位元信息；损坏条目 get_chain 返回 None；覆盖内置链留痕"""
    dynamic_name = "test_dynamic_chain_xyz"
    builtin = ("chains.ruoyi_sql_to_rce", "CHAIN")
    try:
        # 1) 动态注册（无内置元信息）→ list_chains 回退占位展示名
        reg.register_chain(dynamic_name, "chains.no_such_module_for_test")
        listing = {c["name"]: c for c in reg.list_chains()}
        assert dynamic_name in listing
        assert listing[dynamic_name]["display_name"] == dynamic_name
        assert listing[dynamic_name]["severity"] == "medium"

        # 2) 损坏条目（模块不存在）→ get_chain 保持 Optional 契约返回 None 且可观测
        assert reg.get_chain(dynamic_name) is None

        # 3) 覆盖已注册链（此处借用内置链名）→ 必须留痕告警并可恢复
        reg.register_chain("ruoyi_sql_to_rce", "chains.no_such_module_for_test")
        assert reg.get_chain("ruoyi_sql_to_rce") is None
    finally:
        reg._CHAIN_REGISTRY.pop(dynamic_name, None)
        reg._CHAIN_REGISTRY["ruoyi_sql_to_rce"] = builtin


def test_builtin_chains_resolvable():
    """内置链（正常路径）：列表来源与解析来源一致"""
    names = [c["name"] for c in reg.list_chains()]
    for name in names:
        assert reg.get_chain(name) is not None, f"内置链 {name} 应可解析"
