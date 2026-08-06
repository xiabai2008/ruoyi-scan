# D6.2 主入口接入与报告渲染单元测试
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chains.registry import get_chain, list_chains, register_chain
from main import build_parser

# === CLI 参数解析测试 ===

def test_parser_accepts_chain():
    """解析器接受 --chain 参数"""
    parser = build_parser()
    args = parser.parse_args(['--chain', 'ruoyi_sql_to_rce', '-u', 'http://x.com'])
    assert args.chain == 'ruoyi_sql_to_rce'


def test_parser_accepts_chain_list():
    """解析器接受 --chain-list 参数"""
    parser = build_parser()
    args = parser.parse_args(['--chain-list'])
    assert args.chain_list is True


def test_parser_chain_list_with_list_value():
    """--chain list 也能触发列表显示"""
    parser = build_parser()
    args = parser.parse_args(['--chain', 'list'])
    assert args.chain == 'list'


def test_parser_chain_default_none():
    """--chain 默认为 None"""
    parser = build_parser()
    args = parser.parse_args(['-u', 'http://x.com'])
    assert args.chain is None


# === 链注册表测试 ===

def test_list_chains_returns_list():
    """list_chains() 返回链列表"""
    chains = list_chains()
    assert isinstance(chains, list)
    assert len(chains) == 3, f'应注册 3 条链，实际 {len(chains)}'


def test_list_chains_has_required_fields():
    """每个链含 name/display_name/description/severity 字段"""
    chains = list_chains()
    for c in chains:
        assert 'name' in c
        assert 'display_name' in c
        assert 'description' in c
        assert 'severity' in c


def test_list_chains_contains_sql_to_rce():
    """链列表含 ruoyi_sql_to_rce"""
    chains = list_chains()
    names = [c['name'] for c in chains]
    assert 'ruoyi_sql_to_rce' in names


def test_get_chain_returns_none_for_unknown():
    """get_chain() 对未知链返回 None"""
    assert get_chain('nonexistent_chain') is None


def test_register_chain_dynamic():
    """动态注册链（mock 导入避免依赖未创建的模块）"""
    from unittest.mock import patch

    from core.chain import ChainDef
    mock_chain = ChainDef(name='mock', display_name='Mock', description='test')
    # mock importlib.import_module 返回含 CHAIN 属性的 mock 对象
    mock_module = type('MockModule', (), {'CHAIN': mock_chain})()
    with patch('importlib.import_module', return_value=mock_module):
        register_chain('test_dynamic', 'chains.mock_module', 'CHAIN')
        chain = get_chain('test_dynamic')
        assert chain is mock_chain, '动态注册的链应能获取'


if __name__ == '__main__':
    test_parser_accepts_chain()
    test_parser_accepts_chain_list()
    test_parser_chain_list_with_list_value()
    test_parser_chain_default_none()
    test_list_chains_returns_list()
    test_list_chains_has_required_fields()
    test_list_chains_contains_sql_to_rce()
    test_get_chain_returns_none_for_unknown()
    test_register_chain_dynamic()
    print('All D6.2 CLI integration tests passed!')
