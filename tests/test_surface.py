# D14 攻击面清单（lib/surface_inventory.py）单元测试：去重 / 归一化 / 上限 / 非法 URL / 序列化
import json

from lib.surface_inventory import SurfaceEndpoint, SurfaceInventory


def test_add_dedup():
    inv = SurfaceInventory()
    assert inv.add("http://t/a", "crawl") is True
    assert inv.add("http://t/a", "js") is False
    assert len(inv.endpoints) == 1
    assert inv.endpoints[0].source == "crawl"


def test_add_normalizes():
    inv = SurfaceInventory()
    assert inv.add("http://t/", "crawl") is True
    assert inv.add("http://t", "js") is False
    assert len(inv.endpoints) == 1
    assert inv.truncated is False


def test_truncated_at_limit():
    inv = SurfaceInventory(max_endpoints=3)
    assert inv.add("http://t/1", "crawl") is True
    assert inv.add("http://t/2", "crawl") is True
    assert inv.add("http://t/3", "crawl") is True
    assert inv.add("http://t/4", "crawl") is False
    assert inv.truncated is True
    assert len(inv.endpoints) == 3


def test_reject_bad_url():
    inv = SurfaceInventory()
    assert inv.add("", "crawl") is False
    assert inv.add("ftp://x", "crawl") is False
    assert inv.add("javascript:alert(1)", "js") is False
    assert inv.endpoints == []


def test_to_dict_json():
    inv = SurfaceInventory(pages=["http://t/"])
    inv.add("http://t/api/user?id=1", "js")
    data = inv.to_dict()
    serialized = json.dumps(data)
    assert "truncated" in data
    assert data["truncated"] is False
    assert "truncated" in serialized
    assert data["endpoints"] == [{"url": "http://t/api/user?id=1", "source": "js", "method_hint": "GET"}]


def test_custom_endpoints_seed_dedup_index():
    """预置 endpoints（如跨批次合并）时，去重索引必须包含它们"""
    inv = SurfaceInventory(endpoints=[SurfaceEndpoint(url="http://t/a", source="crawl")])
    assert inv.add("http://t/a", "js") is False
    assert len(inv.endpoints) == 1
