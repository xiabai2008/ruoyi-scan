# F7-1：cms 为空时的插件回退必须同时覆盖 plugins.ruoyi 与 plugins.spring。
#
# 背景：C2-2（Spring4Shell，19313）cms=""，旧实现只回退 plugins.ruoyi，
# 报告里没有任何 Spring 插件结果。本测试锁定回退覆盖面、common 追加与去重。
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import plugins.common as common_package  # noqa: E402
import plugins.ruoyi as ruoyi_package  # noqa: E402
import plugins.spring as spring_package  # noqa: E402
from common.models import FingerprintResult  # noqa: E402
from core import orchestrator as orchestrator_module  # noqa: E402
from core.orchestrator import ScanOrchestrator, ScanRequest  # noqa: E402

# 不要在模块导入期快照 plugin_list：其他测试会临时 append 再恢复，
# 模块级快照会永久持有被污染的那个 list 对象（pytest-randomly 下概率性红）。
# 断言时现取 ruoyi_package.plugin_list / spring_package.plugin_list。


def _run_empty_cms_scan(monkeypatch, captured_plugins):
    """跑一次 cms 为空的扫描，捕获引擎实际拿到的插件类。"""
    monkeypatch.setattr(orchestrator_module, "preflight", lambda *a, **k: (True, "connect", ""))
    monkeypatch.setattr(
        orchestrator_module,
        "detect_cms",
        lambda *a, **k: FingerprintResult(cms="", version="", confidence=0.0, matched=[]),
    )
    monkeypatch.setattr(
        orchestrator_module,
        "detect_waf",
        lambda *a, **k: {"waf": "", "display": "", "bypass_hint": ""},
    )
    monkeypatch.setattr("core.basepath.detect_api_base", lambda *a, **k: "")
    monkeypatch.setattr("lib.reachability.detect_blocked", lambda *a, **k: {"blocked": False})
    monkeypatch.setattr(
        "lib.reachability.detect_auth_wall",
        lambda *a, **k: {"wall": False, "reason": "", "status": 0},
    )
    monkeypatch.setattr("lib.plugin_repo.load_user_installed_plugins", lambda: [])
    monkeypatch.setattr("core.loader.load_entry_point_plugins", lambda: [])

    def fake_engine_run(self, plugin_classes, *args, **kwargs):
        captured_plugins.extend(plugin_classes)
        return []

    monkeypatch.setattr(orchestrator_module.ScanEngine, "run", fake_engine_run)

    events = []

    def on_event(event_type, payload):
        events.append((event_type, payload))

    ScanOrchestrator().run_sync(
        ScanRequest(target="http://f7-empty-cms.test/", mode="u"),
        on_event=on_event,
    )
    return events


def test_empty_cms_fallback_loads_ruoyi_and_spring(monkeypatch):
    """cms 为空：ruoyi + spring 都进入候选，且插件不重复。"""
    captured = []
    events = _run_empty_cms_scan(monkeypatch, captured)

    captured_set = set(captured)
    missing_spring = [cls for cls in spring_package.plugin_list if cls not in captured_set]
    missing_ruoyi = [cls for cls in ruoyi_package.plugin_list if cls not in captured_set]
    assert not missing_spring, f"回退未加载 Spring 插件：{[c.__name__ for c in missing_spring]}"
    assert not missing_ruoyi, f"回退未加载 RuoYi 插件：{[c.__name__ for c in missing_ruoyi]}"
    assert len(captured) == len(captured_set), "同一个插件类被重复加入候选"

    fallback_events = [payload for event_type, payload in events if event_type == "plugin_fallback"]
    assert fallback_events, "cms 为空时必须发出 plugin_fallback 事件"
    packages = {item["package"]: item["count"] for item in fallback_events[0]["packages"]}
    assert packages["plugins.ruoyi"] > 0
    assert packages["plugins.spring"] > 0


def test_empty_cms_fallback_still_appends_common(monkeypatch):
    """回退只补 CMS 包，plugins.common 仍必须追加。"""
    captured = []
    _run_empty_cms_scan(monkeypatch, captured)

    captured_set = set(captured)
    missing_common = [cls for cls in common_package.plugin_list if cls not in captured_set]
    assert not missing_common, f"回退后 common 插件缺失：{[c.__name__ for c in missing_common]}"


def test_fallback_dedupes_same_class_across_packages(monkeypatch):
    """两个包导出同一个类对象时只保留一份。"""

    class DummyPlugin:
        pass

    monkeypatch.setattr(orchestrator_module, "load_plugins", lambda package: [DummyPlugin, DummyPlugin])

    plugins, details = orchestrator_module._load_fallback_plugins()

    assert plugins == [DummyPlugin]
    counts = {item["package"]: item["count"] for item in details}
    assert counts == {"plugins.ruoyi": 1, "plugins.spring": 0}


def test_spring_load_failure_does_not_block_ruoyi(monkeypatch):
    """plugins.spring 加载失败只 warning：ruoyi 包仍正常返回。"""
    real_load_plugins = orchestrator_module.load_plugins

    def flaky_load(package):
        if package == "plugins.spring":
            raise ImportError("spring package broken")
        return real_load_plugins(package)

    monkeypatch.setattr(orchestrator_module, "load_plugins", flaky_load)

    plugins, details = orchestrator_module._load_fallback_plugins()

    assert any(cls in plugins for cls in ruoyi_package.plugin_list), "spring 失败不得影响 ruoyi 插件加载"
    spring_detail = next(item for item in details if item["package"] == "plugins.spring")
    assert spring_detail["count"] == 0
    assert "spring package broken" in spring_detail["error"]
