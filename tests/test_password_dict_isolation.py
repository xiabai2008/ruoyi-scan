# A：口令字典并发隔离
#  - 插件级：session.password_dict 优先于进程级 settings.PASSWORD_DICT，并发互不串扰
#  - orchestrator 级：字典分级注入 session，不改写进程级全局
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

from config import settings
from core.orchestrator import ScanOrchestrator, ScanRequest
from plugins.ruoyi.druid_brute import DruidBrutePlugin


class _FakeResponse:
    status_code = 200
    text = "error"

    def json(self):
        raise ValueError("not json")


class _FakeSession:
    """记录所有尝试过的口令；password_dict 为扫描级注入的字典路径"""

    def __init__(self, password_dict=None):
        if password_dict is not None:
            self.password_dict = password_dict
        self.attempts = []

    def post(self, url, data=None, **kwargs):
        self.attempts.append(dict(data or {}))
        return _FakeResponse()


def _write_dict(tmp_path, name, passwords):
    p = tmp_path / name
    p.write_text("\n".join(passwords) + "\n", encoding="utf-8")
    return str(p)


def test_session_dict_takes_precedence(tmp_path, monkeypatch):
    """session.password_dict 生效；进程级 settings.PASSWORD_DICT 不参与本次读取"""
    session_dict = _write_dict(tmp_path, "session.txt", ["AAA_ONLY"])
    monkeypatch.setattr(settings, "PASSWORD_DICT", str(tmp_path / "should_not_be_used.txt"))
    sess = _FakeSession(session_dict)

    DruidBrutePlugin().verify("http://target.test", sess)

    tried = {x.get("loginPassword") for x in sess.attempts}
    assert tried == {"AAA_ONLY"}


def test_fallback_to_settings_without_session_attr(tmp_path, monkeypatch):
    """无 session.password_dict（兼容旧调用方）时回退进程级默认值"""
    fallback_dict = _write_dict(tmp_path, "fallback.txt", ["CCC_FALLBACK"])
    monkeypatch.setattr(settings, "PASSWORD_DICT", fallback_dict)
    sess = _FakeSession()  # 不注入扫描级字典

    DruidBrutePlugin().verify("http://target.test", sess)

    tried = {x.get("loginPassword") for x in sess.attempts}
    assert tried == {"CCC_FALLBACK"}


def test_concurrent_scans_use_their_own_dicts(tmp_path):
    """并发场景：两个扫描各自读自己的字典，互不串扰"""
    dict_a = _write_dict(tmp_path, "a.txt", ["PASS_A"])
    dict_b = _write_dict(tmp_path, "b.txt", ["PASS_B"])
    sessions = [_FakeSession(dict_a), _FakeSession(dict_b)]

    with ThreadPoolExecutor(max_workers=2) as ex:
        list(ex.map(lambda s: DruidBrutePlugin().verify("http://target.test", s), sessions))

    assert {x.get("loginPassword") for x in sessions[0].attempts} == {"PASS_A"}
    assert {x.get("loginPassword") for x in sessions[1].attempts} == {"PASS_B"}


def test_orchestrator_injects_dict_without_global_mutation(tmp_path, monkeypatch):
    """orchestrator：按 pass_level 注入 session.password_dict，不改写进程级全局"""
    from core import orchestrator as orch_mod

    target_dict = _write_dict(tmp_path, "top100.txt", ["X"])
    monkeypatch.setitem(settings.PASSWORD_DICT_BY_LEVEL, "top100", target_dict)
    before = settings.PASSWORD_DICT
    captured = {}
    real_cls = orch_mod.SessionManager

    class _Recorder(real_cls):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured["session"] = self

    orch = ScanOrchestrator()
    req = ScanRequest(target="http://example.com/", mode="p", pass_level="top100")
    with patch("core.orchestrator.SessionManager", _Recorder), patch("core.orchestrator.Router") as mock_router, patch(
        "core.orchestrator.detect_cms"
    ) as mock_cms, patch("core.orchestrator.detect_waf") as mock_waf, patch(
        "core.orchestrator.load_plugins"
    ) as mock_load:
        mock_router.return_value.resolve.return_value = []
        mock_router.return_value.resolve_by_name.return_value = []
        mock_cms.return_value = MagicMock(cms="ruoyi", version="", confidence=0.9, matched=["test"])
        mock_waf.return_value = {"waf": "", "display": "无", "bypass_hint": ""}
        mock_load.return_value = []
        orch.run_sync(req)

    assert settings.PASSWORD_DICT == before, "进程级字典不得被扫描改写"
    assert captured["session"].password_dict == target_dict
