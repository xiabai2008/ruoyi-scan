"""F9 回归：路径作用域分流（根静态资源 vs API 端点）。

背景（实测复现，2026-11-01）
----------------------------
`core/orchestrator.py` 探到 API 前缀后，把 **所有** 插件的探测基准都改写成
`target + api_base`。但 `.git` / `.env` / 备份 / IDE 残留是运维丢在 **web 根** 的
静态文件，加了前缀反而探不到。

R7（RuoYi-Vue 3.8.9，Nginx 只反代 /prod-api/）实测：

    GET  http://127.0.0.1:19107/.git/HEAD        → 200  23 字节「ref: refs/heads/master」
    GET  http://127.0.0.1:19107/prod-api/.git/HEAD → 502

同一座站，仅因后端生死不同，`.git` 结论完全相反：

| R7 后端 | detect_api_base | 实际探测的 URL         | 判定                |
|---------|-----------------|------------------------|---------------------|
| 502     | ""（探不到）     | /.git/HEAD             | CONFIRMED（正确）    |
| 200     | /prod-api       | /prod-api/.git/HEAD    | 不存在（错误 SAFE）  |

修法：插件声明 `path_scope`（api / root / both），引擎按声明选探测基准。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import ScanEngine  # noqa: E402
from plugins.base import PluginBase  # noqa: E402

API_TARGET = "http://127.0.0.1:19107/prod-api/"
ROOT_TARGET = "http://127.0.0.1:19107"


class _ProbeRecorder:
    """记录每个插件实际收到的 target，用来断言引擎分配是否正确。"""

    def __init__(self):
        self.received = {}

    def make_plugin(self, name, path_scope):
        recorder = self

        class _P(PluginBase):
            category = "test"
            severity = "low"
            # 用类属性名覆盖，测试读不到闭包变量
            _test_name = name

            def verify(self, target, session):
                recorder.received[self._test_name] = target
                return self._build_result("SAFE", url=target, evidence="recorder")

        _P.name = name
        _P.path_scope = path_scope
        return _P


def _run(plugins, target=API_TARGET, root_target=ROOT_TARGET):
    recorder = _ProbeRecorder()
    classes = [recorder.make_plugin(n, s) for n, s in plugins]
    ScanEngine(threads=1).run(classes, target, session=object(), root_target=root_target)
    return recorder.received


# ── 核心分流 ──────────────────────────────────────────────


def test_root_scope_plugin_gets_unprefixed_target():
    """path_scope="root" 的插件必须拿到站点根，不能跟随 API 前缀。

    这是 bug 的直接回归：修前它拿到的是 /prod-api/，导致 .git 永远探不到。
    """
    got = _run([("GitLeak", "root")])
    assert got["GitLeak"] == ROOT_TARGET, f"根静态插件被错误地推到 API 前缀下: {got['GitLeak']}"
    assert "/prod-api" not in got["GitLeak"]


def test_api_scope_plugin_gets_prefixed_target():
    """path_scope="api"（默认）的插件继续跟随前缀，行为不变。"""
    got = _run([("SwaggerLeak", "api")])
    assert got["SwaggerLeak"] == API_TARGET


def test_default_scope_is_api():
    """未声明 path_scope 的插件按 api 处理 —— 不能让存量插件静默改变探测位置。"""
    assert PluginBase.path_scope == "api"

    class _NoScope(PluginBase):
        name = "NoScope"
        category = "test"
        severity = "low"
        seen = ""

        def verify(self, target, session):
            _NoScope.seen = target
            return self._build_result("SAFE", url=target, evidence="x")

    ScanEngine(threads=1).run([_NoScope], API_TARGET, session=object(), root_target=ROOT_TARGET)
    assert _NoScope.seen == API_TARGET


# ── 兼容性 ────────────────────────────────────────────────


def test_empty_root_target_falls_back_to_target():
    """未传 root_target 时（老调用方 / 单机版无前缀），root 作用域等价于 target。

    单机版 detect_api_base 返回空串，plugin_target == target，此时两个参数相同，
    root 与 api 没有区别 —— 不能因为没传 root_target 就让插件收到空字符串。
    """
    got = _run([("GitLeak", "root")], target=ROOT_TARGET, root_target="")
    assert got["GitLeak"] == ROOT_TARGET


def test_both_scope_gets_root_target():
    """path_scope="both" 拿到根路径作为基准，由插件自己拼前缀版本做双探。"""
    got = _run([("Dual", "both")])
    assert got["Dual"] == ROOT_TARGET


# ── 真实插件的声明正确性 ──────────────────────────────────


def test_static_leak_plugins_declare_root_scope():
    """根静态资源类插件必须声明 root，否则分离版站点整类漏报。

    这五个插件探的都是部署在 web 根的文件，加了 API 前缀必然探不到。
    """
    from plugins.common.backup_scan import BackupScanPlugin
    from plugins.common.dir_listing import DirListingPlugin
    from plugins.common.env_leak import EnvLeakPlugin
    from plugins.common.git_leak import GitLeakPlugin
    from plugins.common.source_leak import SourceLeakPlugin

    for cls in (GitLeakPlugin, EnvLeakPlugin, BackupScanPlugin, SourceLeakPlugin, DirListingPlugin):
        assert cls.path_scope == "root", f"{cls.__name__} 应声明 path_scope='root'，实际 {cls.path_scope!r}"


def test_api_plugins_keep_api_scope():
    """API 端点类插件保持默认 api，不能改成 root（否则分离版下探不到后端）。"""
    from plugins.common.swagger_leak import SwaggerLeakPlugin
    from plugins.spring.actuator_unauth import SpringActuatorUnauthPlugin

    for cls in (SwaggerLeakPlugin, SpringActuatorUnauthPlugin):
        assert cls.path_scope == "api", f"{cls.__name__} 应保持 path_scope='api'，实际 {cls.path_scope!r}"
