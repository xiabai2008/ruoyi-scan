# -*- coding: utf-8 -*-
"""会话隔离门禁：插件禁止直接实例化 RuoYiAuthChain

背景（2026-09-17 多版本矩阵实测事故）
======================================
各插件复用同一个 SessionManager。若插件在共享会话上登录，认证状态会**一直保留
给后续插件**，而其余插件的判定普遍以「未认证基线」为前提——已认证访问不存在路径
时 v4.7.8 返回 404，但 v4.8.3（Spring Boot 4.0.3）返回 200，于是 v4.8.3 一次性
多出 6 个假 CONFIRMED（备份文件 65 个 / MinIO / RocketMQ / Swagger / IDE 残留 / Plus 认证）。

⚠ 不能用「cookie 快照 + 还原」做隔离——已实测无效：Shiro 把认证状态存在
**服务端** session（按 JSESSIONID 索引），把 cookie 还原成同一个 JSESSIONID，
服务端仍视其为已认证。

唯一正确做法：需鉴权的插件用 `core.auth_chain.isolated_auth_session` 自建独立会话。
本门禁用 AST 静态检查保证 `plugins/**` 不再出现直接实例化，防止回归。

范围说明：仅限 plugins/**。lib/auth_surface.py 的 `--auth-surface` 模式自建并持有
自己的会话（不与插件共享），属合法直连用法，不在门禁范围。
"""

import ast
import os
import pathlib
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parent.parent / "plugins"
FORBIDDEN_NAME = "RuoYiAuthChain"
REQUIRED_HELPER = "isolated_auth_session"


def _plugin_files():
    """全部插件源文件（排除 __init__.py 与链专用包）"""
    excluded_dirs = {"__pycache__", "chain"}
    for path in sorted(PLUGIN_ROOT.rglob("*.py")):
        if any(part in excluded_dirs for part in path.parts):
            continue
        if path.name == "__init__.py":
            continue
        yield path


def test_no_plugin_instantiates_auth_chain_directly():
    """plugins/** 不得出现 RuoYiAuthChain(...) 直接实例化（含 import）

    违规形态：
        from core.auth_chain import RuoYiAuthChain
        chain = RuoYiAuthChain(target, session, ...)   # ← session 是共享会话！

    正确形态：
        from core.auth_chain import isolated_auth_session
        with isolated_auth_session(target, user, pwd) as (sess, ok, reason): ...
    """
    violations = []
    for path in _plugin_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            # import 形态：from core.auth_chain import RuoYiAuthChain
            if isinstance(node, ast.ImportFrom) and node.module == "core.auth_chain":
                for alias in node.names:
                    if alias.name == FORBIDDEN_NAME:
                        violations.append(f"{path.name}:{node.lineno} import {FORBIDDEN_NAME}")
            # 实例化形态：RuoYiAuthChain(...) / auth_chain.RuoYiAuthChain(...)
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else "")
                if name == FORBIDDEN_NAME:
                    violations.append(f"{path.name}:{node.lineno} call {name}(...)")
    assert not violations, (
        "检测到插件直接实例化 RuoYiAuthChain（会把登录态泄漏给共享会话，"
        f"在 v4.8.3 上引发跨插件误报）。请改用 core.auth_chain.isolated_auth_session：{violations}"
    )
    print(f"PASS test_no_plugin_instantiates_auth_chain_directly: plugins/ 全部合规")


def test_auth_plugins_use_isolated_session():
    """所有需要登录态的插件都应通过 isolated_auth_session 获取会话

    以「引用了 RuoYiAuthChain 所在模块」作为需要登录态的判据（import 即特征），
    校验其同时导入了 REQUIRED_HELPER。
    """
    missing = []
    for path in _plugin_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        touches_auth_chain = any(
            isinstance(node, ast.ImportFrom) and node.module == "core.auth_chain"
            for node in ast.walk(tree)
        )
        if not touches_auth_chain:
            continue
        uses_helper = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "core.auth_chain"
            and any(a.name == REQUIRED_HELPER for a in node.names)
            for node in ast.walk(tree)
        )
        if not uses_helper:
            missing.append(path.name)
    assert not missing, (
        f"以下插件引用了 core.auth_chain 却未使用 {REQUIRED_HELPER}（必须用独立会话，"
        f"禁止在共享会话上登录）: {missing}"
    )
    print(f"PASS test_auth_plugins_use_isolated_session")


if __name__ == "__main__":
    test_no_plugin_instantiates_auth_chain_directly()
    test_auth_plugins_use_isolated_session()
    print("ALL_SESSION_ISOLATION_GATE_PASS")
