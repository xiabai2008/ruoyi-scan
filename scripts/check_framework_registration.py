#!/usr/bin/env python
"""框架注册门禁：每个插件包都必须出现在所有「框架清单」里。

为什么需要这个脚本
==================
JeecgBoot 接入时（F5）只把**扫描路径**做通了（R10 上 8/8 CONFIRMED），
但配套清单全漏了。逐条实测确认的后果（2026-11-02）：

  - `--cms jeecgboot` → argparse 直接拒绝 `invalid choice`
  - `--plugin-new --category jeecgboot` → `ValueError: unsupported category`
  - AI 生成插件同样拒绝该类目
  - `export_plugins()` 只导 3 个包 → 模板仓库 / Ed25519 签名分发里没有 jeecg
  - 桌面端 / Web 端把 jeecg 插件标成 `cms=ruoyi`
  - `data/acceptance_baseline.json` 只有若依靶 → jeecg 无 nightly 回归门

这批漏项的共同点：**CI 全都不查**。所以第 3 个框架会再漏一遍同样的清单。

本脚本把「哪些地方需要登记」固化成断言。新增框架时若忘了某处，CI 直接红。

用法
----
    python scripts/check_framework_registration.py          # 检查
    python scripts/check_framework_registration.py -v       # 打印详情

退出码：0 全部登记 / 1 存在遗漏
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def _categories() -> list:
    from core.loader import known_categories

    return known_categories()


def check_cms_choices(cats: list) -> list:
    """--cms 的 choices 必须覆盖所有插件类别（且是从包派生而非写死）"""
    src = io.open(os.path.join(_PROJECT_ROOT, "main.py"), encoding="utf-8").read()
    if "choices=_known_categories()" not in src:
        return ["main.py: --cms 的 choices 没有从 _known_categories() 派生（写死会拒绝新框架）"]
    # 派生后需确认真的能枚举到全部类别
    try:
        from main import _known_categories

        got = set(_known_categories())
    except Exception as e:  # noqa: BLE001
        return [f"main.py: _known_categories() 调用失败: {e}"]
    missing = set(cats) - got
    return [f"main.py: _known_categories() 少了 {missing}"] if missing else []


def check_category_whitelists(cats: list) -> list:
    """三处 category 白名单不得再写死三元组"""
    problems = []
    for rel in ("lib/plugin_sdk.py", "lib/ai_generator.py", "lib/ai_validate.py"):
        src = io.open(os.path.join(_PROJECT_ROOT, rel), encoding="utf-8").read()
        if 'not in ("ruoyi", "spring", "common")' in src:
            problems.append(f"{rel}: category 白名单仍写死三元组，新框架会被拒绝")
        elif "known_categories()" not in src:
            problems.append(f"{rel}: 未使用 known_categories() 派生类别")
    return problems


def check_export_plugins(cats: list) -> list:
    """export_plugins 必须导出所有包（否则模板仓库/签名分发缺包）"""
    src = io.open(os.path.join(_PROJECT_ROOT, "lib/plugin_repo.py"), encoding="utf-8").read()
    if 'for pkg_name in ["plugins.ruoyi", "plugins.spring", "plugins.common"]:' in src:
        return ["lib/plugin_repo.py: export_plugins 的包列表仍写死三元组"]
    if "discover_plugin_packages()" not in src:
        return ["lib/plugin_repo.py: export_plugins 未使用 discover_plugin_packages()"]
    return []


def check_api_cms(cats: list) -> list:
    """插件 API 的 cms 字段必须按插件实际归属派生"""
    src = io.open(os.path.join(_PROJECT_ROOT, "api/routes/plugin.py"), encoding="utf-8").read()
    if 'cms="ruoyi",' in src:
        return ['api/routes/plugin.py: cms 仍写死 "ruoyi"，jeecg 插件会被归错类']
    return []


def check_acceptance_baseline(cats: list) -> list:
    """acceptance baseline 应覆盖每个框架至少一个靶（否则新框架无 nightly 回归门）"""
    path = os.path.join(_PROJECT_ROOT, "data/acceptance_baseline.json")
    try:
        data = json.load(io.open(path, encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return [f"data/acceptance_baseline.json: 无法读取: {e}"]
    names = " ".join(str(t.get("name", "")) + str(t.get("url", "")) for t in data.get("targets", [])).lower()
    desc = str(data.get("description", "")).lower()
    problems = []
    # common 是通用包，不绑定特定框架，不需要专属靶场
    for cat in cats:
        if cat == "common":
            continue
        if cat in names:
            continue
        # 「已登记待建」也算登记——但必须在 description 里写明，
        # 让「有没有回归门」这件事在文档层面可查，而不是静默缺失。
        if cat in desc:
            continue
        problems.append(
            f"data/acceptance_baseline.json: 没有 {cat} 的靶场，也未登记为待建——"
            f"该框架的插件在 nightly acceptance 中永远不会被验证"
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="框架注册完整性门禁")
    parser.add_argument("-v", "--verbose", action="store_true", help="打印每个类别与检查项")
    args = parser.parse_args()

    cats = _categories()
    if args.verbose:
        print(f"发现的插件类别: {cats}")

    problems = []
    for fn in (
        check_cms_choices,
        check_category_whitelists,
        check_export_plugins,
        check_api_cms,
        check_acceptance_baseline,
    ):
        found = fn(cats)
        if args.verbose and not found:
            print(f"  OK   {fn.__name__}")
        problems.extend(found)

    if problems:
        print(f"[!]框架注册不完整（{len(problems)} 处）：", file=sys.stderr)
        for p in problems:
            print(f"    - {p}", file=sys.stderr)
        print("\n新增框架时需同步的清单见 scripts/check_framework_registration.py 顶部注释。", file=sys.stderr)
        return 1

    print(f"[+]框架注册完整：{len(cats)} 个类别（{', '.join(cats)}）均已登记")
    return 0


if __name__ == "__main__":
    sys.exit(main())
