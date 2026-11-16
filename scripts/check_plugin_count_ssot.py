#!/usr/bin/env python
"""v1.7 WP-3：插件数量 SSOT 门禁。

唯一事实源
==========
`scripts/export_plugin_list.py::collect()` 的 `len()`（与运行时 `--plugin-list`
完全一致）。当前为 56：ruoyi 20 / spring 14 / common 12 / jeecgboot 8 / yudao 2。

检查范围
========
只检查「对外口径」文件，避免误伤历史快照：
  - README.md / README_EN.md / ROADMAP.md
  - docs/index.md / docs/community.md / docs/usage.md / docs/plugin_dev.md /
    docs/desktop.md / docs/api.md / docs/quickstart.md
  - docs/wiki/*.md
  - docs/promo/*.txt（生成的 ruoyi-scan-plugins.txt 除外）
  - pyproject.toml
  - desktop/src/data/mock.ts

历史文件（release-notes/、CHANGELOG、blind_test_report*、_plan_*、_task_*、
research_*、artifacts/、lab/、verification-matrix.md、生成的插件清单）不扫描；
这些文件里的 54/52/29/46/48 是当时的真实数据。

用法
====
    python scripts/check_plugin_count_ssot.py
    python scripts/check_plugin_count_ssot.py -v
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.export_plugin_list import collect  # noqa: E402

# 对外口径文件（相对仓库根）
DOC_FILES = [
    "README.md",
    "README_EN.md",
    "ROADMAP.md",
    "pyproject.toml",
    "desktop/src/data/mock.ts",
]
for name in ("index", "community", "usage", "plugin_dev", "desktop", "api", "quickstart", "devsecops"):
    DOC_FILES.append(f"docs/{name}.md")
DOC_FILES += [str(p.relative_to(REPO)) for p in sorted((REPO / "docs" / "wiki").glob("*.md"))]
DOC_FILES += [
    str(p.relative_to(REPO))
    for p in sorted((REPO / "docs" / "promo").glob("*.txt"))
    if p.name != "ruoyi-scan-plugins.txt"
]

# 「总数」口径的正则：匹配数字必须等于运行时插件数
TOTAL_PATTERNS = [
    re.compile(r"(\d+)\s*个\s*(?:检测\s*)?POC\s*插件"),
    re.compile(r"(\d+)\s*个\s*(?:检测\s*)?插件"),
    re.compile(r"(\d+)\s*检测插件"),
    re.compile(r"共\s*(\d+)\s*个插件"),
    re.compile(r"(\d+)\s*POCs?\b", re.IGNORECASE),
    re.compile(r"(\d+)\s*(?:POC\s*)?plugins?\b", re.IGNORECASE),
    re.compile(r"检测插件数\s*\|\s*(\d+)"),
]

# 允许出现「非当前总数」的上下文（历史快照/口径说明/生成物/其他计数口径）
ALLOW_CONTEXT = (
    "盲测",
    "v1.5",
    "历史",
    "原表述",
    "修正为",
    "原 README",
    "原先",
    "旧版",
    "文件总数",
    "实际执行数",
    "口径",
    "release",
    "CHANGELOG",
    "已经过去",
    "18 个插件",  # wiki 的「已修正」表：README 旧表述（若依 18 → 20）
)

# 形如 29/54、46/54、48/54 的历史表：仅允许分母 54，且必须带历史上下文
RATIO_PATTERN = re.compile(r"(\d+)\s*/\s*(\d+)\s*(?:plugins|插件)", re.IGNORECASE)


def _package_counts(plugins: List[dict]) -> dict:
    counts: dict = {}
    for p in plugins:
        counts[p["package"]] = counts.get(p["package"], 0) + 1
    return counts


def _check_line(
    path: str, lineno: int, line: str, runtime: int, package_values: set, verbose: bool
) -> List[str]:
    errors: List[str] = []
    if any(ctx in line for ctx in ALLOW_CONTEXT):
        return errors
    # 中文引号里的「历史表述」不判错
    if "「" in line or "」" in line:
        return errors

    # 分项行（若依 20 / Spring 14 / 通用 12 / Jeecg 8 / 芋道 2）允许出现包级数字
    pkg_hint = ("ruoyi", "spring", "common", "jeecg", "yudao", "若依", "通用", "芋道", "plus")
    has_pkg_hint = any(h in line.lower() for h in pkg_hint)

    seen = set()
    for pattern in TOTAL_PATTERNS:
        for m in pattern.finditer(line):
            value = int(m.group(1))
            if value in seen:
                continue
            seen.add(value)
            if value == runtime:
                continue
            if has_pkg_hint and value in package_values:
                continue
            errors.append(
                f"{path}:{lineno}: 插件数量写作 {value}，运行时为 {runtime}；"
                f"请改为 {runtime} 或注明历史/其他口径"
            )
    for m in RATIO_PATTERN.finditer(line):
        numerator, denominator = int(m.group(1)), int(m.group(2))
        if denominator != runtime:
            errors.append(
                f"{path}:{lineno}: 分表示例 {numerator}/{denominator} 的分母应为 {runtime}"
            )
    if verbose and seen:
        print(f"  {path}:{lineno}: 检查到 {sorted(seen)}")
    return errors


def main(argv: List[str]) -> int:
    verbose = "-v" in argv or "--verbose" in argv
    plugins = collect()
    runtime = len(plugins)
    packages = _package_counts(plugins)
    print(f"[*] 运行时插件数（SSOT）：{runtime}")
    print("    分项：" + " / ".join(f"{k} {v}" for k, v in sorted(packages.items())))

    errors: List[str] = []
    package_values = set(packages.values())
    for rel in DOC_FILES:
        path = REPO / rel
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            errors.extend(_check_line(rel, lineno, line, runtime, package_values, verbose))

    if errors:
        print("\n[!] 插件数量 SSOT 漂移：", file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        print(
            "\n提示：当前口径唯一事实源是 scripts/export_plugin_list.py::collect()。"
            "\n历史快照（盲测 29/54 等）请保留，并在同一行注明「历史/盲测」。",
            file=sys.stderr,
        )
        return 1

    print(f"[+] 插件数量 SSOT 一致：{runtime} 个插件，{len(DOC_FILES)} 个文件无漂移")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
