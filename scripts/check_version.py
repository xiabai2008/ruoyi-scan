# 版本号一致性检查（发布前门禁）
#
# 背景：本项目版本号散落在 5 个文件里，历史上出现过 README/desktop 文档写旧版本、
# wheel 文件里还是 1.5.1 的情况（见 docs/quickstart 与 CHANGELOG 的修正记录）。
# 版本号不一致不会让任何测试失败，但会让用户装到「自称 1.5.2、实际 1.5.1」的包。
#
# 基准：config/settings.py 的 VERSION（运行时 -V 与报告页脚都用它）。
#
# 用法：
#   python scripts/check_version.py                 # 校验全部文件 + CHANGELOG
#   python scripts/check_version.py --tag v1.5.2    # 额外校验 git tag 与版本号一致
#
# 退出码：0 一致；1 存在不一致或缺失。

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

BASE_FILE = "config/settings.py"
PYPROJECT = "pyproject.toml"
DESKTOP_PKG = "desktop/package.json"
TAURI_CONF = "desktop/src-tauri/tauri.conf.json"
CARGO_TOML = "desktop/src-tauri/Cargo.toml"
CHANGELOG = "CHANGELOG.md"


def read_base_version() -> str:
    text = (REPO / BASE_FILE).read_text(encoding="utf-8")
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        raise SystemExit(f"[!] 无法从 {BASE_FILE} 读取 VERSION")
    return m.group(1)


def read_pyproject_version() -> str:
    path = REPO / PYPROJECT
    try:
        import tomllib  # Python 3.11+

        with open(path, "rb") as f:
            return str(tomllib.load(f)["project"]["version"])
    except ImportError:
        # 3.8-3.10 兜底：只取 [project] 段里的第一处 version
        text = path.read_text(encoding="utf-8")
        section = text.split("[project]", 1)[1] if "[project]" in text else text
        m = re.search(r'^version\s*=\s*"([^"]+)"', section, re.M)
        if not m:
            raise SystemExit(f"[!] 无法从 {PYPROJECT} 读取 version")
        return m.group(1)


def read_json_version(rel: str, key: str = "version") -> str:
    data = json.loads((REPO / rel).read_text(encoding="utf-8"))
    return str(data.get(key, ""))


def read_cargo_version() -> str:
    text = (REPO / CARGO_TOML).read_text(encoding="utf-8")
    # 只取 [package] 段，避免命中 [dependencies] 里的同名键
    section = text.split("[package]", 1)[1] if "[package]" in text else text
    m = re.search(r'^version\s*=\s*"([^"]+)"', section, re.M)
    return m.group(1) if m else ""


def changelog_has_version(version: str) -> bool:
    path = REPO / CHANGELOG
    if not path.exists():
        return True
    text = path.read_text(encoding="utf-8")
    return re.search(rf"^##\s*\[{re.escape(version)}\]", text, re.M) is not None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="校验各文件版本号一致")
    parser.add_argument("--tag", default="", help="git tag，如 v1.5.2（会与版本号比对）")
    args = parser.parse_args(argv)

    base = read_base_version()
    rows = [(BASE_FILE, base, True)]

    def add(rel, value):
        rows.append((rel, value, value == base))

    add(PYPROJECT, read_pyproject_version())

    for rel in (DESKTOP_PKG, TAURI_CONF):
        if (REPO / rel).exists():
            add(rel, read_json_version(rel))
        else:
            rows.append((rel, "（文件不存在，跳过）", True))

    if (REPO / CARGO_TOML).exists():
        add(CARGO_TOML, read_cargo_version())

    print(f"[*] 版本号一致性检查（基准 {BASE_FILE}）")
    for rel, value, ok in rows:
        mark = "OK " if ok else "!! "
        print(f"    {mark}{rel:<38}{value}")

    problems = [(rel, value) for rel, value, ok in rows if not ok]

    if not changelog_has_version(base):
        problems.append((CHANGELOG, f"缺少 ## [{base}] 小节"))

    if args.tag:
        tag_ver = args.tag.strip().lstrip("vV")
        if tag_ver != base:
            problems.append((f"git tag {args.tag}", f"与代码版本 {base} 不一致"))

    if problems:
        print("")
        for rel, value in problems:
            print(f"[!] {rel}: {value}（期望 {base}）", file=sys.stderr)
        print(f"[!] 版本号不一致，统一为 {base} 后重试", file=sys.stderr)
        return 1

    print(f"[+] 全部一致：{base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
