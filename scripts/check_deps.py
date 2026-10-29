# 依赖清单一致性检查（CI 门禁）
#
# 背景：本项目有两份依赖声明——pyproject.toml（权威，pip 分发用）与
# requirements.txt / requirements-dev.txt（源码部署与 CI 用）。两份手工维护，
# 历史上漂移过：requests-mock（测试专用 mock 库）被列进 requirements.txt 的
# 「核心依赖（必装）」段，陌生用户检查依赖卫生时第一眼就看出管理松散。
#
# 本脚本校验三件事：
#   1. requirements.txt 的**可安装依赖行**必须与 pyproject 核心依赖一致
#      （其余内容只能是注释，且需指向 pip extras 的安装方式）
#   2. requests-mock 之类的测试依赖不得出现在 requirements.txt（只能在 dev 里）
#   3. requirements-dev.txt 必须覆盖 CI 实际用到的依赖（fastapi/uvicorn 等）
#
# 用法：
#   python scripts/check_deps.py
#
# 退出码：0 一致；1 存在漂移。

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

PYPROJECT = REPO / "pyproject.toml"
REQUIREMENTS = REPO / "requirements.txt"
REQUIREMENTS_DEV = REPO / "requirements-dev.txt"

# 测试专用依赖：只能出现在 requirements-dev.txt，绝不能进 requirements.txt
TEST_ONLY = {"requests-mock", "requests_mock", "pytest", "pytest-cov", "pytest-timeout", "pytest-asyncio"}

# CI 实际执行的工作流需要这些依赖（见 .github/workflows/ci.yml 的测试步骤）：
# fastapi/uvicorn → test_api_* / test_metrics / test_api_ws
# flask → lab/ 靶场冒烟
DEV_REQUIRED = {"fastapi", "uvicorn", "flask", "requests-mock", "pytest"}


def _strip_extras(spec: str) -> str:
    """去掉版本号与 extras，返回包名（小写，- 与 _ 归一）"""
    name = re.split(r"[<>=!~\[]", spec.strip(), 1)[0]
    return name.lower().replace("_", "-")


def parse_pyproject() -> tuple:
    """读 pyproject：返回 (核心依赖列表, {extras名: [依赖...]})"""
    try:
        import tomllib  # Python 3.11+

        with open(PYPROJECT, "rb") as f:
            data = tomllib.load(f)
    except ImportError:
        raise SystemExit("[!] 需要 Python 3.11+ 的 tomllib 才能解析 pyproject.toml")

    project = data.get("project", {})
    core = project.get("dependencies", [])
    extras = project.get("optional-dependencies", {})
    return core, extras


def parse_requirements(path: Path) -> list:
    """读 requirements 文件，返回其中真正会被 pip 安装的依赖 spec 列表"""
    specs = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r ") or line.startswith("--"):
            continue
        specs.append(line)
    return specs


def main() -> int:
    errors = []

    core, extras = parse_pyproject()

    # ── 1. requirements.txt 的依赖行必须等于 pyproject 核心依赖 ──────────────
    req_specs = parse_requirements(REQUIREMENTS)
    core_names = {_strip_extras(s) for s in core}
    req_names = {_strip_extras(s) for s in req_specs}

    if req_names != core_names:
        missing = core_names - req_names
        extra = req_names - core_names
        if missing:
            errors.append(f"requirements.txt 缺少核心依赖：{', '.join(sorted(missing))}")
        if extra:
            errors.append(f"requirements.txt 多出非核心依赖：{', '.join(sorted(extra))}")

    # ── 2. 测试专用依赖不得出现在 requirements.txt ──────────────────────────
    for name in sorted(TEST_ONLY & req_names):
        errors.append(f"requirements.txt 不应包含测试专用依赖：{name}（应只在 requirements-dev.txt）")

    # ── 3. requirements-dev.txt 必须覆盖 CI 所需依赖 ─────────────────────────
    dev_specs = parse_requirements(REQUIREMENTS_DEV)
    dev_names = {_strip_extras(s) for s in dev_specs}
    for name in sorted(DEV_REQUIRED - dev_names):
        errors.append(f"requirements-dev.txt 缺少 CI 所需依赖：{name}")

    # ── 4. requirements.txt 必须给出 extras 安装方式（供不懂 extras 的用户） ──
    req_text = REQUIREMENTS.read_text(encoding="utf-8")
    for extra_name in ("report", "serve", "distributed", "async", "yaml", "lab", "dev"):
        if extra_name not in extras:
            continue
        if f"[{extra_name}]" not in req_text:
            errors.append(f"requirements.txt 未提示 extras 安装方式：pip install \"ruoyi-scan[{extra_name}]\"")

    if errors:
        print("[!] 依赖清单存在漂移：")
        for e in errors:
            print(f"    - {e}")
        print("\n    修复：让 requirements*.txt 与 pyproject.toml 的依赖声明保持一致")
        return 1

    print("[+] 依赖清单一致：")
    print(f"    OK {REQUIREMENTS.name}      核心 {len(req_specs)} 项，与 pyproject 一致")
    print(f"    OK {REQUIREMENTS_DEV.name}  {len(dev_specs)} 项，覆盖 CI 所需依赖")
    print(f"    OK pyproject extras       {', '.join(sorted(extras))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
