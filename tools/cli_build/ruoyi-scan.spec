# -*- mode: python ; coding: utf-8 -*-
# Ruoyi-Scan 终端版打包 spec（PyInstaller onefile，console）
#
# 产物：tools/cli_build/dist/ruoyi-scan.exe
#   - 内嵌 Python + requests + 报告依赖(reportlab/python-docx/openpyxl) + serve 依赖(fastapi/uvicorn)
#   - plugins/ chains/ data/(仅字典与 CVE 库) web/ assets/ 随包分发
#
# 与桌面端引擎 spec 的差别：
#   1. 入口是 tools/cli_build/entry.py（转调 main.py 的 CLI），不是 FastAPI sidecar；
#   2. console=True 且不吃命令行参数，用户直接 `ruoyi-scan -p <url>`；
#   3. data/ 只打运行期真正读的 6 个文件——tasks.db / scan_cache.db / acceptance*.json
#      是本地运行时产物，打进去会带上别人的扫描记录。
#
# 构建（仓库根执行）：
#   python -m PyInstaller tools/cli_build/ruoyi-scan.spec --noconfirm \
#     --distpath tools/cli_build/dist --workpath tools/cli_build/build
# 或直接跑 tools/cli_build/build-cli.cmd（自动建 venv + 冒烟）

import os
import re

from PyInstaller.utils.hooks import collect_submodules

REPO = os.path.abspath(SPECPATH + "/../..")


def _project_version() -> str:
    """从 config/settings.py 读版本号（不 import 项目，避免构建期拉起依赖）"""
    with open(os.path.join(REPO, "config", "settings.py"), encoding="utf-8") as f:
        m = re.search(r'^VERSION\s*=\s*"([^"]+)"', f.read(), re.M)
    return m.group(1) if m else "0.0.0"


def _version_file(dest: str) -> str:
    """生成 Windows 文件属性（右键属性里能看到版本/公司），缺失不影响功能"""
    ver = _project_version()
    nums = [int(x) for x in re.findall(r"\d+", ver)[:3]]
    while len(nums) < 3:
        nums.append(0)
    tup = f"({nums[0]}, {nums[1]}, {nums[2]}, 0)"
    text = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={tup}, prodvers={tup}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'XIABAI'),
      StringStruct('FileDescription', 'Ruoyi-Scan CLI - RuoYi vulnerability scanner'),
      StringStruct('FileVersion', '{ver}'),
      StringStruct('InternalName', 'ruoyi-scan'),
      StringStruct('OriginalFilename', 'ruoyi-scan.exe'),
      StringStruct('ProductName', 'Ruoyi-Scan'),
      StringStruct('ProductVersion', '{ver}'),
      StringStruct('LegalCopyright', 'MIT License')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        f.write(text)
    return dest


# 运行期真正读的数据文件（白名单，别整目录拷）
DATA_FILES = [
    "ruoyi.txt",  # 目录扫描字典
    "password.txt",  # 爆破字典（full）
    "pass_top100.txt",
    "pass_top1000.txt",
    "component_cve_map.json",  # 20 组件 CVE 比对
    "cve_offline.json",  # --cve-offline 离线库
]

hiddenimports = [
    # uvicorn/fastapi：--serve 走命令行动态导入，静态分析看不到
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.http.httptools_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.protocols.websockets.websockets_impl",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "anyio._backends._asyncio",
    # 项目内模块：dispatcher/runner 大量函数内 import，静态分析覆盖不到
    "api.app",
    "cli.distributed_runner",
    "cli.serve_runner",
    "cli.chain_runner",
    "cli.plugin_runner",
    "cli.passive_runner",
    "cli.tool_runner",
    "lib.plugin_sdk",
    "lib.nuclei_loader",
    "lib.scheduler",
    "lib.logic_scan",
    "lib.web_ui",
    "lib.cve_sync",
    "lib.oast",
    "lib.ai_generator",
    "lib.ai_validate",
    "core.orchestrator",
    "core.loader",
    # 可选依赖：装了就带上，没装 PyInstaller 只会告警
    "cryptography",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "redis",
    "aiohttp",
]
for pkg in ("cli", "lib", "core", "api", "chains", "common", "config", "plugins"):
    hiddenimports += collect_submodules(pkg)

a = Analysis(
    [os.path.join(SPECPATH, "entry.py")],
    pathex=[REPO],
    binaries=[],
    datas=[
        # 插件源码目录：core.loader 靠 os.listdir 扫描包目录，必须是真实磁盘目录
        (os.path.join(REPO, "plugins"), "plugins"),
        # 利用链：chains/registry.py 动态 import
        (os.path.join(REPO, "chains"), "chains"),
        # Web 控制台静态资源（--serve 时挂载 web/）
        (os.path.join(REPO, "web"), "web"),
        (os.path.join(REPO, "assets"), "assets"),
    ]
    + [(os.path.join(REPO, "data", name), "data") for name in DATA_FILES],
    hiddenimports=sorted(set(hiddenimports)),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "pytest",
        "requests_mock",
        "PyQt5",
        "PySide6",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ruoyi-scan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # 终端版：stdout 是唯一交互界面，必须保留控制台
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=_version_file(os.path.join(SPECPATH, "build", "version_info.txt")),
)
