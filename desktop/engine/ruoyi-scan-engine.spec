# -*- mode: python ; coding: utf-8 -*-
# Ruoyi-Scan 引擎打包 spec（PyInstaller onefile）
#
# 产物：desktop/engine/dist/ruoyi-scan-engine.exe
#   - 内嵌 Python 3.11 + fastapi/uvicorn + 全部 4 个插件包（ruoyi/spring/common/jeecgboot）
#   - data/（爆破字典）与 web/（Web 控制台）随包分发
#
# 关键设计：
#   1. plugins/ 用 datas 拷为源码目录而非 PYZ：
#      core/loader.discover_plugin_packages() 靠 os.listdir(plugins/) 扫描包目录，
#      onefile 解压后 BASE_DIR 指向 _MEIPASS，磁盘上有真实目录 → 发现机制零改动可用。
#   2. chains/ 同理（chains/registry.py 动态 import，且 excludedimports 需显式放行）。
#   3. hiddenimports 覆盖 uvicorn 标准安装的动态导入组件（websockets/httptools 等）。
#
# 构建命令（仓库根执行）：
#   pyinstaller desktop/engine/ruoyi-scan-engine.spec --noconfirm --distpath desktop/engine/dist --workpath desktop/engine/build

import os

REPO = os.path.abspath(SPECPATH + "/../..")  # desktop/engine → 仓库根

a = Analysis(
    [os.path.join(REPO, "desktop", "engine", "ruoyi_scan_engine.py")],
    pathex=[REPO],
    binaries=[],
    datas=[
        # 插件源码目录（discover_plugin_packages 依赖磁盘目录扫描）
        (os.path.join(REPO, "plugins"), "plugins"),
        # 利用链（chains/registry 动态导入）
        (os.path.join(REPO, "chains"), "chains"),
        # 爆破字典等数据文件（settings.BASE_DIR/data）
        (os.path.join(REPO, "data"), "data"),
        # Web 控制台静态资源（api/app.py 挂载 web/）
        (os.path.join(REPO, "web"), "web"),
        # assets（若被 lib/ 或报告模板引用则一并带上，缺失不致命）
        (os.path.join(REPO, "assets"), "assets"),
    ],
    hiddenimports=[
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
        # 插件/链/扫描器生态
        "plugins",
        "plugins.base",
        "plugins.ruoyi",
        "plugins.spring",
        "plugins.common",
        "plugins.jeecgboot",
        "chains",
        "api.app",
        "api.routes.scan",
        "api.routes.report",
        "api.routes.plugin",
        "api.routes.system",
        "api.ws",
        "api.metrics",
        "api.auth",
        "api.deps",
        "lib.scheduler",
        "lib.plugin_sdk",
        "lib.nuclei_loader",
        "core.orchestrator",
        "core.loader",
        "core.engine",
        "core.fingerprint",
        "core.waf",
        "core.report",
        "cli.serve_runner",
        "common.models",
        "common.logger",
        "config.settings",
        "reportlab",
        "docx",
        "openpyxl",
        "pyyaml",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "pytest",
        "setuptools",
        "PySide6",
        "PyQt5",
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
    name="ruoyi-scan-engine",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # 引擎日志可见：CI 冒烟与排障依赖 stdout
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
