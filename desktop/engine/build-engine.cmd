@echo off
REM Ruoyi-Scan 单 exe 构建脚本（本地全流程）
REM 用法：desktop\engine\build-engine.cmd
REM 产物：desktop\src-tauri\target\release\ruoyi-scan-desktop.exe（引擎已内嵌，单文件双击即用）

setlocal
cd /d "%~dp0..\.."
echo [1/3] 构建引擎（PyInstaller onefile）...
if not exist desktop\engine\.venv-build\Scripts\python.exe (
  echo   创建构建 venv...
  python -m venv desktop\engine\.venv-build || goto :err
  desktop\engine\.venv-build\Scripts\python.exe -m pip install --quiet --upgrade pip || goto :err
  desktop\engine\.venv-build\Scripts\python.exe -m pip install --quiet pyinstaller fastapi "uvicorn[standard]" requests requests-mock reportlab python-docx openpyxl pyyaml || goto :err
)
desktop\engine\.venv-build\Scripts\python.exe -m PyInstaller desktop/engine/ruoyi-scan-engine.spec --noconfirm --distpath desktop/engine/dist --workpath desktop/engine/build || goto :err

echo [2/3] 前端构建 + Tauri 打包（引擎随编译嵌入）...
ts=$(date +%s) 2>NUL
if exist desktop\dist ren desktop\dist dist-old-%RANDOM%
cd desktop
call npm run tauri build || goto :err

echo [3/3] 完成：
echo   安装包: desktop\src-tauri\target\release\bundle\nsis\Ruoyi-Scan_1.4.0_x64-setup.exe
echo   单文件: desktop\src-tauri\target\release\ruoyi-scan-desktop.exe
exit /b 0

:err
echo 构建失败
exit /b 1
