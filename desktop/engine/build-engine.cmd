@echo off
REM Ruoyi-Scan single-exe build script (engine + Tauri desktop).
REM Usage: desktop\engine\build-engine.cmd
REM Output: desktop\src-tauri\target\release\ruoyi-scan-desktop.exe (engine embedded)
REM
REM Keep this file ASCII-only: cmd.exe parses .cmd with the OEM code page (936 on zh-CN),
REM so UTF-8 Chinese comments/echo lines get split into bogus commands.

setlocal
REM Make cargo available when the caller's shell does not have rustup in PATH.
if exist "%USERPROFILE%\.cargo\bin\cargo.exe" set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
if exist "%USERPROFILE%\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\cargo.exe" set "PATH=%USERPROFILE%\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin;%PATH%"
cd /d "%~dp0..\.."
echo [1/3] Building engine (PyInstaller onefile)...
if not exist desktop\engine\.venv-build\Scripts\python.exe (
  echo   Creating build venv...
  python -m venv desktop\engine\.venv-build || goto :err
)
REM Install dependencies even when the build venv already exists: a stale venv
REM would miss newly added packages (e.g. APScheduler) and cron would silently
REM degrade to a 5-minute interval.
desktop\engine\.venv-build\Scripts\python.exe -m pip install --quiet --upgrade pip || goto :err
REM --upgrade + explicit security floors: pip install alone keeps stale venv packages.
REM urllib3/pillow/setuptools/certifi fixed releases require the Python 3.10+ build interpreter.
desktop\engine\.venv-build\Scripts\python.exe -m pip install --quiet --upgrade pyinstaller fastapi "uvicorn[standard]" requests requests-mock reportlab python-docx openpyxl pyyaml apscheduler "urllib3>=2.8.0" "pillow>=13.0.0" "setuptools>=84.2.1" "certifi>=2026.10.19" || goto :err
desktop\engine\.venv-build\Scripts\python.exe -m PyInstaller desktop/engine/ruoyi-scan-engine.spec --noconfirm --distpath desktop/engine/dist --workpath desktop/engine/build || goto :err

echo [2/3] Building frontend + Tauri bundle (engine embedded)...
if exist desktop\dist ren desktop\dist dist-old-%RANDOM%
cd desktop
call npm run tauri build || goto :err

echo [3/3] Done:
echo   Installer: desktop\src-tauri\target\release\bundle\nsis\Ruoyi-Scan_1.5.3_x64-setup.exe
echo   Portable : desktop\src-tauri\target\release\ruoyi-scan-desktop.exe
exit /b 0

:err
echo Build failed
exit /b 1
