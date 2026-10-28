@echo off
REM Ruoyi-Scan CLI single-file build (PyInstaller onefile, console)
REM Usage: tools\cli_build\build-cli.cmd
REM Output: tools\cli_build\dist\ruoyi-scan.exe
REM
REM First run creates an isolated venv and installs runtime deps
REM (compiler/console/report/distributed optional deps included).
REM NOTE: keep this file ASCII-only. cmd.exe on zh-CN uses GBK and would
REM mangle UTF-8 Chinese comments, breaking REM parsing.

setlocal
cd /d "%~dp0..\.."

set VENV=tools\cli_build\.venv-build
set PY=%VENV%\Scripts\python.exe

if not exist "%PY%" (
  echo [1/4] Create build venv...
  python -m venv "%VENV%" || goto :err
  "%PY%" -m pip install --quiet --upgrade pip || goto :err
  echo [2/4] Install dependencies ^(first run only, 1-3 min^)...
  "%PY%" -m pip install --quiet pyinstaller requests reportlab python-docx openpyxl pyyaml ^
    fastapi "uvicorn[standard]" redis aiohttp cryptography || goto :err
) else (
  echo [1/4] Reuse existing venv: %VENV%
)

echo [3/4] PyInstaller build ^(onefile, 1-2 min^)...
"%PY%" -m PyInstaller tools\cli_build\ruoyi-scan.spec --noconfirm ^
  --distpath tools\cli_build\dist --workpath tools\cli_build\build || goto :err

echo [4/4] Smoke test...
tools\cli_build\dist\ruoyi-scan.exe -V || goto :err
tools\cli_build\dist\ruoyi-scan.exe --plugin-list | findstr /R /C:"^ *54 " >nul || goto :err

echo.
echo Done: tools\cli_build\dist\ruoyi-scan.exe
for %%F in (tools\cli_build\dist\ruoyi-scan.exe) do echo Size: %%~zF bytes
exit /b 0

:err
echo.
echo Build failed, see output above.
exit /b 1
