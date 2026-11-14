@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

set "PY="
if exist "C:\msys64\ucrt64\bin\python.exe" set "PY=C:\msys64\ucrt64\bin\python.exe"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [ERROR] Python 3 not found.
    pause
    exit /b 1
)

echo === Antigravity 1M Context ^& Rules Auto-Patcher ===
echo Note: Review targets and type Y to continue.
echo Please close Antigravity IDE / Desktop windows first so they do not auto-restart the backend mid-patch.
echo.
"%PY%" "%~dp0scripts\fix_antigravity_context.py" %*
echo.
pause
