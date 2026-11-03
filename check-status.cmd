@echo off
setlocal
chcp 65001 >nul

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

echo === Checking Antigravity Backend Status (Read-Only) ===
"%PY%" "%~dp0fix_antigravity_context.py" --check %*
echo.
pause

