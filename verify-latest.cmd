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

echo === Verifying Latest Conversation SQLite DB ===
"%PY%" "%~dp0verify_session.py" %*
echo.
pause

