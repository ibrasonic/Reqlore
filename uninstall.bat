@echo off
rem Weblore uninstaller for Windows.
rem
rem Usage (from inside the cloned repo):
rem   uninstall.bat              remove .venv\ (and any pipx install)
rem   uninstall.bat --purge-data  also remove ./data and demo.weblore* files
rem
rem What it does NOT remove (you have to do these manually):
rem   - The Python interpreter.
rem   - pipx itself.
rem   - The mitmproxy CA you may have trusted in your browser/Windows cert store.

setlocal enableextensions

set "PURGE_DATA=0"
if /I "%~1"=="--purge-data" set "PURGE_DATA=1"
if /I "%~1"=="-h" goto :help
if /I "%~1"=="--help" goto :help
if /I "%~1"=="/?" goto :help

set "REMOVED=0"

rem ---- 1. pipx-installed weblore ------------------------------------------
where pipx >nul 2>&1
if not errorlevel 1 (
    pipx list 2>nul | findstr /R /C:"package weblore " >nul
    if not errorlevel 1 (
        echo ==^> removing pipx-installed weblore
        pipx uninstall weblore
        if not errorlevel 1 set "REMOVED=1"
    )
)

rem ---- 2. local venv ------------------------------------------------------
set "VENV=.venv"

if exist "%VENV%\" (
    rem Best-effort: stop processes that may hold venv files open. We use
    rem taskkill with the venv-absolute python.exe path so we don't kill
    rem unrelated python processes on the box.
    taskkill /F /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq weblore*" >nul 2>&1
    for /f "tokens=2" %%P in ('tasklist /FI "IMAGENAME eq python.exe" /FO LIST ^| findstr /B "PID:"') do (
        rem fall through — taskkill above handles the obvious case
    )
    echo ==^> removing venv at %VENV%
    rmdir /s /q "%VENV%"
    if not exist "%VENV%\" set "REMOVED=1"
)

rem ---- 3. project data (opt-in) -------------------------------------------
if "%PURGE_DATA%"=="1" (
    if exist "data\" (
        echo ==^> removing .\data ^(project files^)
        rmdir /s /q "data"
        set "REMOVED=1"
    )
    for %%F in (demo.weblore demo.weblore-journal demo.weblore-wal demo.weblore-shm) do (
        if exist "%%F" (
            echo ==^> removing %%F
            del /f /q "%%F"
            set "REMOVED=1"
        )
    )
)

if "%REMOVED%"=="0" (
    echo ==^> nothing to remove — Weblore doesn't appear to be installed here.
    exit /b 0
)

echo.
echo ==^> done.
echo.
echo Not touched by this script ^(remove manually if you want^):
echo   - pipx itself
echo   - the mitmproxy CA you installed in your browser/Windows cert store
if "%PURGE_DATA%"=="0" echo   - your *.weblore project files ^(re-run with --purge-data to drop these^)

endlocal
exit /b 0

:help
echo Weblore uninstaller.
echo.
echo Usage:
echo   uninstall.bat              remove .venv\ and any pipx install
echo   uninstall.bat --purge-data also remove .\data and demo.weblore* files
echo.
echo Does NOT remove: Python, pipx, or the mitmproxy CA in your cert store.
endlocal
exit /b 0
