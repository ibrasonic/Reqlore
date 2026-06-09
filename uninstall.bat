@echo off
rem Reqlore uninstaller for Windows.
rem
rem Usage (from inside the cloned repo):
rem   uninstall.bat              remove .venv\ (and any pipx install)
rem   uninstall.bat --purge-data  also remove ./data and demo.rlr* files
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

rem ---- 1. pipx-installed reqlore ------------------------------------------
rem Stop processes that hold venv/shim files open BEFORE we call
rem `pipx uninstall`. Otherwise the uninstall can leave a half-deleted venv.
call :stop_reqlore_procs

where pipx >nul 2>&1
if not errorlevel 1 (
    pipx list 2>nul | findstr /R /C:"package reqlore " >nul
    if not errorlevel 1 (
        echo ==^> removing pipx-installed reqlore
        pipx uninstall reqlore
        if not errorlevel 1 set "REMOVED=1"
    )
)

rem ---- 1b. user-site `pip install --user` reqlore (stale shim trap) -------
rem A leftover `pip install --user reqlore` (often from before the rename)
rem leaves %APPDATA%\Python\PythonNN\Scripts\reqlore.exe on PATH and shadows
rem the pipx install. Detect and remove it so `reqlore` resolves cleanly.
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY where python >nul 2>&1 && set "PY=python"
if defined PY (
    %PY% -m pip show reqlore >nul 2>&1
    if not errorlevel 1 (
        echo ==^> removing stale user-site reqlore ^(pip --user shim^)
        %PY% -m pip uninstall -y reqlore >nul 2>&1
        if not errorlevel 1 set "REMOVED=1"
    )
)

rem ---- 2. local venv ------------------------------------------------------
set "VENV=.venv"

if exist "%VENV%\" (
    rem Best-effort: stop processes holding venv files open. Scoped to the
    rem absolute python.exe path inside the venv so we never touch unrelated
    rem python processes on the box. ONE line: see stop_reqlore_procs note.
    powershell -NoProfile -Command "$v = Resolve-Path '%VENV%'; Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -and $_.Path -like ($v.Path + '*') } catch { $false } } | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }" >nul 2>&1
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
    for %%F in (demo.rlr demo.rlr-journal demo.rlr-wal demo.rlr-shm) do (
        if exist "%%F" (
            echo ==^> removing %%F
            del /f /q "%%F"
            set "REMOVED=1"
        )
    )
)

if "%REMOVED%"=="0" (
    echo ==^> nothing to remove — Reqlore doesn't appear to be installed here.
    exit /b 0
)

echo.
echo ==^> done.
echo.
echo Not touched by this script ^(remove manually if you want^):
echo   - pipx itself
echo   - the mitmproxy CA you installed in your browser/Windows cert store
if "%PURGE_DATA%"=="0" echo   - your *.rlr project files ^(re-run with --purge-data to drop these^)

endlocal
exit /b 0

rem ----------------------------------------------------------------------
rem stop_reqlore_procs — kill any reqlore.exe / pipx-venv python.exe that
rem holds files open, so the pipx uninstall below can fully remove them.
rem Kept on ONE line: cmd's `^` continuation conflicts with `|` inside the
rem powershell pipeline and silently drops the script body.
:stop_reqlore_procs
    powershell -NoProfile -Command "$venv = Join-Path $env:USERPROFILE 'pipx\venvs\reqlore'; $shim = Join-Path $env:USERPROFILE '.local\bin\reqlore.exe'; Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -and ($_.Path -like ($venv + '*') -or $_.Path -eq $shim) } catch { $false } } | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }" >nul 2>&1
    exit /b 0

:help
echo Reqlore uninstaller.
echo.
echo Usage:
echo   uninstall.bat              remove .venv\ and any pipx install
echo   uninstall.bat --purge-data also remove .\data and demo.rlr* files
echo.
echo Does NOT remove: Python, pipx, or the mitmproxy CA in your cert store.
endlocal
exit /b 0
