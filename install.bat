@echo off
rem Reqlore installer for Windows.
rem
rem Usage (from inside the cloned repo, in cmd or PowerShell):
rem   install.bat
rem
rem What it does:
rem   1. Verifies Python 3.12+ is present (prefers `py` launcher, then `python`).
rem   2. Ensures pipx is installed (installs it via `pip install --user pipx`
rem      if missing) and uses it to install Reqlore globally so `reqlore`
rem      lands permanently on your PATH and survives across new shells.
rem   3. If pipx can't be used, falls back to a local .venv install.
rem
rem Environment overrides:
rem   PYTHON=py             pick a specific launcher/interpreter
rem   REQLORE_VENV=.venv    venv location for the fallback path
rem   REQLORE_NO_PIPX=1     skip pipx entirely; go straight to venv

setlocal enableextensions enabledelayedexpansion

if not exist "pyproject.toml" (
    echo error: run this from the Reqlore repository root ^(pyproject.toml not found^).
    exit /b 1
)

findstr /b /c:"name = \"reqlore\"" pyproject.toml >nul
if errorlevel 1 (
    echo error: this directory's pyproject.toml is not Reqlore's. Are you in the right folder?
    exit /b 1
)

rem ---- 1. find Python ------------------------------------------------------
set "PY=%PYTHON%"
if not defined PY (
    where py >nul 2>&1 && set "PY=py"
)
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo error: Python not found on PATH.
    echo Install Python 3.12+ from https://www.python.org/downloads/
    echo Make sure to tick "Add python.exe to PATH" during install.
    exit /b 1
)

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)"
if errorlevel 1 (
    echo error: Python 3.12+ required.
    %PY% --version
    exit /b 1
)

rem ---- 2. pipx path (permanent, global) -----------------------------------
if "%REQLORE_NO_PIPX%"=="1" goto :venv

call :try_pipx
if not errorlevel 1 (
    endlocal
    exit /b 0
)

echo warn: couldn't install via pipx -- falling back to local venv
goto :venv

rem ----------------------------------------------------------------------
:try_pipx
    %PY% -m pipx --version >nul 2>&1
    if errorlevel 1 (
        echo ==^> installing pipx ^(per-user, no admin needed^)
        %PY% -m pip install --user --upgrade pipx
        if errorlevel 1 exit /b 1
        %PY% -m pipx --version >nul 2>&1
        if errorlevel 1 (
            echo error: pipx still not importable after install
            exit /b 1
        )
    )

    rem A previous `pip install --user` could have left a reqlore.exe shim
    rem in %APPDATA%\Python\PythonNN\Scripts that's earlier on PATH than
    rem ~\.local\bin and shadows the pipx install. Wipe it before we move on.
    %PY% -m pip uninstall -y reqlore >nul 2>&1

    echo ==^> registering pipx scripts directory on PATH ^(persistent^)
    %PY% -m pipx ensurepath >nul 2>&1

    rem Kill any running reqlore.exe / venv python.exe so we can replace the
    rem files. `pipx install --force` is not reliable on Windows when these
    rem are locked or when the version string hasn't bumped — the install
    rem silently no-ops. The full uninstall + install dance below is the
    rem only sequence that's guaranteed to actually replace the venv.
    call :stop_reqlore_procs

    rem Clear pipx's trash dir. pipx 1.x "uninstalls" by moving the venv to
    rem ~/pipx/trash/ and tries to rmdir() it on the next invocation. If a
    rem prior reqlore process locked a native module (aioquic/_buffer.pyd,
    rem cffi, etc.) the rmdir aborts with WinError 5 and the next install
    rem fails before it starts. Wipe trash now that processes are dead.
    call :clear_pipx_trash

    rem Uninstall any previous reqlore so install is a clean overwrite.
    rem `pipx uninstall` is idempotent (succeeds if not installed).
    %PY% -m pipx uninstall reqlore >nul 2>&1

    rem Trash again after uninstall: pipx just moved the venv into trash.
    call :clear_pipx_trash

    echo ==^> installing Reqlore with pipx ^(isolated, permanent, ~150 MB^)
    %PY% -m pipx install .
    if errorlevel 1 exit /b 1

    echo.
    echo ==^> done.
    echo.
    echo Reqlore is permanently installed and `reqlore` is on your PATH.
    echo.
    echo Open a NEW PowerShell or cmd window ^(so PATH refreshes^), then:
    echo   reqlore --help
    echo   reqlore init demo.rlr
    echo   reqlore both --project demo.rlr
    echo.
    echo UI:    http://127.0.0.1:8787
    echo Proxy: 127.0.0.1:8080
    echo.
    echo To upgrade later from this repo:  upgrade.bat
    echo To remove:                        uninstall.bat
    exit /b 0

rem ----------------------------------------------------------------------
rem stop_reqlore_procs — kill any reqlore.exe / pipx-venv python.exe that
rem would hold files open and make the next install silently no-op.
rem Scoped: only matches PIDs whose ExecutablePath is inside the reqlore
rem pipx venv, so unrelated python processes on the box are untouched.
rem Kept on ONE line: cmd's `^` continuation conflicts with `|` inside the
rem powershell pipeline and silently drops the script body.
:stop_reqlore_procs
    powershell -NoProfile -Command "$venv = Join-Path $env:USERPROFILE 'pipx\venvs\reqlore'; $shim = Join-Path $env:USERPROFILE '.local\bin\reqlore.exe'; Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -and ($_.Path -like ($venv + '*') -or $_.Path -eq $shim) } catch { $false } } | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }" >nul 2>&1
    exit /b 0

rem ----------------------------------------------------------------------
rem clear_pipx_trash — force-delete ~/pipx/trash with up to 3 retries.
rem pipx aborts on startup if it can't rmtree() trash, so a locked PYD
rem from a dead-but-not-yet-released process can permanently block all
rem future pipx commands until the user reboots. We give Windows a moment
rem to release file handles between retries.
:clear_pipx_trash
    powershell -NoProfile -Command "$t = Join-Path $env:USERPROFILE 'pipx\trash'; if (Test-Path $t) { 1..3 | ForEach-Object { try { Remove-Item $t -Recurse -Force -ErrorAction Stop; return } catch { Start-Sleep -Milliseconds 500 } }; Remove-Item $t -Recurse -Force -ErrorAction SilentlyContinue }" >nul 2>&1
    exit /b 0

rem ----------------------------------------------------------------------
:venv
set "VENV=%REQLORE_VENV%"
if not defined VENV set "VENV=.venv"

if not exist "%VENV%\Scripts\python.exe" (
    echo ==^> creating virtual environment at %VENV%
    %PY% -m venv "%VENV%"
    if errorlevel 1 (
        echo error: failed to create venv. Make sure the `venv` module is available.
        exit /b 1
    )
)

echo ==^> upgrading pip
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip >nul

echo ==^> installing Reqlore ^(pulls mitmproxy, ~150 MB; first run can take a few minutes^)
"%VENV%\Scripts\pip.exe" install .
if errorlevel 1 (
    echo error: pip install failed. See messages above.
    exit /b 1
)

echo.
echo ==^> done.
echo.
echo Reqlore is installed into the venv at: %VENV%
echo.
echo Run it without activating ^(simplest^):
echo   %VENV%\Scripts\reqlore.exe init demo.rlr
echo   %VENV%\Scripts\reqlore.exe both --project demo.rlr
echo.
echo Or activate the venv first and use the bare command:
echo   in cmd:        %VENV%\Scripts\activate.bat
echo   in PowerShell: %VENV%\Scripts\Activate.ps1
echo   then:          reqlore init demo.rlr
echo                  reqlore both --project demo.rlr
echo.
echo UI:    http://127.0.0.1:8787
echo Proxy: 127.0.0.1:8080

endlocal
