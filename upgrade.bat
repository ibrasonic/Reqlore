@echo off
rem Reqlore upgrader for Windows.
rem
rem Usage (from inside the cloned repo, in cmd or PowerShell):
rem   upgrade.bat
rem
rem What it does:
rem   1. Pulls the latest source from this repo (git pull, if you ran from a
rem      clone with a tracking branch). If there is no git checkout, that
rem      step is skipped and the upgrade installs whatever the local tree
rem      currently contains.
rem   2. Detects an existing install:
rem        - pipx (preferred)  -> pipx install --force . (clean reinstall)
rem        - local .venv       -> .venv\Scripts\pip install --upgrade .
rem        - nothing installed -> defers to install.bat
rem   3. Purges any stale `pip install --user reqlore` shim that would
rem      otherwise shadow the pipx install on PATH.
rem
rem Environment overrides:
rem   PYTHON=py             pick a specific launcher/interpreter
rem   REQLORE_VENV=.venv    venv location for the venv path
rem   REQLORE_NO_PIPX=1     skip pipx detection; upgrade venv only
rem   REQLORE_NO_GIT=1      skip the `git pull` step

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
    exit /b 1
)

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)"
if errorlevel 1 (
    echo error: Python 3.12+ required.
    %PY% --version
    exit /b 1
)

rem ---- 2. refresh source via git (best-effort) ----------------------------
if "%REQLORE_NO_GIT%"=="1" goto :after_git
where git >nul 2>&1
if errorlevel 1 goto :after_git
if not exist ".git" goto :after_git

echo ==^> pulling latest from the tracking branch
git pull --ff-only
if errorlevel 1 (
    echo warn: git pull failed -- upgrading from the current working tree as-is.
)
:after_git

rem ---- 3. decide path: pipx, venv, or neither -----------------------------
if "%REQLORE_NO_PIPX%"=="1" goto :upgrade_venv

call :detect_pipx_reqlore
if not errorlevel 1 goto :upgrade_pipx

set "VENV=%REQLORE_VENV%"
if not defined VENV set "VENV=.venv"
if exist "%VENV%\Scripts\python.exe" goto :upgrade_venv

echo ==^> no existing Reqlore install found -- running install.bat for a fresh setup.
call install.bat
exit /b %errorlevel%

rem ----------------------------------------------------------------------
:detect_pipx_reqlore
    %PY% -m pipx --version >nul 2>&1
    if errorlevel 1 exit /b 1
    %PY% -m pipx list 2>nul | findstr /r /c:"package reqlore " >nul
    if errorlevel 1 exit /b 1
    exit /b 0

rem ----------------------------------------------------------------------
:upgrade_pipx
    echo ==^> upgrading Reqlore via pipx ^(clean reinstall from this checkout^)

    rem A leftover `pip install --user` shim could re-appear from an old
    rem install attempt. Wipe it before pipx puts a fresh shim on PATH.
    %PY% -m pip uninstall -y reqlore >nul 2>&1

    %PY% -m pipx ensurepath >nul 2>&1
    %PY% -m pipx install --force .
    if errorlevel 1 (
        echo error: pipx install failed. See messages above.
        exit /b 1
    )

    echo.
    echo ==^> upgraded.
    echo.
    %PY% -m pipx list 2>nul | findstr /r /c:"package reqlore "
    echo.
    echo Run ^(open a NEW shell if PATH hasn't refreshed^):
    echo   reqlore --version
    echo   reqlore --help
    endlocal
    exit /b 0

rem ----------------------------------------------------------------------
:upgrade_venv
set "VENV=%REQLORE_VENV%"
if not defined VENV set "VENV=.venv"

if not exist "%VENV%\Scripts\python.exe" (
    echo error: no venv at %VENV% to upgrade. Run install.bat first.
    exit /b 1
)

echo ==^> upgrading Reqlore in venv at %VENV%
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip >nul
"%VENV%\Scripts\pip.exe" install --upgrade .
if errorlevel 1 (
    echo error: pip install --upgrade failed. See messages above.
    exit /b 1
)

echo.
echo ==^> upgraded.
echo.
echo Run:
echo   %VENV%\Scripts\reqlore.exe --version
echo   %VENV%\Scripts\reqlore.exe --help

endlocal
