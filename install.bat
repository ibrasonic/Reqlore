@echo off
rem Weblore installer for Windows.
rem
rem Usage (from inside the cloned repo, in cmd or PowerShell):
rem   install.bat
rem
rem What it does:
rem   1. Finds Python 3.12+ (prefers the `py` launcher, falls back to `python`).
rem   2. Creates a virtual environment in .venv\.
rem   3. Installs Weblore into the venv.
rem   4. Prints instructions to run it.

setlocal enableextensions

if not exist "pyproject.toml" (
    echo error: run this from the Weblore repository root ^(pyproject.toml not found^).
    exit /b 1
)

rem ---- 1. find Python ------------------------------------------------------
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY where python >nul 2>&1 && set "PY=python"

if not defined PY (
    echo error: Python not found on PATH.
    echo Install Python 3.12+ from https://www.python.org/downloads/
    echo Make sure to tick "Add python.exe to PATH" during install.
    exit /b 1
)

rem ---- 2. version check ----------------------------------------------------
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)"
if errorlevel 1 (
    echo error: Python 3.12+ required.
    %PY% --version
    exit /b 1
)

rem ---- 3. venv -------------------------------------------------------------
set "VENV=.venv"

if not exist "%VENV%\Scripts\python.exe" (
    echo ==^> creating virtual environment at %VENV%
    %PY% -m venv "%VENV%"
    if errorlevel 1 (
        echo error: failed to create venv. Make sure the `venv` module is available.
        exit /b 1
    )
)

rem ---- 4. install ----------------------------------------------------------
echo ==^> upgrading pip
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip >nul

echo ==^> installing Weblore ^(pulls mitmproxy, ~150 MB; first run can take a few minutes^)
"%VENV%\Scripts\pip.exe" install .
if errorlevel 1 (
    echo error: pip install failed. See messages above.
    exit /b 1
)

rem ---- 5. done -------------------------------------------------------------
echo.
echo ==^> done.
echo.
echo Weblore is installed into the venv at: %VENV%
echo.
echo Run it without activating ^(simplest^):
echo   %VENV%\Scripts\weblore.exe init demo.weblore
echo   %VENV%\Scripts\weblore.exe both --project demo.weblore
echo.
echo Or activate the venv first and use the bare command:
echo   in cmd:        %VENV%\Scripts\activate.bat
echo   in PowerShell: %VENV%\Scripts\Activate.ps1
echo   then:          weblore init demo.weblore
echo                  weblore both --project demo.weblore
echo.
echo UI:    http://127.0.0.1:8787
echo Proxy: 127.0.0.1:8080

endlocal
