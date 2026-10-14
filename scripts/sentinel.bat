@echo off
setlocal EnableExtensions
rem Sentinel-Code launcher (Windows).
rem Run from ANY git project, after `git add`:   sentinel

rem Clean absolute path of Sentinel's root (the parent of this script's folder).
for %%I in ("%~dp0..") do set "SENTINEL_HOME=%%~fI"

where git >nul 2>&1
if errorlevel 1 goto :no_git

git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 goto :not_repo

rem Prefer Sentinel's own virtual environment, then the py launcher, then python.
set "PY="
if exist "%SENTINEL_HOME%\.venv\Scripts\python.exe" set PY="%SENTINEL_HOME%\.venv\Scripts\python.exe"
if not defined PY py -3 -c "import sys" >nul 2>&1 && set "PY=py -3"
if not defined PY python -c "import sys" >nul 2>&1 && set "PY=python"
if not defined PY goto :no_python

%PY% -c "import importlib.util as u,sys; sys.exit(0 if all(u.find_spec(m) for m in ('langchain_core','langchain_google_genai','dotenv')) else 1)" >nul 2>&1
if errorlevel 1 goto :no_deps

if defined GEMINI_API_KEY goto :run
if defined GOOGLE_API_KEY goto :run
if exist "%SENTINEL_HOME%\.env" goto :run
goto :no_key

:run
set "PYTHONPATH=%SENTINEL_HOME%"
set "PYTHONUTF8=1"
set "PYTHONSAFEPATH=1"
%PY% -m interfaces.cli %*
exit /b %ERRORLEVEL%

:no_git
echo [Sentinel] Git was not found. Install Git, then open a new terminal.
exit /b 1

:not_repo
echo [Sentinel] This folder is not a Git repository. cd into your project first.
exit /b 1

:no_python
echo [Sentinel] Python 3 was not found. Install Python 3.10 or newer.
exit /b 1

:no_deps
echo [Sentinel] Dependencies are missing. Run this once:
echo   %PY% -m pip install -r "%SENTINEL_HOME%\requirements.txt"
exit /b 1

:no_key
echo [Sentinel] No API key found. Create this file:
echo   "%SENTINEL_HOME%\.env"
echo containing the line:  GEMINI_API_KEY=your_key
exit /b 1
