@echo off
setlocal
cd /d "%~dp0"
echo Starting SOC L1 Local Practice Lab at http://localhost:8000
start "" http://localhost:8000
where py >nul 2>&1
if %errorlevel%==0 (
  py -m http.server 8000
  goto :eof
)
where python >nul 2>&1
if %errorlevel%==0 (
  python -m http.server 8000
  goto :eof
)
echo Python was not found. You can still open index.html directly in your browser.
pause
