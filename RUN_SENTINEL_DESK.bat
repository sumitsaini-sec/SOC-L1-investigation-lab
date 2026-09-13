@echo off
setlocal
cd /d "%~dp0"
title Sentinel Desk SOC Lab v3

echo =====================================================
echo   Sentinel Desk SOC Lab v3 - Windows Launcher
echo =====================================================
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js is not installed.
  echo Install Node.js 22.13 or newer, then run this file again.
  echo https://nodejs.org/
  pause
  exit /b 1
)

for /f "tokens=*" %%v in ('node -p "process.versions.node"') do set NODEVER=%%v
echo [OK] Node.js %NODEVER%
node -e "let v=process.versions.node.split('.').map(Number);process.exit((v[0]>22||(v[0]==22&&(v[1]>13||(v[1]==13&&v[2]>=0))))?0:1)"
if errorlevel 1 (
  echo [ERROR] Node.js 22.13+ is required. Current: %NODEVER%
  pause
  exit /b 1
)

echo.
if not exist node_modules (
  echo [1/4] Installing exact project dependencies...
  call npm ci
  if errorlevel 1 goto :fail
) else (
  echo [1/4] Existing dependencies found.
)

echo.
echo [2/4] Building the FINAL v3 source...
call npm run build
if errorlevel 1 goto :fail

echo.
echo [3/4] Applying database migrations...
echo If Wrangler asks "continue?", type Y and press Enter.
call npm run db:local
if errorlevel 1 goto :fail

echo.
echo [4/4] Starting Sentinel Desk v3...
echo Open: http://127.0.0.1:8787
echo Keep this window open. Press Ctrl+C to stop the lab.
echo.
start "" "http://127.0.0.1:8787"
call npm start
exit /b %errorlevel%

:fail
echo.
echo =====================================================
echo [FAILED] Sentinel Desk could not start.
echo Send the error shown above to ChatGPT.
echo =====================================================
pause
exit /b 1
