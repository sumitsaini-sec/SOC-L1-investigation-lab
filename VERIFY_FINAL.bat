@echo off
setlocal
cd /d "%~dp0"
title Verify Sentinel Desk v3

echo =====================================================
echo   Sentinel Desk v3 - Full Verification
 echo =====================================================
echo.
if not exist node_modules (
  echo Installing dependencies first...
  call npm ci
  if errorlevel 1 goto :fail
)
echo [1/3] API acceptance + regression suite
call npm run test:acceptance
if errorlevel 1 goto :fail
echo.
echo [2/3] TypeScript check
call npx tsc --noEmit
if errorlevel 1 goto :fail
echo.
echo [3/3] Production build
call npm run build
if errorlevel 1 goto :fail
echo.
echo =====================================================
echo [PASS] Sentinel Desk v3 passed all verification steps.
echo =====================================================
pause
exit /b 0
:fail
echo.
echo =====================================================
echo [FAILED] A verification step failed. Copy the error above.
echo =====================================================
pause
exit /b 1
