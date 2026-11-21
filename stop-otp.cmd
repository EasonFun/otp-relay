@echo off
chcp 65001 >nul
echo Stopping OTP Assistant (process listening on 8788)...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8788" ^| findstr "LISTENING"') do (
  echo   taskkill /f /pid %%a
  taskkill /f /pid %%a >nul 2>&1
)
echo Done.
timeout /t 2 >nul
