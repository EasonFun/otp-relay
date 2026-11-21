@echo off
chcp 65001 >nul
echo.
echo  Adding firewall rule for TCP port 8788 (needs admin approval)...
echo.
netsh advfirewall firewall show rule name="OTP Assistant 8788" >nul 2>&1
if %errorlevel%==0 (
  echo  Rule already exists.
  pause
  exit /b 0
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process netsh.exe -ArgumentList 'advfirewall','firewall','add','rule','name=OTP Assistant 8788','dir=in','action=allow','protocol=TCP','localport=8788','profile=any' -Verb RunAs -Wait"
echo.
echo  Done. If the phone still cannot connect, see README.md.
pause
