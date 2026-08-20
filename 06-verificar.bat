@echo off
echo ========================================================
echo   PASSO 6 - Verificar Tudo
echo ========================================================
echo.

echo === SERIAL DE DISCO ===
wmic diskdrive get model,serialnumber
echo.

echo === UUID (SMBIOS Type 1) ===
powershell -Command "Get-CimInstance Win32_ComputerSystemProduct | Select-Object UUID | Format-List"

echo === SYSTEM MANUFACTURER ===
powershell -Command "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model | Format-List"

echo === BASEBOARD ===
powershell -Command "Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,SerialNumber | Format-List"

echo === CHASSIS ===
powershell -Command "Get-CimInstance Win32_SystemEnclosure | Select-Object Manufacturer,SerialNumber | Format-List"

echo === MACHINE GUID ===
reg query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid 2>nul
echo.

echo === SQM MACHINE ID ===
reg query "HKLM\SOFTWARE\Microsoft\SQMClient" /v MachineId 2>nul
echo.

echo === PRODUCT ID ===
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductId 2>nul
echo.

echo === MAC ADDRESSES ===
powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name,InterfaceDescription,MacAddress | Format-Table -AutoSize"

echo === EDID SERIAIS (bytes 12-15) ===
powershell -Command "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY' -Recurse -ErrorAction SilentlyContinue | ForEach-Object { try { $edid = (Get-ItemProperty -Path (Join-Path $_.PSPath 'Device Parameters') -Name 'EDID' -ErrorAction Stop).EDID; if ($edid.Length -ge 128) { $serial = '{0:X2}{1:X2}{2:X2}{3:X2}' -f $edid[12],$edid[13],$edid[14],$edid[15]; Write-Host ('  ' + $_.PSChildName + ': ' + $serial) } } catch {} }"
echo.

echo === VALIDACAO DO PROFILE ===
if exist "%~dp0scripts\hwprofile.ps1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0scripts\hwprofile.ps1" -Validate
) else (
    echo [!] hwprofile.ps1 nao encontrado
)

echo.
pause
