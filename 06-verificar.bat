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

echo === MAC ADDRESSES ===
powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name,InterfaceDescription,MacAddress | Format-Table -AutoSize"

echo === EDID SERIAIS (bytes 12-15) ===
powershell -Command "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY' -Recurse -ErrorAction SilentlyContinue | ForEach-Object { try { $edid = (Get-ItemProperty -Path (Join-Path $_.PSPath 'Device Parameters') -Name 'EDID' -ErrorAction Stop).EDID; if ($edid.Length -ge 128) { $serial = '{0:X2}{1:X2}{2:X2}{3:X2}' -f $edid[12],$edid[13],$edid[14],$edid[15]; Write-Host ('  ' + $_.PSChildName + ': ' + $serial) } } catch {} }"
echo.

echo === VALIDACAO DO PROFILE ===
if exist "%~dp0scripts\generate-profile.ps1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0scripts\generate-profile.ps1" -Validate
) else (
    echo [!] generate-profile.ps1 nao encontrado
)

echo.
echo === CONSISTENCY CROSS-CHECK + BIOS MIRROR AUDIT ===
if exist "%~dp0scripts\check-consistency.ps1" (
    rem  Read-only. Sinaliza GAPs onde:
    rem    - HARDWARE\DESCRIPTION\System\BIOS ainda mostra a placa REAL
    rem      (SMBIOS spoof furado nesse ponto)
    rem    - Manufacturer diverge entre ComputerSystem/BaseBoard/Chassis
    rem    - Disk Model vs Serial format inconsistente
    powershell -ExecutionPolicy Bypass -File "%~dp0scripts\check-consistency.ps1"
) else (
    echo [!] scripts\check-consistency.ps1 nao encontrado
)

echo.
pause
