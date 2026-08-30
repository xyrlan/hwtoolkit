@echo off
echo ========================================================
echo   Desinstalar RstFlt (Storage Filter)
echo ========================================================
echo.

rem --- Checar admin ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERRO: Execute como Administrador!
    pause
    goto :eof
)

rem --- Parar e remover servico RstFlt ---
echo [*] Parando servico RstFlt...
sc stop RstFlt >nul 2>&1

echo [*] Removendo servico RstFlt...
sc delete RstFlt >nul 2>&1

rem --- Tambem limpar DiskFilter antigo se existir ---
sc query DiskFilter >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Removendo DiskFilter antigo...
    sc stop DiskFilter >nul 2>&1
    sc delete DiskFilter >nul 2>&1
    del /f "%SystemRoot%\System32\drivers\diskfilter.sys" 2>nul
)

rem --- Restaurar UpperFilters (do backup salvo no install) ---
echo [*] Restaurando UpperFilters ao valor original...
powershell -ExecutionPolicy Bypass -Command ^
  "$k='HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}';" ^
  "$backupKey='HKLM:\SOFTWARE\HWToolkit';" ^
  "$orig = (Get-ItemProperty -Path $backupKey -Name OrigUpperFilters -ErrorAction SilentlyContinue).OrigUpperFilters;" ^
  "if ($orig) {" ^
  "  Set-ItemProperty -Path $k -Name UpperFilters -Value $orig -Type MultiString;" ^
  "  Write-Host ('    Restaurado: ' + ($orig -join ', '));" ^
  "  Remove-ItemProperty -Path $backupKey -Name OrigUpperFilters -ErrorAction SilentlyContinue;" ^
  "} else {" ^
  "  $cur = (Get-ItemProperty -Path $k -Name UpperFilters -ErrorAction SilentlyContinue).UpperFilters;" ^
  "  if ($cur -is [string]) { $cur = @($cur) }" ^
  "  $new = @($cur | Where-Object { $_ -and $_ -ne 'RstFlt' -and $_ -ne 'DiskFilter' });" ^
  "  if (-not $new) { $new = @('partmgr') }" ^
  "  Set-ItemProperty -Path $k -Name UpperFilters -Value $new -Type MultiString;" ^
  "  Write-Host ('    Backup ausente - removido RstFlt do valor atual: ' + ($new -join ', '));" ^
  "}"

rem --- Remover arquivo ---
echo [*] Removendo rstflt.sys...
del /f "%SystemRoot%\System32\drivers\rstflt.sys" 2>nul

rem --- Reverter spoofs Fase 1.6 (registry-based, sobrevivem a remocao do driver) ---
echo.
echo ========================================================
echo   Reverter Fase 1.6 (Windows ID + Disk + PCI + Volume)
echo ========================================================
echo Passar --skip-fase16 para pular esta etapa.
set "SKIP_FASE16=0"
for %%A in (%*) do (
    if /I "%%~A"=="--skip-fase16" set "SKIP_FASE16=1"
    if /I "%%~A"=="/skip-fase16"  set "SKIP_FASE16=1"
)

if "%SKIP_FASE16%"=="1" (
    echo [i] --skip-fase16: pulando restore Fase 1.6.
    goto :fase16_done
)

echo [*] Restaurando MachineGuid + ComputerName + Hostname...
if exist "C:\ProgramData\.hwcfg\windows-id-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-windows-id.ps1" -Restore
) else (
    echo     (windows-id-backup.json ausente, pulando)
)

echo [*] Restaurando PCI HardwareID...
if exist "C:\ProgramData\.hwcfg\pci-hardwareid-mapping.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-pci-hardwareid.ps1" -Restore
) else (
    echo     (pci-hardwareid-mapping.json ausente, pulando)
)

echo [*] Restaurando Disk registry...
if exist "C:\ProgramData\.hwcfg\disk-registry-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-disk-registry.ps1" -Restore
) else (
    echo     (disk-registry-backup.json ausente, pulando)
)

echo [*] Restaurando Volume GUIDs (secundarios)...
if exist "C:\ProgramData\.hwcfg\volume-guid-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-volume-guid.ps1" -Restore
) else (
    echo     (volume-guid-backup.json ausente, pulando)
)

:fase16_done

echo.
echo ========================================================
echo   DESINSTALADO! Reinicie o PC.
echo   Storage/SMBIOS + Fase 1.6 revertidos.
echo   ObS: Audio GUIDs / EDID nao revertidos por este script -
echo        rode 08b-restaurar-smbios.bat se precisar do SMBIOS pre-spoof.
echo ========================================================
echo.
pause
