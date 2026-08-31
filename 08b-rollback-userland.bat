@echo off
rem ============================================================
rem   Rollback userland-only (Level A pipeline)
rem ------------------------------------------------------------
rem   Reverte todos os spoofs userland aplicados por
rem   04b-aplicar-hwid-emac.bat, na ordem inversa.
rem
rem   NAO toca no driver kernel (rstflt.sys / RstFlt service /
rem   UpperFilters). Para remover o driver, rode depois:
rem     08-desinstalar-driver.bat
rem ============================================================
echo ============================================================
echo   Rollback userland (Level A) - reverte spoofs .ps1
echo ============================================================
echo.

rem --- Checar admin ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERRO: Execute como Administrador!
    pause
    exit /b 1
)

rem --- Parse de flags ---
set "SKIP_CPU=0"
set "DRYRUN=0"
set "DRYRUN_ARG="
for %%A in (%*) do (
    if /I "%%~A"=="--skip-cpu"  set "SKIP_CPU=1"
    if /I "%%~A"=="/skip-cpu"   set "SKIP_CPU=1"
    if /I "%%~A"=="--dry-run"   set "DRYRUN=1"
    if /I "%%~A"=="/dry-run"    set "DRYRUN=1"
)
if "%DRYRUN%"=="1" set "DRYRUN_ARG=-DryRun"

rem --- Aviso: driver ainda instalado? ---
sc.exe query RstFlt >nul 2>&1
if %errorlevel% equ 0 (
    echo [i] Aviso: driver RstFlt esta instalado. Este script rollbackea SO os spoofs userland.
    echo     Para remover o driver tambem, rode 08-desinstalar-driver.bat depois.
    echo.
)

set "HWCFG=C:\ProgramData\.hwcfg"
set "SCRIPTS=%~dp0scripts"
set "STATUS=OK"

rem ============================================================
rem  Ordem de rollback = inversa da aplicacao em 04b:
rem   1. CPU userland (unregister task)
rem   2. Volume GUIDs (secundarios)
rem   3. Network PnP ID
rem   4. USB IDs
rem   5. HID IDs
rem   6. PCI HardwareID
rem   7. Disk registry
rem   8. Windows ID (MachineGuid / ComputerName / Hostname)
rem   9. eMAC UUID (re-habilita heranca ACL; NAO deleta o arquivo)
rem  10. Audio GUIDs
rem  11. MAC (nao suportado - reboot para reset da NIC)
rem ============================================================

rem --- 1. CPU userland task ---
if "%SKIP_CPU%"=="1" (
    echo [i] --skip-cpu: pulando unregister do task CPU userland.
) else (
    echo [*] Desregistrando task CPU userland...
    if exist "%SCRIPTS%\spoof-cpu-userland.ps1" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-cpu-userland.ps1" -Uninstall %DRYRUN_ARG%
        if %errorlevel% neq 0 set "STATUS=FAIL(cpu-userland)"
    ) else (
        echo     (spoof-cpu-userland.ps1 ausente, pulando)
    )
)

rem --- 2. Volume GUIDs (secundarios) ---
echo [*] Restaurando Volume GUIDs secundarios...
if exist "%HWCFG%\volume-guid-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-volume-guid.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(volume-guid)"
) else (
    echo     (volume-guid-backup.json ausente, pulando)
)

rem --- 3. Network PnP ID ---
echo [*] Restaurando Network PnP ID...
if exist "%HWCFG%\network-pnpid-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-network-pnpid.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(network-pnpid)"
) else (
    echo     (network-pnpid-backup.json ausente, pulando)
)

rem --- 4. USB IDs ---
echo [*] Restaurando USB IDs...
if exist "%HWCFG%\usb-ids-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-usb-ids.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(usb-ids)"
) else (
    echo     (usb-ids-backup.json ausente, pulando)
)

rem --- 5. HID IDs ---
echo [*] Restaurando HID IDs...
if exist "%HWCFG%\hid-ids-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-hid-ids.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(hid-ids)"
) else (
    echo     (hid-ids-backup.json ausente, pulando)
)

rem --- 6. PCI HardwareID ---
echo [*] Restaurando PCI HardwareID...
if exist "%HWCFG%\pci-hardwareid-mapping.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-pci-hardwareid.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(pci-hardwareid)"
) else (
    echo     (pci-hardwareid-mapping.json ausente, pulando)
)

rem --- 7. Disk registry ---
echo [*] Restaurando Disk registry...
if exist "%HWCFG%\disk-registry-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-disk-registry.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(disk-registry)"
) else (
    echo     (disk-registry-backup.json ausente, pulando)
)

rem --- 8. Windows ID (MachineGuid / ComputerName / Hostname) ---
echo [*] Restaurando MachineGuid + ComputerName + Hostname...
if exist "%HWCFG%\windows-id-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-windows-id.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(windows-id)"
) else (
    echo     (windows-id-backup.json ausente, pulando)
)

rem --- 9. eMAC UUID (re-habilita heranca ACL) ---
echo [*] Restaurando ACLs do eMAC UUID (re-habilita heranca)...
if exist "%HWCFG%\emac-uuid-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\manage-emac-uuid.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(emac-uuid)"
) else (
    echo     (emac-uuid-backup.json ausente, pulando)
    echo     (nota: o arquivo emac-uuid nao e deletado deliberadamente)
)

rem --- 10. Audio GUIDs ---
echo [*] Restaurando Audio GUIDs...
if exist "%HWCFG%\audio-guids-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-audio-guids.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(audio-guids)"
) else (
    echo     (audio-guids-backup.json ausente, pulando)
)

rem --- 11. MAC (nao suportado) ---
echo [i] MAC nao restaurado (script nao suporta - reboot para NIC reset).

echo.
echo ============================================================
echo   AVISOS
echo ============================================================
echo [!] IMPORTANTE: spoof-edid-full.ps1 NAO tem rollback. Para restaurar EDID original:
echo     - Desconecte e reconecte cada monitor (renegocia EDID via DDC), OU
echo     - Delete manualmente HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY\*\Device Parameters\EDID e reboot.
echo.
echo [i] SMBIOS/CPU replay via driver NAO e afetado por este script.
echo     Se voce armou SMBIOS/CPU e quer desarmar, use:
echo       - .\scripts\spoof-smbios.ps1 -ClearOnly
echo       - .\scripts\prep-crashdump.ps1 -Restore   (se aplicavel)
echo.

echo ============================================================
if "%DRYRUN%"=="1" (
    echo   DRY-RUN concluido. STATUS: %STATUS%
    echo   Nenhuma alteracao foi gravada.
) else (
    echo   Rollback userland concluido. STATUS: %STATUS%
    echo   Recomendado: reiniciar o PC para reset limpo de NIC / Enum.
)
echo ============================================================
echo.
pause

if /I "%STATUS%"=="OK" (
    exit /b 0
) else (
    exit /b 1
)
