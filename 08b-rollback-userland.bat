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
set "SKIP_NLS=0"
set "SKIP_PERSISTENCE=0"
set "DRYRUN=0"
set "DRYRUN_ARG="
for %%A in (%*) do (
    if /I "%%~A"=="--skip-cpu"          set "SKIP_CPU=1"
    if /I "%%~A"=="/skip-cpu"           set "SKIP_CPU=1"
    if /I "%%~A"=="--skip-nls"          set "SKIP_NLS=1"
    if /I "%%~A"=="/skip-nls"           set "SKIP_NLS=1"
    if /I "%%~A"=="--skip-persistence"  set "SKIP_PERSISTENCE=1"
    if /I "%%~A"=="/skip-persistence"   set "SKIP_PERSISTENCE=1"
    if /I "%%~A"=="--dry-run"           set "DRYRUN=1"
    if /I "%%~A"=="/dry-run"            set "DRYRUN=1"
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
rem   1. Persistencia PCI+EDID (unregister task, PRIMEIRO para
rem      parar o re-arm loop antes de tocar os outros spoofers)
rem   2. NLS locale (delete das entradas "hw-*" adicionadas)
rem   3. CPU userland (unregister task)
rem   4. Volume GUIDs (secundarios)
rem   5. Network PnP ID
rem   6. USB IDs
rem   7. HID IDs
rem   8. PCI HardwareID
rem   9. Disk registry
rem  10. Windows ID (MachineGuid / ComputerName / Hostname)
rem  11. eMAC UUID (re-habilita heranca ACL; NAO deleta o arquivo)
rem  12. Audio GUIDs
rem  13. MAC (nao suportado - reboot para reset da NIC)
rem ============================================================

rem --- 1. Persistencia PCI+EDID (PRIMEIRO - para o re-arm loop) ---
if "%SKIP_PERSISTENCE%"=="1" goto :nls_step
schtasks /query /tn "\HWToolkit\SpoofPersistence" >nul 2>&1
if errorlevel 1 (
    echo     (task \HWToolkit\SpoofPersistence ausente, pulando)
    goto :nls_step
)
echo [*] Desregistrando task \HWToolkit\SpoofPersistence...
if exist "%SCRIPTS%\spoof-persistence-task.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-persistence-task.ps1" -Uninstall %DRYRUN_ARG%
    if errorlevel 1 set "STATUS=FAIL(persistence-task)"
) else (
    rem Fallback: se o .ps1 sumiu do clone (repo cleanup, partial pull), o
    rem task ainda esta registrado e continua re-armando spoofers todo boot.
    rem Precisamos matar o task DIRETO via schtasks - senao o rollback deixa
    rem o re-arm loop vivo, exatamente o cenario que o rollback existe pra prevenir.
    echo     (spoof-persistence-task.ps1 ausente no repo, fallback: schtasks /delete direto)
    if "%DRYRUN%"=="1" (
        echo     [DryRun] Iria: schtasks /delete /tn "\HWToolkit\SpoofPersistence" /f
    ) else (
        schtasks /delete /tn "\HWToolkit\SpoofPersistence" /f
        if errorlevel 1 set "STATUS=FAIL(persistence-task-fallback)"
    )
)
:nls_step

rem --- 2. NLS locale (delete das entradas "hw-*") ---
if "%SKIP_NLS%"=="1" goto :cpu_step
echo [*] Restaurando NLS locale (delete das entradas hw-*)...
if not exist "%HWCFG%\nls-locale-backup.json" (
    echo     (nls-locale-backup.json ausente, pulando)
    goto :cpu_step
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-nls-locale.ps1" -Restore %DRYRUN_ARG%
if errorlevel 1 set "STATUS=FAIL(nls-locale)"
:cpu_step

rem --- 3. CPU userland task ---
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

rem --- 4. Volume GUIDs (secundarios) ---
echo [*] Restaurando Volume GUIDs secundarios...
if exist "%HWCFG%\volume-guid-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-volume-guid.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(volume-guid)"
) else (
    echo     (volume-guid-backup.json ausente, pulando)
)

rem --- 5. Network PnP ID ---
echo [*] Restaurando Network PnP ID...
if exist "%HWCFG%\network-pnpid-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-network-pnpid.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(network-pnpid)"
) else (
    echo     (network-pnpid-backup.json ausente, pulando)
)

rem --- 6. USB IDs ---
echo [*] Restaurando USB IDs...
if exist "%HWCFG%\usb-ids-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-usb-ids.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(usb-ids)"
) else (
    echo     (usb-ids-backup.json ausente, pulando)
)

rem --- 7. HID IDs ---
echo [*] Restaurando HID IDs...
if exist "%HWCFG%\hid-ids-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-hid-ids.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(hid-ids)"
) else (
    echo     (hid-ids-backup.json ausente, pulando)
)

rem --- 8. PCI HardwareID ---
echo [*] Restaurando PCI HardwareID...
if exist "%HWCFG%\pci-hardwareid-mapping.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-pci-hardwareid.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(pci-hardwareid)"
) else (
    echo     (pci-hardwareid-mapping.json ausente, pulando)
)

rem --- 9. Disk registry ---
echo [*] Restaurando Disk registry...
if exist "%HWCFG%\disk-registry-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-disk-registry.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(disk-registry)"
) else (
    echo     (disk-registry-backup.json ausente, pulando)
)

rem --- 10. Windows ID (MachineGuid / ComputerName / Hostname) ---
echo [*] Restaurando MachineGuid + ComputerName + Hostname...
if exist "%HWCFG%\windows-id-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-windows-id.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(windows-id)"
) else (
    echo     (windows-id-backup.json ausente, pulando)
)

rem --- 11. eMAC UUID (re-habilita heranca ACL) ---
echo [*] Restaurando ACLs do eMAC UUID (re-habilita heranca)...
if exist "%HWCFG%\emac-uuid-backup.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\manage-emac-uuid.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(emac-uuid)"
) else (
    echo     (emac-uuid-backup.json ausente, pulando)
    echo     (nota: o arquivo emac-uuid nao e deletado deliberadamente)
)

rem --- 12. Audio GUIDs ---
echo [*] Restaurando Audio GUIDs...
if exist "%HWCFG%\audio-rotation.json" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTS%\spoof-audio-guids.ps1" -Restore %DRYRUN_ARG%
    if %errorlevel% neq 0 set "STATUS=FAIL(audio-guids)"
) else (
    echo     (audio-rotation.json ausente, pulando)
)

rem --- 13. MAC (nao suportado) ---
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
