@echo off
setlocal EnableDelayedExpansion
echo ========================================================
echo   PASSO 4 - Aplicar HWID Changes (v3.6)
echo   Base: MACs (via profile, OUI real)
echo   Fase 1:   Audio GUIDs, EDID full, EMAC UUID
echo   Fase 1.6: Windows IDs, Disk registry, PCI HardwareID, Volume GUID
echo ========================================================
echo.

rem --- Checar admin ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERRO: Execute como Administrador!
    echo     Clique direito no .bat e "Executar como administrador"
    pause
    goto :eof
)

rem --- Parse flags ---
set "SKIP_VOLUME=0"
set "SKIP_DISK=0"
for %%A in (%*) do (
    if /I "%%~A"=="--skip-volume" set "SKIP_VOLUME=1"
    if /I "%%~A"=="/skip-volume"  set "SKIP_VOLUME=1"
    if /I "%%~A"=="--skip-disk"   set "SKIP_DISK=1"
    if /I "%%~A"=="/skip-disk"    set "SKIP_DISK=1"
)

set "MAC_STATUS=OK"
set "AUDIO_STATUS=OK"
set "EDID_STATUS=OK"
set "EMAC_STATUS=OK"
set "WINID_STATUS=OK"
set "DISK_STATUS=OK"
set "PCI_STATUS=OK"
set "VOL_STATUS=OK"

rem ========================================================
rem   Base: HWID changes (MACs somente aqui; MachineGuid + ComputerName +
rem   TCP/IP Hostname foram restaurados em v3.7 no bloco Fase 1.6, abaixo.
rem   SQM/ProductID confirmados NAO lidos por EMAC (recon v2) - nao spoofados.
rem ========================================================
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-mac.ps1"
if %errorlevel% neq 0 (
    set "MAC_STATUS=FAIL(%errorlevel%)"
    echo.
    echo [!] AVISO: spoof-mac.ps1 retornou erro (%errorlevel%).
    echo     As proximas etapas (Fase 1 e 1.6) ainda serao executadas.
    echo.
)

echo.
echo ========================================================
echo   FASE 1 - GAP #3a: Spoof de GUIDs de dispositivos de audio
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-audio-guids.ps1"
if %errorlevel% neq 0 (
    set "AUDIO_STATUS=FAIL(%errorlevel%)"
    echo [!] AVISO: spoof-audio-guids.ps1 falhou (%errorlevel%) - continuando.
)

echo.
echo ========================================================
echo   FASE 1 - GAP #4: Spoof completo de EDID (nome/serial/blocos)
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-edid-full.ps1"
if %errorlevel% neq 0 (
    set "EDID_STATUS=FAIL(%errorlevel%)"
    echo [!] AVISO: spoof-edid-full.ps1 falhou (%errorlevel%) - continuando.
)

echo.
echo ========================================================
echo   FASE 1 - GAP #6: Gerenciamento do cache emac-uuid
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\manage-emac-uuid.ps1" -Apply
if %errorlevel% neq 0 (
    set "EMAC_STATUS=FAIL(%errorlevel%)"
    echo [!] AVISO: manage-emac-uuid.ps1 falhou (%errorlevel%) - continuando.
)

echo.
echo ========================================================
echo   FASE 1.6 - HOTFIX: MachineGuid + ComputerName + Hostname
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-windows-id.ps1"
if %errorlevel% neq 0 (
    set "WINID_STATUS=FAIL(%errorlevel%)"
    echo [!] AVISO: spoof-windows-id.ps1 falhou (%errorlevel%) - continuando.
)

echo.
echo ========================================================
echo   FASE 1.6 - GAP #7: Spoof de Enum\SCSI\Disk (vendor/model)
echo ========================================================
if "%SKIP_DISK%"=="1" (
    set "DISK_STATUS=SKIPPED"
    echo [i] Flag --skip-disk detectada. Etapa pulada.
    goto :disk_done
)

echo.
echo [!] ATENCAO: Este passo renomeia chaves Enum\SCSI\Disk&Ven_*&Prod_*.
echo             O script protege o disco de BOOT, mas se Get-Disk.Location
echo             nao expuser o padrao esperado para o boot disk, o script
echo             ABORTA por seguranca. Ainda assim, confirmacao manual.
echo.
echo     Recomendacoes: ponto de restauracao + pendrive de instalacao.
echo.
set "DISK_CONFIRM="
set /p "DISK_CONFIRM=Digite SIM para prosseguir, ou qualquer outra coisa para pular: "
if /I not "!DISK_CONFIRM!"=="SIM" (
    set "DISK_STATUS=SKIPPED"
    echo [i] Confirmacao nao recebida. Etapa pulada.
    goto :disk_done
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-disk-registry.ps1"
if %errorlevel% neq 0 (
    set "DISK_STATUS=FAIL(%errorlevel%)"
    echo [!] AVISO: spoof-disk-registry.ps1 falhou (%errorlevel%) - continuando.
)
:disk_done

echo.
echo ========================================================
echo   FASE 1.6 - GAP #8: Spoof de HardwareID granular PCI
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-pci-hardwareid.ps1"
if %errorlevel% neq 0 (
    set "PCI_STATUS=FAIL(%errorlevel%)"
    echo [!] AVISO: spoof-pci-hardwareid.ps1 falhou (%errorlevel%) - continuando.
)

echo.
echo ========================================================
echo   FASE 1.6 - GAP #9: Spoof de GUIDs de volume (SECUNDARIOS)
echo ========================================================
if "%SKIP_VOLUME%"=="1" (
    set "VOL_STATUS=SKIPPED"
    echo [i] Flag --skip-volume detectada. Etapa pulada.
    goto :vol_done
)

echo.
echo [!] ATENCAO: Este passo reescreve GUIDs em HKLM\SYSTEM\...\Enum\STORAGE\Volume
echo             e em HKLM\SYSTEM\MountedDevices.
echo.
echo     RISCO: alterar o volume de BOOT (C:) pode INUTILIZAR a inicializacao
echo            do Windows (brick-boot). O script foi projetado para tocar
echo            apenas volumes SECUNDARIOS/DATA, mas por seguranca a
echo            confirmacao e manual.
echo.
echo     Recomendacoes antes de continuar:
echo       - Faca um ponto de restauracao / backup do registro.
echo       - Tenha um pendrive de instalacao do Windows a mao.
echo.
set "VOL_CONFIRM="
set /p "VOL_CONFIRM=Digite SIM para prosseguir, ou qualquer outra coisa para pular: "
if /I not "!VOL_CONFIRM!"=="SIM" (
    set "VOL_STATUS=SKIPPED"
    echo [i] Confirmacao nao recebida. Etapa pulada.
    goto :vol_done
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-volume-guid.ps1"
if %errorlevel% neq 0 (
    set "VOL_STATUS=FAIL(%errorlevel%)"
    echo [!] AVISO: spoof-volume-guid.ps1 falhou (%errorlevel%) - continuando.
)
:vol_done

echo.
echo ========================================================
echo   PASSO 4 concluido.
echo ========================================================
echo Fase 1+1.6 status: mac=!MAC_STATUS! audio=!AUDIO_STATUS! edid=!EDID_STATUS! emac=!EMAC_STATUS! winid=!WINID_STATUS! disk=!DISK_STATUS! pci=!PCI_STATUS! vol=!VOL_STATUS!
echo ========================================================
pause
endlocal
