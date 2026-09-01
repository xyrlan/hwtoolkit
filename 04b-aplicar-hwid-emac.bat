@echo off
setlocal EnableDelayedExpansion
rem ========================================================
rem  04b-aplicar-hwid-emac.bat  v1.0
rem
rem  Modo Level A (EMAC-only, sem driver kernel).
rem  Base empirica: docs/emac-recon-v3.md.
rem
rem  Este orquestrador roda APENAS spoofers userland, na ordem
rem  correta para evadir a coleta de HWID do EMAC-tier
rem  anti-cheat, SEM instalar o driver RstFlt (BOOT_START) nem
rem  armar o replay SMBIOS/CPU do driver.
rem
rem  Se voce precisa evadir tambem coleta SMBIOS/CPU kernel-mode
rem  (Vanguard, EAC-kernel, BE-kernel), use o pipeline completo:
rem    03-instalar-driver.bat  ->  04-aplicar-hwid.bat  ->  05-aplicar-smbios.bat
rem
rem  FLAGS:
rem    --skip-disk         pula spoof-disk-registry.ps1 (Enum\SCSI\Disk)
rem    --skip-volume       pula spoof-volume-guid.ps1 (GUIDs de volume secundarios)
rem    --skip-hid          pula spoof-hid-ids.ps1
rem    --skip-usb          pula spoof-usb-ids.ps1
rem    --skip-network      pula spoof-network-pnpid.ps1
rem    --skip-cpu          pula spoof-cpu-userland.ps1 (task agendada)
rem    --skip-nls          pula spoof-nls-locale.ps1 (Nls ExtendedLocale/CustomLocale, additive-only)
rem    --skip-persistence  pula spoof-persistence-task.ps1 (re-arm PCI+EDID @ boot via task agendada)
rem ========================================================
echo ========================================================
echo   PASSO 4b - Aplicar HWID (Level A, EMAC-only) v1.0
echo   Sem driver kernel. Sem SMBIOS replay. Sem CPUID replay kernel.
echo   Base empirica: docs\emac-recon-v3.md
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

rem --- Aviso se driver RstFlt estiver instalado ---
rem   NOTA: parens dentro de echoes em bloco `if (...)` sao counted pelo
rem   parser do cmd.exe e podem fechar o bloco prematuramente. Usamos
rem   `goto :label` pra evitar o if-block multi-linha inteiro.
sc.exe query RstFlt >nul 2>&1
if %errorlevel% equ 0 goto :driver_installed_warning
goto :after_driver_check

:driver_installed_warning
echo.
echo [!] AVISO: driver RstFlt esta instalado.
echo     Modo EMAC-only [Level A] assume que ele NAO esta instalado.
echo     Se voce quer o pipeline completo com driver, rode
echo     04-aplicar-hwid.bat + 05-aplicar-smbios.bat.
echo.
echo     Aborta este script [Ctrl+C] ou pressione Enter para
echo     prosseguir mesmo assim [o driver seguira ativo em paralelo].
echo.
pause

:after_driver_check

rem --- Parse flags ---
set "SKIP_DISK=0"
set "SKIP_VOLUME=0"
set "SKIP_HID=0"
set "SKIP_USB=0"
set "SKIP_NETWORK=0"
set "SKIP_CPU=0"
set "SKIP_NLS=0"
set "SKIP_PERSISTENCE=0"
for %%A in (%*) do (
    if /I "%%~A"=="--skip-disk"         set "SKIP_DISK=1"
    if /I "%%~A"=="/skip-disk"          set "SKIP_DISK=1"
    if /I "%%~A"=="--skip-volume"       set "SKIP_VOLUME=1"
    if /I "%%~A"=="/skip-volume"        set "SKIP_VOLUME=1"
    if /I "%%~A"=="--skip-hid"          set "SKIP_HID=1"
    if /I "%%~A"=="/skip-hid"           set "SKIP_HID=1"
    if /I "%%~A"=="--skip-usb"          set "SKIP_USB=1"
    if /I "%%~A"=="/skip-usb"           set "SKIP_USB=1"
    if /I "%%~A"=="--skip-network"      set "SKIP_NETWORK=1"
    if /I "%%~A"=="/skip-network"       set "SKIP_NETWORK=1"
    if /I "%%~A"=="--skip-cpu"          set "SKIP_CPU=1"
    if /I "%%~A"=="/skip-cpu"           set "SKIP_CPU=1"
    if /I "%%~A"=="--skip-nls"          set "SKIP_NLS=1"
    if /I "%%~A"=="/skip-nls"           set "SKIP_NLS=1"
    if /I "%%~A"=="--skip-persistence"  set "SKIP_PERSISTENCE=1"
    if /I "%%~A"=="/skip-persistence"   set "SKIP_PERSISTENCE=1"
)

set "MAC_STATUS=OK"
set "AUDIO_STATUS=OK"
set "EDID_STATUS=OK"
set "EMAC_STATUS=OK"
set "WINID_STATUS=OK"
set "DISK_STATUS=OK"
set "PCI_STATUS=OK"
set "HID_STATUS=OK"
set "USB_STATUS=OK"
set "NETWORK_STATUS=OK"
set "VOL_STATUS=OK"
set "CPU_STATUS=OK"
set "NLS_STATUS=OK"
set "PERSISTENCE_STATUS=OK"

rem ========================================================
rem   ETAPA 1 - MAC address (via profile, OUI real)
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 1 - Spoof de MAC (spoof-mac.ps1)
echo ========================================================
rem -NoPause suprime os Read-Host do spoof-mac.ps1 para nao travar o batch.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-mac.ps1" -NoPause
if %errorlevel% neq 0 (
    set "MAC_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-mac.ps1 retornou erro [%errorlevel%] - continuando.
)

rem ========================================================
rem   ETAPA 2 - GUIDs de dispositivos de audio
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 2 - Spoof de GUIDs de audio (spoof-audio-guids.ps1)
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-audio-guids.ps1"
if %errorlevel% neq 0 (
    set "AUDIO_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-audio-guids.ps1 falhou [%errorlevel%] - continuando.
)

rem ========================================================
rem   ETAPA 3 - EDID completo (nome/serial/blocos)
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 3 - Spoof de EDID (spoof-edid-full.ps1)
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-edid-full.ps1"
if %errorlevel% neq 0 (
    set "EDID_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-edid-full.ps1 falhou [%errorlevel%] - continuando.
)

rem ========================================================
rem   ETAPA 4 - Cache emac-uuid
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 4 - EMAC UUID (manage-emac-uuid.ps1 -Apply)
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\manage-emac-uuid.ps1" -Apply
if %errorlevel% neq 0 (
    set "EMAC_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: manage-emac-uuid.ps1 falhou [%errorlevel%] - continuando.
)

rem ========================================================
rem   ETAPA 5 - MachineGuid + ComputerName + TCP/IP Hostname
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 5 - Windows IDs (spoof-windows-id.ps1)
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-windows-id.ps1"
if %errorlevel% neq 0 (
    set "WINID_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-windows-id.ps1 falhou [%errorlevel%] - continuando.
)

rem ========================================================
rem   ETAPA 6 - Enum\SCSI\Disk (vendor/model)   [PERIGOSO]
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 6 - Spoof de Disk registry (spoof-disk-registry.ps1)
echo ========================================================
if "%SKIP_DISK%"=="1" (
    set "DISK_STATUS=SKIPPED"
    echo [i] Flag --skip-disk detectada. Etapa pulada.
    goto :disk_done
)

echo.
echo [!] ATENCAO: Este passo renomeia chaves Enum\SCSI\Disk^&Ven_*^&Prod_*.
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
    set "DISK_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-disk-registry.ps1 falhou [%errorlevel%] - continuando.
)
:disk_done

rem ========================================================
rem   ETAPA 7 - HardwareID granular PCI
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 7 - Spoof de HardwareID PCI (spoof-pci-hardwareid.ps1)
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-pci-hardwareid.ps1"
if %errorlevel% neq 0 (
    set "PCI_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-pci-hardwareid.ps1 falhou [%errorlevel%] - continuando.
)

rem ========================================================
rem   ETAPA 8 - HID IDs   (RODAR ANTES DE USB)
rem   Ordem importa: renomeacao de HID depende do pai USB
rem   estar estavel. Se USB for renomeado primeiro, a
rem   reidentificacao HID posterior fica invalidada.
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 8 - Spoof de HID IDs (spoof-hid-ids.ps1)
echo ========================================================
if "%SKIP_HID%"=="1" (
    set "HID_STATUS=SKIPPED"
    echo [i] Flag --skip-hid detectada. Etapa pulada.
    goto :hid_done
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-hid-ids.ps1"
if %errorlevel% neq 0 (
    set "HID_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-hid-ids.ps1 falhou [%errorlevel%] - continuando.
)
:hid_done

rem ========================================================
rem   ETAPA 9 - USB IDs   (DEPOIS de HID)
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 9 - Spoof de USB IDs (spoof-usb-ids.ps1)
echo ========================================================
if "%SKIP_USB%"=="1" (
    set "USB_STATUS=SKIPPED"
    echo [i] Flag --skip-usb detectada. Etapa pulada.
    goto :usb_done
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-usb-ids.ps1"
if %errorlevel% neq 0 (
    set "USB_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-usb-ids.ps1 falhou [%errorlevel%] - continuando.
)
:usb_done

rem ========================================================
rem   ETAPA 10 - Network PnP IDs
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 10 - Spoof de Network PnP IDs (spoof-network-pnpid.ps1)
echo ========================================================
if "%SKIP_NETWORK%"=="1" (
    set "NETWORK_STATUS=SKIPPED"
    echo [i] Flag --skip-network detectada. Etapa pulada.
    goto :network_done
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-network-pnpid.ps1"
if %errorlevel% neq 0 (
    set "NETWORK_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-network-pnpid.ps1 falhou [%errorlevel%] - continuando.
)
:network_done

rem ========================================================
rem   ETAPA 11 - GUIDs de volume (SECUNDARIOS)   [PERIGOSO]
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 11 - Spoof de GUIDs de volume (spoof-volume-guid.ps1)
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
    set "VOL_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-volume-guid.ps1 falhou [%errorlevel%] - continuando.
)
:vol_done

rem ========================================================
rem   ETAPA 12 - CPU userland (task agendada)
rem   Instala scheduled task; nao aplica imediatamente a menos
rem   que -RunNow seja passado ao script.
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 12 - Spoof de CPU userland (spoof-cpu-userland.ps1 -Apply)
echo ========================================================
if "%SKIP_CPU%"=="1" (
    set "CPU_STATUS=SKIPPED"
    echo [i] Flag --skip-cpu detectada. Etapa pulada.
    goto :cpu_done
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-cpu-userland.ps1" -Apply
if %errorlevel% neq 0 (
    set "CPU_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-cpu-userland.ps1 falhou [%errorlevel%] - continuando.
)
:cpu_done

rem ========================================================
rem   ETAPA 13 - NLS locale (additive spoof)
rem   Safe: nunca modifica valores existentes, so ADICIONA
rem   1 entrada nova por chave (prefix "hw-"). Nao dispara
rem   PnP re-enum, nao quebra Explorer/Office/date formatters.
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 13 - Spoof NLS locale (spoof-nls-locale.ps1)
echo ========================================================
if "%SKIP_NLS%"=="1" (
    set "NLS_STATUS=SKIPPED"
    echo [i] Flag --skip-nls detectada. Etapa pulada.
    goto :nls_done
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-nls-locale.ps1" -Apply
if %errorlevel% neq 0 (
    set "NLS_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-nls-locale.ps1 falhou [%errorlevel%] - continuando.
)
:nls_done

rem ========================================================
rem   ETAPA 14 - Persistencia PCI + EDID (task agendada)
rem   Registra SYSTEM sched task \HWToolkit\SpoofPersistence
rem   com triggers AtStartup + AtLogOn (com -LogonDelay PT1M).
rem   Re-arma spoof-pci-hardwareid + spoof-edid-full pos-boot,
rem   cobrindo o revert do PnP (PCI enum) e do display miniport
rem   (EDID re-lido via DDC/I2C ao attach do monitor).
rem
rem   NOTA: EDID persistence e INERTE em VMs Hyper-V (driver
rem         sintetico re-le do host). Bare-metal only.
rem   NOTA: Race window - AtStartup dispara ANTES da init PnP
rem         terminar; AtLogOn (pos-winlogon) e o trigger
rem         confiavel. -LogonDelay adiciona 1min pos-logon.
rem ========================================================
echo.
echo ========================================================
echo   ETAPA 14 - Persistencia PCI+EDID (spoof-persistence-task.ps1)
echo ========================================================
if "%SKIP_PERSISTENCE%"=="1" (
    set "PERSISTENCE_STATUS=SKIPPED"
    echo [i] Flag --skip-persistence detectada. Etapa pulada.
    goto :persistence_done
)
rem -RepoPath "%~dp0." e critico: o default do script eh
rem C:\Users\xyrlan\hwtoolkit (a home do author). Sem essa
rem flag o helper on-disk em C:\ProgramData\.hwcfg\SpoofPersistence-Task.ps1
rem grava o path errado, Test-Path falha em qualquer clone que
rem nao seja o do author, e o task fica silent no-op no boot.
rem %~dp0 ja termina em \, e o script faz TrimEnd('\','/') no path.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-persistence-task.ps1" -Apply -LogonDelay -RepoPath "%~dp0."
if %errorlevel% neq 0 (
    set "PERSISTENCE_STATUS=FAIL[%errorlevel%]"
    echo [!] AVISO: spoof-persistence-task.ps1 falhou [%errorlevel%] - continuando.
)
:persistence_done

echo.
echo ========================================================
echo   PASSO 4b concluido.
echo ========================================================
echo Level A status: mac=!MAC_STATUS! audio=!AUDIO_STATUS! edid=!EDID_STATUS! emac=!EMAC_STATUS! winid=!WINID_STATUS! disk=!DISK_STATUS! pci=!PCI_STATUS! hid=!HID_STATUS! usb=!USB_STATUS! network=!NETWORK_STATUS! vol=!VOL_STATUS! cpu=!CPU_STATUS! nls=!NLS_STATUS! persistence=!PERSISTENCE_STATUS!
echo ========================================================
echo.
echo IMPORTANTE:
echo   - NAO rode 03-instalar-driver.bat neste modo (Level A e sem driver).
echo   - NAO rode 05-aplicar-smbios.bat neste modo (arma o driver, que nao existe).
echo   - Para rollback userland, use 08b-rollback-userland.bat.
echo   - Reinicie a maquina para que renomeacoes de dispositivo (HID/USB/PCI/Network)
echo     tenham efeito completo em WMI/SetupAPI.
echo ========================================================
pause
endlocal
