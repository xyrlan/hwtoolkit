@echo off
setlocal EnableDelayedExpansion
echo ========================================================
echo   PASSO 4 - Aplicar HWID Changes (v3.5.1)
echo   Base: MACs (via profile, OUI real)
echo   Fase 1: Audio GUIDs, EDID full, EMAC UUID
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

set "MAC_STATUS=OK"
set "AUDIO_STATUS=OK"
set "EDID_STATUS=OK"
set "EMAC_STATUS=OK"

rem ========================================================
rem   Base: HWID changes (MACs somente; MachineGuid/SQM/ProductID/EDID basico removidos em v3.5.1)
rem ========================================================
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-mac.ps1"
if %errorlevel% neq 0 (
    set "MAC_STATUS=FAIL(%errorlevel%)"
    echo.
    echo [!] AVISO: spoof-mac.ps1 retornou erro (%errorlevel%).
    echo     As proximas etapas (Fase 1) ainda serao executadas.
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
echo   PASSO 4 concluido.
echo ========================================================
echo Fase 1 status: mac=!MAC_STATUS! audio=!AUDIO_STATUS! edid=!EDID_STATUS! emac=!EMAC_STATUS!
echo ========================================================
pause
endlocal
