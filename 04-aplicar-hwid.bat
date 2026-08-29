@echo off
echo ========================================================
echo   PASSO 4 - Aplicar HWID Changes
echo   (Machine GUID, SQM, Product ID, MACs, EDID)
echo   + Fase 1: Audio GUIDs, EDID full, EMAC UUID
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

rem ========================================================
rem   Base: HWID changes (MachineGuid, SQM, ProductID, MACs, EDID basico)
rem ========================================================
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\change-hwid-easy.ps1"
if %errorlevel% neq 0 (
    echo.
    echo [!] AVISO: change-hwid-easy.ps1 retornou erro (%errorlevel%).
    echo     As proximas etapas (Fase 1) ainda serao executadas.
    echo.
)

echo.
echo ========================================================
echo   FASE 1 - GAP #3a: Spoof de GUIDs de dispositivos de audio
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-audio-guids.ps1"
if %errorlevel% neq 0 (
    echo [!] AVISO: spoof-audio-guids.ps1 falhou (%errorlevel%) - continuando.
)

echo.
echo ========================================================
echo   FASE 1 - GAP #4: Spoof completo de EDID (nome/serial/blocos)
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-edid-full.ps1"
if %errorlevel% neq 0 (
    echo [!] AVISO: spoof-edid-full.ps1 falhou (%errorlevel%) - continuando.
)

echo.
echo ========================================================
echo   FASE 1 - GAP #6: Gerenciamento do cache emac-uuid
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\manage-emac-uuid.ps1" -Apply
if %errorlevel% neq 0 (
    echo [!] AVISO: manage-emac-uuid.ps1 falhou (%errorlevel%) - continuando.
)

echo.
echo ========================================================
echo   PASSO 4 concluido.
echo ========================================================
pause
