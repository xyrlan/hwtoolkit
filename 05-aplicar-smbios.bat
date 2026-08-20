@echo off
echo ========================================================
echo   PASSO 5 - Aplicar SMBIOS Spoof
echo   (UUID, System/Board/Chassis strings)
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

echo Escolha uma opcao:
echo   [1] Aplicar agora (efeito ate proximo reboot)
echo   [2] Aplicar + instalar task agendada (persiste entre reboots)
echo   [3] Desinstalar task agendada
echo.
set /p escolha="Opcao (1/2/3): "

if "%escolha%"=="1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-uuid.ps1"
) else if "%escolha%"=="2" (
    powershell -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-uuid.ps1" -InstallTask
) else if "%escolha%"=="3" (
    powershell -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-uuid.ps1" -Uninstall
) else (
    echo [!] Opcao invalida.
)
echo.
pause
