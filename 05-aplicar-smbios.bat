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

rem --- Precheck: driver RstFlt necessario para replay do blob apos reboot ---
sc query RstFlt >nul 2>&1
if errorlevel 1 (
    echo AVISO: driver RstFlt nao instalado. SMBIOS replay em kernel nao vai persistir apos reboot.
    echo         Instale via 03-instalar-driver.bat primeiro para persistencia.
    choice /C SN /M "Continuar mesmo assim"
    if errorlevel 2 exit /b 1
)

echo Escolha uma opcao:
echo   [1] Aplicar agora (efeito ate proximo reboot)
echo   [2] Aplicar + instalar task agendada (persiste entre reboots)
echo   [3] Desinstalar task agendada
echo.
set /p escolha="Opcao (1/2/3): "

if "%escolha%"=="1" (
    powershell -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-smbios.ps1"
) else if "%escolha%"=="2" (
    powershell -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-smbios.ps1" -InstallTask
) else if "%escolha%"=="3" (
    powershell -ExecutionPolicy Bypass -File "%~dp0scripts\spoof-smbios.ps1" -Uninstall
) else (
    echo [!] Opcao invalida.
)
echo.
pause
