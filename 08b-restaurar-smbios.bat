@echo off
echo ========================================================
echo   PASSO 8b - Restaurar SMBIOS do Firmware
echo   (limpa spoof persistido no registro / cache do driver)
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

powershell -ExecutionPolicy Bypass -File "%~dp0scripts\restore-smbios.ps1"
if %errorlevel% neq 0 (
    echo.
    echo [!] AVISO: restore-smbios.ps1 retornou erro (%errorlevel%).
)

echo.
echo ========================================================
echo   PASSO 8b concluido. Reinicie para ler SMBIOS do firmware.
echo ========================================================
pause
