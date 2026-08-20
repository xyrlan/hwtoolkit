@echo off
echo ========================================================
echo   PASSO 4 - Aplicar HWID Changes
echo   (Machine GUID, SQM, Product ID, MACs, EDID)
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

powershell -ExecutionPolicy Bypass -File "%~dp0scripts\change-hwid-easy.ps1"
