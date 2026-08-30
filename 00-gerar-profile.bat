@echo off
echo ========================================================
echo   PASSO 0 - Gerar Profile de Hardware
echo   (roda 1x, ou quando quiser novos IDs)
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

powershell -ExecutionPolicy Bypass -File "%~dp0scripts\generate-profile.ps1" -Generate

echo.
pause
