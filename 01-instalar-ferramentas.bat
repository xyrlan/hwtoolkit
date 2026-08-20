@echo off
echo ========================================================
echo   PASSO 1 - Instalar Visual Studio Build Tools + WDK
echo   (roda 1x, reinicie o PC depois)
echo ========================================================
echo.

echo [1/2] Instalando VS 2022 Build Tools (Desktop C++)...
winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --quiet --wait"
echo.

echo [2/2] Instalando Windows Driver Kit 10.0.22621...
winget install Microsoft.WindowsWDK.10.0.22621
echo.

echo ========================================================
echo   PRONTO! Reinicie o PC antes de compilar.
echo ========================================================
pause
