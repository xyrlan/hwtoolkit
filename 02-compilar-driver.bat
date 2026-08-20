@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   PASSO 2 - Compilando rstflt.sys (v3.1)
echo ========================================================
echo.

rem --- Procurar vcvars64.bat em locais conhecidos ---
set "VCVARS="

set "P=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if exist "!P!" set "VCVARS=!P!"

if "!VCVARS!"=="" set "P=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if "!VCVARS!"=="" if exist "!P!" set "VCVARS=!P!"

if "!VCVARS!"=="" set "P=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
if "!VCVARS!"=="" if exist "!P!" set "VCVARS=!P!"

if "!VCVARS!"=="" set "P=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if "!VCVARS!"=="" if exist "!P!" set "VCVARS=!P!"

if "!VCVARS!"=="" (
    echo [!] ERRO: vcvars64.bat nao encontrado!
    echo     Rode 01-instalar-ferramentas.bat primeiro.
    echo.
    pause
    goto :eof
)

echo [*] Usando: !VCVARS!
echo.
call "!VCVARS!"
echo.

rem --- Limpar e compilar ---
echo [*] Compilando driver...
cd /d "%~dp0driver"

nmake /f makefile.mak clean 2>nul
nmake /f makefile.mak

echo.
if exist rstflt.sys (
    echo ========================================================
    echo   SUCESSO! rstflt.sys compilado.
    echo ========================================================
) else (
    echo ========================================================
    echo   ERRO na compilacao. Verifique os erros acima.
    echo ========================================================
)
echo.
pause
