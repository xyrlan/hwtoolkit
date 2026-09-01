@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   PASSO 2 - Compilando rstflt.sys (driver v5.0.4)
echo ========================================================
echo.

rem --- Procurar vcvars64.bat em locais conhecidos ---
rem v4.0.6: adicionado suporte para VS 18 (2026) que instala em
rem "Microsoft Visual Studio\18\<edition>" (numero-de-produto em vez do ano).
set "VCVARS="

for %%V in (18 2022) do (
    for %%E in (BuildTools Community Professional Enterprise) do (
        set "P=C:\Program Files\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvars64.bat"
        if "!VCVARS!"=="" if exist "!P!" set "VCVARS=!P!"
        set "P=C:\Program Files (x86)\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvars64.bat"
        if "!VCVARS!"=="" if exist "!P!" set "VCVARS=!P!"
    )
)

if "!VCVARS!"=="" (
    echo [!] ERRO: vcvars64.bat nao encontrado!
    echo     Rode 01-instalar-ferramentas.bat primeiro.
    echo     Ou instale o "Desktop development with C++" workload do Visual Studio 2022/2026.
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
set "OK_R=0"
if exist rstflt.sys set "OK_R=1"

echo ========================================================
if "!OK_R!"=="1" ( echo   [OK]  rstflt.sys ) else ( echo   [FAIL] rstflt.sys )
echo ========================================================
if "!OK_R!"=="0" echo   Erros de compilacao acima.
echo.
pause
