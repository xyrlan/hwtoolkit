@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   PASSO 3b - Instalar VolFlt (Volume Serial minifilter)
echo   REQUER ADMIN. Nao precisa reboot para carregar.
echo ========================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERRO: Execute como Administrador!
    pause
    goto :eof
)

set "SYS=%~dp0driver\volflt.sys"
if not exist "!SYS!" (
    echo [!] ERRO: volflt.sys nao encontrado!
    echo     Rode 02-compilar-driver.bat primeiro.
    pause
    goto :eof
)

rem --- Test signing precisa estar ligado (isso ja foi feito por 03) ---
bcdedit /enum "{current}" 2>nul | findstr /i "testsigning.*Yes" >nul 2>&1
if %errorlevel% neq 0 (
    bcdedit /enum "{default}" 2>nul | findstr /i "testsigning.*Yes" >nul 2>&1
    if !errorlevel! neq 0 (
        echo [!] ERRO: test signing NAO esta ligado.
        echo     Rode 03-instalar-driver.bat primeiro ^(ele liga testsigning^).
        pause
        goto :eof
    )
)

rem --- Remover instalacao anterior via fltmc + sc ---
sc query VolFlt >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Removendo instalacao anterior de VolFlt...
    fltmc unload VolFlt >nul 2>&1
    sc stop VolFlt >nul 2>&1
    sc delete VolFlt >nul 2>&1
    timeout /t 2 /nobreak >nul
)

echo [*] Copiando volflt.sys para System32\drivers...
copy /y "!SYS!" "%SystemRoot%\System32\drivers\volflt.sys" >nul
if %errorlevel% neq 0 (
    echo [!] ERRO ao copiar volflt.sys
    pause
    goto :eof
)

echo [*] Criando servico VolFlt (filesys, system-start)...
sc create VolFlt type= filesys start= system error= normal ^
    binPath= "%SystemRoot%\System32\drivers\volflt.sys" ^
    group= "FSFilter Activity Monitor" ^
    DisplayName= "Intel(R) Volume Serial Filter"
if %errorlevel% neq 0 (
    echo [!] ERRO ao criar servico VolFlt
    pause
    goto :eof
)

rem --- Registro minifilter: DefaultInstance + Altitude ---
rem  Altitude 385200 esta dentro do range Activity Monitor (360000-389998).
rem  Nao esta oficialmente registrada com a Microsoft — para uso privado
rem  em test-signing mode isso e aceitavel; producao exigiria requisitar
rem  uma altitude via allocatedaltitudes program.
echo [*] Registrando altitude do minifilter...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VolFlt\Instances" ^
    /v DefaultInstance /t REG_SZ /d "VolFlt Instance" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VolFlt\Instances\VolFlt Instance" ^
    /v Altitude /t REG_SZ /d 385200 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VolFlt\Instances\VolFlt Instance" ^
    /v Flags /t REG_DWORD /d 0 /f >nul

rem --- Compartilhar seed do rstflt em Parameters (leitura em kernel) ---
echo [*] Copiando SerialSeed de rstflt para VolFlt Parameters...
powershell -ExecutionPolicy Bypass -Command ^
  "$rstf='HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters';" ^
  "$volf='HKLM:\SYSTEM\CurrentControlSet\Services\VolFlt\Parameters';" ^
  "if (-not (Test-Path $volf)) { New-Item -Path $volf -Force | Out-Null }" ^
  "try {" ^
  "  $seed = (Get-ItemProperty -Path $rstf -Name SerialSeed -ErrorAction Stop).SerialSeed;" ^
  "  Set-ItemProperty -Path $volf -Name SerialSeed -Value $seed -Type Binary;" ^
  "  Write-Host ('    Seed copiado (' + $seed.Length + ' bytes)')" ^
  "} catch {" ^
  "  Write-Host '    [!] Sem seed em rstflt — VolFlt usara defaults zerados.'" ^
  "  Write-Host '        Rode 00-gerar-profile depois 03-instalar-driver para popular.'" ^
  "}"

echo [*] Carregando VolFlt via fltmc...
fltmc load VolFlt
if %errorlevel% neq 0 (
    echo [!] fltmc load falhou. Detalhes:
    fltmc filters
    echo.
    echo     Se filter nao apareceu ^(cod 0x801f0011 = NAME_COLLISION^),
    echo     alguma altitude conflita. Escolha outra em 03b.
    pause
    goto :eof
)

echo.
echo ========================================================
echo   VolFlt INSTALADO E CARREGADO.
echo.
echo   Verificacao rapida ^(deve devolver VSN spoofado^):
echo     powershell -Command "(Get-Volume C).UniqueId"
echo     vol C:
echo.
echo   Se algo der errado:
echo     fltmc unload VolFlt
echo     sc delete VolFlt
echo ========================================================
echo.
pause
