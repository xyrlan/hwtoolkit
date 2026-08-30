@echo off
setlocal enabledelayedexpansion

rem ========================================================
rem   pre-test-checklist.bat
rem
rem   Pre-flight para testes com rstflt.
rem   Modos:
rem     (default)  : relatorio somente, nao altera nada
rem     --arm      : aplica todas as mudancas + pede reboot
rem     --disarm   : desliga Driver Verifier
rem
rem   O que cobre (por que existe: no ultimo BSOD nao vimos
rem   STOP code na tela e nao houve dump em disco):
rem     1. Driver Verifier em rstflt.sys
rem     2. AutoReboot=0 (para ver o STOP code na tela)
rem     3. CrashDumpEnabled=7 (Automatic — kernel dump)
rem     4. DedicatedDumpFile ou pagefile >= RAM
rem     5. Estado do driver (servico, SmbiosBlob,
rem        EnableSmbiosReplay, OrigSmbiosData backup)
rem        (v3.6: SerialSeed nao existe mais - IOCTL intercept removido)
rem     6. testsigning + HVCI
rem ========================================================

set "MODE=check"
if /i "%~1"=="--arm"    set "MODE=arm"
if /i "%~1"=="--disarm" set "MODE=disarm"
if /i "%~1"=="/arm"     set "MODE=arm"
if /i "%~1"=="/disarm"  set "MODE=disarm"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERRO: Execute como Administrador!
    pause
    goto :eof
)

echo ========================================================
echo   PRE-TEST CHECKLIST  ^(modo: !MODE!^)
echo ========================================================
echo.

rem ----------------------------------------------------------
rem  1. Test signing + HVCI (delegado ao 03, so relatamos)
rem ----------------------------------------------------------
echo [1/6] BCD / HVCI / test signing
echo -------------------------------------

set "BCDID={current}"
bcdedit /enum "{current}" >nul 2>&1
if !errorlevel! neq 0 set "BCDID={default}"

set "TESTSIGN=OFF"
bcdedit /enum "!BCDID!" 2>nul | findstr /i "testsigning.*Yes" >nul 2>&1
if !errorlevel! equ 0 set "TESTSIGN=ON"
echo    testsigning        : !TESTSIGN!    ^(BCD id !BCDID!^)

for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue; if ($dg.SecurityServicesRunning -contains 2) { 'ON' } else { 'OFF' }"`) do set "HVCI=%%v"
echo    HVCI/MemIntegrity  : !HVCI!

if /i "!TESTSIGN!"=="OFF" (
    echo    ^> testsigning OFF: driver nao vai carregar. Rode 03 para ligar.
)
if /i "!HVCI!"=="ON" (
    echo    ^> HVCI ON: driver nao vai carregar mesmo com testsigning. Desligue MemInt.
)
echo.

rem ----------------------------------------------------------
rem  2. AutoReboot (queremos VER o STOP na tela azul)
rem ----------------------------------------------------------
echo [2/6] AutoReboot em BSOD
echo -------------------------------------

for /f "tokens=3" %%v in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot 2^>nul ^| findstr AutoReboot') do set "AR=%%v"
if not defined AR set "AR=?"
echo    AutoReboot         : !AR!    ^(queremos 0x0^)

if /i "!MODE!"=="arm" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 0 /f >nul
    echo    ^> setado 0x0
)
echo.

rem ----------------------------------------------------------
rem  3. CrashDumpEnabled — quero kernel dump ou automatico
rem     Valores: 0=none, 1=complete, 2=kernel, 3=small, 7=automatic
rem ----------------------------------------------------------
echo [3/6] CrashDumpEnabled
echo -------------------------------------

for /f "tokens=3" %%v in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled 2^>nul ^| findstr CrashDumpEnabled') do set "CDE=%%v"
if not defined CDE set "CDE=?"
echo    CrashDumpEnabled   : !CDE!    ^(0=none 1=complete 2=kernel 3=mini 7=auto^)

for /f "tokens=3" %%v in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v DumpFile 2^>nul ^| findstr DumpFile') do set "DF=%%v"
if not defined DF set "DF=(default)"
echo    DumpFile           : !DF!

for /f "tokens=3" %%v in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v MinidumpDir 2^>nul ^| findstr MinidumpDir') do set "MDIR=%%v"
if not defined MDIR set "MDIR=(default)"
echo    MinidumpDir        : !MDIR!

if /i "!MODE!"=="arm" (
    rem  7 = automatic  ^(kernel dump com dedicated file managed pelo Windows^)
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled     /t REG_DWORD /d 7 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AlwaysKeepMemoryDump /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v Overwrite            /t REG_DWORD /d 1 /f >nul
    echo    ^> CrashDumpEnabled=7 ^(automatic^) + AlwaysKeepMemoryDump=1
)
echo.

rem ----------------------------------------------------------
rem  4. Pagefile / DedicatedDumpFile — dump precisa de espaco
rem ----------------------------------------------------------
echo [4/6] Espaco de dump
echo -------------------------------------

for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)"`) do set "RAMGB=%%v"
echo    RAM total          : !RAMGB! GB

for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "$p = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | Select-Object -First 1; if ($p) { [math]::Round($p.AllocatedBaseSize / 1024, 1) } else { 0 }"`) do set "PFGB=%%v"
echo    Pagefile alocado   : !PFGB! GB

for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "$k=(Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'); $v = $k.GetValue('DedicatedDumpFile', $null); if ($v) { $v } else { '(nenhum)' }"`) do set "DDF=%%v"
echo    DedicatedDumpFile  : !DDF!

echo    ^> Kernel dump tipico usa ~^(RAM/3^). Automatic dump escreve num
echo      dedicated file que o Windows cria/gerencia sozinho — nao precisa
echo      tunar pagefile. Se voce quer COMPLETE dump ^(dumpEnabled=1^),
echo      pagefile precisa ser >= RAM+1GB no volume de dump.
echo.

rem ----------------------------------------------------------
rem  5. Estado do driver (rstflt) e artefatos criticos
rem ----------------------------------------------------------
echo [5/6] Estado do driver e artefatos
echo -------------------------------------

for /f "tokens=4" %%v in ('sc qc RstFlt 2^>nul ^| findstr START_TYPE') do set "RST_ST=%%v"
if not defined RST_ST set "RST_ST=(nao instalado)"
echo    RstFlt START_TYPE  : !RST_ST!    ^(2 = SYSTEM_START recomendado^)

echo.
echo    RstFlt\Parameters:
powershell -NoProfile -Command ^
  "$p='HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters';" ^
  "if (-not (Test-Path $p)) { '    (chave ausente)' } else {" ^
  "  $blob = (Get-ItemProperty -Path $p -Name SmbiosBlob         -ErrorAction SilentlyContinue).SmbiosBlob;" ^
  "  $ena  = (Get-ItemProperty -Path $p -Name EnableSmbiosReplay -ErrorAction SilentlyContinue).EnableSmbiosReplay;" ^
  "  $orig = (Get-ItemProperty -Path $p -Name OrigSmbiosData     -ErrorAction SilentlyContinue).OrigSmbiosData;" ^
  "  '      SmbiosBlob         : ' + $(if ($blob) { $blob.Length.ToString() + ' bytes' } else { '(ausente)' });" ^
  "  '      EnableSmbiosReplay : ' + $(if ($ena -ne $null) { $ena                      } else { '(ausente=OFF)' });" ^
  "  '      OrigSmbiosData     : ' + $(if ($orig) { $orig.Length.ToString() + ' bytes' } else { '(ausente)' });" ^
  "}"

echo.
echo    Interpretacao de risco:
powershell -NoProfile -Command ^
  "$p='HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters';" ^
  "if (Test-Path $p) {" ^
  "  $blob = (Get-ItemProperty -Path $p -Name SmbiosBlob         -ErrorAction SilentlyContinue).SmbiosBlob;" ^
  "  $ena  = (Get-ItemProperty -Path $p -Name EnableSmbiosReplay -ErrorAction SilentlyContinue).EnableSmbiosReplay;" ^
  "  if ($blob -and $ena -eq 1) { Write-Host '      >> RISCO: replay ARMADO. Se o blob esta ruim, proximo boot bricka.' -ForegroundColor Yellow }" ^
  "  elseif ($blob -and (-not $ena)) { Write-Host '      >> OK: blob cacheado mas replay OFF. Driver nao aplica.' -ForegroundColor Green }" ^
  "  elseif (-not $blob) { Write-Host '      >> OK: sem blob cacheado, sem replay.' -ForegroundColor Green }" ^
  "}"
echo.

rem ----------------------------------------------------------
rem  6. Driver Verifier
rem ----------------------------------------------------------
echo [6/6] Driver Verifier
echo -------------------------------------

verifier /query 2>nul | findstr /i "rstflt" >nul 2>&1
if !errorlevel! equ 0 (
    echo    Verifier          : ATIVO em rstflt
    verifier /query 2>nul | findstr /i "Verified Drivers"
    verifier /query 2>nul | findstr /i "^\s*rstflt"
) else (
    echo    Verifier          : NAO ativo em rstflt
)

if /i "!MODE!"=="arm" (
    echo    ^> Ativando Verifier /standard para rstflt.sys...
    verifier /standard /driver rstflt.sys
    if !errorlevel! neq 0 (
        echo    ^> verifier retornou erro — se rstflt.sys ainda nao foi
        echo      copiado para System32\drivers, isso e esperado. Rode
        echo      03-instalar-driver.bat antes.
    )
)
if /i "!MODE!"=="disarm" (
    echo    ^> Desligando Verifier...
    verifier /reset
)
echo.

rem ----------------------------------------------------------
rem  Resumo + acao sugerida
rem ----------------------------------------------------------
echo ========================================================
if /i "!MODE!"=="check" (
    echo   MODO CHECK — nada foi alterado.
    echo.
    echo   Para armar tudo antes do proximo teste:
    echo     pre-test-checklist.bat --arm
    echo.
    echo   Para desarmar Verifier depois:
    echo     pre-test-checklist.bat --disarm
) else if /i "!MODE!"=="arm" (
    echo   MODO ARM aplicado.
    echo.
    echo   Reboot AGORA para Verifier + CrashControl entrarem em efeito.
    echo   Depois do reboot, rode seu teste normalmente.
    echo   Se BSOD acontecer:
    echo     - Voce vera o STOP code na tela ^(AutoReboot=0^)
    echo     - MEMORY.DMP ficara em %SystemRoot%\MEMORY.DMP
    echo     - Minidumps em %SystemRoot%\Minidump\
    echo   Se boot travar: WinRE + 09-recuperar-boot.bat.
) else (
    echo   MODO DISARM — Verifier resetado. Reboot para efetivar.
)
echo ========================================================
echo.
pause
