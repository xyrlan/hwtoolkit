@echo off
setlocal enabledelayedexpansion
echo ========================================================
echo   RECUPERACAO DE BOOT - RstFlt (v4.0.1 - cmd-only)
echo.
echo   Use este script SOMENTE se o Windows nao iniciar
echo   apos instalar o driver.
echo.
echo   Como chegar aqui:
echo   1. Na tela de reparo, va em Solucionar Problemas
echo   2. Opcoes Avancadas
echo   3. Prompt de Comando
echo   4. Navegue ate este arquivo e execute-o
echo.
echo   NOTA v4.0.1: script reescrito sem PowerShell.
echo   WinRE base image nao carrega powershell.exe.
echo   Agora usa somente reg.exe + del + cmd builtins.
echo ========================================================
echo.

rem =======================================================
rem  Encontrar a letra do drive Windows no WinRE
rem  Sob WinRE C: normalmente e o ramdisk WinPE.
rem  Windows real pode estar em D:/E:/F:/W:/G:/H:. Precisamos
rem  varrer TODAS as letras montadas, nao so C-F.
rem =======================================================
set "WINDRV="
for %%L in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist "%%L:\Windows\System32\config\SYSTEM" (
        if not defined WINDRV set "WINDRV=%%L:"
    )
)

if not defined WINDRV (
    echo [!] Nao encontrei a instalacao do Windows em nenhuma letra.
    echo     Tente manualmente:
    echo       diskpart
    echo         list volume
    echo         exit
    echo       reg load HKLM\OFFSYS X:\Windows\System32\config\SYSTEM
    echo     ^(substitua X: pela letra do drive do Windows^)
    echo.
    pause
    goto :eof
)

echo [*] Windows encontrado em %WINDRV%
echo.

rem =======================================================
rem  Load SYSTEM hive offline
rem =======================================================
echo [*] Carregando HKLM\SYSTEM offline em HKLM\OFFSYS...
reg load HKLM\OFFSYS "%WINDRV%\Windows\System32\config\SYSTEM" >nul 2>&1
if errorlevel 1 (
    echo [!] Falha ao carregar SYSTEM hive.
    echo     Provavel causa: hive ja carregado ^(reboot o WinRE^) ou
    echo     arquivo corrompido. Rode manualmente:
    echo       reg load HKLM\OFFSYS %WINDRV%\Windows\System32\config\SYSTEM
    pause
    goto :eof
)
echo [+] SYSTEM hive carregado.
echo.

rem =======================================================
rem  Iterar sobre ControlSet001, ControlSet002 (e 003 raro)
rem =======================================================
for %%C in (ControlSet001 ControlSet002 ControlSet003) do (
    call :cleanControlSet %%C
)

rem =======================================================
rem  Unload SYSTEM hive
rem =======================================================
echo.
echo [*] Descarregando HKLM\OFFSYS...
rem  Pequena espera para o garbage collector do kernel liberar handles
rem  (equivalente ao [gc]::Collect() + sleep 300 da versao PowerShell).
ping -n 2 127.0.0.1 >nul
reg unload HKLM\OFFSYS >nul 2>&1
if errorlevel 1 (
    echo [!] Falha ao descarregar OFFSYS - tentativa 2 apos 3s...
    ping -n 4 127.0.0.1 >nul
    reg unload HKLM\OFFSYS >nul 2>&1
    if errorlevel 1 (
        echo [!] Ainda falhou. Reinicie o PC assim mesmo - hive sera
        echo     descarregada quando WinRE terminar.
    ) else (
        echo [+] OFFSYS descarregado na segunda tentativa.
    )
) else (
    echo [+] OFFSYS descarregado.
)
echo.

rem =======================================================
rem  Deleta arquivos .sys
rem =======================================================
echo [*] Removendo arquivos do driver...
if exist "%WINDRV%\Windows\System32\drivers\rstflt.sys" (
    del /f "%WINDRV%\Windows\System32\drivers\rstflt.sys" >nul 2>&1
    if not exist "%WINDRV%\Windows\System32\drivers\rstflt.sys" (
        echo [+] rstflt.sys removido.
    ) else (
        echo [!] Falha ao remover rstflt.sys ^(read-only?^).
    )
) else (
    echo [i] rstflt.sys nao existe - nada a fazer.
)

if exist "%WINDRV%\Windows\System32\drivers\diskfilter.sys" (
    del /f "%WINDRV%\Windows\System32\drivers\diskfilter.sys" >nul 2>&1
    echo [+] diskfilter.sys ^(legacy^) removido.
)

echo.
echo ========================================================
echo   PRONTO! Reinicie o PC normalmente.
echo   O driver foi completamente removido.
echo.
echo   Se ainda houver problema apos reboot, considere restaurar
echo   o hive SYSTEM de backup ^(v4.0.1 fallback^):
echo     copy /y %WINDRV%\Windows\System32\config\SYSTEM ^
%WINDRV%\Windows\System32\config\SYSTEM.brk
echo     copy /y %WINDRV%\Windows\System32\config\RegBack\SYSTEM ^
%WINDRV%\Windows\System32\config\SYSTEM
echo   ^(RegBack pode ter ate 10 dias de defasagem - use so em
echo   ultimo caso^)
echo ========================================================
echo.
pause
goto :eof


rem =======================================================
rem  :cleanControlSet <ControlSet-name>
rem  Limpa RstFlt de um ControlSet especifico. Silenciosamente
rem  ignora se o ControlSet nao existir (comum para ControlSet003).
rem =======================================================
:cleanControlSet
set "CS=%~1"

rem  Verifica se o ControlSet existe
reg query "HKLM\OFFSYS\%CS%" >nul 2>&1
if errorlevel 1 goto :eof

echo [*] Processando %CS%...

rem  1. Remove servico RstFlt inteiro
reg delete "HKLM\OFFSYS\%CS%\Services\RstFlt" /f >nul 2>&1
if errorlevel 1 (
    echo    [i] %CS%\Services\RstFlt nao existe - ok.
) else (
    echo    [+] %CS%\Services\RstFlt removido.
)

rem  2. Remove servico DiskFilter legacy
reg delete "HKLM\OFFSYS\%CS%\Services\DiskFilter" /f >nul 2>&1

rem  3. Restaura UpperFilters do DiskDrive class para o baseline.
rem     UpperFilters e REG_MULTI_SZ. reg.exe aceita \0 como separator
rem     no /d, mas o parser da linha de comando cmd tem problemas com
rem     \0 literal. Alternativa robusta: sobrescrever com valor unico
rem     "partmgr" (o que 03-instalar-driver.bat originalmente encontra
rem     em maquinas limpas). Se voce tinha outros filtros de terceiros
rem     antes (raro em SATA/NVMe padrao), eles precisarao ser
rem     re-registrados manualmente - mas isso e melhor que boot loop.
set "CLASSKEY=HKLM\OFFSYS\%CS%\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}"
reg query "%CLASSKEY%" /v UpperFilters >nul 2>&1
if not errorlevel 1 (
    reg add "%CLASSKEY%" /v UpperFilters /t REG_MULTI_SZ /d "partmgr" /f >nul 2>&1
    if errorlevel 1 (
        echo    [!] %CS% UpperFilters restore falhou.
    ) else (
        echo    [+] %CS% UpperFilters restaurado para 'partmgr'.
    )
) else (
    echo    [i] %CS%\Control\Class\{DiskDrive}\UpperFilters ausente - ok.
)

rem  4. Restaurar SMBiosData do backup salvo pelo driver v3.4+.
rem     reg.exe puro NAO consegue copiar REG_BINARY entre valores
rem     diretamente. Skip esta etapa - o SMBIOS spoofado no registro
rem     nao brica boot ^(mssmbios apenas expoe os valores^). Pos-boot,
rem     rodar spoof-smbios.ps1 -Uninstall restaura via Grant-Sm...
rem     ACL + OrigSmbiosData backup. Aqui a prioridade e desbrickar,
rem     nao restaurar SMBIOS.
echo    [i] %CS% SMBiosData nao restaurado offline ^(feito pos-boot^).

rem  5. Remove CpuStrings + EnableCpuReplay ^(v4.0+^) do Parameters.
rem     HARDWARE\DESCRIPTION\System e volatil - o kernel reconstroi
rem     CentralProcessor\* do CPUID a cada boot com valores reais.
rem     Desligar EnableCpuReplay + remover CpuStrings evita replay
rem     futuro. OrigCpuStrings fica preservado para spoof-smbios.ps1
rem     -Uninstall usar depois.
reg delete "HKLM\OFFSYS\%CS%\Services\RstFlt\Parameters" /v EnableCpuReplay /f >nul 2>&1
reg delete "HKLM\OFFSYS\%CS%\Services\RstFlt\Parameters" /v CpuStrings       /f >nul 2>&1
reg delete "HKLM\OFFSYS\%CS%\Services\RstFlt\Parameters" /v EnableSmbiosReplay /f >nul 2>&1
echo    [+] %CS% CPU replay + SMBIOS replay opt-ins desligados.

goto :eof
