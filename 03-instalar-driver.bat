@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   PASSO 3 - Instalar RstFlt (Storage Filter Driver)
echo   REQUER ADMIN + REBOOT DEPOIS
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

rem --- Checar se o .sys existe ---
set "SYS=%~dp0driver\rstflt.sys"
if not exist "!SYS!" (
    echo [!] ERRO: rstflt.sys nao encontrado!
    echo     Rode 02-compilar-driver.bat primeiro.
    pause
    goto :eof
)

rem --- Checar HVCI / Memory Integrity ---
rem  Se HVCI (Hypervisor-protected Code Integrity) esta ativo, o kernel
rem  IGNORA testsigning e recusa qualquer driver nao assinado, mesmo apos
rem  bcdedit /set testsigning on. Nao adianta prosseguir.
echo [*] Verificando HVCI / Memory Integrity...
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue; if ($dg.SecurityServicesRunning -contains 2) { 'ON' } else { 'OFF' }"`) do set "HVCI=%%v"
if /i "!HVCI!"=="ON" (
    echo.
    echo [!] ERRO: HVCI / Memory Integrity esta ATIVO.
    echo     Com HVCI, o Windows nao carrega drivers nao assinados
    echo     nem com testsigning ligado.
    echo.
    echo     Para desativar:
    echo       1. Abra "Windows Security"
    echo       2. Device Security ^> Core isolation details
    echo       3. Desligue "Memory integrity"
    echo       4. Reinicie e rode este script de novo
    echo.
    echo     Alternativa via registro ^(precisa reboot^):
    echo       reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
    echo.
    pause
    goto :eof
)
echo [*] HVCI: OFF - ok

rem --- Descobrir qual identifier bcdedit reconhece (current vs default) ---
rem  Alguns sistemas so tem {default}, outros so {current}, alguns ambos.
set "BCDID={current}"
bcdedit /enum "{current}" >nul 2>&1
if !errorlevel! neq 0 (
    set "BCDID={default}"
    bcdedit /enum "{default}" >nul 2>&1
    if !errorlevel! neq 0 (
        echo [!] ERRO: bcdedit nao acha nem {current} nem {default}
        echo     Rode 'bcdedit' para ver o estado do BCD.
        pause
        goto :eof
    )
)
echo [*] Usando BCD identifier: !BCDID!

rem --- Checar test signing ---
echo [*] Verificando test signing...
bcdedit /enum "!BCDID!" | findstr /i "testsigning.*Yes" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Habilitando test signing...
    bcdedit /set "!BCDID!" testsigning on
    if !errorlevel! neq 0 (
        echo.
        echo [!] ERRO: Nao foi possivel habilitar test signing em !BCDID!.
        echo     Possiveis causas:
        echo       - Secure Boot ainda ativo na BIOS
        echo       - HVCI/Memory Integrity ligado
        echo       - BCD corrompido (rode 'bcdedit' pra ver)
        pause
        goto :eof
    )
    echo [*] Test signing habilitado em !BCDID!.
) else (
    echo [*] Test signing ja estava habilitado.
)
echo.

rem --- Remover driver antigo (DiskFilter ou RstFlt) ---
sc query DiskFilter >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Removendo DiskFilter antigo...
    sc stop DiskFilter >nul 2>&1
    sc delete DiskFilter >nul 2>&1
    del /f "%SystemRoot%\System32\drivers\diskfilter.sys" 2>nul
    timeout /t 2 /nobreak >nul
)

sc query RstFlt >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Removendo instalacao anterior de RstFlt...
    sc stop RstFlt >nul 2>&1
    sc delete RstFlt >nul 2>&1
    timeout /t 2 /nobreak >nul
)

rem --- Copiar driver ---
echo [*] Copiando rstflt.sys para System32\drivers...
copy /y "!SYS!" "%SystemRoot%\System32\drivers\rstflt.sys" >nul
if %errorlevel% neq 0 (
    echo [!] ERRO ao copiar o driver!
    pause
    goto :eof
)

rem --- Criar servico (BOOT_START) ---
rem  v4.0.3 fix: DiskDrive class UpperFilters sao walked durante o
rem  BOOT_START phase (storvsc/disk.sys). O v3.4->v4.0.2 usavam
rem  start=system que carrega DEPOIS de disk.sys enumerar o boot PDO
rem  -> UpperFilters walk nao acha o servico -> CM_PROB_FAILED_ADD ->
rem  STOP 0x7B INACCESSIBLE_BOOT_DEVICE em todo boot que tem RstFlt
rem  registrado como upper filter da classe. O v3.4 downgrade foi
rem  uma tentativa de safety (evitar brick) mas na verdade CAUSAVA o
rem  brick assim que UpperFilters era populado; escapou porque testes
rem  de campo nao chegaram a essa combinacao ate v4.0 na VM.
rem
rem  A safety real e ErrorControl=Normal (=1): se DriverEntry/AddDevice
rem  falhar, o kernel loga o erro e continua o boot (driver so nao
rem  carrega nesta sessao). Isso da o mesmo "nao brica" que o
rem  system-start pretendia, sem o efeito colateral do 0x7B.
rem
rem  Canonical: WDK diskperf INF ships StartType=0 + Group="PnP Filter"
rem  + ErrorControl=Normal. Ver docs/postmortem-v4-phase5/
rem  incident-v402-signature-plus-filter.md para o research completo
rem  (3 verifiers adversariais unanimes; MSDN "Troubleshooting a
rem  Stop 0x7B" documenta explicitamente essa failure mode).
echo [*] Criando servico RstFlt (boot start, PnP Filter group)...
sc create RstFlt type= kernel start= boot error= normal binPath= "%SystemRoot%\System32\drivers\rstflt.sys" DisplayName= "Intel(R) RST Storage Filter"
if %errorlevel% neq 0 (
    echo [!] ERRO ao criar servico!
    pause
    goto :eof
)

rem --- v3.4: garantir que SMBIOS replay em kernel NAO herda estado de
rem     um install anterior. O opt-in flag agora e explicito e default
rem     off. spoof-smbios.ps1 seta este flag em 1 depois de validar via WMI.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters" /v EnableSmbiosReplay /t REG_DWORD /d 0 /f >nul 2>&1

rem --- Definir grupo de carga ---
rem  v4.0.3: "PnP Filter" e o grupo canonico para upper filters de
rem  classes PnP-enumerated (bate com diskperf WDK sample). Coloca
rem  RstFlt no phase BOOT_START junto com storvsc/disk.sys/partmgr,
rem  antes do UpperFilters walk resolver o servico.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RstFlt" /v Group /t REG_SZ /d "PnP Filter" /f >nul

rem --- Adicionar ao UpperFilters (preservando os existentes) ---
echo [*] Registrando como upper filter da classe DiskDrive...
rem O overwrite cru destruiria filtros legitimos (BitLocker, RST OEM,
rem backup em bloco, etc). Fazemos backup do valor atual, prependamos
rem RstFlt, e gravamos de volta como REG_MULTI_SZ.
powershell -ExecutionPolicy Bypass -Command ^
  "$k='HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}';" ^
  "$cur = (Get-ItemProperty -Path $k -Name UpperFilters -ErrorAction SilentlyContinue).UpperFilters;" ^
  "if (-not $cur) { $cur = @('partmgr') }" ^
  "elseif ($cur -is [string]) { $cur = @($cur) }" ^
  "$backupKey='HKLM:\SOFTWARE\HWToolkit';" ^
  "if (-not (Test-Path $backupKey)) { New-Item -Path $backupKey -Force | Out-Null }" ^
  "if (-not (Get-ItemProperty -Path $backupKey -Name OrigUpperFilters -ErrorAction SilentlyContinue)) {" ^
  "  Set-ItemProperty -Path $backupKey -Name OrigUpperFilters -Value $cur -Type MultiString" ^
  "}" ^
  "$new = @('RstFlt') + ($cur | Where-Object { $_ -ne 'RstFlt' });" ^
  "Set-ItemProperty -Path $k -Name UpperFilters -Value $new -Type MultiString;" ^
  "Write-Host ('    UpperFilters agora: ' + ($new -join ', '))"
if %errorlevel% neq 0 (
    echo [!] ERRO ao registrar UpperFilters!
    sc delete RstFlt >nul 2>&1
    pause
    goto :eof
)

rem --- Preparar chave Parameters do driver ---
rem v3.6: nao ha mais seed/prefix/length de serial pra escrever.
rem O -WriteDriver so cria a chave Parameters vazia (e limpa
rem residuos SerialSeed/SerialPrefix/SerialLength de instalacoes
rem anteriores do v3.5). SmbiosBlob + EnableSmbiosReplay entram
rem depois via 05-aplicar-smbios.
echo [*] Preparando chave Parameters do driver...
if exist "%~dp0scripts\generate-profile.ps1" (
    powershell -ExecutionPolicy Bypass -Command "& '%~dp0scripts\generate-profile.ps1' -WriteDriver" 2>nul
    if !errorlevel! equ 0 (
        echo [OK] Chave Parameters criada
    ) else (
        echo [!] Falha ao criar Parameters - rode 00-gerar-profile.bat primeiro
    )
) else (
    echo [!] generate-profile.ps1 nao encontrado em scripts\
)

echo.
echo ========================================================
echo   INSTALADO COM SUCESSO!
echo.
echo   IMPORTANTE:
echo   - Reinicie o PC para ativar o driver
echo   - Se o Windows nao iniciar, entre no WinRE e rode
echo     09-recuperar-boot.bat do Prompt de Comando
echo   - Apos reiniciar, verifique com:
echo       wmic diskdrive get serialnumber
echo ========================================================
echo.
pause
