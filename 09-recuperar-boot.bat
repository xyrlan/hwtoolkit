@echo off
echo ========================================================
echo   RECUPERACAO DE BOOT - RstFlt
echo.
echo   Use este script SOMENTE se o Windows nao iniciar
echo   apos instalar o driver.
echo.
echo   Como chegar aqui:
echo   1. Na tela de reparo, va em Solucionar Problemas
echo   2. Opcoes Avancadas
echo   3. Prompt de Comando
echo   4. Navegue ate este arquivo e execute-o
echo ========================================================
echo.

rem --- Encontrar a instalacao do Windows ---
set "WINDRV="

if exist "C:\Windows\System32\config\SYSTEM" set "WINDRV=C:"
if "%WINDRV%"=="" if exist "D:\Windows\System32\config\SYSTEM" set "WINDRV=D:"
if "%WINDRV%"=="" if exist "E:\Windows\System32\config\SYSTEM" set "WINDRV=E:"
if "%WINDRV%"=="" if exist "F:\Windows\System32\config\SYSTEM" set "WINDRV=F:"

if "%WINDRV%"=="" (
    echo [!] Nao encontrei a instalacao do Windows!
    echo     Tente manualmente:
    echo       reg load HKLM\OFFLINE X:\Windows\System32\config\SYSTEM
    echo     (substitua X: pela letra do drive do Windows)
    pause
    goto :eof
)

echo [*] Windows encontrado em %WINDRV%
echo.

echo [*] Executando recuperacao via PowerShell (SYSTEM + SOFTWARE offline)...
powershell -ExecutionPolicy Bypass -Command ^
  "$sys='%WINDRV%\Windows\System32\config\SYSTEM';" ^
  "$sw ='%WINDRV%\Windows\System32\config\SOFTWARE';" ^
  "$classGuid='{4d36e967-e325-11ce-bfc1-08002be10318}';" ^
  "$rc = & reg load HKLM\OFFSYS $sys 2>&1; if ($LASTEXITCODE) { Write-Host '[!] Falha ao carregar SYSTEM'; exit 1 }" ^
  "$swOk = $false; & reg load HKLM\OFFSW $sw *>$null; if ($LASTEXITCODE -eq 0) { $swOk = $true }" ^
  "$orig = $null;" ^
  "if ($swOk) { try { $orig = (Get-ItemProperty -Path 'HKLM:\OFFSW\HWToolkit' -Name OrigUpperFilters -ErrorAction Stop).OrigUpperFilters } catch {} }" ^
  "foreach ($cs in @('ControlSet001','ControlSet002')) {" ^
  "  Remove-Item -Path (\"HKLM:\OFFSYS\{0}\Services\RstFlt\" -f $cs)     -Recurse -Force -ErrorAction SilentlyContinue;" ^
  "  Remove-Item -Path (\"HKLM:\OFFSYS\{0}\Services\DiskFilter\" -f $cs) -Recurse -Force -ErrorAction SilentlyContinue;" ^
  "  $classKey = \"HKLM:\OFFSYS\{0}\Control\Class\{1}\" -f $cs, $classGuid;" ^
  "  if ($orig) {" ^
  "    $clean = @($orig | Where-Object { $_ -and $_ -ne 'RstFlt' -and $_ -ne 'DiskFilter' });" ^
  "    if (-not $clean) { $clean = @('partmgr') }" ^
  "    Set-ItemProperty -Path $classKey -Name UpperFilters -Value $clean -Type MultiString;" ^
  "    Write-Host (\"[+] $cs UpperFilters restaurado: $($clean -join ', ')\");" ^
  "  } else {" ^
  "    $cur = (Get-ItemProperty -Path $classKey -Name UpperFilters -ErrorAction SilentlyContinue).UpperFilters;" ^
  "    if ($cur -is [string]) { $cur = @($cur) }" ^
  "    $clean = @($cur | Where-Object { $_ -and $_ -ne 'RstFlt' -and $_ -ne 'DiskFilter' });" ^
  "    if (-not $clean) { $clean = @('partmgr') }" ^
  "    Set-ItemProperty -Path $classKey -Name UpperFilters -Value $clean -Type MultiString;" ^
  "    Write-Host (\"[+] $cs UpperFilters limpo (sem backup): $($clean -join ', ')\");" ^
  "  }" ^
  "  # v3.4: restaurar SMBiosData original se o driver salvou backup" ^
  "  $paramsKey = \"HKLM:\OFFSYS\{0}\Services\RstFlt\Parameters\" -f $cs;" ^
  "  $mssmbKey  = \"HKLM:\OFFSYS\{0}\Services\mssmbios\Data\"     -f $cs;" ^
  "  try {" ^
  "    $backup = (Get-ItemProperty -Path $paramsKey -Name OrigSmbiosData -ErrorAction Stop).OrigSmbiosData;" ^
  "    if ($backup -and $backup.Length -gt 32) {" ^
  "      Set-ItemProperty -Path $mssmbKey -Name SMBiosData -Value $backup -Type Binary;" ^
  "      Write-Host (\"[+] $cs SMBiosData restaurado do backup ($($backup.Length) bytes)\");" ^
  "    }" ^
  "  } catch {}" ^
  "}" ^
  "if ($swOk) { Remove-ItemProperty -Path 'HKLM:\OFFSW\HWToolkit' -Name OrigUpperFilters -ErrorAction SilentlyContinue }" ^
  "[gc]::Collect(); Start-Sleep -Milliseconds 300;" ^
  "& reg unload HKLM\OFFSYS *>$null;" ^
  "if ($swOk) { & reg unload HKLM\OFFSW *>$null }"

echo [*] Removendo arquivos do driver...
del /f "%WINDRV%\Windows\System32\drivers\rstflt.sys"      2>nul
del /f "%WINDRV%\Windows\System32\drivers\diskfilter.sys"  2>nul

echo.
echo ========================================================
echo   PRONTO! Reinicie o PC normalmente.
echo   O driver foi completamente removido.
echo ========================================================
echo.
pause
