@echo off
echo ========================================================
echo   Desinstalar RstFlt (Storage Filter)
echo ========================================================
echo.

rem --- Checar admin ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERRO: Execute como Administrador!
    pause
    goto :eof
)

rem --- Parar e remover servico RstFlt ---
echo [*] Parando servico RstFlt...
sc stop RstFlt >nul 2>&1

echo [*] Removendo servico RstFlt...
sc delete RstFlt >nul 2>&1

rem --- Tambem limpar DiskFilter antigo se existir ---
sc query DiskFilter >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Removendo DiskFilter antigo...
    sc stop DiskFilter >nul 2>&1
    sc delete DiskFilter >nul 2>&1
    del /f "%SystemRoot%\System32\drivers\diskfilter.sys" 2>nul
)

rem --- Restaurar UpperFilters (do backup salvo no install) ---
echo [*] Restaurando UpperFilters ao valor original...
powershell -ExecutionPolicy Bypass -Command ^
  "$k='HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}';" ^
  "$backupKey='HKLM:\SOFTWARE\HWToolkit';" ^
  "$orig = (Get-ItemProperty -Path $backupKey -Name OrigUpperFilters -ErrorAction SilentlyContinue).OrigUpperFilters;" ^
  "if ($orig) {" ^
  "  Set-ItemProperty -Path $k -Name UpperFilters -Value $orig -Type MultiString;" ^
  "  Write-Host ('    Restaurado: ' + ($orig -join ', '));" ^
  "  Remove-ItemProperty -Path $backupKey -Name OrigUpperFilters -ErrorAction SilentlyContinue;" ^
  "} else {" ^
  "  $cur = (Get-ItemProperty -Path $k -Name UpperFilters -ErrorAction SilentlyContinue).UpperFilters;" ^
  "  if ($cur -is [string]) { $cur = @($cur) }" ^
  "  $new = @($cur | Where-Object { $_ -and $_ -ne 'RstFlt' -and $_ -ne 'DiskFilter' });" ^
  "  if (-not $new) { $new = @('partmgr') }" ^
  "  Set-ItemProperty -Path $k -Name UpperFilters -Value $new -Type MultiString;" ^
  "  Write-Host ('    Backup ausente - removido RstFlt do valor atual: ' + ($new -join ', '));" ^
  "}"

rem --- Remover arquivo ---
echo [*] Removendo rstflt.sys...
del /f "%SystemRoot%\System32\drivers\rstflt.sys" 2>nul

echo.
echo ========================================================
echo   DESINSTALADO! Reinicie o PC.
echo   Os seriais voltam ao original apos reiniciar.
echo ========================================================
echo.
pause
