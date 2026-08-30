@echo off
setlocal enabledelayedexpansion
title Limpeza COMPLETA - v3
color 0A

echo ============================================
echo   Limpeza COMPLETA de Traces - v3
echo   Cobre 30+ locais do Windows
echo ============================================
echo.

rem --- Checar admin ---
net session >nul 2>&1
if %errorlevel% equ 0 set "ADM=1"
if %errorlevel% neq 0 set "ADM=0"

if "!ADM!"=="1" echo [+] Rodando como Administrador - limpeza COMPLETA
if "!ADM!"=="0" echo [!] SEM admin - rode como administrador para limpeza completa
echo.

rem ============================================================
rem  1/11  PROCESSOS
rem ============================================================
echo [*] 1/11  Encerrando processos...
taskkill /f /im "rubinot*" >nul 2>&1
taskkill /f /im "RubinOT*" >nul 2>&1
taskkill /f /im "rubinot_dx.exe" >nul 2>&1
echo     [OK] Processos encerrados
echo.

rem ============================================================
rem  2/11  ARQUIVOS E PASTAS
rem ============================================================
echo [*] 2/11  Removendo arquivos e pastas...

rem AppData Local - launcher Electron
if not exist "%LOCALAPPDATA%\rubinot-launcher" goto local_ok
rmdir /s /q "%LOCALAPPDATA%\rubinot-launcher" 2>nul
echo     [X] AppData\Local\rubinot-launcher
goto local_done
:local_ok
echo     [OK] AppData\Local\rubinot-launcher
:local_done

rem AppData Roaming
if not exist "%APPDATA%\rubinot-launcher" goto roam_ok
rmdir /s /q "%APPDATA%\rubinot-launcher" 2>nul
echo     [X] AppData\Roaming\rubinot-launcher
goto roam_done
:roam_ok
echo     [OK] AppData\Roaming\rubinot-launcher
:roam_done

rem Program Files - instalacao
set "PF86=C:\Program Files (x86)\RubinOT 2.0"
if not exist "!PF86!" goto pf_ok
rmdir /s /q "!PF86!" 2>nul
echo     [X] Program Files\RubinOT 2.0
goto pf_done
:pf_ok
echo     [OK] Program Files\RubinOT 2.0
:pf_done

rem Downloads - qualquer arquivo rubinot
for /f "delims=" %%f in ('dir /b "%USERPROFILE%\Downloads\*rubinot*" 2^>nul') do del /f /q "%USERPROFILE%\Downloads\%%f" 2>nul & echo     [X] Downloads\%%f

rem Screenshots
if exist "%USERPROFILE%\OneDrive\Pictures\Screenshots\rubinot.png" del /f /q "%USERPROFILE%\OneDrive\Pictures\Screenshots\rubinot.png" 2>nul & echo     [X] Screenshots\rubinot.png

rem Desktop shortcuts
if exist "%USERPROFILE%\Desktop\RubinOT.lnk" del /f /q "%USERPROFILE%\Desktop\RubinOT.lnk" 2>nul & echo     [X] Desktop\RubinOT.lnk
if exist "C:\Users\Public\Desktop\RubinOT.lnk" del /f /q "C:\Users\Public\Desktop\RubinOT.lnk" 2>nul & echo     [X] Public Desktop\RubinOT.lnk

rem Start Menu
for /f "delims=" %%f in ('dir /b /s "%APPDATA%\Microsoft\Windows\Start Menu\*rubinot*" 2^>nul') do del /f /q "%%f" 2>nul & echo     [X] Start Menu: %%~nxf
for /f "delims=" %%f in ('dir /b /s "%ProgramData%\Microsoft\Windows\Start Menu\*rubinot*" 2^>nul') do del /f /q "%%f" 2>nul & echo     [X] Start Menu All Users: %%~nxf

rem Icon cache
del /f /q "%LOCALAPPDATA%\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\AppIconCache\100\*rubinot*" 2>nul

echo     [OK] Arquivos limpos
echo.

rem ============================================================
rem  3/11  REGISTRO - HKCU chaves com nome rubinot
rem ============================================================
echo [*] 3/11  Limpando registro HKCU chaves...

for /f "tokens=*" %%k in ('reg query "HKCU\Software" /s /f "rubinot" /k 2^>nul ^| findstr /i "HKEY_"') do reg delete "%%k" /f >nul 2>&1 & echo     [X] %%k

echo     [OK] Chaves HKCU limpas
echo.

rem ============================================================
rem  4/11  REGISTRO - HKLM precisa admin
rem ============================================================
echo [*] 4/11  Limpando registro HKLM...

if "!ADM!"=="0" echo     [!] Pulando - precisa admin & goto skip_hklm

rem Uninstall entry
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{7BB3430F-E0F5-41C1-84CF-5DA059E405A3}_is1" /f >nul 2>&1
echo     [X] Uninstall key

rem RADAR HeapLeakDetection
reg delete "HKLM\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications\rubinot_dx.exe" /f >nul 2>&1
echo     [X] RADAR entry

rem Busca geral HKLM
for /f "tokens=*" %%k in ('reg query "HKLM\SOFTWARE" /s /f "rubinot" /k 2^>nul ^| findstr /i "HKEY_"') do reg delete "%%k" /f >nul 2>&1 & echo     [X] %%k

echo     [OK] HKLM limpo
:skip_hklm
echo.

rem ============================================================
rem  5/11  UserAssist ROT13 encoded
rem ============================================================
echo [*] 5/11  Limpando UserAssist ROT13...
echo     rubinot em ROT13 = ehovabg / EhovaBG

powershell -Command "Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $p = $_.PSPath; $_.GetValueNames() | Where-Object { $_ -match 'ehovabg|EhovaBG|EHOVABG' } | ForEach-Object { Remove-ItemProperty -Path $p -Name $_ -Force -ErrorAction SilentlyContinue; Write-Host '    [X] UserAssist entry removed' } }"

echo     [OK] UserAssist limpo
echo.

rem ============================================================
rem  6/11  AppCompatFlags + traces HKCU diversos
rem ============================================================
echo [*] 6/11  Limpando AppCompatFlags e traces diversos...

rem AppCompatFlags Compatibility Assistant Store
powershell -Command "$p = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'; if (Test-Path $p) { try { (Get-Item $p).GetValueNames() | Where-Object { $_ -match 'rubinot' } | ForEach-Object { Remove-ItemProperty -Path $p -Name $_ -Force -ErrorAction SilentlyContinue; Write-Host '    [X] AppCompat entry removed' } } catch {} }"

rem AppCompatFlags Layers
powershell -Command "$p = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'; if (Test-Path $p) { try { (Get-Item $p).GetValueNames() | Where-Object { $_ -match 'rubinot' } | ForEach-Object { Remove-ItemProperty -Path $p -Name $_ -Force -ErrorAction SilentlyContinue; Write-Host '    [X] Layers entry removed' } } catch {} }"

rem FeatureUsage AppSwitched, AppBadgeUpdated, AppLaunch
powershell -Command "foreach ($sub in @('AppSwitched','AppBadgeUpdated','AppLaunch')) { $p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\' + $sub; if (Test-Path $p) { try { (Get-Item $p).GetValueNames() | Where-Object { $_ -match 'rubinot' } | ForEach-Object { Remove-ItemProperty -Path $p -Name $_ -Force -ErrorAction SilentlyContinue; Write-Host '    [X] FeatureUsage entry removed' } } catch {} } }"

rem Notifications QuietHours
powershell -Command "$p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\QuietHours'; if (Test-Path $p) { try { (Get-Item $p).GetValueNames() | Where-Object { $_ -match 'rubinot' } | ForEach-Object { Remove-ItemProperty -Path $p -Name $_ -Force -ErrorAction SilentlyContinue; Write-Host '    [X] QuietHours entry removed' } } catch {} }"

rem UFH\SHC
powershell -Command "$p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UFH\SHC'; if (Test-Path $p) { try { (Get-Item $p).GetValueNames() | Where-Object { $_ -match 'rubinot' } | ForEach-Object { Remove-ItemProperty -Path $p -Name $_ -Force -ErrorAction SilentlyContinue; Write-Host '    [X] UFH entry removed' } } catch {} }"

rem WER RuntimeExceptionHelperModules - crashpad_wer.dll
powershell -Command "$p = 'HKCU:\Software\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules'; if (Test-Path $p) { try { (Get-Item $p).GetValueNames() | Where-Object { $_ -match 'rubinot' } | ForEach-Object { Remove-ItemProperty -Path $p -Name $_ -Force -ErrorAction SilentlyContinue; Write-Host '    [X] WER Module removed' } } catch {} }"

echo     [OK] Traces diversos limpos
echo.

rem ============================================================
rem  7/11  Jump Lists
rem ============================================================
echo [*] 7/11  Limpando Jump Lists...

for /f "delims=" %%f in ('findstr /m /i "rubinot" "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*" 2^>nul') do del /f /q "%%f" 2>nul & echo     [X] AutoDest: %%~nxf
for /f "delims=" %%f in ('findstr /m /i "rubinot" "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*" 2^>nul') do del /f /q "%%f" 2>nul & echo     [X] CustomDest: %%~nxf

echo     [OK] Jump Lists limpos
echo.

rem ============================================================
rem  8/11  Prefetch admin
rem ============================================================
echo [*] 8/11  Limpando Prefetch...

if "!ADM!"=="0" echo     [!] Pulando - precisa admin & goto skip_prefetch

del /f /q "C:\Windows\Prefetch\*RUBINOT*" 2>nul
del /f /q "C:\Windows\Prefetch\*rubinot*" 2>nul
echo     [OK] Prefetch limpo

:skip_prefetch
echo.

rem ============================================================
rem  9/11  BAM + SRUM + ShimCache admin, deep clean
rem ============================================================
echo [*] 9/11  Limpeza profunda BAM, SRUM, ShimCache...

if "!ADM!"=="0" echo     [!] Pulando - precisa admin & goto skip_deep

rem BAM - Background Activity Moderator
powershell -Command "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' -ErrorAction SilentlyContinue | ForEach-Object { $p = $_.PSPath; $_.GetValueNames() | Where-Object { $_ -match 'rubinot' } | ForEach-Object { Remove-ItemProperty -Path $p -Name $_ -Force -ErrorAction SilentlyContinue; Write-Host '    [X] BAM entry removed' } }"

rem DAM - Desktop Activity Moderator
powershell -Command "Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings' -ErrorAction SilentlyContinue | ForEach-Object { $p = $_.PSPath; $_.GetValueNames() | Where-Object { $_ -match 'rubinot' } | ForEach-Object { Remove-ItemProperty -Path $p -Name $_ -Force -ErrorAction SilentlyContinue; Write-Host '    [X] DAM entry removed' } }"

rem SRUM database - parar servico, deletar, reiniciar
echo     [*] Limpando SRUM...
net stop DPS /y >nul 2>&1
net stop DiagTrack /y >nul 2>&1
del /f /q "C:\Windows\System32\sru\SRUDB.dat" 2>nul
if %errorlevel% equ 0 echo     [X] SRUDB.dat deletado
if %errorlevel% neq 0 echo     [!] SRUDB.dat locked - sera limpo no reboot
net start DPS >nul 2>&1
net start DiagTrack >nul 2>&1

rem ShimCache / AppCompatCache
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache /f >nul 2>&1
echo     [X] ShimCache limpo

echo     [OK] Limpeza profunda concluida

:skip_deep
echo.

rem ============================================================
rem  10/11  DNS Cache
rem ============================================================
echo [*] 10/11  Limpando DNS cache...
ipconfig /flushdns >nul 2>&1
echo     [OK] DNS cache limpo
echo.

rem ============================================================
rem  11/11  GameConfigStore (historico de jogos)
rem ============================================================
echo [*] 11/11  Limpando GameConfigStore...

reg delete "HKCU\System\GameConfigStore" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo     [X] GameConfigStore deletado
) else (
    echo     [OK] GameConfigStore ja estava limpo ou nao existe
)

rem (removido: HKCU\System\CurrentControlSet\Control nao existe por padrao
rem  e apagar poderia destruir dados de apps de terceiros sem beneficio real)
echo.

rem ============================================================
rem  NOTA: wevtutil cl removido em v3.5.1 - wipe do Security log
rem  gera Event 1102 (louder than what it hides). Deixar os logs
rem  intactos e menos suspeito que apaga-los.
rem ============================================================

rem ============================================================
rem  RESUMO
rem ============================================================
echo ============================================
echo   LIMPEZA CONCLUIDA!
echo ============================================
echo.
echo   Limpo:
echo     - Processos, arquivos, pastas
echo     - Registro HKCU + HKLM chaves e valores
echo     - UserAssist ROT13 decodificado
echo     - AppCompatFlags, FeatureUsage, QuietHours
echo     - Jump Lists, Prefetch, BAM, DNS
echo     - SRUM, ShimCache
echo     - GameConfigStore + HKCU device tracking
echo.
echo   NAO limpo (deliberadamente):
echo     - Event Logs: wevtutil cl gera Event 1102 (louder
echo       than what it hides). Removido em v3.5.1.
echo.
if "!ADM!"=="0" echo   [!] Para limpeza completa, rode como ADMIN & echo.
echo   [!] NAO limpaveis online:
echo       - Amcache.hve - locked pelo kernel
echo.
echo   [!] Este arquivo .bat tambem e um trace!
echo       Delete manualmente apos usar.
echo ============================================
echo.
echo   Pressione qualquer tecla para fechar...
pause >nul
