#Requires -RunAsAdministrator
# ============================================================
#  prep-crashdump.ps1 - v4.0.6 (Bug 4 evidence collection)
#
#  Prepara o guest para o proximo boot com coleta REAL de dump
#  completo de kernel, apos o crash Event-41-sem-bugcheck em
#  ~52-56s post-Winlogon observado no postmortem v4.0.5.
#
#  Sem estes ajustes, dumps sao truncados ou nao escritos porque:
#    (a) CrashDumpEnabled default = 7 (Automatic) usa mini-dump so
#        se pagefile couber e AutoReboot=1 nao espera fsync.
#    (b) MEMORY.DMP em C:\Windows usa pagefile - VMs pequenas com
#        pagefile <8 GB perdem escrita silenciosamente.
#    (c) AutoReboot=1 pode reboot antes do dump finalizar.
#
#  Este script aplica:
#    HKLM\SYSTEM\CurrentControlSet\Control\CrashControl
#      CrashDumpEnabled     = 1        (complete memory dump)
#      AutoReboot           = 0        (freeze na tela STOP)
#      AlwaysKeepMemoryDump = 1        (nunca deleta apos leitura)
#      IgnorePagefileSize   = 1        (usa DedicatedDumpFile)
#      DedicatedDumpFile    = C:\rstflt-dump.sys
#      DumpFileSize         = 8192 (MB)
#
#  Ver: docs/postmortem-v4-phase5/incident-v405-vm-pipeline-validation.md (Bug 4)
#
#  Uso:
#    .\prep-crashdump.ps1              # aplica config de investigacao
#    .\prep-crashdump.ps1 -Restore     # reverte para default do Windows
#
#  NOTA: ASCII puro. Windows PowerShell 5.1 le arquivos sem BOM como
#  Windows-1252, entao caracteres UTF-8 multi-byte (em-dash, acentos)
#  quebram o parser. Ver comentario correspondente em check-consistency.ps1.
# ============================================================

param(
    [switch]$Restore
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_ui-common.ps1"

$cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'

if ($Restore) {
    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Yellow
    Write-Host "    prep-crashdump - RESTORE (default Windows)" -ForegroundColor Yellow
    Write-Host "  ============================================" -ForegroundColor Yellow
    Write-Host ""

    Set-ItemProperty -Path $cc -Name 'CrashDumpEnabled'     -Value 7 -Type DWord
    Set-ItemProperty -Path $cc -Name 'AutoReboot'           -Value 1 -Type DWord
    Set-ItemProperty -Path $cc -Name 'AlwaysKeepMemoryDump' -Value 0 -Type DWord
    Remove-ItemProperty -Path $cc -Name 'IgnorePagefileSize' -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $cc -Name 'DedicatedDumpFile'  -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $cc -Name 'DumpFileSize'       -ErrorAction SilentlyContinue
    Write-OK "CrashControl restaurado para default (CrashDumpEnabled=7 Automatic, AutoReboot=1)"

    if (Test-Path 'C:\rstflt-dump.sys') {
        Write-Info "Removendo C:\rstflt-dump.sys (dedicated dump file antigo)..."
        Remove-Item 'C:\rstflt-dump.sys' -Force
        Write-OK "Removido"
    }
    exit 0
}

Write-Host ""
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host "    prep-crashdump - Bug 4 evidence collection" -ForegroundColor Cyan
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "Aplicando CrashControl para coleta de dump completo..."

Set-ItemProperty -Path $cc -Name 'CrashDumpEnabled'     -Value 1    -Type DWord    # 1=complete
Set-ItemProperty -Path $cc -Name 'AutoReboot'           -Value 0    -Type DWord    # freeze on STOP
Set-ItemProperty -Path $cc -Name 'AlwaysKeepMemoryDump' -Value 1    -Type DWord
Set-ItemProperty -Path $cc -Name 'IgnorePagefileSize'   -Value 1    -Type DWord
Set-ItemProperty -Path $cc -Name 'DedicatedDumpFile'    -Value 'C:\rstflt-dump.sys' -Type String
Set-ItemProperty -Path $cc -Name 'DumpFileSize'         -Value 8192 -Type DWord    # MB (must exceed RAM)

Write-OK "CrashDumpEnabled     = 1     (complete memory dump)"
Write-OK "AutoReboot           = 0     (freeze na tela STOP)"
Write-OK "AlwaysKeepMemoryDump = 1"
Write-OK "IgnorePagefileSize   = 1"
Write-OK "DedicatedDumpFile    = C:\rstflt-dump.sys"
Write-OK "DumpFileSize         = 8192 MB"

# Prevent System log rollover during investigation (max size 256 MB)
try {
    & wevtutil sl System /rt:true /ms:262144000 2>&1 | Out-Null
    Write-OK "System event log max size = 256 MB, retention enabled"
} catch {
    Write-Warn "wevtutil falhou: $_"
}

Write-Host ""
Write-Host "  ============================================" -ForegroundColor Yellow
Write-Host "    AVISOS IMPORTANTES" -ForegroundColor Yellow
Write-Host "  ============================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  * AutoReboot=0: um BSOD vai congelar na tela STOP." -ForegroundColor Yellow
Write-Host "    Requer reset manual pelo console Hyper-V." -ForegroundColor Yellow
Write-Host ""
Write-Host "  * Apos o crash, pegue o dump em: C:\rstflt-dump.sys" -ForegroundColor Cyan
Write-Host "    (dedicated dump file - MEMORY.DMP em %SystemRoot% NAO sera criado)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  * Para analisar: rodar em WinDbg do host" -ForegroundColor Cyan
Write-Host "      windbg -y srv*C:\symbols*https://msdl.microsoft.com/download/symbols" -ForegroundColor Gray
Write-Host "      File > Open Crash Dump > C:\rstflt-dump.sys" -ForegroundColor Gray
Write-Host "      !analyze -v" -ForegroundColor Gray
Write-Host ""
Write-Host "  * Para reverter tudo: .\prep-crashdump.ps1 -Restore" -ForegroundColor Cyan
Write-Host ""
