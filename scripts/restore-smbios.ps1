#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Restaura SMBIOS do firmware, limpa residuos de spoof antigo.
.DESCRIPTION
    Estado revelado pelo consistency-check: SMBIOS misto (System=MSI,
    Board=Gigabyte, Board Version com string de BIOS). Isso vem de
    spoof antigo mal-revertido, e provavelmente foi o trigger do BSOD
    em boot com rstflt v3.3 (blob quebrado replayado em kernel).

    Fluxo:
      1. Remove scheduled tasks antigas (SpoofSMBIOS / SpoofUUID)
      2. Limpa cache do rstflt (SmbiosBlob / EnableSmbiosReplay /
         OrigSmbiosData) se rstflt esta instalado
      3. Toma ownership de mssmbios\Data e:
         a) Tenta reler SMBIOS direto do firmware via
            GetSystemFirmwareTable('RSMB') e reescrever
            (nao precisa reboot).
         b) Se (a) falhar, deleta o valor SMBiosData - mssmbios
            recria a partir do firmware no proximo boot.

    Parametros:
      -DeleteOnly : pula (3a), so deleta valor (forca reboot pra
                    regenerar). Util se voce desconfia do estado
                    atual e quer garantia total.
      -CleanupOnly: so faz (1) e (2), nao toca em mssmbios.

    ASCII puro (Windows PowerShell 5.1 sem BOM lidando com codepage).
#>

param(
    [switch]$DeleteOnly,
    [switch]$CleanupOnly
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"
. "$PSScriptRoot\_smbios-common.ps1"

Write-Host ""
Write-Host "========================================================" -ForegroundColor White
Write-Host "  restore-smbios.ps1" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor White
Write-Host ""

# ============================================================
#  Step 1: Remove scheduled tasks antigas
# ============================================================
Write-Host "[1/3] Removendo scheduled tasks antigas..." -ForegroundColor White

foreach ($t in @("SpoofSMBIOS", "SpoofUUID")) {
    $existing = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
        Write-OK "Task removida: $t"
    } else {
        Write-Info "Task ausente (ja limpa): $t"
    }
}

# ============================================================
#  Step 2: Cleanup do rstflt Parameters (cache do spoof)
# ============================================================
Write-Host ""
Write-Host "[2/3] Limpando cache do rstflt..." -ForegroundColor White

$rstflt = "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters"
if (Test-Path $rstflt) {
    foreach ($v in @("SmbiosBlob", "EnableSmbiosReplay", "OrigSmbiosData")) {
        $p = Get-ItemProperty -Path $rstflt -Name $v -ErrorAction SilentlyContinue
        if ($p) {
            Remove-ItemProperty -Path $rstflt -Name $v -ErrorAction SilentlyContinue
            Write-OK "Removido: rstflt Parameters\$v"
        } else {
            Write-Info "Ja ausente: rstflt Parameters\$v"
        }
    }
} else {
    Write-Info "rstflt nao instalado (Parameters ausente) - nada a limpar aqui"
}

if ($CleanupOnly) {
    Write-Host ""
    Write-Host "  CleanupOnly - saindo antes de mexer em mssmbios." -ForegroundColor Yellow
    exit 0
}

# ============================================================
#  Step 3: Restaurar SMBiosData do firmware
# ============================================================
Write-Host ""
Write-Host "[3/3] Restaurando mssmbios\Data\SMBiosData do firmware..." -ForegroundColor White

$keyPath = "SYSTEM\CurrentControlSet\Services\mssmbios\Data"

# --- 3.0: Take ownership + Full Control para Administrators
Write-Info "Ajustando ACL de mssmbios\Data (owner + FullControl para Administrators)..."
try {
    Grant-SmbiosDataWrite
    Write-OK "Ownership + FullControl concedidos"
} catch {
    Write-Err "Falha ao tomar ownership: $_"
    exit 1
}

if ($DeleteOnly) {
    # ---- Caminho B direto: deletar valor, deixar mssmbios recriar ----
    Write-Info "DeleteOnly: deletando SMBiosData (mssmbios regenera no reboot)..."
    try {
        Remove-ItemProperty -Path "HKLM:\$keyPath" -Name "SMBiosData" -ErrorAction Stop
        Write-OK "SMBiosData removido"
        Write-Host ""
        Write-Host "  ==> REBOOT AGORA. mssmbios recria SMBiosData do firmware." -ForegroundColor Yellow
        Write-Host "      Depois rode check-consistency.ps1 para confirmar." -ForegroundColor Yellow
    } catch {
        Write-Err "Falha ao deletar: $_"
        exit 1
    }
    exit 0
}

# ---- Caminho A: reler do firmware via GetSystemFirmwareTable ----
Write-Info "Tentando reler SMBIOS direto do firmware via API..."

# Assinatura C:
#   UINT GetSystemFirmwareTable(
#     DWORD FirmwareTableProviderSignature,   // 'RSMB' = 0x52534D42
#     DWORD FirmwareTableID,                  // 0 = default
#     PVOID pFirmwareTableBuffer,             // NULL = query size
#     DWORD BufferSize);
# Retorno: bytes escritos (ou tamanho necessario se buffer for pequeno/NULL)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FwApi {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint GetSystemFirmwareTable(
        uint FirmwareTableProviderSignature,
        uint FirmwareTableID,
        IntPtr pFirmwareTableBuffer,
        uint BufferSize);
}
"@ -ErrorAction SilentlyContinue

# 'RSMB' little-endian: 'R'=0x52, 'S'=0x53, 'M'=0x4D, 'B'=0x42
# Como DWORD passado ASCII em ordem inversa: 0x52534D42
$RSMB = 0x52534D42

$needed = [FwApi]::GetSystemFirmwareTable($RSMB, 0, [IntPtr]::Zero, 0)
if ($needed -eq 0) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Warn "GetSystemFirmwareTable(size query) falhou (err=$err). Caindo em DeleteOnly."
    Remove-ItemProperty -Path "HKLM:\$keyPath" -Name "SMBiosData" -ErrorAction SilentlyContinue
    Write-OK "SMBiosData deletado - mssmbios regenera no reboot"
    Write-Host ""
    Write-Host "  ==> REBOOT AGORA para completar a restauracao." -ForegroundColor Yellow
    exit 0
}
Write-Info "Firmware SMBIOS tem $needed bytes (com header RawSMBIOSData)"

$buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$needed)
try {
    $got = [FwApi]::GetSystemFirmwareTable($RSMB, 0, $buf, $needed)
    if ($got -eq 0 -or $got -gt $needed) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Warn "GetSystemFirmwareTable(read) falhou (err=$err). Caindo em DeleteOnly."
        Remove-ItemProperty -Path "HKLM:\$keyPath" -Name "SMBiosData" -ErrorAction SilentlyContinue
        Write-OK "SMBiosData deletado - mssmbios regenera no reboot"
        Write-Host ""
        Write-Host "  ==> REBOOT AGORA para completar a restauracao." -ForegroundColor Yellow
        exit 0
    }

    $bytes = New-Object byte[] $got
    [System.Runtime.InteropServices.Marshal]::Copy($buf, $bytes, 0, [int]$got)

    Write-Info "Lidos $got bytes de firmware SMBIOS. Escrevendo em mssmbios\Data\SMBiosData..."
    Set-ItemProperty -Path "HKLM:\$keyPath" -Name "SMBiosData" -Value $bytes -Type Binary
    Write-OK "SMBiosData reescrito com firmware real ($got bytes)"

    # Restart WMI para invalidar cache
    Write-Info "Reiniciando winmgmt (WMI) para invalidar cache..."
    Restart-Service winmgmt -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Write-Host ""
    Write-Host "  ==> Sem reboot necessario (mas reboot nao machuca)." -ForegroundColor Green
    Write-Host "      Rode agora: scripts\check-consistency.ps1" -ForegroundColor Green
    Write-Host "      System/Board/Chassis devem TODOS mostrar MSI real." -ForegroundColor Green

} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
}
