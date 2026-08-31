#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Reescreve o valor PnPInstanceId por adaptador em
    HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}\{connection-GUID}\Connection
    (REG_SZ). Fase 1.7 - value-set spoof do cache-registry lido pelo EMAC.

.DESCRIPTION
    Reconnaissance v2 (procmon rubinot_dx.exe / display-affinity-lab
    docs/emac-hwid-recon.md rev.3) confirmou que EMAC realiza RegQueryValueEx
    sobre este cache para cada adaptador de rede (4 adaptadores por captura,
    leitura estavel entre reboots). O caminho eh uma "sombra" do
    DEVICE_INSTANCE_ID do adaptador PnP (typicamente
    PCI\VEN_xxxx&DEV_xxxx&SUBSYS_xxxxxxxx&REV_xx\<inst>).

    Objetivo: alinhar o cache Control\Network com o rewrite ja aplicado em
    Enum\PCI\VEN_&DEV_\<inst>\HardwareID por spoof-pci-hardwareid.ps1,
    para que um anti-cheat que cross-checka
        Enum\PCI\<vendev>\<inst>\HardwareID (SUBSYS+REV)
    vs
        Control\Network\{class}\{cGUID}\Connection\PnPInstanceId (SUBSYS+REV)
    receba valores consistentes por adaptador.

    Determinismo (CROSS-CONSISTENCY com spoof-pci-hardwareid.ps1):
      - Extraimos VEN_xxxx&DEV_xxxx da string PnPInstanceId corrente e
        alimentamos EXATAMENTE essa chave em Get-Fnv1a64Hash - identico
        ao formato consumido em spoof-pci-hardwareid.ps1 (Parse-VenDev
        emite "VEN_xxxx&DEV_xxxx" upper). Mesma seed + mesmo VEN&DEV =>
        mesmo SUBSYS_XXXXXXXX + mesmo REV_XX. Isso garante que os dois
        scripts, executados na mesma maquina, produzam pares SUBSYS/REV
        identicos para o mesmo device PCI.
      - Instancia PnP (tail do PnPInstanceId, ex.: "4&2af66358&0&00E0")
        NAO eh reescrita. Ela reflete a topologia PCIe real e nao eh
        alterada por spoof-pci-hardwareid.ps1 (que so mexe em SUBSYS+REV,
        deixando o nome da subchave <instance> intacto). Reescrever aqui
        criaria mismatch entre Control\Network e Enum\PCI.

    Safety:
      - NAO tocamos no nome da subchave {connection-GUID} - ele eh o
        NetCfgInstanceId (identidade independente usada por NDIS/DHCP);
        renomear quebra binding e faz o DHCP client soltar o lease.
      - NAO tocamos em siblings: NetCfgInstanceId, Descriptions, Config.
      - Enumeradores desconhecidos (nem PCI, nem USB, nem BTH, nem VMBUS,
        nem SW) sao SKIP com Write-Warn - nao arriscamos formatos que nao
        entendemos.
      - Falha individual por adaptador nunca aborta o script.

    Uso:
      .\spoof-network-pnpid.ps1              # aplica
      .\spoof-network-pnpid.ps1 -DryRun      # so mostra o que faria
      .\spoof-network-pnpid.ps1 -Restore     # reverte via backup
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Restore
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"
$backupPath  = "C:\ProgramData\.hwcfg\network-pnpid-backup.json"
$netClassKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}"

# ============================================================
#  Helpers - identicos aos de spoof-pci-hardwareid.ps1
# ============================================================

# FNV-1a 64bit deterministico.
function Get-Fnv1a64Hash {
    param([string]$InputText)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
    $hash  = [System.Numerics.BigInteger]::Parse("14695981039346656037")
    $prime = [System.Numerics.BigInteger]::Parse("1099511628211")
    $mask  = [System.Numerics.BigInteger]::Parse("18446744073709551615")
    foreach ($b in $bytes) {
        $hash = $hash -bxor ([System.Numerics.BigInteger]$b)
        $hash = ($hash * $prime) -band $mask
    }
    return [uint64]$hash
}

# Mesmo formato de spoof-pci-hardwareid.ps1: "SUBSYS|<seed>|VEN_XXXX&DEV_XXXX"
function Get-FakeSubsys {
    param([string]$Seed, [string]$VendorDeviceKey)
    $h = Get-Fnv1a64Hash -InputText ("SUBSYS|" + $Seed + "|" + $VendorDeviceKey)
    $sub = [uint32](($h -shr 32) -band 0xFFFFFFFF)
    return ("{0:X8}" -f $sub)
}

function Get-FakeRev {
    param([string]$Seed, [string]$VendorDeviceKey)
    $h = Get-Fnv1a64Hash -InputText ("REV|" + $Seed + "|" + $VendorDeviceKey)
    $rev = [byte]($h -band 0xFF)
    if ($rev -eq 0) { $rev = 1 }
    return ("{0:X2}" -f $rev)
}

# Determina um seed para o script. Se profile.json ausente ou sem seed
# valido, cria seed efemero (nao persiste). Retorna hex string [32].
function Resolve-Seed {
    if (Test-Path $profilePath) {
        try {
            $prof = Get-Content $profilePath -Raw | ConvertFrom-Json
            if ($prof.pci_hardwareid -and $prof.pci_hardwareid.randomize_seed) {
                $s = [string]$prof.pci_hardwareid.randomize_seed
                if ($s -match '^[0-9a-fA-F]{32}$') {
                    Write-OK ("Seed carregado do profile (" + $s.Length + " chars)")
                    return $s.ToLower()
                } else {
                    Write-Warn ("Seed do profile invalido (len=" + $s.Length + "). Usando seed efemero.")
                }
            } else {
                Write-Warn "Profile sem bloco pci_hardwareid.randomize_seed - usando seed efemero."
            }
        } catch {
            Write-Warn ("Profile ilegivel (" + $_.Exception.Message + ") - usando seed efemero.")
        }
    } else {
        Write-Warn ("Profile ausente (" + $profilePath + ") - usando seed efemero (nao persistido).")
    }
    $ephem = [guid]::NewGuid().ToString('N').ToLower()
    Write-Warn "Seed efemero: rewrites nao serao reproduziveis em execucoes futuras."
    Write-Warn "Rode .\generate-profile.ps1 -Generate para seed persistente."
    return $ephem
}

# Extrai VEN&DEV da string PnPInstanceId (PCI). Retorna null se nao for PCI
# ou se nao casar formato.
function Parse-PciVenDev {
    param([string]$PnPId)
    if ($PnPId -match '^PCI\\(VEN_[0-9A-Fa-f]{4}&DEV_[0-9A-Fa-f]{4})') {
        return $Matches[1].ToUpper()
    }
    return $null
}

# Reescreve SUBSYS_XXXXXXXX e REV_XX numa string PnPInstanceId PCI.
# Preserva prefixo (PCI\VEN&DEV&...) e sufixo (\<instance>) intactos.
function Rewrite-PciPnpId {
    param(
        [string]$Original,
        [string]$NewSubsys,
        [string]$NewRev
    )
    $out = $Original
    $out = [regex]::Replace($out, '(?i)SUBSYS_[0-9A-Fa-f]{8}', "SUBSYS_$NewSubsys")
    $out = [regex]::Replace($out, '(?i)REV_[0-9A-Fa-f]{2}',    "REV_$NewRev")
    return $out
}

# Reescreve o serial numa PnPInstanceId USB. Formato tipico:
#   USB\VID_xxxx&PID_xxxx\<serial>
# Preservamos o VID&PID e trocamos apenas a porcao apos o ultimo '\'.
function Rewrite-UsbPnpId {
    param(
        [string]$Original,
        [string]$Seed
    )
    if ($Original -notmatch '^(USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}(?:&[^\\]+)?)\\(.+)$') {
        return $null
    }
    $head    = $Matches[1]
    $oldSer  = $Matches[2]
    # Preserva length aproximado gerando hex FNV da mesma quantidade quando
    # possivel; se serial original tem chars nao-hex (ex.: '&'), fallback
    # para 16 hex chars.
    $len = [Math]::Max(8, [Math]::Min(24, $oldSer.Length))
    $h1 = Get-Fnv1a64Hash -InputText ("USB-SERIAL-A|" + $Seed + "|" + $head + "|" + $oldSer)
    $h2 = Get-Fnv1a64Hash -InputText ("USB-SERIAL-B|" + $Seed + "|" + $head + "|" + $oldSer)
    $hex = ("{0:X16}{1:X16}" -f $h1, $h2)
    $newSer = $hex.Substring(0, $len)
    return ($head + "\" + $newSer)
}

# Reescreve o instance tail numa PnPInstanceId BTH.
#   BTH\MS_BTHPAN\6&xxxxxxxx&0&2
# Preservamos prefixo (BTH\<driver-node>\) e trocamos o restante.
function Rewrite-BthPnpId {
    param(
        [string]$Original,
        [string]$Seed
    )
    if ($Original -notmatch '^(BTH\\[^\\]+)\\(.+)$') {
        return $null
    }
    $head   = $Matches[1]
    $oldTail = $Matches[2]
    # Se cabecalho eh "6&xxxxxxxx&0&Y", preservar prefixo "6&" e sufixo "&0&Y"
    if ($oldTail -match '^(6&)[0-9A-Fa-f]{8}(&0&[0-9A-Fa-f]+)$') {
        $h = Get-Fnv1a64Hash -InputText ("BTH-TAIL|" + $Seed + "|" + $head + "|" + $oldTail)
        $middle = ("{0:X8}" -f ([uint32](($h -shr 32) -band 0xFFFFFFFF)))
        return ($head + "\" + $Matches[1] + $middle + $Matches[2])
    }
    # fallback: rewrite full tail preservando comprimento
    $len = [Math]::Max(4, [Math]::Min(32, $oldTail.Length))
    $h = Get-Fnv1a64Hash -InputText ("BTH-TAIL-FB|" + $Seed + "|" + $head + "|" + $oldTail)
    $hex = ("{0:X16}" -f $h)
    if ($hex.Length -lt $len) { $hex = $hex.PadRight($len, '0') }
    return ($head + "\" + $hex.Substring(0, $len))
}

# ============================================================
#  Restore mode
# ============================================================
if ($Restore) {
    Write-Section "Restore de PnPInstanceId (Control\Network)"
    if (-not (Test-Path $backupPath)) {
        Write-Err ("Backup nao encontrado: " + $backupPath)
        exit 1
    }
    try {
        $bak = Get-Content $backupPath -Raw | ConvertFrom-Json
    } catch {
        Write-Err ("Backup corrompido: " + $_.Exception.Message)
        exit 1
    }

    $restored = 0
    $failed   = 0

    foreach ($e in $bak.entries) {
        $connKey = Join-Path $netClassKey ($e.connection_guid + "\Connection")
        if (-not (Test-Path $connKey)) {
            Write-Warn ("Subchave ausente: " + $connKey)
            $failed++
            continue
        }
        try {
            Set-ItemProperty -Path $connKey -Name "PnPInstanceId" -Value ([string]$e.original_pnpid) -Type String -Force
            Write-OK ("Restaurado: " + $e.connection_guid + " -> " + $e.original_pnpid)
            $restored++
        } catch {
            Write-Err ("Falha restaurando " + $e.connection_guid + ": " + $_.Exception.Message)
            $failed++
        }
    }

    try {
        Remove-Item $backupPath -Force -ErrorAction Stop
        Write-OK ("Backup removido: " + $backupPath)
    } catch {
        Write-Warn ("Nao consegui remover backup: " + $_.Exception.Message)
    }

    Write-Section "Resumo restore"
    Write-Host ("  Restaurados : " + $restored) -ForegroundColor Cyan
    Write-Host ("  Falhas      : " + $failed)   -ForegroundColor Cyan
    Write-Warn "Reboot recomendado para NDIS re-avaliar as bindings."
    if ($failed -gt 0) { exit 1 }
    exit 0
}

# ============================================================
#  Rewrite mode
# ============================================================
Write-Section "Spoof de PnPInstanceId (Control\Network)"

if (-not (Test-Path $netClassKey)) {
    Write-Err ("Classe Net nao encontrada: " + $netClassKey)
    exit 1
}

$seed = Resolve-Seed

if ($DryRun) { Write-Warn "-DryRun: nenhuma escrita sera feita" }

# Enumerar {connection-GUID} sob a classe Net
$connGuids = Get-ChildItem -Path $netClassKey -ErrorAction SilentlyContinue |
             Where-Object { $_.PSChildName -match '^\{[0-9A-Fa-f\-]{36}\}$' }

Write-Info ("Adapter connection GUIDs encontrados: " + @($connGuids).Count)

$stats = @{
    Examined = 0
    Rewritten = 0
    Skipped = 0
    Failed = 0
}
$backupEntries = @()

foreach ($cg in $connGuids) {
    $stats.Examined++
    $cGuid   = $cg.PSChildName
    $connKey = Join-Path $cg.PSPath "Connection"

    if (-not (Test-Path $connKey)) {
        Write-Warn ("[SKIP] " + $cGuid + " - sem subkey Connection")
        $stats.Skipped++
        continue
    }

    $origPnp = $null
    try {
        $prop = Get-ItemProperty -Path $connKey -Name "PnPInstanceId" -ErrorAction Stop
        $origPnp = [string]$prop.PnPInstanceId
    } catch {
        Write-Warn ("[SKIP] " + $cGuid + " - sem valor PnPInstanceId")
        $stats.Skipped++
        continue
    }

    if ([string]::IsNullOrWhiteSpace($origPnp)) {
        Write-Warn ("[SKIP] " + $cGuid + " - PnPInstanceId vazio")
        $stats.Skipped++
        continue
    }

    # Nome do adapter (Name/PnpInstanceIdDescription) para logging - best effort.
    $adapterName = $null
    try {
        $p = Get-ItemProperty -Path $connKey -Name "Name" -ErrorAction Stop
        $adapterName = [string]$p.Name
    } catch {}

    # Determinar enumerador top-level
    $enumerator = ($origPnp -split '\\', 2)[0]
    $newPnp = $null

    switch -Regex ($enumerator) {
        '^(?i)PCI$' {
            $vendev = Parse-PciVenDev -PnPId $origPnp
            if ($null -eq $vendev) {
                Write-Warn ("[SKIP] " + $cGuid + " - PCI sem VEN&DEV parseavel: " + $origPnp)
                $stats.Skipped++
                break
            }
            $newSubsys = Get-FakeSubsys -Seed $seed -VendorDeviceKey $vendev
            $newRev    = Get-FakeRev    -Seed $seed -VendorDeviceKey $vendev
            $newPnp = Rewrite-PciPnpId -Original $origPnp -NewSubsys $newSubsys -NewRev $newRev
        }
        '^(?i)USB$' {
            $newPnp = Rewrite-UsbPnpId -Original $origPnp -Seed $seed
            if ($null -eq $newPnp) {
                Write-Warn ("[SKIP] " + $cGuid + " - USB formato inesperado: " + $origPnp)
                $stats.Skipped++
                break
            }
        }
        '^(?i)BTH$' {
            $newPnp = Rewrite-BthPnpId -Original $origPnp -Seed $seed
            if ($null -eq $newPnp) {
                Write-Warn ("[SKIP] " + $cGuid + " - BTH formato inesperado: " + $origPnp)
                $stats.Skipped++
                break
            }
        }
        '^(?i)VMBUS$' {
            Write-Warn ("[SKIP] " + $cGuid + " - enumerador VMBUS (Hyper-V synthetic NIC), nao mexemos")
            $stats.Skipped++
            break
        }
        '^(?i)SW$' {
            Write-Warn ("[SKIP] " + $cGuid + " - enumerador SW (software adapter), nao mexemos")
            $stats.Skipped++
            break
        }
        default {
            Write-Warn ("[SKIP] " + $cGuid + " - enumerador desconhecido '" + $enumerator + "'")
            $stats.Skipped++
        }
    }

    if ($null -eq $newPnp) { continue }

    if ($newPnp -eq $origPnp) {
        Write-Info ("[IDEM] " + $cGuid + " - PnPInstanceId ja igual ao alvo")
        $stats.Rewritten++
        continue
    }

    $tag = if ($adapterName) { $cGuid + " (" + $adapterName + ")" } else { $cGuid }
    Write-OK ("[" + $tag + "]")
    Write-Host ("           antes:  " + $origPnp) -ForegroundColor DarkGray
    Write-Host ("           depois: " + $newPnp)  -ForegroundColor Gray

    if (-not $DryRun) {
        try {
            Set-ItemProperty -Path $connKey -Name "PnPInstanceId" -Value $newPnp -Type String -Force
            $backupEntries += [pscustomobject]@{
                connection_guid = $cGuid
                original_pnpid  = $origPnp
                new_pnpid       = $newPnp
                adapter_name    = $adapterName
            }
            $stats.Rewritten++
        } catch {
            $stats.Failed++
            Write-Err ("    Falha gravando " + $connKey + ": " + $_.Exception.Message)
        }
    } else {
        $stats.Rewritten++
    }
}

# Persistir backup
if (-not $DryRun -and $backupEntries.Count -gt 0) {
    Write-Section "Persistindo backup"
    $backupDir = Split-Path $backupPath -Parent
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }
    $doc = [pscustomobject]@{
        version    = 1
        created_at = (Get-Date).ToString("o")
        entries    = $backupEntries
    }
    $tmp = $backupPath + ".tmp"
    $doc | ConvertTo-Json -Depth 6 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $backupPath -Force
    Write-OK ("Backup salvo em: " + $backupPath)
}

# Resumo
Write-Section "Resumo"
Write-Host ("  Adaptadores examinados : " + $stats.Examined)  -ForegroundColor Cyan
Write-Host ("  Reescritos             : " + $stats.Rewritten) -ForegroundColor Cyan
Write-Host ("  Skipped                : " + $stats.Skipped)   -ForegroundColor DarkGray
Write-Host ("  Falhas                 : " + $stats.Failed)    -ForegroundColor Cyan
if ($DryRun) {
    Write-Warn "-DryRun: nada foi escrito. Rode sem -DryRun para aplicar."
} else {
    Write-Warn "Reboot recomendado para NDIS re-avaliar as bindings."
    Write-Info ("Para reverter: .\spoof-network-pnpid.ps1 -Restore")
}
if ($stats.Failed -gt 0) { exit 1 }
exit 0
