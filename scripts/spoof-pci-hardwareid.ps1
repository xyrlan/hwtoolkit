#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Reescreve HardwareID / CompatibleIDs granulares em Enum\PCI\* - Fase 1.6.

.DESCRIPTION
    Reconnaissance v2 confirmou 362 leituras (procmon) de EMAC contra:
      HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_XXXX&DEV_XXXX\<instance>\HardwareID
    valor REG_MULTI_SZ com variantes de granularidade, ex.:
      PCI\VEN_10DE&DEV_2488&SUBSYS_140A7377&REV_A1
      PCI\VEN_10DE&DEV_2488&SUBSYS_140A7377
      PCI\VEN_10DE&DEV_2488&CC_030200
      PCI\VEN_10DE&DEV_2488&CC_0302
      PCI\VEN_10DE&DEV_2488

    Objetivo: alterar apenas SUBSYS e REV para inserir ruido de fingerprint
    determinstico por seed. VEN, DEV e CC ficam INTACTOS (mudar VEN/DEV troca
    o driver; mudar CC troca a class do device).

    Riscos e mitigacoes:
      - Alguns drivers fazem binding por VEN&DEV+SUBSYS. Se mudarmos SUBSYS
        num device cuja HardwareID SO tem uma entrada granular sem fallback
        VEN&DEV puro, o driver pode nao re-bindar. Mitigacao: so alteramos
        se houver >= 2 variantes no HardwareID (garantindo fallback puro
        PCI\VEN_&DEV_ ou variante CC_).
      - CompatibleIDs tambem pode conter SUBSYS - tratado do mesmo jeito.
      - Determinismo: SUBSYS e REV derivados via FNV-1a 64bit de (seed + VEN&DEV).
        Rerun com mesmo profile = mesmos valores.

    Uso:
      .\spoof-pci-hardwareid.ps1              # aplica
      .\spoof-pci-hardwareid.ps1 -DryRun      # so mostra o que faria
      .\spoof-pci-hardwareid.ps1 -Restore     # reverte via mapping
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Restore
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"
$mappingPath = "C:\ProgramData\.hwcfg\pci-hardwareid-mapping.json"
$pciRootPs   = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"

# ============================================================
#  Helpers
# ============================================================

# FNV-1a 64bit - deterministico, sem dependencia externa.
# Multiplicacao uint64 * uint64 pode overflow no PS 5.1 (checked por padrao),
# entao usamos BigInteger + mask 64-bit.
function Get-Fnv1a64Hash {
    param([string]$InputText)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
    $hash  = [System.Numerics.BigInteger]::Parse("14695981039346656037")   # FNV offset basis
    $prime = [System.Numerics.BigInteger]::Parse("1099511628211")           # FNV prime
    $mask  = [System.Numerics.BigInteger]::Parse("18446744073709551615")    # 2^64 - 1
    foreach ($b in $bytes) {
        $hash = $hash -bxor ([System.Numerics.BigInteger]$b)
        $hash = ($hash * $prime) -band $mask
    }
    return [uint64]$hash
}

# Gera SUBSYS de 8 hex (32 bits) a partir do seed + chave do device
function Get-FakeSubsys {
    param([string]$Seed, [string]$VendorDeviceKey)
    $h = Get-Fnv1a64Hash -InputText ("SUBSYS|" + $Seed + "|" + $VendorDeviceKey)
    # Pegar 32 bits altos para minimizar correlacao com REV (que usa 8 bits baixos)
    $sub = [uint32](($h -shr 32) -band 0xFFFFFFFF)
    return ("{0:X8}" -f $sub)
}

# Gera REV de 2 hex (8 bits). Evita 0x00 (usado como "no revision" em alguns devices).
function Get-FakeRev {
    param([string]$Seed, [string]$VendorDeviceKey)
    $h = Get-Fnv1a64Hash -InputText ("REV|" + $Seed + "|" + $VendorDeviceKey)
    $rev = [byte]($h -band 0xFF)
    if ($rev -eq 0) { $rev = 1 }
    return ("{0:X2}" -f $rev)
}

# Extrai VEN&DEV do nome de subchave (ex: "VEN_10DE&DEV_2488" -> "VEN_10DE&DEV_2488").
# Retorna $null se nao casar.
function Parse-VenDev {
    param([string]$SubkeyName)
    if ($SubkeyName -match '^(VEN_[0-9A-Fa-f]{4}&DEV_[0-9A-Fa-f]{4})') {
        return $Matches[1].ToUpper()
    }
    return $null
}

# Substitui SUBSYS_XXXXXXXX e REV_XX em UMA string, preservando o resto.
# Retorna a nova string. Se nao houver SUBSYS nem REV, retorna a original.
function Rewrite-IdString {
    param(
        [string]$Original,
        [string]$NewSubsys,   # 8 hex chars (upper)
        [string]$NewRev       # 2 hex chars (upper)
    )
    $out = $Original
    $out = [regex]::Replace($out, '(?i)SUBSYS_[0-9A-Fa-f]{8}', "SUBSYS_$NewSubsys")
    $out = [regex]::Replace($out, '(?i)REV_[0-9A-Fa-f]{2}',    "REV_$NewRev")
    return $out
}

# Le REG_MULTI_SZ preservando ordem. PowerShell 5.1 retorna string[] direto.
function Get-MultiSz {
    param([string]$KeyPath, [string]$Name)
    try {
        $v = Get-ItemProperty -Path $KeyPath -Name $Name -ErrorAction Stop
        $val = $v.$Name
        if ($null -eq $val) { return $null }
        if ($val -is [string]) { return @($val) }
        return @($val)
    } catch {
        return $null
    }
}

# Grava REG_MULTI_SZ. Set-ItemProperty com -Type MultiString aceita string[]
# e cuida do double-null-terminator internamente.
function Set-MultiSz {
    param([string]$KeyPath, [string]$Name, [string[]]$Values)
    # Filtrar strings vazias no fim (as vezes vem por conta do NUL final)
    $clean = @($Values | Where-Object { $_ -ne $null -and $_ -ne "" })
    # -Force converte tipo se a propriedade existe como EXPAND_SZ ou STRING
    # (algumas INFs vendor gravam HardwareID com tipo errado).
    Set-ItemProperty -Path $KeyPath -Name $Name -Value $clean -Type MultiString -Force
}

# ============================================================
#  Restore mode
# ============================================================
if ($Restore) {
    Write-Section "Restore de HardwareIDs PCI"
    if (-not (Test-Path $mappingPath)) {
        Write-Err ("Mapping nao encontrado: " + $mappingPath)
        exit 1
    }
    try {
        $mapping = Get-Content $mappingPath -Raw | ConvertFrom-Json
    } catch {
        Write-Err ("Mapping corrompido: " + $_.Exception.Message)
        exit 1
    }

    $restored = 0
    $failed   = 0

    foreach ($entry in $mapping.entries) {
        $keyPath = $entry.key_path
        if (-not (Test-Path $keyPath)) {
            Write-Warn ("Subchave ausente (device removido?): " + $keyPath)
            $failed++
            continue
        }
        try {
            if ($entry.original_hardwareid) {
                Set-MultiSz -KeyPath $keyPath -Name "HardwareID" -Values @($entry.original_hardwareid)
            }
            if ($entry.original_compatibleids) {
                Set-MultiSz -KeyPath $keyPath -Name "CompatibleIDs" -Values @($entry.original_compatibleids)
            }
            Write-OK ("Restaurado: " + $entry.vendev + " @ " + $entry.instance)
            $restored++
        } catch {
            Write-Err ("Falha restaurando " + $keyPath + ": " + $_.Exception.Message)
            $failed++
        }
    }

    try {
        Remove-Item $mappingPath -Force -ErrorAction Stop
        Write-OK ("Mapping removido: " + $mappingPath)
    } catch {
        Write-Warn ("Nao consegui remover mapping: " + $_.Exception.Message)
    }

    Write-Section "Resumo restore"
    Write-Host ("  Restaurados : " + $restored) -ForegroundColor Cyan
    Write-Host ("  Falhas      : " + $failed)   -ForegroundColor Cyan
    Write-Warn "Reiniciar para os drivers re-bindarem com os IDs originais."
    exit 0
}

# ============================================================
#  Rewrite mode
# ============================================================
Write-Section "Spoof de HardwareIDs PCI (SUBSYS + REV)"

if (-not (Test-Path $profilePath)) {
    Write-Err ("Profile nao encontrado: " + $profilePath)
    Write-Err "Rode primeiro: .\generate-profile.ps1 -Generate"
    exit 1
}

$prof = Get-Content $profilePath -Raw | ConvertFrom-Json

$profVer = 0
if ($prof.PSObject.Properties['version']) {
    [int]::TryParse([string]$prof.version, [ref]$profVer) | Out-Null
}
Write-OK ("Profile carregado (v" + $profVer + ")")
if ($profVer -lt 8) {
    Write-Warn ("Profile schema v" + $profVer + " nao contem bloco pci_hardwareid. Regenere o profile.")
    exit 1
}

if (-not $prof.pci_hardwareid) {
    Write-Err "Profile nao contem bloco 'pci_hardwareid' - regenere."
    exit 1
}

$seed = [string]$prof.pci_hardwareid.randomize_seed
if ([string]::IsNullOrWhiteSpace($seed)) {
    Write-Err "pci_hardwareid.randomize_seed vazio no profile."
    exit 1
}
if ($seed -notmatch '^[0-9a-fA-F]{32}$') {
    Write-Err ("Seed invalido (len=" + $seed.Length + "); esperado exatamente 32 hex chars.")
    Write-Err "Regenere o profile com generate-profile.ps1 -Generate."
    exit 1
}
Write-OK ("Seed carregado (" + $seed.Length + " chars)")

if ($DryRun) { Write-Warn "-DryRun: nenhuma escrita sera feita" }

# ---- Enumerar Enum\PCI\VEN_*&DEV_* ----
if (-not (Test-Path $pciRootPs)) {
    Write-Err ("PCI root nao encontrado: " + $pciRootPs)
    exit 1
}

$vendevKeys = Get-ChildItem -Path $pciRootPs -ErrorAction SilentlyContinue |
              Where-Object { $_.PSChildName -match '^VEN_[0-9A-Fa-f]{4}&DEV_[0-9A-Fa-f]{4}' }

Write-Info ("Vendor/Device subkeys encontradas: " + @($vendevKeys).Count)

# Whitelist de ClassGUID cosmetico — cobertura conservadora.
# Rewrite so em: Display, Audio, Net, USB Controller, Multimedia,
# HDC (HID/Human Interface). Fora dessas classes = skip por seguranca.
# NUNCA: Storage (boot path), Bridge (PCI-to-PCI), System (chipset LPC/
# memory controllers/DMA), Encryption/TPM (BitLocker), Base System.
$whitelistClassGuids = @(
    '{4d36e968-e325-11ce-bfc1-08002be10318}',   # Display
    '{4d36e96c-e325-11ce-bfc1-08002be10318}',   # MediaClass (audio+video capture)
    '{4d36e972-e325-11ce-bfc1-08002be10318}',   # Net
    '{36fc9e60-c465-11cf-8056-444553540000}',   # USB
    '{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}'    # Camera
)
$whitelistClassGuidsLower = @($whitelistClassGuids | ForEach-Object { $_.ToLower() })

# Blacklist explicita de ClassGUID que NUNCA devemos tocar (redundante com
# whitelist mas serve de defesa em profundidade contra whitelist ampliada).
$blacklistClassGuids = @(
    '{4d36e97b-e325-11ce-bfc1-08002be10318}',   # SCSIAdapter
    '{4d36e967-e325-11ce-bfc1-08002be10318}',   # DiskDrive
    '{71a27cdd-812a-11d0-bec7-08002be2092f}',   # Volume
    '{4d36e96a-e325-11ce-bfc1-08002be10318}',   # HDC (IDE/SATA controllers)
    '{4d36e97d-e325-11ce-bfc1-08002be10318}',   # System (chipset)
    '{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}',   # SecurityDevices (TPM)
    '{50127dc3-0f36-415e-a6cc-4cb3be910b65}'    # Processor
)
$blacklistClassGuidsLower = @($blacklistClassGuids | ForEach-Object { $_.ToLower() })

function Test-InstanceIsSafeClass {
    param([string]$InstanceKeyPath)
    $cg = $null
    try {
        $ip = Get-ItemProperty -Path $InstanceKeyPath -Name ClassGUID -ErrorAction Stop
        if ($ip) { $cg = ([string]$ip.ClassGUID).ToLower() }
    } catch {}
    if ([string]::IsNullOrEmpty($cg)) {
        # Sem ClassGUID = sem driver bindado = pode ser device recem-enumerado
        # ou display adapter sem driver. Skip por seguranca — nao sabemos se
        # e boot-critical.
        return $false
    }
    if ($blacklistClassGuidsLower -contains $cg) { return $false }
    if ($whitelistClassGuidsLower -contains $cg) { return $true }
    return $false
}

# ---- Mapping para -Restore ----
$mappingEntries = @()
$stats = @{
    Devices        = 0
    Instances      = 0
    Rewritten      = 0
    SkippedSingle  = 0     # so 1 variante -> risco de driver nao bindar
    SkippedNoGranular = 0  # nenhuma entrada com SUBSYS nem REV
    SkippedUnparsed  = 0
    SkippedUnsafeClass = 0 # ClassGUID fora da whitelist (storage/TPM/bridge)
    Failed         = 0
}

foreach ($vd in $vendevKeys) {
    $vendev = Parse-VenDev -SubkeyName $vd.PSChildName
    if ($null -eq $vendev) {
        $stats.SkippedUnparsed++
        continue
    }
    $stats.Devices++

    $newSubsys = Get-FakeSubsys -Seed $seed -VendorDeviceKey $vendev
    $newRev    = Get-FakeRev    -Seed $seed -VendorDeviceKey $vendev

    # Enumerar instancias (subchaves debaixo do VEN&DEV)
    $instances = Get-ChildItem -Path $vd.PSPath -ErrorAction SilentlyContinue
    foreach ($inst in $instances) {
        $stats.Instances++
        $keyPathPs = $inst.PSPath  # forma Registry::HKEY_LOCAL_MACHINE\...

        # Skip devices fora da whitelist de classes cosmeticas.
        # Storage controllers, TPM, chipset bridges, etc — NAO tocar.
        if (-not (Test-InstanceIsSafeClass -InstanceKeyPath $keyPathPs)) {
            $stats.SkippedUnsafeClass++
            continue
        }

        $hwid    = Get-MultiSz -KeyPath $keyPathPs -Name "HardwareID"
        $compat  = Get-MultiSz -KeyPath $keyPathPs -Name "CompatibleIDs"

        if ($null -eq $hwid -or @($hwid).Count -eq 0) {
            # sem HardwareID => nada a fazer
            continue
        }

        # Precisa ter >= 2 variantes para termos fallback caso o driver bind por SUBSYS
        if (@($hwid).Count -lt 2) {
            $stats.SkippedSingle++
            Write-Info ("  [SKIP single] " + $vendev + " @ " + $inst.PSChildName + " (so 1 entrada em HardwareID)")
            continue
        }

        # Ha pelo menos uma entrada com SUBSYS ou REV para reescrever?
        $hasGranular = $false
        foreach ($s in $hwid) {
            if ($s -match '(?i)SUBSYS_[0-9A-Fa-f]{8}' -or $s -match '(?i)REV_[0-9A-Fa-f]{2}') {
                $hasGranular = $true
                break
            }
        }
        if (-not $hasGranular -and $compat) {
            foreach ($s in $compat) {
                if ($s -match '(?i)SUBSYS_[0-9A-Fa-f]{8}' -or $s -match '(?i)REV_[0-9A-Fa-f]{2}') {
                    $hasGranular = $true
                    break
                }
            }
        }
        if (-not $hasGranular) {
            $stats.SkippedNoGranular++
            continue
        }

        # Capturar SUBSYS original (para logging) - primeira ocorrencia em HardwareID
        $origSubsys = "-"
        foreach ($s in $hwid) {
            if ($s -match '(?i)SUBSYS_([0-9A-Fa-f]{8})') {
                $origSubsys = $Matches[1].ToUpper()
                break
            }
        }
        $origRev = "-"
        foreach ($s in $hwid) {
            if ($s -match '(?i)REV_([0-9A-Fa-f]{2})') {
                $origRev = $Matches[1].ToUpper()
                break
            }
        }

        # Construir novos arrays preservando ordem
        $newHwid = @()
        foreach ($s in $hwid) {
            $newHwid += ,(Rewrite-IdString -Original $s -NewSubsys $newSubsys -NewRev $newRev)
        }
        $newCompat = $null
        if ($compat) {
            $newCompat = @()
            foreach ($s in $compat) {
                $newCompat += ,(Rewrite-IdString -Original $s -NewSubsys $newSubsys -NewRev $newRev)
            }
        }

        # Nenhuma alteracao efetiva? (ex: SUBSYS ja igual ao que gerariamos)
        $hwidChanged   = $false
        for ($i=0; $i -lt $hwid.Count; $i++) {
            if ($hwid[$i] -ne $newHwid[$i]) { $hwidChanged = $true; break }
        }
        $compatChanged = $false
        if ($compat) {
            for ($i=0; $i -lt $compat.Count; $i++) {
                if ($compat[$i] -ne $newCompat[$i]) { $compatChanged = $true; break }
            }
        }
        if (-not $hwidChanged -and -not $compatChanged) {
            # ja idempotente - conta como reescrito para nao alarmar, mas nao grava
            $stats.Rewritten++
            Write-Info ("  [IDEM] " + $vendev + " @ " + $inst.PSChildName + " SUBSYS=" + $newSubsys + " REV=" + $newRev)
            continue
        }

        Write-OK ("  [" + $vendev + " @ " + $inst.PSChildName + "] SUBSYS " + $origSubsys + " -> " + $newSubsys + " | REV " + $origRev + " -> " + $newRev)

        if (-not $DryRun) {
            try {
                if ($hwidChanged) {
                    Set-MultiSz -KeyPath $keyPathPs -Name "HardwareID" -Values $newHwid
                }
                if ($compatChanged -and $null -ne $newCompat) {
                    Set-MultiSz -KeyPath $keyPathPs -Name "CompatibleIDs" -Values $newCompat
                }
                $mappingEntries += [pscustomobject]@{
                    vendev                  = $vendev
                    instance                = $inst.PSChildName
                    key_path                = $keyPathPs
                    original_subsys         = $origSubsys
                    original_rev            = $origRev
                    new_subsys              = $newSubsys
                    new_rev                 = $newRev
                    original_hardwareid     = $hwid
                    original_compatibleids  = if ($compat) { $compat } else { $null }
                    new_hardwareid          = $newHwid
                    new_compatibleids       = $newCompat
                }
                $stats.Rewritten++
            } catch {
                $stats.Failed++
                Write-Err ("    Falha gravando " + $keyPathPs + ": " + $_.Exception.Message)
            }
        } else {
            $stats.Rewritten++
        }
    }
}

# ---- Persistir mapping ----
if (-not $DryRun -and $mappingEntries.Count -gt 0) {
    Write-Section "Persistindo mapping"
    $mappingDir = Split-Path $mappingPath -Parent
    if (-not (Test-Path $mappingDir)) {
        New-Item -ItemType Directory -Path $mappingDir -Force | Out-Null
    }
    $doc = [pscustomobject]@{
        version    = 1
        created_at = (Get-Date).ToString("o")
        seed       = $seed
        entries    = $mappingEntries
    }
    $tmp = $mappingPath + ".tmp"
    $doc | ConvertTo-Json -Depth 6 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $mappingPath -Force
    Write-OK ("Mapping salvo em: " + $mappingPath)
}

# ---- Resumo ----
Write-Section "Resumo"
Write-Host ("  Devices (VEN&DEV)         : " + $stats.Devices)          -ForegroundColor Cyan
Write-Host ("  Instancias examinadas     : " + $stats.Instances)        -ForegroundColor Cyan
Write-Host ("  Reescritas                : " + $stats.Rewritten)        -ForegroundColor Cyan
Write-Host ("  Skip (so 1 variante)      : " + $stats.SkippedSingle)    -ForegroundColor DarkGray
Write-Host ("  Skip (sem SUBSYS nem REV) : " + $stats.SkippedNoGranular)-ForegroundColor DarkGray
Write-Host ("  Skip (classe unsafe)      : " + $stats.SkippedUnsafeClass) -ForegroundColor DarkGray
Write-Host ("  Falhas                    : " + $stats.Failed)           -ForegroundColor Cyan
if ($DryRun) {
    Write-Warn "-DryRun: nada foi escrito. Rode sem -DryRun para aplicar."
} else {
    Write-Warn "Reboot recomendado para o PnP re-avaliar os drivers."
    Write-Info ("Para reverter: .\spoof-pci-hardwareid.ps1 -Restore")
}
if ($stats.Failed -gt 0) { exit 1 }
exit 0
