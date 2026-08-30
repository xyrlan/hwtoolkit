#Requires -RunAsAdministrator
# ============================================================
#  EDID Full Spoof v1 - GAP #4 (post-BSOD hardening v3.5)
#
#  Substitui o spoof parcial (bytes 12-15) do spoof-mac.ps1
#  por um spoof COMPLETO do EDID:
#    - PNP ID (bytes 8-9, EISA 3-letter compressed)
#    - Product code (bytes 10-11 little-endian)
#    - Serial numerico (bytes 12-15 little-endian)
#    - Semana e ano de fabricacao (bytes 16-17)
#    - Descriptor block 0xFF (serial ASCII)
#    - Descriptor block 0xFC (product name)
#    - Checksum do bloco 0 (byte 127)
#    - Checksum do bloco de extensao (byte 255) se existir
#
#  Tambem varre e reescreve as caches auxiliares onde o EDID
#  aparece embutido:
#    - HKLM\...\Enum\DISPLAY\*\Device Parameters\EDID (primary)
#    - HKLM\...\Enum\DISPLAY\*\Device Parameters\BADEDID (fallback)
#    - HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration
#    - HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Connectivity
#
#  Perfil eh a fonte unica da verdade. Le monitor.mfr_pnp_id,
#  product_code, serial_num, mfg_week, mfg_year, serial_ascii,
#  model_name. Campos ausentes sao derivados de forma estavel a
#  partir de monitor.edid_serial (v4 profile) quando possivel.
#
#  Uso:
#    .\spoof-edid-full.ps1              # aplica no registry
#    .\spoof-edid-full.ps1 -DryRun      # so mostra o que faria
# ============================================================

[CmdletBinding()]
param(
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------

# EDID Magic header: 00 FF FF FF FF FF FF 00
$Script:EdidMagic = @(0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00)

function Test-EdidMagic {
    param([byte[]]$Data, [int]$Offset = 0)
    if ($null -eq $Data) { return $false }
    if (($Data.Length - $Offset) -lt 128) { return $false }
    for ($i = 0; $i -lt 8; $i++) {
        if ($Data[$Offset + $i] -ne $Script:EdidMagic[$i]) { return $false }
    }
    return $true
}

function Convert-PnpIdToBytes {
    param([Parameter(Mandatory)][string]$Str3)
    if ($Str3.Length -ne 3) {
        throw "PNP ID deve ter exatamente 3 letras: '$Str3'"
    }
    $s = $Str3.ToUpperInvariant()
    $c1 = [byte]([byte][char]$s[0] - [byte][char]'A' + 1)
    $c2 = [byte]([byte][char]$s[1] - [byte][char]'A' + 1)
    $c3 = [byte]([byte][char]$s[2] - [byte][char]'A' + 1)
    foreach ($c in @($c1, $c2, $c3)) {
        if ($c -lt 1 -or $c -gt 26) {
            throw "PNP ID '$Str3' contem caractere fora de A-Z"
        }
    }
    # bit layout (bytes 8-9, big-endian): 0 | c1(5) | c2(5) | c3(5)
    $b0 = [byte]((($c1 -band 0x1F) -shl 2) -bor (($c2 -shr 3) -band 0x03))
    $b1 = [byte]((($c2 -band 0x07) -shl 5) -bor ($c3 -band 0x1F))
    return ,[byte[]]@($b0, $b1)
}

function Convert-BytesToPnpId {
    param([byte[]]$Data, [int]$Offset = 8)
    $b0 = $Data[$Offset]
    $b1 = $Data[$Offset + 1]
    $c1 = ($b0 -shr 2) -band 0x1F
    $c2 = ((($b0 -band 0x03) -shl 3) -bor (($b1 -shr 5) -band 0x07)) -band 0x1F
    $c3 = $b1 -band 0x1F
    $chars = @($c1, $c2, $c3) | ForEach-Object {
        if ($_ -ge 1 -and $_ -le 26) {
            [char]([byte][char]'A' + $_ - 1)
        } else {
            '?'
        }
    }
    return ($chars -join '')
}

function Set-EdidChecksum {
    param([byte[]]$Data, [int]$BlockOffset = 0)
    $sum = 0
    for ($i = 0; $i -lt 127; $i++) {
        $sum = ($sum + $Data[$BlockOffset + $i]) -band 0xFF
    }
    $Data[$BlockOffset + 127] = [byte]((256 - $sum) -band 0xFF)
}

function Set-EdidDescriptorText {
    param(
        [byte[]]$Data,
        [int]$Offset,
        [string]$Text
    )
    # Preserva o header do descriptor [off..off+4]:
    #   off, off+1, off+2 = 00 00 00 (indica display descriptor)
    #   off+3            = tipo (0xFF, 0xFC, 0xFE, etc.)
    #   off+4            = reserved / flag (varia)
    # Reescreve payload [off+5..off+17] (13 bytes) com ASCII,
    # 0x0A como terminador se cabivel, resto pad 0x20.

    $maxLen = 13
    $t = $Text
    if ($null -eq $t) { $t = "" }
    # ASCII printable somente. Sanitiza.
    $ascii = ""
    foreach ($ch in $t.ToCharArray()) {
        $code = [int][char]$ch
        if ($code -ge 0x20 -and $code -le 0x7E) {
            $ascii += $ch
        }
    }
    if ($ascii.Length -gt $maxLen) {
        $ascii = $ascii.Substring(0, $maxLen)
    }

    for ($i = 0; $i -lt $maxLen; $i++) {
        if ($i -lt $ascii.Length) {
            $Data[$Offset + 5 + $i] = [byte][char]$ascii[$i]
        } elseif ($i -eq $ascii.Length) {
            $Data[$Offset + 5 + $i] = 0x0A
        } else {
            $Data[$Offset + 5 + $i] = 0x20
        }
    }
}

function Get-EdidDescriptorText {
    param(
        [byte[]]$Data,
        [int]$Offset
    )
    $chars = @()
    for ($i = 0; $i -lt 13; $i++) {
        $b = $Data[$Offset + 5 + $i]
        if ($b -eq 0x0A) { break }
        if ($b -ge 0x20 -and $b -le 0x7E) {
            $chars += [char]$b
        }
    }
    return (-join $chars).TrimEnd()
}

function Get-EdidSummary {
    param([byte[]]$Data)
    if ($Data.Length -lt 128) { return $null }
    $pnp     = Convert-BytesToPnpId -Data $Data -Offset 8
    $prodLo  = $Data[10]
    $prodHi  = $Data[11]
    $product = ([int]$prodHi -shl 8) -bor [int]$prodLo
    $ser     = "{0:X2}{1:X2}{2:X2}{3:X2}" -f $Data[15], $Data[14], $Data[13], $Data[12]
    $week    = $Data[16]
    $year    = 1990 + $Data[17]

    $serialAscii = ""
    $modelName   = ""
    foreach ($off in @(54, 72, 90, 108)) {
        if (($off + 17) -ge $Data.Length) { break }
        if ($Data[$off] -eq 0 -and $Data[$off + 1] -eq 0 -and $Data[$off + 2] -eq 0) {
            switch ($Data[$off + 3]) {
                0xFF { $serialAscii = Get-EdidDescriptorText -Data $Data -Offset $off }
                0xFC { $modelName   = Get-EdidDescriptorText -Data $Data -Offset $off }
            }
        }
    }

    return [PSCustomObject]@{
        Pnp         = $pnp
        Product     = $product
        SerialNum   = $ser
        Week        = $week
        Year        = $year
        SerialAscii = $serialAscii
        ModelName   = $modelName
    }
}

function Compare-ByteArray {
    param([byte[]]$A, [byte[]]$B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    if ($A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) {
        if ($A[$i] -ne $B[$i]) { return $false }
    }
    return $true
}

function Update-EdidBytes {
    param(
        [byte[]]$Data,
        [byte[]]$PnpIdBytes,
        [int]$ProductCode,
        [uint32]$SerialNum,
        [byte]$MfgWeek,
        [int]$MfgYear,
        [string]$SerialAscii,
        [string]$ModelName
    )
    if ($Data.Length -lt 128) {
        throw "EDID muito curto ($($Data.Length) bytes), esperado >= 128"
    }

    # PNP ID (bytes 8-9, big-endian)
    $Data[8] = $PnpIdBytes[0]
    $Data[9] = $PnpIdBytes[1]

    # Product code (bytes 10-11 little-endian)
    $Data[10] = [byte]($ProductCode -band 0xFF)
    $Data[11] = [byte](($ProductCode -shr 8) -band 0xFF)

    # Serial numerico (bytes 12-15 little-endian)
    $Data[12] = [byte]($SerialNum -band 0xFF)
    $Data[13] = [byte](($SerialNum -shr 8) -band 0xFF)
    $Data[14] = [byte](($SerialNum -shr 16) -band 0xFF)
    $Data[15] = [byte](($SerialNum -shr 24) -band 0xFF)

    # Semana e ano
    $Data[16] = $MfgWeek
    $yearByte = $MfgYear - 1990
    if ($yearByte -lt 0)  { $yearByte = 0 }
    if ($yearByte -gt 255) { $yearByte = 255 }
    $Data[17] = [byte]$yearByte

    # Descriptor blocks - reescreve slots ja 0xFF/0xFC; se o EDID original
    # nao tem slot 0xFC (nome) nem 0xFF (serial), promove o slot 108 (ultimo)
    # para acomodar model_name como 0xFC. Slot 108 e o mais comumente livre
    # e sacrificar 1 timing entry extra nao afeta a resolucao nativa (que
    # vem do DTD em bytes 54-71, block 0).
    $hasNameSlot   = $false
    $hasSerialSlot = $false
    foreach ($off in @(54, 72, 90, 108)) {
        if (($off + 17) -ge $Data.Length) { continue }
        if ($Data[$off] -ne 0 -or $Data[$off + 1] -ne 0 -or $Data[$off + 2] -ne 0) { continue }
        if ($Data[$off + 3] -eq 0xFC) { $hasNameSlot = $true }
        if ($Data[$off + 3] -eq 0xFF) { $hasSerialSlot = $true }
    }

    foreach ($off in @(54, 72, 90, 108)) {
        if (($off + 17) -ge $Data.Length) { continue }
        if ($Data[$off] -ne 0 -or $Data[$off + 1] -ne 0 -or $Data[$off + 2] -ne 0) {
            # timing descriptor, nao mexer (exceto promocao do slot 108 abaixo)
            continue
        }
        switch ($Data[$off + 3]) {
            0xFF {
                if ($SerialAscii) {
                    Set-EdidDescriptorText -Data $Data -Offset $off -Text $SerialAscii
                }
            }
            0xFC {
                if ($ModelName) {
                    Set-EdidDescriptorText -Data $Data -Offset $off -Text $ModelName
                }
            }
        }
    }

    # Promocao: se nao havia slot 0xFC e temos model_name, converter o slot 108
    # (ou o primeiro slot livre a partir de 108 para tras) em bloco 0xFC.
    if (-not $hasNameSlot -and $ModelName -and ($Data.Length -ge 126)) {
        $promoteOff = 108
        if (($promoteOff + 17) -lt $Data.Length) {
            # Zera header + define tag 0xFC
            $Data[$promoteOff]     = 0
            $Data[$promoteOff + 1] = 0
            $Data[$promoteOff + 2] = 0
            $Data[$promoteOff + 3] = 0xFC
            $Data[$promoteOff + 4] = 0
            Set-EdidDescriptorText -Data $Data -Offset $promoteOff -Text $ModelName
        }
    }

    # Checksum bloco 0
    Set-EdidChecksum -Data $Data -BlockOffset 0

    # Checksum bloco de extensao SO se byte 126 indicar extensoes presentes.
    # byte 126 = numero de extension blocks. Se == 0, bytes 128-255 nao sao EDID valido
    # (podem ser lixo/padding do driver) e recomputar checksum ali corrompe dados.
    if ($Data.Length -ge 256 -and $Data[126] -gt 0) {
        Set-EdidChecksum -Data $Data -BlockOffset 128
    }
}

# ------------------------------------------------------------
#  Carregar profile
# ------------------------------------------------------------

Write-Host ""
Write-Host "=== EDID Full Spoof v1 (Profile-Based) ===" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "  [DRY-RUN] Nenhuma escrita sera feita" -ForegroundColor Yellow
}
Write-Host ""

$profilePath = "C:\ProgramData\.hwcfg\profile.json"
if (-not (Test-Path $profilePath)) {
    Write-Host "  [X] Profile nao encontrado: $profilePath" -ForegroundColor Red
    Write-Host "  [X] Rode primeiro:  .\generate-profile.ps1 -Generate" -ForegroundColor Red
    exit 1
}

$prof = Get-Content $profilePath -Raw | ConvertFrom-Json

if (-not $prof.monitor) {
    Write-Host "  [X] Profile nao tem secao 'monitor'. Regenerar o perfil." -ForegroundColor Red
    exit 1
}

$mon = $prof.monitor

# ------------------------------------------------------------
#  Resolver campos do profile (com fallback estavel)
# ------------------------------------------------------------

# edid_serial (4 bytes hex) eh a semente estavel do profile v4.
$edidSerialHex = if ($mon.PSObject.Properties['edid_serial']) { $mon.edid_serial } else { $null }
$seedBytes = $null
if ($edidSerialHex -and $edidSerialHex.Length -ge 8) {
    $seedBytes = New-Object byte[] 4
    for ($i = 0; $i -lt 4; $i++) {
        $seedBytes[$i] = [Convert]::ToByte($edidSerialHex.Substring($i * 2, 2), 16)
    }
}

# Numero serial numerico (little-endian derivado do seed se ausente)
$profileSerialNum = [uint32]0
if ($mon.PSObject.Properties['serial_num'] -and $null -ne $mon.serial_num) {
    # Usa BigInteger para aceitar valores hand-editados fora de uint32 sem OverflowException
    try {
        $snBig = [System.Numerics.BigInteger]::Parse("$($mon.serial_num)")
        if ($snBig -lt 0) { $snBig = [System.Numerics.BigInteger]::Zero }
        # Reduz mod 2^32 se necessario
        $mask = [System.Numerics.BigInteger]::Parse("4294967296")
        $snBig = $snBig % $mask
        $profileSerialNum = [uint32]([long]$snBig)
    } catch {
        Write-Host ("  [!] serial_num do profile invalido: {0} - usando 0" -f $mon.serial_num) -ForegroundColor Yellow
        $profileSerialNum = [uint32]0
    }
} elseif ($seedBytes) {
    $profileSerialNum = [uint32]$seedBytes[0] `
                    -bor ([uint32]$seedBytes[1] -shl 8) `
                    -bor ([uint32]$seedBytes[2] -shl 16) `
                    -bor ([uint32]$seedBytes[3] -shl 24)
}

# PNP ID (3 letras, EISA). Default AUS (asus) se nada no profile.
$profilePnp = if ($mon.PSObject.Properties['mfr_pnp_id'] -and $mon.mfr_pnp_id) { $mon.mfr_pnp_id.ToString().ToUpperInvariant() } else { "AUS" }

# Product code (16-bit). Default derivado do seed.
$profileProduct = 0
if ($mon.PSObject.Properties['product_code'] -and $null -ne $mon.product_code) {
    $profileProduct = [int]$mon.product_code
} elseif ($seedBytes) {
    $profileProduct = ([int]$seedBytes[0]) -bor (([int]$seedBytes[1]) -shl 8)
    if ($profileProduct -eq 0) { $profileProduct = 0x1234 }
} else {
    $profileProduct = 0x1234
}

# Semana e ano de fabricacao
$profileWeek = 0
if ($mon.PSObject.Properties['mfg_week'] -and $null -ne $mon.mfg_week) {
    $profileWeek = [byte]([int]$mon.mfg_week -band 0xFF)
} elseif ($seedBytes) {
    $w = ($seedBytes[2] % 52) + 1
    $profileWeek = [byte]$w
}

$profileYear = 0
if ($mon.PSObject.Properties['mfg_year'] -and $null -ne $mon.mfg_year) {
    $profileYear = [int]$mon.mfg_year
} elseif ($seedBytes) {
    # 2015..2023 range estavel
    $profileYear = 2015 + ($seedBytes[3] % 9)
} else {
    $profileYear = 2020
}

# ASCII serial e model name. Se ausentes, gera algo estavel a partir do seed.
$profileSerialAscii = if ($mon.PSObject.Properties['serial_ascii'] -and $mon.serial_ascii) { $mon.serial_ascii.ToString() } else { $null }
$profileModelName   = if ($mon.PSObject.Properties['model_name']   -and $mon.model_name)   { $mon.model_name.ToString()   } else { $null }

if (-not $profileSerialAscii -and $edidSerialHex) {
    $profileSerialAscii = "SN" + $edidSerialHex.ToUpperInvariant()
}
if (-not $profileSerialAscii) {
    # ultimo fallback estavel — sem isso o descriptor 0xFF nao seria reescrito
    # e o serial ASCII real do monitor sobreviveria no EDID spoofado.
    $profileSerialAscii = ("SN{0:X8}" -f ((Get-Random -Minimum 0 -Maximum 0x7FFFFFFF)))
}
if (-not $profileModelName) {
    $profileModelName = "$profilePnp Display"
}

# Limita ASCII a 13 chars conforme spec
if ($profileSerialAscii.Length -gt 13) { $profileSerialAscii = $profileSerialAscii.Substring(0, 13) }
if ($profileModelName.Length   -gt 13) { $profileModelName   = $profileModelName.Substring(0, 13)   }

# Encoda PNP ID
try {
    $pnpBytes = Convert-PnpIdToBytes -Str3 $profilePnp
} catch {
    Write-Host "  [X] PNP ID invalido no profile: $profilePnp - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "=== Valores do profile (aplicados a todos os monitores) ===" -ForegroundColor Cyan
Write-Host ("  PNP ID       : {0}  (bytes 8-9 = {1:X2} {2:X2})" -f $profilePnp, $pnpBytes[0], $pnpBytes[1])
Write-Host ("  Product code : 0x{0:X4}" -f $profileProduct)
Write-Host ("  Serial num   : 0x{0:X8}" -f $profileSerialNum)
Write-Host ("  Mfg week/year: {0} / {1}" -f $profileWeek, $profileYear)
Write-Host ("  Serial ASCII : '{0}'" -f $profileSerialAscii)
Write-Host ("  Model name   : '{0}'" -f $profileModelName)
Write-Host ""

# ------------------------------------------------------------
#  Passo 1: DISPLAY\...\Device Parameters\EDID (primary)
# ------------------------------------------------------------

$displayRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
$primaryUpdated = 0
$primarySkipped = 0
$primaryTooShort = 0
$primaryOriginals = @()   # guarda os EDID originais para varrer caches

Write-Host "=== Passo 1: EDID primario (Enum\DISPLAY) ===" -ForegroundColor Cyan

if (-not (Test-Path $displayRegPath)) {
    Write-Host "  [!] $displayRegPath nao existe. Pulando." -ForegroundColor Yellow
} else {
    $vendors = Get-ChildItem $displayRegPath -ErrorAction SilentlyContinue
    foreach ($vendor in $vendors) {
        $instances = Get-ChildItem $vendor.PSPath -ErrorAction SilentlyContinue
        foreach ($instance in $instances) {
            $devParamsPath = Join-Path $instance.PSPath "Device Parameters"
            if (-not (Test-Path $devParamsPath)) { continue }

            foreach ($valName in @("EDID", "BADEDID")) {
                $edidRaw = $null
                try {
                    $edidRaw = (Get-ItemProperty -Path $devParamsPath -Name $valName -ErrorAction Stop).$valName
                } catch {
                    continue
                }
                if ($edidRaw -isnot [byte[]]) { continue }
                if ($edidRaw.Length -lt 128) {
                    Write-Host ("  [!] {0}\{1} tem {2} bytes (<128), pulando." -f $instance.PSChildName, $valName, $edidRaw.Length) -ForegroundColor Yellow
                    $primaryTooShort++
                    continue
                }

                if (-not (Test-EdidMagic -Data $edidRaw)) {
                    Write-Host ("  [!] {0}\{1} nao tem magic EDID valido, pulando." -f $instance.PSChildName, $valName) -ForegroundColor Yellow
                    $primarySkipped++
                    continue
                }

                # Copia para nao mutar o array original em memoria antes de comparar
                $newBytes = New-Object byte[] $edidRaw.Length
                [Array]::Copy($edidRaw, $newBytes, $edidRaw.Length)

                # Guarda copia do original ANTES da mutacao para busca em caches
                $originalCopy = New-Object byte[] $edidRaw.Length
                [Array]::Copy($edidRaw, $originalCopy, $edidRaw.Length)

                $before = Get-EdidSummary -Data $edidRaw

                Update-EdidBytes -Data $newBytes `
                    -PnpIdBytes $pnpBytes `
                    -ProductCode $profileProduct `
                    -SerialNum $profileSerialNum `
                    -MfgWeek $profileWeek `
                    -MfgYear $profileYear `
                    -SerialAscii $profileSerialAscii `
                    -ModelName $profileModelName

                $after = Get-EdidSummary -Data $newBytes

                Write-Host ""
                Write-Host ("  [{0}] {1}\{2}" -f $vendor.PSChildName, $instance.PSChildName, $valName) -ForegroundColor White
                Write-Host ("    ANTES: PNP={0} Prod=0x{1:X4} Ser=0x{2} Wk/Yr={3}/{4} SN='{5}' Model='{6}'" -f `
                    $before.Pnp, $before.Product, $before.SerialNum, $before.Week, $before.Year, $before.SerialAscii, $before.ModelName) -ForegroundColor DarkGray
                Write-Host ("    DEPOIS: PNP={0} Prod=0x{1:X4} Ser=0x{2} Wk/Yr={3}/{4} SN='{5}' Model='{6}'" -f `
                    $after.Pnp,  $after.Product,  $after.SerialNum,  $after.Week,  $after.Year,  $after.SerialAscii,  $after.ModelName) -ForegroundColor Green

                if ($DryRun) {
                    Write-Host "    [DRY-RUN] nao escrito" -ForegroundColor Yellow
                } else {
                    try {
                        Set-ItemProperty -Path $devParamsPath -Name $valName -Value $newBytes -Type Binary -Force
                        $primaryUpdated++
                    } catch {
                        Write-Host ("    [X] Falha ao escrever: {0}" -f $_.Exception.Message) -ForegroundColor Red
                    }
                }

                $primaryOriginals += ,[PSCustomObject]@{
                    Original = $originalCopy
                    Replaced = $newBytes
                    Source   = "{0}\{1}\{2}" -f $vendor.PSChildName, $instance.PSChildName, $valName
                }
            }
        }
    }
}

Write-Host ""
Write-Host ("  Primario: {0} atualizados, {1} pulados, {2} muito curtos" -f $primaryUpdated, $primarySkipped, $primaryTooShort)

# ------------------------------------------------------------
#  Passo 2: varredura de caches (Configuration, Connectivity)
# ------------------------------------------------------------

Write-Host ""
Write-Host "=== Passo 2: caches GraphicsDrivers ===" -ForegroundColor Cyan

if ($primaryOriginals.Count -eq 0) {
    Write-Host "  [!] Nenhum EDID primario encontrado, pulando varredura de cache." -ForegroundColor Yellow
} else {

    $cacheRoots = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration",
        "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Connectivity"
    )

    $cacheHits = 0
    $cacheEmbedded = 0

    foreach ($root in $cacheRoots) {
        if (-not (Test-Path $root)) {
            Write-Host ("  [!] {0} nao existe, pulando." -f $root) -ForegroundColor Yellow
            continue
        }

        Write-Host ("  Varrendo: {0}" -f $root) -ForegroundColor Gray

        # Enumera recursivamente. Get-ChildItem -Recurse na Registry funciona.
        $keys = @($root) + (Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.PSPath })

        foreach ($keyPath in $keys) {
            $props = $null
            try {
                $props = Get-ItemProperty -Path $keyPath -ErrorAction Stop
            } catch {
                continue
            }
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -like "PS*") { continue }
                $val = $prop.Value
                if ($val -isnot [byte[]]) { continue }
                if ($val.Length -lt 128) { continue }

                # Estrategia A: valor eh exatamente um EDID (comeca com magic no offset 0)
                if (Test-EdidMagic -Data $val -Offset 0) {
                    $matchedIdx = -1
                    for ($i = 0; $i -lt $primaryOriginals.Count; $i++) {
                        $orig = $primaryOriginals[$i].Original
                        if (Compare-ByteArray -A $orig -B $val) {
                            $matchedIdx = $i
                            break
                        }
                    }
                    if ($matchedIdx -ge 0) {
                        $newBlob = $primaryOriginals[$matchedIdx].Replaced
                        Write-Host ("    [HIT] {0}\{1} (exato)" -f $keyPath, $prop.Name) -ForegroundColor Green
                        if (-not $DryRun) {
                            try {
                                Set-ItemProperty -Path $keyPath -Name $prop.Name -Value $newBlob -Type Binary -Force
                                $cacheHits++
                            } catch {
                                Write-Host ("      [X] Falha ao escrever: {0}" -f $_.Exception.Message) -ForegroundColor Red
                            }
                        } else {
                            Write-Host "      [DRY-RUN] nao escrito" -ForegroundColor Yellow
                            $cacheHits++
                        }
                        continue
                    }
                }

                # Estrategia B: EDID embutido em algum offset (varre offsets alinhados)
                $embeddedFound = $false
                # Passo de 4 bytes para nao ficar caro em blobs grandes; magic tem 8 bytes.
                for ($off = 0; ($off + 128) -le $val.Length; $off += 4) {
                    if (-not (Test-EdidMagic -Data $val -Offset $off)) { continue }

                    # Extrai janela de 128 bytes (ou 256 se couber e comecar com magic)
                    $windowLen = 128
                    if (($off + 256) -le $val.Length) {
                        # so trata como 256 se o segundo bloco existir e o EDID original que
                        # bateu tambem tem 256, se nao arriscamos danificar dados alem.
                        # Vamos comparar como 128 primeiro; se der match e o original for 256,
                        # promovemos para 256.
                    }

                    $window = New-Object byte[] $windowLen
                    [Array]::Copy($val, $off, $window, 0, $windowLen)

                    $matchedIdx = -1
                    for ($i = 0; $i -lt $primaryOriginals.Count; $i++) {
                        $orig = $primaryOriginals[$i].Original
                        # match dos primeiros 128 bytes
                        $len = [Math]::Min(128, $orig.Length)
                        $slice = New-Object byte[] $len
                        [Array]::Copy($orig, 0, $slice, 0, $len)
                        if (Compare-ByteArray -A $slice -B $window) {
                            $matchedIdx = $i
                            break
                        }
                    }
                    if ($matchedIdx -lt 0) { continue }

                    $orig     = $primaryOriginals[$matchedIdx].Original
                    $replaced = $primaryOriginals[$matchedIdx].Replaced
                    $useLen = 128
                    if ($orig.Length -ge 256 -and ($off + 256) -le $val.Length) {
                        # confirma que os bytes 128-255 tambem batem antes de sobrescrever 256
                        $tailOrig = New-Object byte[] 128
                        [Array]::Copy($orig, 128, $tailOrig, 0, 128)
                        $tailReg  = New-Object byte[] 128
                        [Array]::Copy($val, $off + 128, $tailReg, 0, 128)
                        if (Compare-ByteArray -A $tailOrig -B $tailReg) {
                            $useLen = 256
                        }
                    }

                    # Copia val, sobrescreve regiao [off..off+useLen-1] com replaced[0..useLen-1]
                    $newVal = New-Object byte[] $val.Length
                    [Array]::Copy($val, $newVal, $val.Length)
                    [Array]::Copy($replaced, 0, $newVal, $off, $useLen)

                    Write-Host ("    [HIT] {0}\{1} (embutido @ offset {2}, {3} bytes)" -f $keyPath, $prop.Name, $off, $useLen) -ForegroundColor Green

                    if (-not $DryRun) {
                        try {
                            Set-ItemProperty -Path $keyPath -Name $prop.Name -Value $newVal -Type Binary -Force
                            $cacheEmbedded++
                        } catch {
                            Write-Host ("      [X] Falha ao escrever: {0}" -f $_.Exception.Message) -ForegroundColor Red
                        }
                    } else {
                        Write-Host "      [DRY-RUN] nao escrito" -ForegroundColor Yellow
                        $cacheEmbedded++
                    }
                    $embeddedFound = $true
                    # Assume um EDID por valor. Break.
                    break
                }
                if ($embeddedFound) { continue }
            }
        }
    }

    Write-Host ""
    Write-Host ("  Cache: {0} exatos, {1} embutidos" -f $cacheHits, $cacheEmbedded)
}

# ------------------------------------------------------------
#  Resumo final
# ------------------------------------------------------------

Write-Host ""
Write-Host "=== RESUMO ===" -ForegroundColor Cyan
Write-Host ("  Monitores atualizados (primario): {0}" -f $primaryUpdated)
Write-Host ("  EDID muito curto (ignorados)    : {0}" -f $primaryTooShort)
Write-Host ("  Sem magic EDID (ignorados)      : {0}" -f $primarySkipped)

if ($DryRun) {
    Write-Host ""
    Write-Host "  [DRY-RUN] Nenhuma alteracao gravada. Rode sem -DryRun para aplicar." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "  [!] O driver grafico so vai reler o EDID apos:" -ForegroundColor Yellow
    Write-Host "        - Reboot, OU" -ForegroundColor Yellow
    Write-Host "        - Desabilitar/reabilitar o adaptador de video, OU" -ForegroundColor Yellow
    Write-Host "        - Restart do display session (logoff/logon nem sempre basta)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [!] Recomendacao: reiniciar antes de rodar o anti-cheat." -ForegroundColor Yellow
}
Write-Host ""
