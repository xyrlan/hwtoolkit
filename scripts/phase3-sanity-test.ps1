#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sanity-test do Track D v5.0.6 Phase 2 (OEM string synthesizer via
    RegNtPostQueryValueKey) dentro da VM.

.DESCRIPTION
    Rodar DENTRO DO GUEST apos:
      1. .\03-instalar-driver.bat (driver v5.0.6 Phase 2) + reboot
      2. .\scripts\track-d-arm.ps1 -Enable + reboot
      3. .\scripts\track-d-arm.ps1 -EnableValueRewrite
      4. .\scripts\track-d-arm.ps1 -EnableSynth
      5. (voce esta aqui)

    O check central prova a **cross-value brand coherence** que a v5.0.6
    Phase 2 existe para garantir:  DeviceDesc, FriendlyName e Mfg do
    MESMO parent SCSI DEVEM vir da MESMA row do MESMO pool.  A harness
    re-implementa em PowerShell a formula de row-selection do driver
    (documentada em driver/trackd_inventory.h e em rstflt.c
    TrackDInvSelectRowIndex):
        subSeed   = FNV1a64(g_TrackDSeed_bytes || '|' || "SCSI"_utf16le_bytes)
        parentH   = FNV1a64(parent_utf16le_bytes)
        mixed     = FNV1a64(subSeed_bytes || '|' || parentH_bytes)
        rowIndex  = (mixed >> 32) % rowCount
    e busca a row esperada da inventory hard-coded aqui (mirror da
    trackd_inventory.h para o pool SCSI, 19 rows).  Compara byte-exato
    contra o output do gated rubinot_probe.exe.

    Pass criteria hard (fail = exit 2):
      - Sem BSOD.
      - EnableRegCallback=1, EnableValueReadRewrite=1, EnableValueSynth=1.
      - Gated DeviceDesc / FriendlyName / Mfg do parent SCSI casam BYTE-EXATO
        com a row esperada pela recipe PS.
      - As tres colunas vem da MESMA row (cross-value coherence).
      - Non-gated (reg.exe original, imagem nao-rubinot) retorna o valor REAL
        - o gate discrimina corretamente.
      - Hive nao foi mutado (reg query com nova sessao continua devolvendo
        real - synth grava so no buffer do caller).
    Pass criteria soft (warn):
      - SynthHit_SCSI_DeviceDesc + _FriendlyName + _Mfg incrementaram
        (persistencia async - contador zera no reboot + flush pode nao ter
        rodado; a prova HARD e o valor byte-exato).
      - Todos os Synth*Bail counters = 0.
      - Hot-toggle round-trip (-DisableSynth -> pass-through -> -EnableSynth
        -> gate volta a engajar) apos um tap sem reboot.

    Exit codes: 0=PASS, 1=pre-check falhou, 2=hard-fail.

.EXAMPLE
    .\phase3-sanity-test.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\_ui-common.ps1"

$paramsKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters'
$scsiRoot   = 'HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI'
$probeDir   = 'C:\hwtoolkit'
$probeSrc   = "$env:SystemRoot\System32\reg.exe"
$probeName  = 'rubinot_probe.exe'
$probePath  = Join-Path $probeDir $probeName

# ============================================================
#  FNV recipe (mirror do driver TrackDFnvHash64)
# ============================================================
function Get-Fnv1a64Bytes {
    param([byte[]]$Data)
    $hash  = [System.Numerics.BigInteger]::Parse("14695981039346656037")  # offset basis
    $prime = [System.Numerics.BigInteger]::Parse("1099511628211")          # FNV prime
    $mask  = [System.Numerics.BigInteger]::Parse("18446744073709551615")   # 2^64-1
    foreach ($b in $Data) {
        $hash = $hash -bxor ([System.Numerics.BigInteger]$b)
        $hash = ($hash * $prime) -band $mask
    }
    return [uint64]$hash
}

# Reproduz TrackDMixWithSeed: FNV1a64(seedBytes || '|' || bytes).
function Get-MixWithSeed {
    param([byte[]]$SeedBytes, [byte[]]$Bytes)
    $buf = New-Object System.Collections.Generic.List[byte]
    if ($SeedBytes -and $SeedBytes.Length -gt 0) { $buf.AddRange($SeedBytes) }
    $buf.Add([byte]0x7C)  # '|'
    if ($Bytes -and $Bytes.Length -gt 0) { $buf.AddRange($Bytes) }
    return (Get-Fnv1a64Bytes $buf.ToArray())
}

# Reproduz TrackDMixTwo: FNV1a64(seed64_bytes || '|' || bytes).
function Get-MixTwo {
    param([uint64]$Seed64, [byte[]]$Bytes)
    $buf = New-Object System.Collections.Generic.List[byte]
    # seed64 as 8 LE bytes
    for ($i = 0; $i -lt 8; $i++) {
        $buf.Add([byte](($Seed64 -shr ($i * 8)) -band 0xFF))
    }
    $buf.Add([byte]0x7C)  # '|'
    if ($Bytes -and $Bytes.Length -gt 0) { $buf.AddRange($Bytes) }
    return (Get-Fnv1a64Bytes $buf.ToArray())
}

# Reproduz TrackDInvSelectRowIndex(className, parent, rowCount).
function Get-RowIndex {
    param([string]$ClassName, [string]$ParentPath, [int]$RowCount, [byte[]]$SeedBytes)
    $classBytes  = [System.Text.Encoding]::Unicode.GetBytes($ClassName)
    $parentBytes = [System.Text.Encoding]::Unicode.GetBytes($ParentPath)
    $subSeed     = Get-MixWithSeed -SeedBytes $SeedBytes -Bytes $classBytes
    $parentHash  = Get-Fnv1a64Bytes $parentBytes
    # parentHash as 8 LE bytes into MixTwo
    $parentHashBytes = New-Object byte[] 8
    for ($i = 0; $i -lt 8; $i++) {
        $parentHashBytes[$i] = [byte](($parentHash -shr ($i * 8)) -band 0xFF)
    }
    $mixed = Get-MixTwo -Seed64 $subSeed -Bytes $parentHashBytes
    return [int]((($mixed -shr 32) -band 0xFFFFFFFF) % [uint64]$RowCount)
}

# ============================================================
#  SCSI pool - MIRROR de driver/trackd_inventory.h §Composition.
#  DEVE ficar em sync manualmente com o header C.  Ordem = row index.
# ============================================================
$SCSI_POOL = @(
    @{ Vendor='MICRON  '; Product='5300 MAX';         Rev='M002'; DeviceDesc='MICRON 5300 MAX SCSI Disk Device';  FriendlyName='MICRON 5300 MAX SCSI Disk Device';  Mfg='Micron Technology, Inc.' },
    @{ Vendor='MICRON  '; Product='5400 PRO';         Rev='M042'; DeviceDesc='MICRON 5400 PRO SCSI Disk Device';  FriendlyName='MICRON 5400 PRO SCSI Disk Device';  Mfg='Micron Technology, Inc.' },
    @{ Vendor='MICRON  '; Product='7400 PRO';         Rev='U200'; DeviceDesc='NVMe MICRON 7400 PRO';              FriendlyName='NVMe MICRON 7400 PRO';              Mfg='Micron Technology, Inc.' },
    @{ Vendor='MICRON  '; Product='9300 MAX';         Rev='E301'; DeviceDesc='NVMe MICRON 9300 MAX';              FriendlyName='NVMe MICRON 9300 MAX';              Mfg='Micron Technology, Inc.' },
    @{ Vendor='SAMSUNG '; Product='MZ7L3960HCJR';     Rev='4104'; DeviceDesc='SAMSUNG MZ7L3960HCJR SCSI Disk Device'; FriendlyName='SAMSUNG MZ7L3960HCJR SCSI Disk Device'; Mfg='Samsung Electronics Co., Ltd.' },
    @{ Vendor='SAMSUNG '; Product='MZQL21T9HCJR';     Rev='GDC7'; DeviceDesc='NVMe SAMSUNG MZQL21T9HCJR';         FriendlyName='NVMe SAMSUNG MZQL21T9HCJR';         Mfg='Samsung Electronics Co., Ltd.' },
    @{ Vendor='SAMSUNG '; Product='MZWLJ3T8HBLS';     Rev='EPA7'; DeviceDesc='NVMe SAMSUNG MZWLJ3T8HBLS';         FriendlyName='NVMe SAMSUNG MZWLJ3T8HBLS';         Mfg='Samsung Electronics Co., Ltd.' },
    @{ Vendor='INTEL   '; Product='SSDSC2KG960G8';    Rev='010B'; DeviceDesc='INTEL SSDSC2KG960G8 SCSI Disk Device'; FriendlyName='INTEL SSDSC2KG960G8 SCSI Disk Device'; Mfg='Intel Corporation' },
    @{ Vendor='INTEL   '; Product='SSDPE2KE016T8';    Rev='VDV1'; DeviceDesc='NVMe INTEL SSDPE2KE016T8';          FriendlyName='NVMe INTEL SSDPE2KE016T8';          Mfg='Intel Corporation' },
    @{ Vendor='SOLIDIGM'; Product='SSDPF2KX076T1';    Rev='9CV1'; DeviceDesc='NVMe SOLIDIGM SSDPF2KX076T1';       FriendlyName='NVMe SOLIDIGM SSDPF2KX076T1';       Mfg='Solidigm' },
    @{ Vendor='KIOXIA  '; Product='KCD6XVUL3T84';     Rev='0104'; DeviceDesc='NVMe KIOXIA KCD6XVUL3T84';          FriendlyName='NVMe KIOXIA KCD6XVUL3T84';          Mfg='Kioxia Corporation' },
    @{ Vendor='KIOXIA  '; Product='KPM6VVUG1T60';     Rev='3P04'; DeviceDesc='KIOXIA KPM6VVUG1T60 SAS SCSI Disk Device'; FriendlyName='KIOXIA KPM6VVUG1T60 SAS SCSI Disk Device'; Mfg='Kioxia Corporation' },
    @{ Vendor='WDC     '; Product='WUH721818ALE6L4';  Rev='RE00'; DeviceDesc='WDC WUH721818ALE6L4 SCSI Disk Device';    FriendlyName='WDC WUH721818ALE6L4 SCSI Disk Device';    Mfg='Western Digital Corporation' },
    @{ Vendor='SEAGATE '; Product='ST18000NM000J';    Rev='SN02'; DeviceDesc='SEAGATE ST18000NM000J SCSI Disk Device'; FriendlyName='SEAGATE ST18000NM000J SCSI Disk Device'; Mfg='Seagate Technology LLC' },
    @{ Vendor='TOSHIBA '; Product='MG09ACA18TE';      Rev='0102'; DeviceDesc='TOSHIBA MG09ACA18TE SCSI Disk Device';   FriendlyName='TOSHIBA MG09ACA18TE SCSI Disk Device';   Mfg='Toshiba Corporation' },
    @{ Vendor='HGST    '; Product='HUH721010ALE604';  Rev='T2H0'; DeviceDesc='HGST HUH721010ALE604 SCSI Disk Device';  FriendlyName='HGST HUH721010ALE604 SCSI Disk Device';  Mfg='HGST, a Western Digital Company' },
    @{ Vendor='HP      '; Product='LOGICAL VOLUME';   Rev='6.88'; DeviceDesc='HP LOGICAL VOLUME SCSI Disk Device';      FriendlyName='HP LOGICAL VOLUME SCSI Disk Device';      Mfg='Hewlett Packard Enterprise' },
    @{ Vendor='DELL    '; Product='PERC H755 Front';  Rev='5.16'; DeviceDesc='DELL PERC H755 Front SCSI Disk Device';   FriendlyName='DELL PERC H755 Front SCSI Disk Device';   Mfg='Dell Inc.' },
    @{ Vendor='TOSHIBA '; Product='MG10ACA20TE';      Rev='0104'; DeviceDesc='TOSHIBA MG10ACA20TE SCSI Disk Device';   FriendlyName='TOSHIBA MG10ACA20TE SCSI Disk Device';   Mfg='Toshiba Corporation' }
)

function Read-Counter {
    param([string]$Name)
    $v = (Get-ItemProperty -Path $paramsKey -Name $Name -EA SilentlyContinue).$Name
    if ($null -eq $v) { return $null }
    return [int]$v
}

# ============================================================
#  1. Pre-check
# ============================================================
Write-Section 'Pre-check - driver + value handler + synth armed'
if (-not (Test-Path $paramsKey)) {
    Write-Err ("Parameters key ausente: {0}" -f $paramsKey)
    Write-Warn 'Rode 03-instalar-driver.bat + reboot antes desta harness.'
    exit 1
}

$armCallback = Read-Counter 'EnableRegCallback'
$armValRead  = Read-Counter 'EnableValueReadRewrite'
$armSynth    = Read-Counter 'EnableValueSynth'
Write-Info ("EnableRegCallback       = {0}" -f $armCallback)
Write-Info ("EnableValueReadRewrite  = {0}" -f $armValRead)
Write-Info ("EnableValueSynth        = {0}" -f $armSynth)

if ($armCallback -ne 1 -or $armValRead -ne 1 -or $armSynth -ne 1) {
    Write-Err 'Gates nao armados. Rode:'
    Write-Err '   .\scripts\track-d-arm.ps1 -Enable'
    Write-Err '   .\scripts\track-d-arm.ps1 -EnableValueRewrite'
    Write-Err '   .\scripts\track-d-arm.ps1 -EnableSynth'
    exit 1
}

# Le seed (hex ASCII) da Parameters\RegCallbackSeed
$seedHex = (Get-ItemProperty -Path $paramsKey -Name 'RegCallbackSeed' -EA SilentlyContinue).RegCallbackSeed
if (-not $seedHex) {
    Write-Err 'RegCallbackSeed ausente. -Enable deveria ter gravado.'
    exit 1
}
$seedBytes = [System.Text.Encoding]::ASCII.GetBytes($seedHex)
Write-Info ("Seed length (bytes)     = {0}" -f $seedBytes.Length)

# Copia rubinot_probe.exe (reg.exe renomeado, pra bater o filtro _strnicmp('rubinot',7))
if (-not (Test-Path $probeDir)) { New-Item -ItemType Directory -Path $probeDir | Out-Null }
if (-not (Test-Path $probePath)) {
    Copy-Item -Path $probeSrc -Destination $probePath -Force
}
Write-Ok "Probe pronto: $probePath"

# ============================================================
#  2. Descoberta - achar um parent SCSI existente na VM
# ============================================================
Write-Section 'Descoberta - listar Enum\SCSI\Disk&Ven_* na VM'
$scsiChildren = Get-ChildItem -Path $scsiRoot -EA SilentlyContinue |
    Where-Object { $_.PSChildName -like 'Disk&Ven_*' }
if (-not $scsiChildren) {
    Write-Err "Nenhum Disk&Ven_* filho de $scsiRoot"
    Write-Warn "VM sem disco SCSI virtual?  Nao ha como testar SCSI synth."
    exit 1
}
Write-Info ("SCSI disks encontrados: {0}" -f $scsiChildren.Count)
foreach ($c in $scsiChildren) { Write-Info ("   " + $c.PSChildName) }

# Pega o primeiro instance sob o primeiro Disk&Ven_ pra ser nosso parent-alvo
$diskKey = $scsiChildren[0]
$instances = Get-ChildItem -Path $diskKey.PSPath -EA SilentlyContinue
if (-not $instances) {
    Write-Err "$($diskKey.PSChildName) sem filhos-instance"
    exit 1
}
$targetInstance = $instances[0]
# CANONICAL kernel form of a registry path returned by CmCallbackGetKeyObjectID
# is `\REGISTRY\MACHINE\SYSTEM\ControlSetXXX\...` - uppercase `\REGISTRY\MACHINE\`
# and the REAL ControlSetXXX name (not the `CurrentControlSet` symbolic link).
# We resolve the real ControlSet via HKLM:\SYSTEM\Select.
$currentCs = (Get-ItemProperty -Path 'HKLM:\SYSTEM\Select' -Name 'Current' -EA SilentlyContinue).Current
if (-not $currentCs) { $currentCs = 1 }
$csName = ('ControlSet{0:D3}' -f [int]$currentCs)
$parentPath = "\REGISTRY\MACHINE\SYSTEM\{0}\Enum\SCSI\{1}\{2}" -f `
                $csName, $diskKey.PSChildName, $targetInstance.PSChildName
Write-Info ("Target parent path (canonical kernel form): {0}" -f $parentPath)

# ============================================================
#  3. Recipe PS -> row esperada
# ============================================================
Write-Section 'Recipe PS - calcular row esperada (mirror do TrackDInvSelectRowIndex)'
$expectedIndex = Get-RowIndex -ClassName 'SCSI' -ParentPath $parentPath `
                              -RowCount $SCSI_POOL.Count -SeedBytes $seedBytes
$expected = $SCSI_POOL[$expectedIndex]
Write-Info ("rowIndex esperado       = {0} / {1}" -f $expectedIndex, $SCSI_POOL.Count)
Write-Info ("Expected DeviceDesc     = " + $expected.DeviceDesc)
Write-Info ("Expected FriendlyName   = " + $expected.FriendlyName)
Write-Info ("Expected Mfg            = " + $expected.Mfg)

# ============================================================
#  4. Probe GATED - le DeviceDesc / FriendlyName / Mfg
# ============================================================
Write-Section 'Probe GATED (rubinot_probe.exe)'

function Query-ValueViaProbe {
    param([string]$Probe, [string]$KeyPath, [string]$ValueName)
    # regKey esperado pelo reg.exe: "HKLM\SYSTEM\..." sem o prefix \Registry\Machine\
    $reg = $KeyPath -replace '^\\Registry\\Machine\\', 'HKLM\'
    $raw = & $Probe query $reg /v $ValueName 2>&1 | Out-String
    # Formato esperado: "    DeviceDesc    REG_SZ    <value>"
    # (varia com locale, mas o nome do valor + REG_SZ + espacos + texto sao consistentes)
    $lines = $raw -split "`r?`n" | Where-Object { $_ -match "\s+$([regex]::Escape($ValueName))\s+REG_SZ\s+(.+)$" }
    if (-not $lines) { return $null }
    return ($Matches[1]).TrimEnd()
}

$parentReg = "\Registry\Machine\SYSTEM\CurrentControlSet\Enum\SCSI\{0}\{1}" -f `
                $diskKey.PSChildName, $targetInstance.PSChildName

$g_DevDesc  = Query-ValueViaProbe -Probe $probePath -KeyPath $parentReg -ValueName 'DeviceDesc'
$g_Friendly = Query-ValueViaProbe -Probe $probePath -KeyPath $parentReg -ValueName 'FriendlyName'
$g_Mfg      = Query-ValueViaProbe -Probe $probePath -KeyPath $parentReg -ValueName 'Mfg'

Write-Info ("GATED DeviceDesc        = " + ($g_DevDesc | Out-String).TrimEnd())
Write-Info ("GATED FriendlyName      = " + ($g_Friendly | Out-String).TrimEnd())
Write-Info ("GATED Mfg               = " + ($g_Mfg | Out-String).TrimEnd())

# ============================================================
#  5. Probe NON-GATED - reg.exe original (imagem nao-rubinot)
# ============================================================
Write-Section 'Probe NON-GATED (reg.exe)'
$n_DevDesc  = Query-ValueViaProbe -Probe $probeSrc -KeyPath $parentReg -ValueName 'DeviceDesc'
$n_Friendly = Query-ValueViaProbe -Probe $probeSrc -KeyPath $parentReg -ValueName 'FriendlyName'
$n_Mfg      = Query-ValueViaProbe -Probe $probeSrc -KeyPath $parentReg -ValueName 'Mfg'
Write-Info ("NON-GATED DeviceDesc    = " + ($n_DevDesc | Out-String).TrimEnd())
Write-Info ("NON-GATED FriendlyName  = " + ($n_Friendly | Out-String).TrimEnd())
Write-Info ("NON-GATED Mfg           = " + ($n_Mfg | Out-String).TrimEnd())

# ============================================================
#  6. Asserts HARD
#
#  Priority order (per v5.0.6 Phase 2 invariants):
#    HARD-1  cross-value coherence  (the primary v5.0.6 goal - all 3
#            gated values MUST come from the SAME pool row)
#    HARD-2  isolation              (non-gated reg.exe MUST see real values)
#    HARD-3  hive non-persistence   (Get-ItemProperty non-gated MUST see real)
#    HARD-4  PS mirror byte-exact   (PS recipe MUST compute same row as kernel)
#
#  HARD-4 is last because a PS-mirror drift in canonical path shape does NOT
#  invalidate the kernel's correctness - the first three prove that.
# ============================================================
Write-Section 'Asserts HARD - cross-value coherence + isolation + hive + PS mirror'
$hardFail = 0

# HARD-1: cross-value coherence - as 3 colunas vieram da MESMA row do pool.
# Estrategia: procurar a row cujo DeviceDesc === g_DevDesc.  Se achou, verifica
# se FriendlyName e Mfg da mesma row tambem batem.
$observedRow = $null
for ($i = 0; $i -lt $SCSI_POOL.Count; $i++) {
    if ($SCSI_POOL[$i].DeviceDesc -eq $g_DevDesc) { $observedRow = $i; break }
}
if ($null -eq $observedRow) {
    Write-Err ("HARD-FAIL[1]: gated DeviceDesc [{0}] nao casa com nenhuma row do pool SCSI (19 rows)" -f $g_DevDesc)
    $hardFail++
} else {
    $obs = $SCSI_POOL[$observedRow]
    Write-Info ("Observed pool row       = {0} / {1}" -f $observedRow, $SCSI_POOL.Count)
    Write-Info ("Observed DeviceDesc     = " + $obs.DeviceDesc)
    Write-Info ("Observed FriendlyName   = " + $obs.FriendlyName)
    Write-Info ("Observed Mfg            = " + $obs.Mfg)
    $devOk  = $g_DevDesc  -eq $obs.DeviceDesc
    $frOk   = $g_Friendly -eq $obs.FriendlyName
    $mfgOk  = $g_Mfg      -eq $obs.Mfg
    if ($devOk -and $frOk -and $mfgOk) {
        Write-Ok ("HARD-1 cross-value coherence: DeviceDesc + FriendlyName + Mfg all from pool row {0}" -f $observedRow)
    } else {
        if (-not $devOk)  { Write-Err ("HARD-FAIL[1a]: DeviceDesc mismatch vs observed row {0}"  -f $observedRow); $hardFail++ }
        if (-not $frOk)   { Write-Err ("HARD-FAIL[1b]: FriendlyName mismatch vs observed row {0}: gated=[{1}] pool=[{2}]" -f $observedRow, $g_Friendly, $obs.FriendlyName); $hardFail++ }
        if (-not $mfgOk)  { Write-Err ("HARD-FAIL[1c]: Mfg mismatch vs observed row {0}: gated=[{1}] pool=[{2}]" -f $observedRow, $g_Mfg, $obs.Mfg); $hardFail++ }
    }
}

# HARD-2: Isolation - NON-GATED devolve valores REAIS
$nonGatedIsReal = ($n_DevDesc  -notin ($SCSI_POOL | ForEach-Object { $_.DeviceDesc })) -or
                  ($n_Friendly -notin ($SCSI_POOL | ForEach-Object { $_.FriendlyName })) -or
                  ($n_Mfg      -notin ($SCSI_POOL | ForEach-Object { $_.Mfg }))
if (-not $nonGatedIsReal) {
    Write-Err "HARD-FAIL[2]: NON-GATED devolve strings do pool (deveria devolver real cleartext)"
    $hardFail++
} else {
    Write-Ok "HARD-2 isolation: NON-GATED devolve valores REAIS - gate discrimina corretamente"
}

# HARD-3: Hive nao mutado
$hive_DevDesc = (Get-ItemProperty -Path ("Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\SCSI\{0}\{1}" -f $diskKey.PSChildName, $targetInstance.PSChildName) -Name 'DeviceDesc' -EA SilentlyContinue).DeviceDesc
if ($hive_DevDesc -in ($SCSI_POOL | ForEach-Object { $_.DeviceDesc })) {
    Write-Err "HARD-FAIL[3]: hive foi mutado - Get-ItemProperty (nao-gated) ainda ve string do pool"
    $hardFail++
} else {
    Write-Ok ("HARD-3 hive non-persistence: Get-ItemProperty non-gated ve [{0}]" -f $hive_DevDesc)
}

# HARD-4: PS mirror byte-exact
if ($null -ne $observedRow -and $observedRow -eq $expectedIndex) {
    Write-Ok ("HARD-4 PS mirror: recipe computed row {0} matches observed row {1}" -f $expectedIndex, $observedRow)
} elseif ($null -ne $observedRow) {
    Write-Err ("HARD-FAIL[4]: PS mirror drift - recipe computed row {0} but kernel produced row {1}" -f $expectedIndex, $observedRow)
    Write-Warn "  Kernel is CORRECT (HARD-1 passed); harness FNV path canonicalization diverges."
    Write-Warn "  Investigate parent path shape returned by CmCallbackGetKeyObjectID vs harness parentPath variable."
    $hardFail++
}

# ============================================================
#  7. Counters (SOFT)
# ============================================================
Write-Section 'Counters (SOFT - flush async)'
$sc = @{
    SynthHit_SCSI_DeviceDesc   = Read-Counter 'CallbackSynthHit_SCSI_DeviceDesc'
    SynthHit_SCSI_FriendlyName = Read-Counter 'CallbackSynthHit_SCSI_FriendlyName'
    SynthHit_SCSI_Mfg          = Read-Counter 'CallbackSynthHit_SCSI_Mfg'
    SynthTypeMismatchBail      = Read-Counter 'CallbackSynthTypeMismatchBail'
    SynthOverflowBail          = Read-Counter 'CallbackSynthOverflowBail'
    SynthSizeSanityBail        = Read-Counter 'CallbackSynthSizeSanityBail'
    SynthInventoryMissBail     = Read-Counter 'CallbackSynthInventoryMissBail'
    HitCount                   = Read-Counter 'CallbackHitCount'
}
foreach ($k in $sc.Keys) { Write-Info ("   {0,-32} = {1}" -f $k, $sc[$k]) }

foreach ($k in 'SynthHit_SCSI_DeviceDesc','SynthHit_SCSI_FriendlyName','SynthHit_SCSI_Mfg') {
    if (-not $sc[$k] -or $sc[$k] -le 0) {
        Write-Warn ("SOFT: {0} = 0 (flush async pode nao ter rodado; HARD passou)" -f $k)
    } else {
        Write-Ok ("{0} > 0" -f $k)
    }
}
foreach ($k in 'SynthTypeMismatchBail','SynthOverflowBail','SynthSizeSanityBail','SynthInventoryMissBail') {
    if ($sc[$k] -and $sc[$k] -gt 0) {
        Write-Warn ("SOFT: {0} = {1} (>0; investigar se afetou coverage)" -f $k, $sc[$k])
    }
}

# ============================================================
#  8. Hot-toggle round-trip (SOFT)
# ============================================================
Write-Section 'Hot-toggle -DisableSynth / -EnableSynth (SOFT)'
$armScript = Join-Path $PSScriptRoot 'track-d-arm.ps1'
if (Test-Path $armScript) {
    & $armScript -DisableSynth | Out-Null
    Start-Sleep -Milliseconds 500
    $off_DevDesc = Query-ValueViaProbe -Probe $probePath -KeyPath $parentReg -ValueName 'DeviceDesc'
    if ($off_DevDesc -eq $expected.DeviceDesc) {
        Write-Warn "SOFT: -DisableSynth: gated ainda retorna synth (tap talvez nao propagou; nao HARD-FAIL)"
    } else {
        Write-Ok ("-DisableSynth: gated retorna [{0}] (real ou substring-only)" -f $off_DevDesc)
    }
    & $armScript -EnableSynth | Out-Null
    Start-Sleep -Milliseconds 500
    $on_DevDesc = Query-ValueViaProbe -Probe $probePath -KeyPath $parentReg -ValueName 'DeviceDesc'
    if ($on_DevDesc -eq $expected.DeviceDesc) {
        Write-Ok "-EnableSynth: gated volta a retornar synth (hot-toggle OK)"
    } else {
        Write-Warn ("SOFT: -EnableSynth: gated retorna [{0}] (tap talvez nao propagou; nao HARD-FAIL)" -f $on_DevDesc)
    }
} else {
    Write-Warn "SOFT: track-d-arm.ps1 nao encontrado - skip hot-toggle"
}

# ============================================================
#  Verdict
# ============================================================
Write-Section 'Verdict'
if ($hardFail -eq 0) {
    Write-Ok 'PASS - todos os HARD-CHECKS passaram'
    exit 0
} else {
    Write-Err ("HARD-FAIL - {0} check(s) falharam" -f $hardFail)
    exit 2
}
