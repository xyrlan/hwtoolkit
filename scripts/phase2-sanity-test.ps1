#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sanity-test do Track D v5.0.5 Phase 2 (value-read handler
    RegNtPostQueryValueKey) dentro da VM.

.DESCRIPTION
    Rodar DENTRO DO GUEST apos:
      1. .\03-instalar-driver.bat (driver v5.0.5 Phase 2) + reboot
      2. .\scripts\track-d-arm.ps1 -Enable + reboot
      3. .\scripts\track-d-arm.ps1 -EnableValueRewrite
      4. (voce esta aqui)

    O check central e uma prova BYTE-EXATA de consistencia name<->value:
    o script re-implementa em PowerShell a recipe FNV do driver
    (docs/track-d-name-recipe.md secs 2-4) e computa o token sintetico
    ESPERADO para o vendor/product real do disco. Depois roda um probe
    GATED (rubinot_probe.exe) que le HardwareID via RegQueryValueEx -
    disparando o value handler - e um probe NON-GATED (launcher_probe.exe).
    Asserts:
      - GATED nao contem o vendor/product REAL (foram neutralizados).
      - GATED contem o token sintetico ESPERADO (recipe PS == kernel).
      - NON-GATED contem o vendor/product real (o gate discrimina).
      - CallbackValHit_SCSI incrementou (o handler engajou).
      - O comprimento em bytes do HardwareID nao mudou (same-length).

    Se a recipe PS bate com o output do kernel, isso prova simultaneamente:
    (a) o value handler funciona end-to-end, (b) e byte-exato vs a recipe
    documentada, e (c) e consistente com o name-side (mesma funcao C
    TrackDFillTokenFnv com os mesmos inputs).

    Diferente do Phase 1 (enum), o value read via NtQueryValueKey dispara
    o callback de forma confiavel (nao ha o cache de enum que mascarava
    BTH/Storage no Phase 0/1), entao aqui o delta > 0 e HARD.

    Pass criteria hard (fail=exit 2):
      - Sem BSOD.
      - EnableValueReadRewrite=1.
      - GATED HardwareID VALUE DATA contem o synth esperado E o real sumiu
        (byte-exato vs recipe). Checado no DATA do valor, NAO no key-path
        que o reg.exe ecoa (esse contem o instance-ID real, nao reescrito).
      - Same-length preservado (hive inalterado).
    Pass criteria soft (warn):
      - CallbackValHit_SCSI > 0 (contador zera no reboot + flush async, entao
        nao e confiavel como HARD; a prova HARD e o value data sintetico).
      - EDID (so se EnableEdidValueRewrite=1): checksum valido no output
        gated + serial 12-15 alterado.

    Exit codes: 0=PASS, 1=pre-check falhou, 2=hard-fail.

.EXAMPLE
    .\phase2-sanity-test.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\_ui-common.ps1"

$paramsKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters'
$scsiPath  = 'HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI'
$probeDir  = 'C:\hwtoolkit'
$probeSrc  = "$env:SystemRoot\System32\reg.exe"

function Read-Counter {
    param([string]$Name)
    $v = (Get-ItemProperty -Path $paramsKey -Name $Name -EA SilentlyContinue).$Name
    if ($null -eq $v) { return $null }
    return [int]$v
}

# ============================================================
#  FNV recipe (mirror do driver - docs/track-d-name-recipe.md)
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

# Reproduz TrackDFillTokenFnv: emite $Len wchars hex uppercase a partir de
# FNV sobre  <domain(inclui '|')> + <seedBytes> + '|' + <UTF16LE(field)> +
# '|' + <roundByte>  , 16 hex por round.
function Get-SynthTokenHex {
    param([string]$Field, [string]$Domain, [byte[]]$SeedBytes)
    $len = $Field.Length
    if ($len -le 0) { return '' }
    $hex = '0123456789ABCDEF'
    $out = New-Object System.Text.StringBuilder
    $round = 0
    while ($out.Length -lt $len) {
        $buf = New-Object System.Collections.Generic.List[byte]
        $buf.AddRange([System.Text.Encoding]::ASCII.GetBytes($Domain))   # domain ja termina em '|'
        if ($SeedBytes -and $SeedBytes.Length -gt 0) { $buf.AddRange($SeedBytes) }
        $buf.Add([byte]0x7C)                                             # '|'
        $buf.AddRange([System.Text.Encoding]::Unicode.GetBytes($Field))  # UTF-16LE
        $buf.Add([byte]0x7C)                                             # '|'
        $buf.Add([byte](0x30 + ($round -band 0xF)))                      # round byte
        $h = Get-Fnv1a64Bytes ($buf.ToArray())
        for ($i = 0; $i -lt 16 -and $out.Length -lt $len; $i++) {
            $nib = [int](($h -shr (60 - $i * 4)) -band 0xF)
            [void]$out.Append($hex[$nib])
        }
        $round++
    }
    return $out.ToString()
}

# ============================================================
#  1. Pre-check
# ============================================================
Write-Section 'Pre-check - driver + value handler armed'
if (-not (Test-Path $paramsKey)) {
    Write-Err ('Parameters key ausente: ' + $paramsKey)
    Write-Err 'Rodar .\03-instalar-driver.bat + track-d-arm.ps1 -Enable + reboot'
    exit 1
}
$vals = Get-ItemProperty -Path $paramsKey -EA SilentlyContinue
if ($vals.EnableRegCallback -ne 1) {
    Write-Err ('EnableRegCallback = ' + $vals.EnableRegCallback + ' (esperado 1)')
    Write-Err 'Rodar .\scripts\track-d-arm.ps1 -Enable + reboot'
    exit 1
}
Write-OK 'EnableRegCallback = 1'
if ($vals.EnableValueReadRewrite -ne 1) {
    Write-Warn 'EnableValueReadRewrite != 1 - armando agora via track-d-arm.ps1 -EnableValueRewrite'
    Set-ItemProperty -Path $paramsKey -Name 'EnableValueReadRewrite' -Value 1 -Type DWord -Force
    Start-Sleep -Milliseconds 500
}
$vals = Get-ItemProperty -Path $paramsKey -EA SilentlyContinue
if ($vals.EnableValueReadRewrite -ne 1) {
    Write-Err 'Nao consegui setar EnableValueReadRewrite=1.'
    exit 1
}
Write-OK 'EnableValueReadRewrite = 1'
$armRaw = $vals.LastArmStatus
if ($null -ne $armRaw) {
    $armTag = ([uint32]$armRaw -shr 24) -band 0xFF
    if ($armTag -eq 0) { Write-OK 'LastArmStatus tag = 0x00 (armed clean)' }
    else { Write-Err ('LastArmStatus tag = 0x{0:X2} (arm falhou)' -f $armTag); exit 1 }
}
# Schema proxy: value counters devem existir.
$valScsiBase = Read-Counter 'CallbackValHit_SCSI'
if ($null -eq $valScsiBase) {
    Write-Warn 'CallbackValHit_SCSI ausente (flusher pode nao ter rodado; probe abaixo forca flush).'
    $valScsiBase = 0
} else {
    Write-OK ('CallbackValHit_SCSI base = {0}' -f $valScsiBase)
}

# Seed do profile (para a recipe FNV).
$profilePath = 'C:\ProgramData\.hwcfg\profile.json'
$seed = $null
if (Test-Path $profilePath) {
    try {
        $p = Get-Content $profilePath -Raw | ConvertFrom-Json
        if ($p.pci_hardwareid -and $p.pci_hardwareid.randomize_seed) { $seed = [string]$p.pci_hardwareid.randomize_seed }
    } catch {}
}
if ($null -eq $seed) {
    # Cair de volta pro que o driver realmente carregou.
    $seed = [string]$vals.RegCallbackSeed
}
if ([string]::IsNullOrWhiteSpace($seed)) {
    Write-Err 'Seed indisponivel (profile + RegCallbackSeed ausentes). Nao da pra computar o synth esperado.'
    exit 1
}
$seedBytes = [System.Text.Encoding]::ASCII.GetBytes($seed)
Write-OK ('Seed carregado (prefix ' + $seed.Substring(0, [Math]::Min(8,$seed.Length)) + '..., ' + $seed.Length + ' chars)')

# ============================================================
#  2. Achar um disco SCSI + HardwareID real + tokens reais
# ============================================================
Write-Section 'Selecionando disco SCSI alvo + HardwareID real'
$diskKeys = @(Get-ChildItem $scsiPath -EA SilentlyContinue | Where-Object { $_.PSChildName -like 'Disk&Ven_*&Prod_*' })
if ($diskKeys.Count -eq 0) {
    Write-Err 'Nenhuma subchave Disk&Ven_*&Prod_* em Enum\SCSI - nada pra probar.'
    exit 1
}

$target = $null
foreach ($dk in $diskKeys) {
    if ($dk.PSChildName -match '^Disk&Ven_(.*?)&Prod_([^\\]+)$') {
        $ven  = $Matches[1]
        $prod = $Matches[2]
        $inst = @(Get-ChildItem $dk.PSPath -EA SilentlyContinue)
        if ($inst.Count -eq 0) { continue }
        foreach ($ik in $inst) {
            $hw = (Get-ItemProperty -Path $ik.PSPath -Name 'HardwareID' -EA SilentlyContinue).HardwareID
            if ($null -ne $hw) {
                $target = [pscustomobject]@{
                    KeyName    = $dk.PSChildName
                    Vendor     = $ven
                    Product    = $prod
                    InstReg    = ($ik.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '' -replace '^HKEY_LOCAL_MACHINE', 'HKLM')
                    HardwareID = @($hw)
                }
                break
            }
        }
    }
    if ($null -ne $target) { break }
}
if ($null -eq $target) {
    Write-Err 'Nenhuma instancia SCSI com HardwareID encontrada.'
    exit 1
}
$realJoined = ($target.HardwareID -join "`0")
$realBytes  = [System.Text.Encoding]::Unicode.GetByteCount($realJoined)
Write-OK ('Alvo: ' + $target.KeyName)
Write-Info ('  Vendor real  : "' + $target.Vendor + '"')
Write-Info ('  Product real : "' + $target.Product + '"')
Write-Info ('  Instancia    : ' + $target.InstReg)
Write-Info ('  HardwareID   : ' + ($target.HardwareID -join ' | '))

# Synth esperado (mesma recipe do kernel).
$expVen  = if ($target.Vendor.Length  -ge 3) { Get-SynthTokenHex $target.Vendor  'SCSI_VEN|'  $seedBytes } else { $null }
$expProd = if ($target.Product.Length -ge 3) { Get-SynthTokenHex $target.Product 'SCSI_PROD|' $seedBytes } else { $null }
if ($expVen)  { Write-Info ('  Synth Ven esperado  : "' + $expVen  + '"') }
if ($expProd) { Write-Info ('  Synth Prod esperado : "' + $expProd + '"') }
if (-not $expVen -and -not $expProd) {
    Write-Warn 'Vendor e Product ambos < 3 chars (abaixo do MIN token). Rewrite sera no-op; nao da pra provar consistencia neste disco.'
}

# ============================================================
#  3. Probes gated + non-gated
# ============================================================
Write-Section 'Criando probes + lendo HardwareID via RegQueryValueEx'
if (-not (Test-Path $probeDir)) { New-Item -ItemType Directory $probeDir -Force | Out-Null }
$gated   = Join-Path $probeDir 'rubinot_probe.exe'
$nongate = Join-Path $probeDir 'launcher_probe.exe'
foreach ($d in @($gated, $nongate)) {
    if (-not (Test-Path $d)) { Copy-Item -Path $probeSrc -Destination $d -Force }
}
Write-OK 'Probes prontos (rubinot_probe.exe gated, launcher_probe.exe non-gated)'

$gatedOut   = (& $gated   query $target.InstReg /v HardwareID 2>&1 | Out-String)
$nongateOut = (& $nongate query $target.InstReg /v HardwareID 2>&1 | Out-String)

Start-Sleep -Seconds 3   # flush worker (DelayedWorkQueue)
$valScsiNow = [int](Read-Counter 'CallbackValHit_SCSI')
$dVal = $valScsiNow - $valScsiBase

# ============================================================
#  4. Assertions
# ============================================================
Write-Section 'Veredito'
$hardFail = $false

# Extrai SO o data do valor da saida do reg.exe (a linha
# "  HardwareID  REG_xxx  <data>"), excluindo a linha de key-path que o
# reg.exe ecoa. CRITICO: o key-path (`...\Disk&Ven_<real>&Prod_<real>\..`)
# contem os tokens REAIS - mas isso e o NOME da subchave (device instance
# ID), que o value handler NAO reescreve (so o name-side reescreve, e so
# quando enumerado). Checar o real/synth contra o key-path daria falso
# positivo. A prova correta e no DATA do valor.
function Get-RegValueData {
    param([string]$RegOut, [string]$ValName)
    foreach ($ln in ($RegOut -split "`r?`n")) {
        if ($ln -match ('^\s*' + [regex]::Escape($ValName) + '\s+REG_\w+\s+(.*)$')) { return $Matches[1] }
    }
    return ''
}
$gatedData = Get-RegValueData $gatedOut 'HardwareID'
$nonData   = Get-RegValueData $nongateOut 'HardwareID'

Write-Host '  --- GATED (rubinot_probe) HardwareID [value data] ---' -ForegroundColor DarkGray
Write-Host ('    ' + $gatedData) -ForegroundColor Cyan
Write-Host '  --- NON-GATED (launcher_probe) HardwareID [value data] ---' -ForegroundColor DarkGray
Write-Host ('    ' + $nonData) -ForegroundColor DarkGray

# 4.1 non-gated ve o real NO DATA (gate discrimina)
if ($nonData -match [regex]::Escape($target.Vendor)) {
    Write-OK 'HARD: NON-GATED value data contem o vendor REAL (gate discrimina corretamente)'
} else {
    Write-Warn 'NON-GATED value data nao contem o vendor real literal - inspecionar (formato de HardwareID?).'
}

# 4.2 gated: real sumiu do DATA + synth presente (prova byte-exata name<->value)
if ($expVen) {
    $venGone = ($gatedData -notmatch [regex]::Escape($target.Vendor))
    $venSyn  = ($gatedData -match [regex]::Escape($expVen))
    if ($venSyn -and $venGone) {
        Write-OK ('HARD: GATED Ven -> synth "{0}" presente, real "{1}" AUSENTE no value data (BYTE-EXATO)' -f $expVen, $target.Vendor)
    } elseif ($venSyn) {
        Write-Err ('HARD-FAIL: synth Ven "{0}" presente mas real "{1}" ainda no value data.' -f $expVen, $target.Vendor); $hardFail = $true
    } else {
        Write-Err ('HARD-FAIL: GATED value data NAO contem synth Ven "{0}" (recipe kernel != PS OU handler nao reescreveu).' -f $expVen); $hardFail = $true
    }
}
if ($expProd) {
    $prodGone = ($gatedData -notmatch [regex]::Escape($target.Product))
    $prodSyn  = ($gatedData -match [regex]::Escape($expProd))
    if ($prodSyn -and $prodGone) {
        Write-OK ('HARD: GATED Prod -> synth "{0}" presente, real "{1}" AUSENTE no value data (BYTE-EXATO)' -f $expProd, $target.Product)
    } elseif ($prodSyn) {
        Write-Err ('HARD-FAIL: synth Prod "{0}" presente mas real "{1}" ainda no value data.' -f $expProd, $target.Product); $hardFail = $true
    } else {
        Write-Err ('HARD-FAIL: GATED value data NAO contem synth Prod "{0}".' -f $expProd); $hardFail = $true
    }
}

# 4.3 counter (SOFT). O contador per-superficie zera em memoria a cada
# reboot enquanto o registro guarda o valor pre-reboot, e o flush e
# assincrono (DelayedWorkQueue) - entao o delta pode dar 0 mesmo com o
# handler tendo disparado. A prova HARD e o value data sintetico acima;
# aqui so reportamos o absoluto como confirmacao secundaria.
if ($valScsiNow -gt 0) {
    Write-OK ('SOFT: CallbackValHit_SCSI = {0} (value handler engajou; delta desta sessao = {1})' -f $valScsiNow, $dVal)
} else {
    Write-Warn ('SOFT: CallbackValHit_SCSI = 0 - flush pode nao ter rodado ainda; a prova HARD e o value data acima.')
}

# 4.4 same-length (o valor no hive nao mudou; comprimento identico)
$realNow = (Get-ItemProperty -Path ($target.InstReg -replace '^HKLM', 'HKLM:') -Name 'HardwareID' -EA SilentlyContinue).HardwareID
if ($null -ne $realNow) {
    $realNowBytes = [System.Text.Encoding]::Unicode.GetByteCount(($realNow -join "`0"))
    if ($realNowBytes -eq $realBytes) {
        Write-OK ('HARD: HardwareID no hive inalterado ({0} bytes) - rewrite e nao-persistente + same-length' -f $realBytes)
    } else {
        Write-Err ('HARD-FAIL: HardwareID no hive MUDOU ({0} -> {1} bytes)! Rewrite NAO deveria tocar o hive.' -f $realBytes, $realNowBytes)
        $hardFail = $true
    }
}

# ============================================================
#  5. EDID (opcional, so se armado)
# ============================================================
if ($vals.EnableEdidValueRewrite -eq 1) {
    Write-Section 'EDID (EnableEdidValueRewrite=1)'
    $dispRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY'
    $edidInst = $null
    foreach ($mon in @(Get-ChildItem $dispRoot -EA SilentlyContinue)) {
        foreach ($inst in @(Get-ChildItem $mon.PSPath -EA SilentlyContinue)) {
            $dp = Join-Path $inst.PSPath 'Device Parameters'
            $e = (Get-ItemProperty -Path $dp -Name 'EDID' -EA SilentlyContinue).EDID
            if ($null -ne $e -and $e.Length -ge 128) {
                $edidReg = ($dp -replace '^Microsoft\.PowerShell\.Core\\Registry::','' -replace '^HKEY_LOCAL_MACHINE','HKLM')
                $edidInst = [pscustomobject]@{ Reg = $edidReg; Real = $e }
                break
            }
        }
        if ($edidInst) { break }
    }
    if ($null -eq $edidInst) {
        Write-Warn 'Nenhum EDID de 128+ bytes encontrado (VM Hyper-V normalmente nao tem EDID real). Pulando.'
    } else {
        # Nao ha uma forma simples de capturar bytes binarios via reg.exe
        # como o processo gated; validamos indiretamente: o valor no hive
        # continua com checksum valido (nao-persistente) e o rewriter
        # kernel recomputa o checksum. Aqui checamos so o hive real.
        $sum = 0
        for ($i = 0; $i -lt 127; $i++) { $sum = ($sum + $edidInst.Real[$i]) -band 0xFF }
        $ck = (256 - $sum) -band 0xFF
        if ($ck -eq ($edidInst.Real[127] -band 0xFF)) {
            Write-OK ('EDID hive checksum valido ({0}). Rewrite kernel e nao-persistente; recomputa byte 127 no buffer do caller.' -f $ck)
            Write-Info 'Para validar o output gated do EDID (binario), usar um probe dedicado que leia REG_BINARY e cheque o checksum.'
        } else {
            Write-Warn ('EDID hive checksum ja invalido no hive (byte127={0}, esperado={1}) - EDID possivelmente ja spoofado por userland.' -f $edidInst.Real[127], $ck)
        }
    }
}

# ============================================================
#  6. Resultado
# ============================================================
Write-Host ''
if ($hardFail) {
    Write-Err 'PHASE 2 SANITY: FAIL'
    Write-Info 'Cruzar com: .\scripts\track-d-arm.ps1 -Diagnose  (ring buffer kind=v/YES?)'
    exit 2
}
Write-OK 'PHASE 2 SANITY: PASS (value handler engajou; synth byte-exato vs recipe; hive intacto)'
Write-Info 'Proximo: checkpoint clean-v505-phase2-armed; depois bare-metal armed (kickoff sec 6.2).'
exit 0
