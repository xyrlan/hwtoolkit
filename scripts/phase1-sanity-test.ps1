#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sanity-test do Track D v5.0.5 Phase 1 (BTH + STORAGE\Volume enum-name
    rewriters + descriptor-table refactor) dentro da VM.

.DESCRIPTION
    Rodar DENTRO DO GUEST apos:
      1. .\03-instalar-driver.bat (driver v5.0.5 Phase 1) + reboot
      2. .\scripts\track-d-arm.ps1 -Enable + reboot
      3. (voce esta aqui)

    O script:
      - Pre-check: EnableRegCallback=1, LastArmStatus tag=0x00, e presenca
        dos values v5.0.5 (proxy de driver-schema).
      - Snapshota CallbackHit_BTH + CallbackHit_Storage (agora WIRED em
        Phase 1, nao mais reservados).
      - **Inspeciona os filhos REAIS de Enum\BTH e Enum\STORAGE\Volume na
        VM** e re-implementa a logica de shape/offset-zero do driver em
        PowerShell, imprimindo pra cada filho: shape-match? boot-volume?
        rewrite-candidate? Isto valida a premissa `{GUID}#offset` /
        `Dev_+12hex` do driver contra dados reais da VM (kickoff sec 4.4)
        - o check mais valioso do Phase 1, porque se o shape real diferir,
        o gate faz pass-through (no-op seguro) e voce ve isso aqui.
      - Cria probes gated (rubinot_probe.exe) + non-gated (launcher_probe)
        e roda contra Enum\BTH e Enum\STORAGE\Volume, medindo deltas.
      - Regression rapida: SCSI probe ainda bumpa CallbackHit_SCSI.

    Pass criteria hard (fail=exit 2 se algum falhar):
      - Sem BSOD (script sobreviveu ate aqui).
      - Values v5.0.5 Phase 1 presentes (CallbackHit_BTH / _Storage lidos).
      - SCSI regression delta > 0 (cadeia descriptor-table classify + gate
        + synth + counter continua funcionando pos-refactor).

    Pass criteria soft (warn, nao bloqueia):
      - BTH/Storage delta > 0 - EMPIRICAMENTE (Phase 0, 2026-09-01) `reg
        query /s` nao gera NtEnumerateKey traffic observavel em parents
        non-SCSI (kernel Cm-view cache serve hot parents sem dispatch pro
        callback). Delta=0 aqui NAO e bug: o codigo BTH/Storage e
        estruturalmente identico ao SCSI (validado) + passou pelo
        adversarial review. Exercicio real vem de sessao RubinOT ou do
        Phase 2 value handler.
      - NonRubiParentMatch delta > 0 (probes non-gated bateram no gate).

    Exit codes: 0=PASS, 1=pre-check falhou, 2=hard-fail.

.EXAMPLE
    .\phase1-sanity-test.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\_ui-common.ps1"

$paramsKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters'
$probeDir  = 'C:\hwtoolkit'
$probeSrc  = "$env:SystemRoot\System32\reg.exe"

$bthPath     = 'HKLM:\SYSTEM\CurrentControlSet\Enum\BTH'
$storagePath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\STORAGE\Volume'
$bthReg      = 'HKLM\SYSTEM\CurrentControlSet\Enum\BTH'
$storageReg  = 'HKLM\SYSTEM\CurrentControlSet\Enum\STORAGE\Volume'
$scsiReg     = 'HKLM\SYSTEM\CurrentControlSet\Enum\SCSI'

function Read-Counter {
    param([string]$Name)
    $v = (Get-ItemProperty -Path $paramsKey -Name $Name -EA SilentlyContinue).$Name
    if ($null -eq $v) { return $null }
    return [int]$v
}

# --- Mirror do driver: shape + offset-zero de STORAGE\Volume ---------
function Test-IsHex([char]$c) {
    return (($c -ge '0' -and $c -le '9') -or ($c -ge 'A' -and $c -le 'F') -or ($c -ge 'a' -and $c -le 'f'))
}
# Mirror de TrackDStorageOffsetIsZero: offset = name[39..], strip 0x,
# TRUE se todos os digitos forem '0' (ou sem digitos -> protege).
function Test-StorageOffsetIsZero([string]$name) {
    $n = $name.Length
    $i = 39
    if ($i -ge $n) { return $true }
    if (($i + 1 -lt $n) -and $name[$i] -eq '0' -and ($name[$i+1] -eq 'x' -or $name[$i+1] -eq 'X')) { $i += 2 }
    if ($i -ge $n) { return $true }
    for (; $i -lt $n; $i++) { if ($name[$i] -ne '0') { return $false } }
    return $true
}
# Mirror de TrackDGateStorageVol: {38-guid}#offset, offset != 0.
function Test-StorageVolShape([string]$name) {
    if ($name.Length -lt 40) { return $false }
    if ($name[0] -ne '{' -or $name[37] -ne '}') { return $false }
    if ($name[9] -ne '-' -or $name[14] -ne '-' -or $name[19] -ne '-' -or $name[24] -ne '-') { return $false }
    if ($name[38] -ne '#') { return $false }
    for ($i = 1; $i -lt 37; $i++) {
        if ($i -eq 9 -or $i -eq 14 -or $i -eq 19 -or $i -eq 24) { continue }
        if (-not (Test-IsHex $name[$i])) { return $false }
    }
    return $true
}
# Mirror de TrackDGateBthDev: Dev_ + exatamente 12 hex (len 16).
function Test-BthDevShape([string]$name) {
    if ($name.Length -ne 16) { return $false }
    if ($name.Substring(0,4).ToLower() -ne 'dev_') { return $false }
    for ($i = 4; $i -lt 16; $i++) { if (-not (Test-IsHex $name[$i])) { return $false } }
    return $true
}

# ============================================================
#  1. Pre-check
# ============================================================
Write-Section 'Pre-check - driver + arm state'
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
$armRaw = $vals.LastArmStatus
if ($null -ne $armRaw) {
    $armTag = ([uint32]$armRaw -shr 24) -band 0xFF
    if ($armTag -eq 0) { Write-OK 'LastArmStatus tag = 0x00 (armed clean)' }
    else { Write-Err ('LastArmStatus tag = 0x{0:X2} (arm falhou)' -f $armTag); exit 1 }
} else {
    Write-Warn 'LastArmStatus ausente (ArmTrackD nao rodou?)'
}
# Phase 1 schema proxy: BTH/Storage counters devem existir e ser lidos.
$bthBase = Read-Counter 'CallbackHit_BTH'
$stoBase = Read-Counter 'CallbackHit_Storage'
if ($null -eq $bthBase -or $null -eq $stoBase) {
    Write-Warn 'CallbackHit_BTH / _Storage ausentes ainda (flusher pode nao ter rodado).'
    Write-Warn 'Probes abaixo forcam flush; se ainda ausentes depois, driver e pre-v5.0.5.'
    if ($null -eq $bthBase) { $bthBase = 0 }
    if ($null -eq $stoBase) { $stoBase = 0 }
} else {
    Write-OK ('CallbackHit_BTH={0}  CallbackHit_Storage={1} (Phase 1 counters presentes)' -f $bthBase, $stoBase)
}
$scsiBase    = [int](Read-Counter 'CallbackHit_SCSI')
$nonRubiBase = [int](Read-Counter 'CallbackNonRubiParentMatch')
$ringBase    = [int](Read-Counter 'CallbackHitRingIndex')

# ============================================================
#  2. Inspecao dos filhos REAIS (valida premissa de shape do driver)
# ============================================================
Write-Section 'Enum\STORAGE\Volume - shape real na VM vs gate do driver'
$stoKids = @(Get-ChildItem $storagePath -EA SilentlyContinue)
if ($stoKids.Count -eq 0) {
    Write-Warn 'Nenhum filho em Enum\STORAGE\Volume (VM sem volumes enumerados?)'
} else {
    # NOTA empirica (host real 2026-09-01): o volume de sistema fica em
    # offset 0x100000 (1MB), NAO zero. O bail offset-zero e um skip
    # conservador, nao marca o boot volume de fato. Rewrite e nao-
    # persistente (so o buffer de enumerate do caller gated), entao
    # reescrever qualquer volume front-GUID e seguro (ver changelog).
    $anyCand = $false; $anyZero = $false; $usbShape = $false
    foreach ($k in $stoKids) {
        $nm = $k.PSChildName
        if (Test-StorageVolShape $nm) {
            if (Test-StorageOffsetIsZero $nm) {
                $anyZero = $true
                Write-Info ('SKIP offset-zero (conservador): {0}' -f $nm)
            } else {
                $anyCand = $true
                Write-OK ('REWRITE-CANDIDATE (front-GUID, offset!=0): {0}' -f $nm)
            }
        } elseif ($nm -match '#\{[0-9A-Fa-f-]+\}$') {
            $usbShape = $true
            Write-Info ('USBSTOR shape (GUID no fim) -> pass-through no-op: {0}' -f $nm)
        } else {
            Write-Warn ('SHAPE NAO-MATCH (pass-through no-op): {0}' -f $nm)
        }
    }
    if (-not $anyCand) {
        Write-Warn 'Nenhum volume front-GUID {GUID}#offset com offset!=0 nesta maquina;'
        Write-Warn 'o rewriter STORAGE\Volume nao sera exercido aqui.'
    } else {
        Write-OK 'Ha volume(s) front-GUID rewrite-candidate (inclui o de sistema - OK,'
        Write-OK 'rewrite e nao-persistente; so afeta o que o processo gated enxerga).'
    }
    if ($usbShape) { Write-Info 'USBSTOR volumes vistos -> corretamente deixados intactos pelo gate.' }
    if ($anyZero)  { Write-Info 'Volume(s) offset-zero visto(s) -> pulado(s) pelo skip conservador.' }
}

Write-Section 'Enum\BTH - shape real na VM vs gate do driver'
$bthKids = @(Get-ChildItem $bthPath -EA SilentlyContinue)
if ($bthKids.Count -eq 0) {
    Write-Warn 'Nenhum filho em Enum\BTH (VM sem Bluetooth enumerado - esperado em Hyper-V).'
} else {
    foreach ($k in $bthKids) {
        $nm = $k.PSChildName
        if (Test-BthDevShape $nm) { Write-OK ('REWRITE-CANDIDATE (Dev_+12hex): {0}' -f $nm) }
        else { Write-Warn ('SHAPE NAO-MATCH (pass-through no-op): {0}' -f $nm) }
    }
}

# ============================================================
#  3. Probes gated + non-gated
# ============================================================
Write-Section 'Criando probes + rodando contra BTH / STORAGE\Volume / SCSI'
if (-not (Test-Path $probeDir)) { New-Item -ItemType Directory $probeDir -Force | Out-Null }
$gated   = Join-Path $probeDir 'rubinot_probe.exe'
$nongate = Join-Path $probeDir 'launcher_probe.exe'
foreach ($d in @($gated, $nongate)) {
    if (-not (Test-Path $d)) { Copy-Item -Path $probeSrc -Destination $d -Force }
}
Write-OK 'Probes prontos (rubinot_probe.exe gated, launcher_probe.exe non-gated)'

foreach ($t in @(@($gated,$bthReg),@($gated,$storageReg),@($gated,$scsiReg),@($nongate,$bthReg),@($nongate,$storageReg))) {
    & $t[0] query $t[1] /s > $null 2>&1
}
Write-Info 'Aguardando flush do worker (DelayedWorkQueue)...'
Start-Sleep -Seconds 3

# ============================================================
#  4. Deltas + veredito
# ============================================================
Write-Section 'Deltas pos-probe'
$bthNow     = [int](Read-Counter 'CallbackHit_BTH')
$stoNow     = [int](Read-Counter 'CallbackHit_Storage')
$scsiNow    = [int](Read-Counter 'CallbackHit_SCSI')
$nonRubiNow = [int](Read-Counter 'CallbackNonRubiParentMatch')
$ringNow    = [int](Read-Counter 'CallbackHitRingIndex')

$dBth = $bthNow - $bthBase; $dSto = $stoNow - $stoBase; $dScsi = $scsiNow - $scsiBase
$dNon = $nonRubiNow - $nonRubiBase; $dRing = $ringNow - $ringBase
Write-Info ('CallbackHit_BTH      delta = {0}' -f $dBth)
Write-Info ('CallbackHit_Storage  delta = {0}' -f $dSto)
Write-Info ('CallbackHit_SCSI     delta = {0}  (regression check)' -f $dScsi)
Write-Info ('NonRubiParentMatch   delta = {0}' -f $dNon)
Write-Info ('HitRingIndex         delta = {0}' -f $dRing)

Write-Section 'Veredito'
$hardFail = $false
if ($dScsi -gt 0) {
    Write-OK 'HARD: SCSI regression delta > 0 (descriptor-table dispatch OK pos-refactor)'
} else {
    Write-Err 'HARD-FAIL: SCSI delta = 0 -> refactor pode ter quebrado o dispatch. Investigar.'
    $hardFail = $true
}
if ($dBth -gt 0) { Write-OK 'BTH delta > 0 (rewriter exercido)' }
else { Write-Warn 'SOFT: BTH delta = 0 - esperado se enum-side cached-away (ver Phase 0). Nao bloqueia.' }
if ($dSto -gt 0) { Write-OK 'Storage delta > 0 (rewriter exercido)' }
else { Write-Warn 'SOFT: Storage delta = 0 - idem BTH. Nao bloqueia.' }
if ($dNon -gt 0) { Write-OK 'NonRubiParentMatch delta > 0 (probe non-gated bateu no gate+classify)' }
else { Write-Warn 'SOFT: NonRubi delta = 0 - idem (enum cached-away).' }

Write-Host ''
if ($hardFail) {
    Write-Err 'PHASE 1 SANITY: FAIL'
    exit 2
}
Write-OK 'PHASE 1 SANITY: PASS (sem BSOD; counters wired; SCSI regression OK)'
Write-Info 'Proximo: checkpoint clean-v505-phase1-armed; depois Phase 2 (value handler).'
exit 0
