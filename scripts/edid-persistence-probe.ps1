#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Testa se o valor EDID em HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\*\
    Device Parameters\EDID persiste atraves de um hot-plug de monitor.

.DESCRIPTION
    Q3 do triage v5.0.5 (docs/postmortem-v5-track-d/incident-v505-post-
    ban-triage.md secao 7). Determina se o Phase 2 EDID rewriter e
    defense-in-depth (registry duravel) OU load-bearing (PnP re-escreve
    a chave a cada evento de monitor).

    Uso (bare-metal, 2 passes):

      Pass 1 - baseline capture:
        .\edid-persistence-probe.ps1 -Baseline
        Salva SHA256 + primeiros 32 bytes de cada EDID em
        C:\hwtoolkit\edid-baseline.json.

      <trigger fisico: unplug + replug HDMI/DP cable de 1 monitor;
       OU sleep+wake do monitor; OU DXGI reset via app>

      Pass 2 - post-event comparison:
        .\edid-persistence-probe.ps1 -Compare
        Re-le EDIDs, compara SHA256 vs baseline.

    Outcomes:
      DURAVEL:  todos os EDIDs bateram byte-a-byte -> registry-side
                spoof (Level A userland write) persiste; Phase 2 EDID
                rewriter e defense-in-depth (nao load-bearing).
      RECRIADO: pelo menos 1 EDID mudou -> PnP re-escreveu o valor
                real; userland write foi perdido; Phase 2 EDID value
                rewriter (RegNtPostQueryValueKey handler) e OBRIGATORIO
                pra sobreviver hot-plug/sleep/DXGI reset.

    Ambos outcomes convergem em "Phase 2 EDID value handler e a defesa
    correta"; o teste so calibra se Level A registry write ja resolve
    (menos provavel) OU se so o kernel intercept resolve (provavel).

.EXAMPLE
    .\edid-persistence-probe.ps1 -Baseline
    # <unplug + replug HDMI>
    .\edid-persistence-probe.ps1 -Compare
#>

[CmdletBinding(DefaultParameterSetName = 'Baseline')]
param(
    [Parameter(ParameterSetName = 'Baseline')]
    [switch]$Baseline,

    [Parameter(ParameterSetName = 'Compare')]
    [switch]$Compare
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\_ui-common.ps1"

$baselinePath = 'C:\hwtoolkit\edid-baseline.json'
$displayRoot  = 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY'

function Get-EdidSnapshot {
    $snap = [ordered]@{}
    if (-not (Test-Path $displayRoot)) {
        Write-Warn 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY ausente (VM sem monitor emulado?)'
        return $snap
    }
    $monitors = Get-ChildItem $displayRoot -EA SilentlyContinue
    foreach ($mon in $monitors) {
        $instances = Get-ChildItem $mon.PSPath -EA SilentlyContinue
        foreach ($inst in $instances) {
            $devParams = Join-Path $inst.PSPath 'Device Parameters'
            $edid = (Get-ItemProperty -Path $devParams -Name EDID -EA SilentlyContinue).EDID
            if ($edid) {
                $key = "$($mon.PSChildName)\$($inst.PSChildName)"
                $sha = [System.BitConverter]::ToString(
                    [System.Security.Cryptography.SHA256]::Create().ComputeHash($edid)
                ).Replace('-', '').ToLower()
                # Primeiros 32 bytes (header + basic display parameters)
                # como hex string, pra ver visualmente o que mudou se algo.
                $head = ([System.BitConverter]::ToString($edid[0..31])).Replace('-', '')
                $snap[$key] = @{
                    Length  = $edid.Length
                    Sha256  = $sha
                    Head32  = $head
                }
            }
        }
    }
    return $snap
}

if ($PSCmdlet.ParameterSetName -eq 'Baseline') {
    Write-Section 'EDID baseline capture'
    $snap = Get-EdidSnapshot
    if ($snap.Count -eq 0) {
        Write-Err 'Nenhum EDID encontrado sob HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\*\*\Device Parameters'
        exit 1
    }
    foreach ($k in $snap.Keys) {
        Write-Info $k
        Write-Host ('        length : ' + $snap[$k].Length + ' bytes') -ForegroundColor DarkGray
        Write-Host ('        sha256 : ' + $snap[$k].Sha256) -ForegroundColor DarkGray
        Write-Host ('        head32 : ' + $snap[$k].Head32) -ForegroundColor DarkGray
    }
    $dir = Split-Path $baselinePath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }
    $snap | ConvertTo-Json -Depth 5 | Out-File -FilePath $baselinePath -Encoding utf8 -Force
    Write-OK ('Baseline salvo em ' + $baselinePath)
    Write-Info ''
    Write-Info 'Proximo passo: hot-plug fisico (unplug+replug HDMI/DP em 1 monitor,'
    Write-Info 'OU sleep+wake do monitor, OU trigger DXGI reset via app), depois:'
    Write-Info '  .\edid-persistence-probe.ps1 -Compare'
    exit 0
}

# ============================================================
#  Compare mode
# ============================================================
Write-Section 'EDID compare (baseline vs current)'

if (-not (Test-Path $baselinePath)) {
    Write-Err ('Baseline ausente: ' + $baselinePath)
    Write-Err 'Rode -Baseline primeiro, depois hot-plug, depois -Compare.'
    exit 1
}

$baselineRaw = Get-Content -Path $baselinePath -Raw | ConvertFrom-Json
# ConvertFrom-Json volta um PSCustomObject com propriedades por chave;
# reconstruir hashtable pra comparar contra Get-EdidSnapshot atual
$baselineSnap = [ordered]@{}
foreach ($p in $baselineRaw.PSObject.Properties) {
    $baselineSnap[$p.Name] = @{
        Length = [int]$p.Value.Length
        Sha256 = [string]$p.Value.Sha256
        Head32 = [string]$p.Value.Head32
    }
}

$current = Get-EdidSnapshot

if ($current.Count -eq 0) {
    Write-Err 'Nenhum EDID encontrado no compare pass (monitor removido?)'
    exit 1
}

# Comparar por chave (monitor\instance)
$allKeys = @()
foreach ($k in $baselineSnap.Keys) { $allKeys += $k }
foreach ($k in $current.Keys) { if ($allKeys -notcontains $k) { $allKeys += $k } }

$anyChanged = $false
$anyAdded = $false
$anyRemoved = $false

foreach ($k in $allKeys) {
    $b = $baselineSnap[$k]
    $c = $current[$k]

    if ($null -eq $b) {
        Write-Warn ($k + ' [ADDED post-hot-plug]')
        Write-Host ('        current sha256: ' + $c.Sha256) -ForegroundColor DarkGray
        $anyAdded = $true
        continue
    }
    if ($null -eq $c) {
        Write-Warn ($k + ' [REMOVED post-hot-plug]')
        Write-Host ('        baseline sha256: ' + $b.Sha256) -ForegroundColor DarkGray
        $anyRemoved = $true
        continue
    }

    if ($b.Sha256 -eq $c.Sha256) {
        Write-OK ($k + ' UNCHANGED (sha256 match)')
    } else {
        Write-Warn ($k + ' CHANGED (sha256 differ)')
        Write-Host ('        baseline sha256: ' + $b.Sha256) -ForegroundColor DarkGray
        Write-Host ('        current  sha256: ' + $c.Sha256) -ForegroundColor DarkGray
        Write-Host ('        baseline head32: ' + $b.Head32) -ForegroundColor DarkGray
        Write-Host ('        current  head32: ' + $c.Head32) -ForegroundColor DarkGray
        $anyChanged = $true
    }
}

Write-Section 'Verdict'

if ($anyChanged -or $anyRemoved -or $anyAdded) {
    Write-Warn 'RECRIADO: PnP re-escreveu pelo menos 1 EDID entre os dois passes.'
    Write-Info 'Implicacao: userland registry write (Level A) NAO persiste atraves'
    Write-Info 'de hot-plug/sleep/DXGI reset. Phase 2 EDID value handler (RegNt-'
    Write-Info 'PostQueryValueKey intercept com checksum recompute) e OBRIGATORIO'
    Write-Info 'pra spoofing durar. Ver docs/track-d-v505-value-handler-kickoff.md'
    Write-Info 'secao 5.3 pro contract do EDID rewriter (byte 127 checksum critical).'
    exit 2
} else {
    Write-OK 'DURAVEL: todos os EDIDs bateram byte-a-byte entre os passes.'
    Write-Info 'Implicacao: registry-side spoof (Level A userland write) persiste'
    Write-Info 'atraves do trigger fisico executado. Phase 2 EDID rewriter continua'
    Write-Info 'sendo defense-in-depth (recomendado mas nao load-bearing).'
    Write-Info ''
    Write-Info 'CAVEAT: este teste so exercitou UM tipo de evento. Rerodar com'
    Write-Info 'triggers diferentes (sleep S3 wake, hibernate S4 resume, DXGI'
    Write-Info 'device reset via app) da confidence maior. Se algum trigger'
    Write-Info 'recriar o EDID, o veredicto muda pra RECRIADO.'
    exit 0
}
