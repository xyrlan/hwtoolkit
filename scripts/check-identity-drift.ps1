#Requires -RunAsAdministrator
# ============================================================
#  check-identity-drift.ps1
#
#  Reads C:\ProgramData\.hwcfg\profile.json and compares each
#  identity-critical field against live registry / WMI / adapter
#  state. Exits 0 if all fields match, 4 if any drift.
#
#  Called by pre-test-checklist.bat step [7/N] (v5.0.7 P0.5
#  preview). Motivated by ban #6 (2026-09-02) where the real CPU
#  string "i5-11600K" leaked 16x because Level A userland CPU
#  spoof was never applied on the bare-metal setup. See
#  docs/postmortem-v5-track-d/incident-v506-phase2-ban-driver-
#  file-read.md sec 3.6.1 for the empirical evidence.
#
#  Fields verified:
#    - HKLM\HARDWARE\...\CentralProcessor\0\ProcessorNameString
#      vs profile.cpu.name_string
#    - $env:COMPUTERNAME vs profile.windows.computer_name
#    - HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
#      vs profile.windows.machine_guid
#    - Primary NIC MacAddress vs profile.network[0].mac
#    - HWToolkit\SpoofCPUUserland scheduled task exists
#    - C:\ProgramData\.hwcfg\emac-uuid file
#      vs profile.emac.persistent_uuid
#
#  Exit codes:
#    0  all fields match (or absent-but-unexpected = warning)
#    3  profile.json missing or unreadable (pre-condition fail)
#    4  one or more fields drift (fail-fast for a bare-metal test)
# ============================================================

$ErrorActionPreference = 'Continue'

$profilePath = 'C:\ProgramData\.hwcfg\profile.json'

if (-not (Test-Path $profilePath)) {
    Write-Host "    profile.json         : AUSENTE em $profilePath" -ForegroundColor Red
    Write-Host "    > Rode 00-gerar-profile.bat antes de qualquer teste." -ForegroundColor Red
    exit 3
}

try {
    $prof = Get-Content $profilePath -Raw -ErrorAction Stop | ConvertFrom-Json
} catch {
    Write-Host ("    profile.json         : ILEGIVEL (" + $_.Exception.Message + ")") -ForegroundColor Red
    exit 3
}

$drift = 0

function Check-Field {
    param(
        [string]$Label,
        [string]$Actual,
        [string]$Expected,
        [int]$MaxLen = 60
    )
    $act = if ($null -ne $Actual) { $Actual.Trim() } else { '(null)' }
    $exp = if ($null -ne $Expected) { $Expected.Trim() } else { '(null)' }
    $actShown = if ($act.Length -gt $MaxLen) { $act.Substring(0, $MaxLen) + '...' } else { $act }
    $expShown = if ($exp.Length -gt $MaxLen) { $exp.Substring(0, $MaxLen) + '...' } else { $exp }
    if ($act -ieq $exp) {
        Write-Host ("    {0,-21}: OK    ({1})" -f $Label, $actShown) -ForegroundColor Green
    } else {
        Write-Host ("    {0,-21}: DRIFT" -f $Label) -ForegroundColor Red
        Write-Host ("                             live   : {0}" -f $actShown) -ForegroundColor Red
        Write-Host ("                             expect : {0}" -f $expShown) -ForegroundColor Red
        $script:drift = $script:drift + 1
    }
}

# --- CPU ProcessorNameString (Level A userland OR Level C kernel) -----
$liveCpu = (Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' `
                -Name ProcessorNameString -ErrorAction SilentlyContinue).ProcessorNameString
$expectCpu = if ($prof.cpu -and $prof.cpu.name_string) { $prof.cpu.name_string } else { $null }
if ($expectCpu) {
    Check-Field 'ProcessorNameString' $liveCpu $expectCpu
} else {
    Write-Host "    ProcessorNameString  : WARN profile.cpu.name_string ausente (profile v<9)" -ForegroundColor Yellow
}

# --- ComputerName -----------------------------------------------------
$liveHost = $env:COMPUTERNAME
$expectHost = if ($prof.windows -and $prof.windows.computer_name) { $prof.windows.computer_name } else { $null }
if ($expectHost) {
    Check-Field 'ComputerName' $liveHost $expectHost
} else {
    Write-Host "    ComputerName         : WARN profile.windows.computer_name ausente" -ForegroundColor Yellow
}

# --- MachineGuid ------------------------------------------------------
$liveGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
                -Name MachineGuid -ErrorAction SilentlyContinue).MachineGuid
$expectGuid = if ($prof.windows -and $prof.windows.machine_guid) { $prof.windows.machine_guid } else { $null }
if ($expectGuid) {
    Check-Field 'MachineGuid' $liveGuid $expectGuid
} else {
    Write-Host "    MachineGuid          : WARN profile.windows.machine_guid ausente" -ForegroundColor Yellow
}

# --- Primary NIC MAC --------------------------------------------------
$liveMac = (Get-NetAdapter -Physical -ErrorAction SilentlyContinue `
            | Where-Object Status -eq 'Up' `
            | Sort-Object InterfaceIndex `
            | Select-Object -First 1).MacAddress
$expectMac = if ($prof.network -and $prof.network.Count -gt 0) { $prof.network[0].mac } else { $null }
if ($expectMac) {
    $lmNorm = if ($liveMac) { ($liveMac -replace '[:-]', '').ToUpper() } else { '' }
    $emNorm = ($expectMac -replace '[:-]', '').ToUpper()
    Check-Field 'PrimaryNIC MAC' $lmNorm $emNorm
} else {
    Write-Host "    PrimaryNIC MAC       : WARN profile.network[0].mac ausente" -ForegroundColor Yellow
}

# --- HWToolkit\SpoofCPUUserland task existence ------------------------
$taskState = try {
    (Get-ScheduledTask -TaskPath '\HWToolkit\' -TaskName 'SpoofCPUUserland' -ErrorAction Stop).State
} catch {
    'ABSENT'
}
if ($taskState -eq 'ABSENT') {
    Write-Host "    SpoofCPUUserland task: ABSENT (Level A userland CPU spoof not installed)" -ForegroundColor Red
    Write-Host "                             fix: .\04b-aplicar-hwid-emac.bat --skip-disk --skip-volume --skip-usb --skip-hid" -ForegroundColor Red
    $drift = $drift + 1
} else {
    Write-Host ("    SpoofCPUUserland task: {0}" -f $taskState) -ForegroundColor Green
}

# --- EMAC persistent uuid ---------------------------------------------
$emacPath = 'C:\ProgramData\.hwcfg\emac-uuid'
if (Test-Path $emacPath) {
    $liveEmac = (Get-Content $emacPath -Raw).Trim()
    $expectEmac = if ($prof.emac -and $prof.emac.persistent_uuid) { $prof.emac.persistent_uuid } else { $null }
    if ($expectEmac) {
        Check-Field 'emac persistent uuid' $liveEmac $expectEmac
    } else {
        Write-Host "    emac persistent uuid : WARN profile.emac.persistent_uuid ausente" -ForegroundColor Yellow
    }
} else {
    Write-Host "    emac persistent uuid : arquivo ausente em C:\ProgramData\.hwcfg\emac-uuid" -ForegroundColor Yellow
}

Write-Host ''
if ($drift -gt 0) {
    Write-Host ("    RESULT: {0} campo(s) em DRIFT vs profile.json." -f $drift) -ForegroundColor Red
    Write-Host "    > Se este e um teste bare-metal contra RubinOT, ABORTE." -ForegroundColor Red
    Write-Host "    > Ban #6 (2026-09-02) confirmou empiricamente que identity drift" -ForegroundColor Red
    Write-Host "      leva ao ban ANTES mesmo do driver-scan bater (postmortem sec 3.6.1)." -ForegroundColor Red
    Write-Host "    > Fix: .\04b-aplicar-hwid-emac.bat --skip-disk --skip-volume --skip-usb --skip-hid" -ForegroundColor Red
    Write-Host "    > Reboot + rode pre-test-checklist.bat de novo pra confirmar." -ForegroundColor Red
    exit 4
} else {
    Write-Host "    RESULT: identity spoof COMPLETO. Todos os campos casam profile.json." -ForegroundColor Green
    exit 0
}
