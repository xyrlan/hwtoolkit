#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Aplica identificadores Windows (MachineGuid, ComputerName, TCP/IP Hostname)
    do profile.json para o registry.

.DESCRIPTION
    Reconhecimento v2 confirmou que o cliente EMAC user-mode le, via
    RegQueryValueEx, tres identificadores "Windows-level" alem de PCI/SMBIOS/etc:

      1. HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
         (padrao "Buffer Overflow" seguido de "Success" = duas leituras,
          primeira sem buffer pra medir tamanho, segunda pra pegar o valor.)

      2. HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\ComputerName
         (nome NetBIOS ativo. O cliente NAO le a variante "ComputerName\ComputerName"
          [pending value], mas mantemos os dois em sync pra nao gerar
          warning do Windows nem dessincronia depois do reboot.)

      3. HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Hostname
         (hostname TCP/IP; costuma refletir ComputerName mas e uma chave separada.)

    Estrategia:
      - Escrita direta em registry (sem Rename-Computer). Rename-Computer
        dispara eventos AD/DNS, atualiza SPNs, e em maquinas com dominio
        acionaria trafego de rede novo - qualquer heuristica de anti-VM
        poderia usar isso pra flag. Escrita direta e silenciosa.

      - Backup atomico em C:\ProgramData\.hwcfg\windows-id-backup.json
        criado no PRIMEIRO -Apply. Se o backup ja existe, nao sobrescreve
        (preserva os valores originais da maquina). -Restore le esse backup.

      - Reboot recomendado apos -Apply. ComputerName tem cache em varios
        subsistemas (SMB, RPC, Netlogon, DNS resolver) que so re-leem no
        boot. MachineGuid e Hostname sao lidos on-demand pelo EMAC entao
        valem imediatamente pra proximo start do cliente.

    Sanity:
      - profile.version >= 8 (v7 nao tinha windows.machine_guid).
      - computer_name <= 15 chars (limite NetBIOS).
      - machine_guid no formato UUID 8-4-4-4-12 sem chaves.

.PARAMETER Apply
    Le profile, salva backup (uma vez), escreve os tres valores. Default.

.PARAMETER Restore
    Le C:\ProgramData\.hwcfg\windows-id-backup.json e restaura os valores
    originais. Falha se o backup nao existir.

.PARAMETER Show
    Mostra os valores atuais no registry + valores do profile + backup, sem escrever.
#>

[CmdletBinding(DefaultParameterSetName='Apply')]
param(
    [Parameter(ParameterSetName='Apply')]   [switch]$Apply,
    [Parameter(ParameterSetName='Restore')] [switch]$Restore,
    [Parameter(ParameterSetName='Show')]    [switch]$Show
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"
$backupPath  = "C:\ProgramData\.hwcfg\windows-id-backup.json"

# Caminhos de registry (formato PS provider)
$cryptoPath         = "HKLM:\SOFTWARE\Microsoft\Cryptography"
$computerNamePath   = "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
$activeCompNamePath = "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
$tcpipParamsPath    = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

# ============================================================
#  HELPERS
# ============================================================

function Get-RegString {
    param([string]$Path, [string]$Name)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return [string]($v.$Name)
    } catch {
        return $null
    }
}

function Set-RegString {
    param([string]$Path, [string]$Name, [string]$Value)
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type String -Force
}

function Read-CurrentValues {
    return [pscustomobject]@{
        MachineGuid         = Get-RegString $cryptoPath         "MachineGuid"
        ComputerName        = Get-RegString $computerNamePath   "ComputerName"
        ActiveComputerName  = Get-RegString $activeCompNamePath "ComputerName"
        TcpipHostname       = Get-RegString $tcpipParamsPath    "Hostname"
        TcpipNvHostname     = Get-RegString $tcpipParamsPath    "NV Hostname"
    }
}

function Write-Header {
    Write-Host ""
    Write-Host "=== Spoof Windows-level identifiers ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  MachineGuid, ComputerName, TCP/IP Hostname" -ForegroundColor Gray
    Write-Host "  Reconhecimento v2: os 3 sao lidos por EMAC user-mode via registry." -ForegroundColor Gray
    Write-Host ""
}

# ============================================================
#  CARREGAR PROFILE
# ============================================================
Write-Header

if (-not (Test-Path $profilePath)) {
    Write-Err "Profile nao encontrado em $profilePath"
    Write-Err "Rode primeiro:  .\generate-profile.ps1 -Generate"
    exit 1
}

$prof = Get-Content $profilePath -Raw | ConvertFrom-Json

# Guard de versao. Profile v<8 nao tem windows.machine_guid e nem windows.computer_name.
if (-not $prof.PSObject.Properties['version']) {
    Write-Warn "profile sem campo 'version' - recomendado v8+."
} else {
    $pv = [int]$prof.version
    if ($pv -lt 8) {
        Write-Warn ("profile v{0} detectado, recomendado v8+." -f $pv)
        Write-Warn "Regenere com .\generate-profile.ps1 -Generate pra popular windows.machine_guid/computer_name/tcpip_hostname."
    }
}

if (-not $prof.PSObject.Properties['windows']) {
    Write-Err "profile.windows ausente. Regenere o profile (v8+) antes de rodar este script."
    exit 1
}

$win = $prof.windows

# ============================================================
#  DISPATCH: Show
# ============================================================
$mode = $PSCmdlet.ParameterSetName
if (-not ($Apply -or $Restore -or $Show)) { $mode = 'Apply' }

if ($mode -eq 'Show') {
    Write-Section "Registry atual"
    $cur = Read-CurrentValues
    Write-Info ("MachineGuid                     : {0}" -f $cur.MachineGuid)
    Write-Info ("ComputerName (pending)          : {0}" -f $cur.ComputerName)
    Write-Info ("ActiveComputerName              : {0}" -f $cur.ActiveComputerName)
    Write-Info ("Tcpip\Parameters Hostname       : {0}" -f $cur.TcpipHostname)
    Write-Info ("Tcpip\Parameters NV Hostname    : {0}" -f $cur.TcpipNvHostname)

    Write-Section "Profile alvo"
    $mgProf = if ($win.PSObject.Properties['machine_guid'])   { [string]$win.machine_guid }   else { "<ausente>" }
    $cnProf = if ($win.PSObject.Properties['computer_name'])  { [string]$win.computer_name }  else { "<ausente>" }
    $hnProf = if ($win.PSObject.Properties['tcpip_hostname']) { [string]$win.tcpip_hostname } else { "<ausente>" }
    Write-Info ("windows.machine_guid            : {0}" -f $mgProf)
    Write-Info ("windows.computer_name           : {0}" -f $cnProf)
    Write-Info ("windows.tcpip_hostname          : {0}" -f $hnProf)

    Write-Section "Backup"
    if (Test-Path $backupPath) {
        Write-OK ("Existe: {0}" -f $backupPath)
        $bk = Get-Content $backupPath -Raw | ConvertFrom-Json
        Write-Info ("  MachineGuid original     : {0}" -f $bk.MachineGuid)
        Write-Info ("  ComputerName original    : {0}" -f $bk.ActiveComputerName)
        Write-Info ("  Hostname original        : {0}" -f $bk.TcpipHostname)
    } else {
        Write-Warn "Sem backup ainda (primeiro -Apply cria)."
    }

    Write-Host ""
    Write-Host "=== Fim ===" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# ============================================================
#  DISPATCH: Restore
# ============================================================
if ($mode -eq 'Restore') {
    Write-Section "Restore (le windows-id-backup.json)"
    if (-not (Test-Path $backupPath)) {
        Write-Err "Backup nao encontrado em $backupPath"
        Write-Err "Nao ha o que restaurar (nunca foi feito -Apply nesta maquina?)."
        exit 1
    }

    $bk = Get-Content $backupPath -Raw | ConvertFrom-Json

    if ($bk.MachineGuid) {
        $old = Get-RegString $cryptoPath "MachineGuid"
        Set-RegString $cryptoPath "MachineGuid" $bk.MachineGuid
        Write-OK ("MachineGuid: {0} -> {1}" -f $old, $bk.MachineGuid)
    } else {
        Write-Warn "Backup sem MachineGuid, pulando."
    }

    if ($bk.ComputerName) {
        $old = Get-RegString $computerNamePath "ComputerName"
        Set-RegString $computerNamePath "ComputerName" $bk.ComputerName
        Write-OK ("ComputerName (pending): {0} -> {1}" -f $old, $bk.ComputerName)
    }
    if ($bk.ActiveComputerName) {
        $old = Get-RegString $activeCompNamePath "ComputerName"
        Set-RegString $activeCompNamePath "ComputerName" $bk.ActiveComputerName
        Write-OK ("ActiveComputerName: {0} -> {1}" -f $old, $bk.ActiveComputerName)
    }

    if ($bk.TcpipHostname) {
        $old = Get-RegString $tcpipParamsPath "Hostname"
        Set-RegString $tcpipParamsPath "Hostname" $bk.TcpipHostname
        Write-OK ("Tcpip Hostname: {0} -> {1}" -f $old, $bk.TcpipHostname)
    }
    if ($bk.TcpipNvHostname) {
        $old = Get-RegString $tcpipParamsPath "NV Hostname"
        Set-RegString $tcpipParamsPath "NV Hostname" $bk.TcpipNvHostname
        Write-OK ("Tcpip NV Hostname: {0} -> {1}" -f $old, $bk.TcpipNvHostname)
    }

    Write-Host ""
    Write-Warn "Reboot recomendado pra ComputerName voltar em todos os subsistemas cacheados."
    Write-Host ""
    Write-Host "=== Fim ===" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# ============================================================
#  DISPATCH: Apply (default)
# ============================================================
Write-Section "Apply (escreve profile.windows.* no registry)"

# ------------------------------------------------------------
# Guard CRITICO: refuse em maquinas joined-to-domain ou Azure AD.
# Escrever ComputerName direto no registry (sem Rename-Computer)
# NAO atualiza o machine account no DC. Apos ~30 dias, Netlogon
# rotaciona a senha, DC ainda tem OLD_NAME$, auth quebra, usuario
# perde acesso. Em maquinas corporativas sem local admin backup,
# equivale a lockout total.
# ------------------------------------------------------------
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($cs.PartOfDomain) {
        Write-Err ("Maquina esta joined-to-domain (Domain='{0}')." -f $cs.Domain)
        Write-Err "Reescrever ComputerName sem Rename-Computer quebra trust com o DC."
        Write-Err "RECUSANDO por seguranca. Rode este script apenas em maquinas workgroup."
        exit 1
    }
} catch {
    Write-Warn ("Nao consegui verificar PartOfDomain: " + $_.Exception.Message)
    Write-Warn "Continuando, mas se esta maquina esta em dominio o resultado sera trust broken."
}

try {
    $dsreg = & dsregcmd /status 2>$null
    if ($LASTEXITCODE -eq 0 -and $dsreg) {
        $dsregText = ($dsreg -join "`n")
        if ($dsregText -match 'AzureAdJoined\s*:\s*YES' -or $dsregText -match 'EnterpriseJoined\s*:\s*YES') {
            Write-Err "Maquina esta Azure AD / Entra joined."
            Write-Err "Reescrever ComputerName sem sync com AAD quebra device identity."
            Write-Err "RECUSANDO por seguranca."
            exit 1
        }
        if ($dsregText -match 'DomainJoined\s*:\s*YES') {
            Write-Err "dsregcmd reporta DomainJoined=YES."
            Write-Err "RECUSANDO por seguranca."
            exit 1
        }
    }
} catch {
    # dsregcmd nao disponivel (Windows Home, versao antiga) - ok seguir
}

# ------------------------------------------------------------
# Sanity dos campos do profile
# ------------------------------------------------------------
$missing = @()
foreach ($n in @('machine_guid','computer_name','tcpip_hostname')) {
    if (-not $win.PSObject.Properties[$n] -or [string]::IsNullOrWhiteSpace([string]$win.$n)) {
        $missing += $n
    }
}
if ($missing.Count -gt 0) {
    Write-Err ("profile.windows falta campo(s): {0}" -f ($missing -join ', '))
    Write-Err "Regenere com .\generate-profile.ps1 -Generate (v8+)."
    exit 1
}

$newMachineGuid   = [string]$win.machine_guid
$newComputerName  = [string]$win.computer_name
$newTcpipHostname = [string]$win.tcpip_hostname

# machine_guid: 8-4-4-4-12 hex, SEM chaves. E o formato que o Windows grava
# em SOFTWARE\Microsoft\Cryptography\MachineGuid (REG_SZ, minusculas, sem {}).
if ($newMachineGuid -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Err "windows.machine_guid nao esta no formato UUID (8-4-4-4-12, sem chaves)."
    Write-Err ("Valor: '{0}'" -f $newMachineGuid)
    exit 1
}

# computer_name: limite NetBIOS = 15 chars. Rejeita ' ' e chars proibidos.
if ($newComputerName.Length -gt 15) {
    Write-Err ("windows.computer_name tem {0} chars > 15 (limite NetBIOS)." -f $newComputerName.Length)
    Write-Err ("Valor: '{0}'" -f $newComputerName)
    exit 1
}
if ($newComputerName -match '[\\/:*?"<>|\s]') {
    Write-Err ("windows.computer_name contem char invalido pra NetBIOS: '{0}'" -f $newComputerName)
    exit 1
}

# tcpip_hostname: costuma bater com computer_name; validamos separadamente
# pra permitir hostname diferente (DNS-only, fora do limite NetBIOS)
# porem o EMAC ate agora nunca correlacionou os dois - so seguimos o padrao.
if ([string]::IsNullOrWhiteSpace($newTcpipHostname)) {
    Write-Err "windows.tcpip_hostname vazio."
    exit 1
}

# ------------------------------------------------------------
# Backup UMA VEZ (primeiro -Apply preserva o original real da maquina)
# ------------------------------------------------------------
if (-not (Test-Path $backupPath)) {
    $backupDir = Split-Path $backupPath -Parent
    if (-not (Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }

    $cur = Read-CurrentValues
    $bkObj = [ordered]@{
        created_utc         = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        MachineGuid         = $cur.MachineGuid
        ComputerName        = $cur.ComputerName
        ActiveComputerName  = $cur.ActiveComputerName
        TcpipHostname       = $cur.TcpipHostname
        TcpipNvHostname     = $cur.TcpipNvHostname
    }
    $json = $bkObj | ConvertTo-Json -Depth 5

    # Escrita atomica (tmp + move) pra nao expor JSON parcial a leitor concorrente.
    $tmp = "$backupPath.tmp"
    Set-Content -Path $tmp -Value $json -Encoding UTF8 -Force
    Move-Item -Path $tmp -Destination $backupPath -Force
    Write-OK ("Backup criado: {0}" -f $backupPath)
} else {
    Write-Info ("Backup ja existe (preservado): {0}" -f $backupPath)
}

# ------------------------------------------------------------
# 1) MachineGuid
# ------------------------------------------------------------
Write-Section "MachineGuid"
$oldMg = Get-RegString $cryptoPath "MachineGuid"
Set-RegString $cryptoPath "MachineGuid" $newMachineGuid
Write-OK ("{0}" -f $cryptoPath)
Write-Info ("  antes: {0}" -f $oldMg)
Write-Info ("  agora: {0}" -f $newMachineGuid)

# ------------------------------------------------------------
# 2) ComputerName (pending + active, mantidos em sync)
#     Escrita direta pra evitar side-effects de Rename-Computer
#     (SPN update, evento no event log com nome antigo/novo, tentativa
#      de contato com DC se joined-to-domain, etc).
# ------------------------------------------------------------
Write-Section "ComputerName"
$oldCn  = Get-RegString $computerNamePath   "ComputerName"
$oldAcn = Get-RegString $activeCompNamePath "ComputerName"

Set-RegString $computerNamePath   "ComputerName" $newComputerName
Set-RegString $activeCompNamePath "ComputerName" $newComputerName

Write-OK ("{0}\ComputerName" -f $computerNamePath)
Write-Info ("  antes: {0}" -f $oldCn)
Write-Info ("  agora: {0}" -f $newComputerName)
Write-OK ("{0}\ComputerName" -f $activeCompNamePath)
Write-Info ("  antes: {0}" -f $oldAcn)
Write-Info ("  agora: {0}" -f $newComputerName)

# ------------------------------------------------------------
# 3) TCP/IP Hostname (Hostname + NV Hostname pra manter consistencia)
# ------------------------------------------------------------
Write-Section "TCP/IP Hostname"
$oldHn   = Get-RegString $tcpipParamsPath "Hostname"
$oldNvHn = Get-RegString $tcpipParamsPath "NV Hostname"

Set-RegString $tcpipParamsPath "Hostname"    $newTcpipHostname
Set-RegString $tcpipParamsPath "NV Hostname" $newTcpipHostname

Write-OK ("{0}\Hostname" -f $tcpipParamsPath)
Write-Info ("  antes: {0}" -f $oldHn)
Write-Info ("  agora: {0}" -f $newTcpipHostname)
Write-OK ("{0}\NV Hostname" -f $tcpipParamsPath)
Write-Info ("  antes: {0}" -f $oldNvHn)
Write-Info ("  agora: {0}" -f $newTcpipHostname)

# ------------------------------------------------------------
# Aviso final
# ------------------------------------------------------------
Write-Host ""
Write-Warn "REBOOT RECOMENDADO."
Write-Warn "  MachineGuid: EMAC le on-demand - vale ja no proximo start do cliente."
Write-Warn "  ComputerName: varios subsistemas (SMB, RPC, DNS resolver, Netlogon)"
Write-Warn "                mantem cache in-memory ate reboot. Sem reboot, algumas"
Write-Warn "                APIs ainda retornam o nome antigo."
Write-Warn "  Hostname:     mesmo caso do ComputerName pra Tcpip stack."
Write-Host ""
Write-Info ("Para reverter:  .\spoof-windows-id.ps1 -Restore")
Write-Info ("Para inspecionar: .\spoof-windows-id.ps1 -Show")
Write-Host ""
Write-Host "=== Fim ===" -ForegroundColor Cyan
Write-Host ""
