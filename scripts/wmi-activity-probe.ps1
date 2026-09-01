#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Captura ETW Microsoft-Windows-WMI-Activity durante uma sessao
    RubinOT para determinar empiricamente se rubinot_dx.exe faz
    queries WMI in-process (via wbemprox.dll linkado).

.DESCRIPTION
    Fecha (ou eleva) formalmente a decisao sobre Phase 3 UMDF WMI
    provider shadow. Recon-v2 correction #6 + recon-v3 TL;DR:33
    documentaram WmiPrvSE.exe = 0 events em 25min de captura combinada
    (out-of-process WMI descartado). Este script cobre o vetor comple-
    mentar: in-process wbemprox no rubinot_dx.exe. Se ETW mostra zero
    eventos WMI-Activity do rubinot_dx.exe -> Phase 3 formalmente
    closed. Se mostra eventos -> Phase 3 elevado para v5.0.6 backlog.

    Uso (bare-metal, 3 passes):

      Pass 1 - start ETW session:
        .\wmi-activity-probe.ps1 -Start
        Inicia logman capture no provider Microsoft-Windows-WMI-Activity
        gravando em C:\hwtoolkit\wmi-activity.etl.

      Pass 2 - <RubinOT session>:
        Abra RubinOT normalmente. Login + primeiros 5-10 minutos de
        gameplay sao suficientes (EMAC HW collection burst acontece
        no login + re-registration se emac-uuid renovado).

      Pass 3 - stop + parse:
        .\wmi-activity-probe.ps1 -Stop
        Para logman, decoda o .etl via Get-WinEvent, filtra por
        Process Name matchando rubinot* / emac* / RubinOT*, e
        printa contagem + amostra de eventos.

    Outcomes:
      ZERO eventos rubinot/emac/RubinOT   -> Phase 3 formalmente closed
                                             (in-process wbemprox NAO usado
                                             empiricamente pelo target).
      EVENTOS > 0                         -> Phase 3 elevado; documentar
                                             classes queried (Win32_*) no
                                             postmortem-v5-track-d/incident-
                                             v506-*.md.

    Status auxiliar:
      .\wmi-activity-probe.ps1 -Status
      Mostra se ha ETW session ativa; util pra checar se -Start rodou
      OU se sessao anterior ficou orfa apos crash.

.NOTES
    Provider ID GUID: {1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}
    (Microsoft-Windows-WMI-Activity)

    Manifest-based provider - Get-WinEvent decoda bem sem tracerpt.
    File .etl fica em C:\hwtoolkit\ pos-Stop; NAO deletar antes de
    revisar (util pra postmortem).
#>

[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Start')]
    [switch]$Start,

    [Parameter(ParameterSetName = 'Stop')]
    [switch]$Stop,

    [Parameter(ParameterSetName = 'Status')]
    [switch]$Status
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\_ui-common.ps1"

$sessionName = 'WmiCheck'
$etlPath     = 'C:\hwtoolkit\wmi-activity.etl'
$provider    = 'Microsoft-Windows-WMI-Activity'
$targetRegex = '^(rubinot|emac)'   # match rubinot_dx.exe, RubinOT.exe,
                                    # emac-client64.dll host

function Test-SessionRunning {
    $out = & logman.exe query -ets 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    return ($out -match ('\s' + [regex]::Escape($sessionName) + '\s'))
}

# ============================================================
#  Start
# ============================================================
if ($PSCmdlet.ParameterSetName -eq 'Start') {
    Write-Section ('ETW WMI-Activity - Start (session: ' + $sessionName + ')')

    if (Test-SessionRunning) {
        Write-Warn ('Session "' + $sessionName + '" ja esta rodando.')
        Write-Info 'Se e sessao orfa, para com: .\wmi-activity-probe.ps1 -Stop'
        Write-Info 'Se e sessao ativa em uso, deixa continuar.'
        exit 1
    }

    $dir = Split-Path $etlPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }
    if (Test-Path $etlPath) { Remove-Item $etlPath -Force }

    & logman.exe start $sessionName -p $provider -o $etlPath -ets
    if ($LASTEXITCODE -ne 0) {
        Write-Err ('logman start falhou (exit ' + $LASTEXITCODE + ')')
        exit 1
    }
    Write-OK ('ETW session "' + $sessionName + '" armada')
    Write-OK ('Output: ' + $etlPath)
    Write-Info ''
    Write-Info 'Proximo passo:'
    Write-Info '  1. Abre RubinOT (launcher + login + 5-10 min de gameplay)'
    Write-Info '  2. Depois volta e roda: .\wmi-activity-probe.ps1 -Stop'
    exit 0
}

# ============================================================
#  Stop + parse
# ============================================================
if ($PSCmdlet.ParameterSetName -eq 'Stop') {
    Write-Section ('ETW WMI-Activity - Stop + parse')

    if (-not (Test-SessionRunning)) {
        Write-Warn ('Nenhuma session "' + $sessionName + '" ativa; nada pra parar.')
        if (Test-Path $etlPath) {
            Write-Info ('Arquivo .etl existente em ' + $etlPath + ' - vou tentar parsear mesmo assim')
        } else {
            Write-Err 'Sem .etl pra decodar. Rode -Start antes.'
            exit 1
        }
    } else {
        & logman.exe stop $sessionName -ets
        if ($LASTEXITCODE -ne 0) {
            Write-Err ('logman stop falhou (exit ' + $LASTEXITCODE + ')')
            exit 1
        }
        Write-OK ('Session parada; parseando ' + $etlPath)
    }

    if (-not (Test-Path $etlPath)) {
        Write-Err ('ETL ausente: ' + $etlPath)
        exit 1
    }

    Write-Section 'Parse'

    $allEvents = $null
    try {
        $allEvents = Get-WinEvent -Path $etlPath -Oldest -EA Stop
    } catch {
        Write-Err ('Get-WinEvent falhou: ' + $_.Exception.Message)
        Write-Info 'Tente `tracerpt.exe ' + $etlPath + ' -o C:\hwtoolkit\wmi-activity.xml -of XML`'
        Write-Info 'e inspecione o XML manualmente.'
        exit 1
    }

    $totalCount = ($allEvents | Measure-Object).Count
    Write-Info ('Total events na sessao ETW: ' + $totalCount)

    # Filtra eventos onde process name matcha rubinot|emac. WMI-Activity
    # eventos incluem ClientProcessId + geralmente ClientMachine no
    # EventData; usamos Get-Process pra resolver ClientProcessId -> nome.
    $matched = @()
    $processCache = @{}
    foreach ($ev in $allEvents) {
        # NOTA: $pid e automatic variable do PowerShell (PID do PS host);
        # usar $evtPid pra evitar sombreamento.
        # ClientProcessId tipicamente em ev.ProcessId (o processo QUE ORIGINOU
        # o event no ETW, que pra WMI-Activity e o cliente da query).
        $evtPid = $ev.ProcessId
        if ($null -eq $evtPid -or $evtPid -eq 0) { continue }

        if (-not $processCache.ContainsKey($evtPid)) {
            $p = Get-Process -Id $evtPid -EA SilentlyContinue
            if ($p) {
                $processCache[$evtPid] = $p.ProcessName
            } else {
                # processo pode ter morrido apos o event; marca como dead-pid
                $processCache[$evtPid] = '<dead-pid-' + $evtPid + '>'
            }
        }
        $pname = $processCache[$evtPid]
        if ($pname -match $targetRegex) {
            $matched += [pscustomobject]@{
                Time = $ev.TimeCreated
                Pid  = $evtPid
                Proc = $pname
                Id   = $ev.Id
                Task = $ev.TaskDisplayName
                Msg  = ($ev.Message -split "`n" | Select-Object -First 1)
            }
        }
    }

    $matchedCount = ($matched | Measure-Object).Count
    Write-Info ('Events matching /' + $targetRegex + '/: ' + $matchedCount)

    Write-Section 'Verdict'

    if ($matchedCount -eq 0) {
        Write-OK 'ZERO WMI-Activity events do rubinot/emac/RubinOT.'
        Write-OK 'Phase 3 UMDF WMI provider shadow FORMALMENTE CLOSED (empiricamente).'
        Write-Info 'Combinado com recon-v2 correction #6 + recon-v3 TL;DR:33'
        Write-Info '(WmiPrvSE=0 events), agora BOTH out-of-process E in-process'
        Write-Info 'WMI vectors sao empiricamente cold para EMAC. Phase 3 fica'
        Write-Info 'em roadmap-v41 backlog para future non-EMAC target.'
        exit 0
    } else {
        Write-Warn ($matchedCount + ' WMI-Activity events do target detectados.')
        Write-Info 'Phase 3 UMDF shadow ELEVADO para backlog v5.0.6.'
        Write-Info 'Ver amostra de eventos abaixo pra identificar classes queried:'
        Write-Info ''
        $matched | Select-Object -First 20 | Format-Table Time,Pid,Proc,Id,Task,Msg -AutoSize -Wrap
        Write-Info ''
        Write-Info ('Dump completo salvo em ' + $etlPath)
        Write-Info 'Documentar findings em docs/postmortem-v5-track-d/incident-v506-*.md'
        exit 2
    }
}

# ============================================================
#  Status
# ============================================================
Write-Section ('ETW WMI-Activity - Status')

if (Test-SessionRunning) {
    Write-OK ('Session "' + $sessionName + '" ATIVA')
    if (Test-Path $etlPath) {
        $sz = (Get-Item $etlPath).Length
        Write-Info ('Output ETL: ' + $etlPath + ' (' + $sz + ' bytes ate agora)')
    }
    Write-Info 'Continue a sessao RubinOT; depois rode -Stop.'
} else {
    Write-Info ('Session "' + $sessionName + '" nao esta rodando.')
    if (Test-Path $etlPath) {
        $sz = (Get-Item $etlPath).Length
        Write-Info ('ETL do run anterior: ' + $etlPath + ' (' + $sz + ' bytes)')
        Write-Info 'Rode -Stop pra reparsear, OU -Start pra nova sessao.'
    } else {
        Write-Info 'Nenhum .etl anterior. Rode -Start pra comecar captura.'
    }
}
