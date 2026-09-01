#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Arma/desarma/diagnostica o Track D (Cm registry callback kernel)
    do driver rstflt.sys v5.0.0+.

.DESCRIPTION
    Track D e a linha de spoof kernel do rstflt.sys que reescreve nomes
    de subchaves de Enum\SCSI\Disk&Ven_* em runtime, para intercepcao
    fingerprint contra EMAC/RubinOT (docs/track-d-kernel-registry-
    callback-kickoff.md e emac-recon-v3.md).

    Este script gerencia SOMENTE a config Parameters do driver -
    nao instala, nao desinstala, nao mexe em UpperFilters. O driver
    precisa ja ter sido instalado via 03-instalar-driver.bat e a
    maquina rebootada.

    Valores em HKLM\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters
    manipulados por este script:
      EnableRegCallback     REG_DWORD  master gate (0=off default, 1=on)
      RegCallbackSeed       REG_SZ     32-hex FNV seed (do profile)
      LastCallbackStatus    REG_DWORD  breadcrumb hot path (leitura)
      LastArmStatus         REG_DWORD  breadcrumb arm-time (leitura)
      CallbackHitCount      REG_DWORD  rewrites que landaram (leitura)
      CallbackInvokeCount   REG_DWORD  vezes que callback entrou (leitura)
      CallbackNameMissCount REG_DWORD  invokes rejeitados pelo name gate
      LastMissImageName     REG_SZ     ultimo image name que falhou o gate

    v5.0.4: RubinOtPid + -SetPid removidos. O gate agora e image-name
    inline (PsGetProcessImageFileName + _strnicmp "rubinot") em vez de
    PID array populado por PsSetCreateProcessNotifyRoutineEx.

    Uso:
      .\track-d-arm.ps1 -Enable
        Le seed de C:\ProgramData\.hwcfg\profile.json (pci_hardwareid.
        randomize_seed), escreve EnableRegCallback=1 e RegCallbackSeed.
        NAO reboota - se driver ja estava carregado ANTES do arm, o
        callback so entra em vigor apos o proximo reboot.

      .\track-d-arm.ps1 -Disable
        Escreve EnableRegCallback=0. Efeito imediato (callback continua
        registrado no kernel, mas a hot path g_TrackDEnabled=FALSE
        transforma tudo em pass-through).

      .\track-d-arm.ps1 -Diagnose
        Le todos os valores Parameters + decoded LastCallbackStatus/
        LastArmStatus (tag/status), CallbackHitCount, CallbackInvokeCount,
        CallbackNameMissCount, LastMissImageName.
#>

[CmdletBinding(DefaultParameterSetName = 'Diagnose')]
param(
    [Parameter(ParameterSetName = 'Enable')]
    [switch]$Enable,

    [Parameter(ParameterSetName = 'Disable')]
    [switch]$Disable,

    [Parameter(ParameterSetName = 'Diagnose')]
    [switch]$Diagnose
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\_ui-common.ps1"

$profilePath = 'C:\ProgramData\.hwcfg\profile.json'
$paramsKey   = 'HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters'
$serviceKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt'

# ============================================================
#  Tag table (mirror rstflt.c v5.0.4 TRACKD_TAG_*)
# ============================================================
$tagTable = @{
    0x00 = 'OK             (rewrite landed OU arm-time sucesso)'
    0x01 = 'NAME-MISS      (v5.0.4: image name nao bateu com rubinot)'
    0x02 = 'RESERVED       (era PID-STALE pre-v5.0.4; slot mantido)'
    0x03 = 'PATH-GET-FAIL  (CmCallbackGetKeyObjectID falhou)'
    0x04 = 'BUFFER-BAD     (KEY_INFORMATION malformada)'
    0x05 = 'ALLOC-FAIL     (arm falhou; NonPagedPool ou CmRegister)'
    0x06 = 'SEH-FAULT      (__except capturou fault na rewrite)'
}

function Assert-DriverInstalled {
    if (-not (Test-Path $serviceKey)) {
        Write-Err ("Servico RstFlt nao existe (chave " + $serviceKey + " ausente).")
        Write-Err 'Rode primeiro: .\03-instalar-driver.bat + reboot.'
        exit 1
    }
    if (-not (Test-Path $paramsKey)) {
        Write-Info ("Criando chave Parameters ausente: " + $paramsKey)
        New-Item -Path $paramsKey -Force | Out-Null
    }
}

function Get-ProfileSeed {
    if (-not (Test-Path $profilePath)) {
        Write-Err ("Profile ausente: " + $profilePath)
        Write-Err 'Rode primeiro: .\00-gerar-profile.bat'
        exit 1
    }
    try {
        $p = Get-Content -Path $profilePath -Raw | ConvertFrom-Json
    } catch {
        Write-Err ('Profile corrompido: ' + $_.Exception.Message)
        exit 1
    }
    if (-not $p.pci_hardwareid -or -not $p.pci_hardwareid.randomize_seed) {
        Write-Err 'Profile nao contem pci_hardwareid.randomize_seed - regenere com generate-profile.ps1 -Generate.'
        exit 1
    }
    $seed = [string]$p.pci_hardwareid.randomize_seed
    if ($seed -notmatch '^[0-9a-fA-F]{32}$') {
        Write-Err ('Seed invalido (' + $seed.Length + ' chars); esperado 32 hex.')
        exit 1
    }
    return $seed
}

function Format-Status {
    param([uint32]$Value)
    $tag    = ($Value -shr 24) -band 0xFF
    $status = $Value -band 0x00FFFFFF
    $label  = $tagTable[[int]$tag]
    if (-not $label) { $label = 'UNKNOWN' }
    $signed = [int]$status
    if ($signed -lt 0) { $signed = -$signed }
    return ('0x{0:X8}  tag=0x{1:X2} {2}  status=0x{3:X6}' -f $Value, $tag, $label, $status)
}

# ============================================================
#  Modes
# ============================================================
switch ($PSCmdlet.ParameterSetName) {

    'Enable' {
        Write-Section 'Track D - Enable'
        Assert-DriverInstalled
        $seed = Get-ProfileSeed
        Write-OK ('Seed carregado (prefix ' + $seed.Substring(0, 8) + '..., ' + $seed.Length + ' chars)')

        Set-ItemProperty -Path $paramsKey -Name 'EnableRegCallback' -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $paramsKey -Name 'RegCallbackSeed'   -Value $seed -Type String -Force

        Write-OK 'EnableRegCallback = 1'
        Write-OK ('RegCallbackSeed   = ' + $seed)
        Write-Warn 'Reboot necessario se o driver ja estava carregado ANTES desta chamada.'
        Write-Info 'Sem reboot: proximo boot arma o callback; gate por image name (rubinot*) passa a valer.'
    }

    'Disable' {
        Write-Section 'Track D - Disable'
        Assert-DriverInstalled
        Set-ItemProperty -Path $paramsKey -Name 'EnableRegCallback' -Value 0 -Type DWord -Force
        Write-OK 'EnableRegCallback = 0'
        Write-Info 'Efeito imediato (v5.0.1+): tap RegNtPreSetValueKey da propria Parameters key detecta'
        Write-Info 'a escrita e alterna g_TrackDEnabled=FALSE em runtime. Callback continua registrado no'
        Write-Info 'kernel; hot path vira pass-through para todos os PIDs.'
    }

    'Diagnose' {
        Write-Section 'Track D - Diagnose'
        Assert-DriverInstalled
        $vals = Get-ItemProperty -Path $paramsKey -ErrorAction SilentlyContinue

        function Show-Val {
            param([string]$Name, [string]$Default = '(ausente)')
            $v = $null
            if ($vals -and $vals.PSObject.Properties.Name -contains $Name) {
                $v = $vals.$Name
            }
            if ($null -eq $v) {
                Write-Host ('  {0,-22}: {1}' -f $Name, $Default) -ForegroundColor DarkGray
            } else {
                Write-Host ('  {0,-22}: {1}' -f $Name, $v) -ForegroundColor Cyan
            }
        }

        Show-Val 'EnableRegCallback'
        Show-Val 'RegCallbackSeed'
        Show-Val 'CallbackHitCount'      '(0 ou nenhum rewrite landou)'
        Show-Val 'CallbackInvokeCount'   '(0 ou callback nunca entrou)'
        Show-Val 'CallbackNameMissCount' '(0 ou nenhum invoke rejeitado)'
        Show-Val 'LastMissImageName'     '(nenhum miss registrado)'

        # LastCallbackStatus decoded (hot path breadcrumb)
        $last = $null
        if ($vals -and $vals.PSObject.Properties.Name -contains 'LastCallbackStatus') {
            $last = [uint32]$vals.LastCallbackStatus
        }
        if ($null -eq $last) {
            Write-Host ('  {0,-22}: (ausente - callback nunca fired hot path)' -f 'LastCallbackStatus') -ForegroundColor DarkGray
        } else {
            Write-Host ('  {0,-22}: {1}' -f 'LastCallbackStatus', (Format-Status -Value $last)) -ForegroundColor Cyan
        }

        # LastArmStatus decoded (v5.0.4+ arm-time breadcrumb)
        $arm = $null
        if ($vals -and $vals.PSObject.Properties.Name -contains 'LastArmStatus') {
            $arm = [uint32]$vals.LastArmStatus
        }
        if ($null -eq $arm) {
            Write-Host ('  {0,-22}: (ausente - driver pre-v5.0.4 ou arm nao rodou)' -f 'LastArmStatus') -ForegroundColor DarkGray
        } else {
            Write-Host ('  {0,-22}: {1}' -f 'LastArmStatus', (Format-Status -Value $arm)) -ForegroundColor Cyan
        }

        Write-Section 'Tag legend'
        foreach ($k in ($tagTable.Keys | Sort-Object)) {
            Write-Host ('  0x{0:X2}  {1}' -f $k, $tagTable[$k]) -ForegroundColor DarkGray
        }

        Write-Section 'Interpretation (v5.0.4)'
        Write-Host '  InvokeCount=0                                       -> callback nao armado; inspecionar LastArmStatus' -ForegroundColor DarkGray
        Write-Host '  InvokeCount>0 & HitCount=0 & NameMissCount>0        -> callback fires mas name gate rejeita todos' -ForegroundColor DarkGray
        Write-Host '                                                         (LastMissImageName mostra quem dominou os misses)' -ForegroundColor DarkGray
        Write-Host '  InvokeCount>0 & HitCount>0                          -> callback opera; cruzar com check-consistency.ps1' -ForegroundColor DarkGray
        Write-Host '  LastMissImageName ~= rubinot* & NameMissCount>0     -> rubinot bateu no gate mas foi rejeitado pelo' -ForegroundColor DarkGray
        Write-Host '                                                         next-char guard (verificar leaf name real)' -ForegroundColor DarkGray
    }
}

exit 0
