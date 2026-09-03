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
      EnableRegCallback          REG_DWORD  master gate (0=off default, 1=on)
      RegCallbackSeed            REG_SZ     32-hex FNV seed (do profile)
      LastCallbackStatus         REG_DWORD  breadcrumb hot path (leitura)
      LastArmStatus              REG_DWORD  breadcrumb arm-time (leitura)
      CallbackHitCount           REG_DWORD  rewrites que landaram (leitura)
      CallbackInvokeCount        REG_DWORD  vezes que callback entrou (leitura)
      CallbackNameMissCount      REG_DWORD  invokes rejeitados pelo name gate
      LastMissImageName          REG_SZ     ultimo image name que falhou o gate

    v5.0.5 Phase 0 additions (todos leitura):
      CallbackHit_SCSI           REG_DWORD  per-type breakdown de CallbackHitCount
      CallbackHit_PCI            REG_DWORD  idem
      CallbackHit_USB            REG_DWORD  idem
      CallbackHit_HID            REG_DWORD  idem
      CallbackHit_AudioR         REG_DWORD  idem
      CallbackHit_AudioC         REG_DWORD  idem
      CallbackHit_BTH            REG_DWORD  v5.0.5 Phase 1: Enum\BTH Dev_ rewrites
      CallbackHit_Storage        REG_DWORD  v5.0.5 Phase 1: Enum\STORAGE\Volume GUID rewrites
      CallbackNonRubiParentMatch REG_DWORD  invokes onde parent classificou como
                                            um dos targets MAS image name nao
                                            bateu com "rubinot" - triage para
                                            "quem toca nossos parents fora do gate"
      CallbackHitRingIndex       REG_DWORD  proximo slot a ser escrito (mod ring size)
      HitRingBuffer              REG_BINARY N * 96 bytes; ver decoder em -Diagnose
                                            (v5.0.5: N=16; v5.0.6 Phase 0: N=128)

    v5.0.5 Phase 2 additions:
      EnableValueReadRewrite     REG_DWORD  gate do value-read handler
                                            (RegNtPostQueryValueKey); 0=off default,
                                            1=on. Independente de EnableRegCallback.
      EnableEdidValueRewrite     REG_DWORD  gate SEPARADO do EDID binary rewriter;
                                            0=off default (userland ja spoofa EDID).
      CallbackValHit_SCSI        REG_DWORD  value reads onde o handler SCSI engajou
      CallbackValHit_PCI         REG_DWORD  idem PCI
      CallbackValHit_BTH         REG_DWORD  idem BTH (no-op se valor nao carrega addr)
      CallbackValHit_Storage     REG_DWORD  idem STORAGE\Volume
      CallbackValHit_Edid        REG_DWORD  idem EDID (requer EnableEdidValueRewrite)
      CallbackNonRubiValueMatch  REG_DWORD  processo non-rubi leu um value alvo

    v5.0.6 Phase 0 additions (todos leitura):
      EnableValueSynth                     REG_DWORD  scaffolding gate do synthesizer OEM
                                                       string (DeviceDesc/FriendlyName/Mfg);
                                                       0=off default. NAO tem reader em
                                                       Phase 0 - persistencia + hot-toggle
                                                       so; Phase 2 vai wirar o reader.
      CallbackSynthHit_SCSI_FriendlyName   REG_DWORD  Phase 2: SCSI FriendlyName synth run
      CallbackSynthHit_SCSI_DeviceDesc     REG_DWORD  Phase 2: SCSI DeviceDesc synth run
      CallbackSynthHit_SCSI_Mfg            REG_DWORD  Phase 2: SCSI Mfg synth run
      CallbackSynthHit_PCI_FriendlyName    REG_DWORD  Phase 2: PCI FriendlyName synth run
      CallbackSynthHit_PCI_DeviceDesc      REG_DWORD  Phase 2: PCI DeviceDesc synth run
      CallbackSynthHit_PCI_Mfg             REG_DWORD  Phase 2: PCI Mfg synth run
      CallbackSynthHit_USB_FriendlyName    REG_DWORD  Phase 2: USB FriendlyName synth run
      CallbackSynthHit_HID_FriendlyName    REG_DWORD  Phase 2: HID FriendlyName synth run
      CallbackSynthHit_BTH_FriendlyName    REG_DWORD  Phase 2: BTH FriendlyName synth run
      CallbackSynthTypeMismatchBail        REG_DWORD  Phase 2: REG type mismatched descriptor
      CallbackSynthOverflowBail            REG_DWORD  Phase 2: synth larger than caller buffer
      CallbackSynthSizeSanityBail          REG_DWORD  Phase 2: real value size out of bounds
      CallbackSynthInventoryMissBail       REG_DWORD  Phase 2: synth pool lookup returned none
      CallbackValHit_LocationInfo          REG_DWORD  Phase 0 measure-first: gated caller leu
                                                       LocationInformation em parent classificado
      CallbackValHit_LocationPaths         REG_DWORD  idem LocationPaths
      CallbackValHit_ContainerID           REG_DWORD  idem ContainerID

    v5.0.7 Phase 0 additions (filesystem minifilter scaffolding):
      EnableFsFilter                       REG_DWORD  scaffolding gate do FltMgr minifilter
                                                       (Phase 1 wira PreCreate/PreDirCtl hide
                                                       de rstflt.sys). NAO tem reader em Phase 0
                                                       - persistencia + hot-toggle so.
      LastFsFilterStatus                   REG_DWORD  breadcrumb do arm-worker (tag<<24|status).
                                                       Tags: 0x01 INSTANCES-WRITE-FAIL, 0x02
                                                       FLT-REGISTER-FAIL, 0x03 FLT-START-FAIL,
                                                       0x04 ARM-OK, 0x05 NULL-DRVOBJ.
      FsFilterRegistered                   REG_DWORD  1 apos FltRegisterFilter+FltStartFiltering
                                                       ambos NT_SUCCESS; 0 caso contrario.
      FsFilterInstanceCount                REG_DWORD  volumes atacheados via InstanceSetup;
                                                       Phase 0: >=1 comprova registration OK.
      FsHideHitCount                       REG_DWORD  Phase 1: hides que landaram
      FsFilterCreateHit                    REG_DWORD  Phase 1: PreCreate invocations em rstflt.sys
      FsFilterReadHit                      REG_DWORD  Phase 1: PreRead invocations idem
      FsFilterDirCtlHit                    REG_DWORD  Phase 1: PostDirCtl invocations que
                                                       encontraram rstflt.sys na enum
      FsGateMissCount                      REG_DWORD  Phase 1: opens rejeitados pelo image-name
                                                       gate (nao-rubi tocou rstflt.sys)
      FsFilterAllocBail                    REG_DWORD  Phase 1: FltGetFileNameInformation fail
      FsProbe_InstallDir                   REG_DWORD  Phase 1 measure-first: probes em
                                                       %ProgramFiles*%\RubinOT*\rstflt.sys
      FsProbe_System32Drivers              REG_DWORD  Phase 1 measure-first: probes em
                                                       %SystemRoot%\System32\drivers\rstflt.sys
      FsProbe_CatRoot                      REG_DWORD  Phase 1 measure-first: probes em
                                                       %SystemRoot%\System32\CatRoot\* (signer)

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

      .\track-d-arm.ps1 -EnableValueRewrite [-Edid]
        Escreve EnableValueReadRewrite=1 (arma o value-read handler
        RegNtPostQueryValueKey). Requer EnableRegCallback ja =1 (o callback
        precisa estar registrado). Efeito imediato via tap. Com -Edid,
        tambem escreve EnableEdidValueRewrite=1 (so em deployment kernel-
        EDID-only; senao double-spoofa com spoof-edid-full.ps1).

      .\track-d-arm.ps1 -DisableValueRewrite
        Escreve EnableValueReadRewrite=0 e EnableEdidValueRewrite=0. Efeito
        imediato; name-side (EnableRegCallback) permanece como estava.

      .\track-d-arm.ps1 -EnableSynth
        Escreve EnableValueSynth=1 (v5.0.6 Phase 0 scaffolding gate do
        synthesizer OEM string). NAO tem efeito observavel em Phase 0 (o
        synthesizer callback so entra em Phase 2). Persistencia + hot-
        toggle via tap RegNtPreSetValueKey validam o pipeline; um arm
        agora fica honored quando o Phase 2 wirar o reader.

      .\track-d-arm.ps1 -DisableSynth
        Escreve EnableValueSynth=0. Efeito imediato via tap.

      .\track-d-arm.ps1 -EnableFsFilter
        Escreve EnableFsFilter=1 (v5.0.7 Phase 0 scaffolding gate do
        filesystem minifilter). Phase 0 NAO tem reader - todas as FLT
        preop callbacks retornam FLT_PREOP_SUCCESS_NO_CALLBACK sem
        consultar o flag. Serve para validar persistencia + hot-toggle
        antes de Phase 1 wirar PreCreate/PostDirCtl. FltRegisterFilter e
        FltStartFiltering ja rodam automaticamente (via workitem em
        DelayedWorkQueue) no boot, independente deste flag; ver
        LastFsFilterStatus + FsFilterInstanceCount pra confirmar arm.

      .\track-d-arm.ps1 -DisableFsFilter
        Escreve EnableFsFilter=0. Efeito imediato via tap; sem efeito
        observavel em Phase 0. Nao desregistra o filtro (Phase 0 sempre
        registra no boot; disarm real = Phase 1+).

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

    # v5.0.5 Phase 2: arm/disarm the value-read handler (RegNtPostQueryValueKey).
    [Parameter(ParameterSetName = 'EnableValue')]
    [switch]$EnableValueRewrite,

    # Optional companion to -EnableValueRewrite: also arm the EDID binary
    # rewriter (EnableEdidValueRewrite). OFF by default because the
    # recommended deployment spoofs EDID from userland (spoof-edid-full.ps1);
    # enabling both would double-spoof. Only pass -Edid in a kernel-EDID-only
    # deployment.
    [Parameter(ParameterSetName = 'EnableValue')]
    [switch]$Edid,

    [Parameter(ParameterSetName = 'DisableValue')]
    [switch]$DisableValueRewrite,

    # v5.0.6 Phase 0: arm/disarm the synthesizer scaffolding gate.
    # NO reader in Phase 0 - flag is dormant until Phase 2 wires the
    # synthesizer callback. Kept as a first-class switch so the userland
    # cycle can validate the persistence + hot-toggle end-to-end today.
    [Parameter(ParameterSetName = 'EnableSynth')]
    [switch]$EnableSynth,

    [Parameter(ParameterSetName = 'DisableSynth')]
    [switch]$DisableSynth,

    # v5.0.7 Phase 0: arm/disarm the filesystem-minifilter scaffolding
    # gate. NO reader in Phase 0 - IRP preops return SUCCESS_NO_CALLBACK
    # unconditionally. Kept as a first-class switch so the userland cycle
    # validates persistence + hot-toggle end-to-end today.
    [Parameter(ParameterSetName = 'EnableFsFilter')]
    [switch]$EnableFsFilter,

    [Parameter(ParameterSetName = 'DisableFsFilter')]
    [switch]$DisableFsFilter,

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

    'EnableValue' {
        Write-Section 'Track D - Enable value-read handler (Phase 2)'
        Assert-DriverInstalled
        $cur = Get-ItemProperty -Path $paramsKey -ErrorAction SilentlyContinue
        $regCb = if ($cur -and $cur.PSObject.Properties.Name -contains 'EnableRegCallback') { [int]$cur.EnableRegCallback } else { 0 }
        if ($regCb -ne 1) {
            Write-Warn 'EnableRegCallback != 1 - o callback nao esta armado; o value handler nao dispara.'
            Write-Warn 'Rode primeiro: .\track-d-arm.ps1 -Enable (+ reboot se o driver carregou antes do arm).'
        }
        Set-ItemProperty -Path $paramsKey -Name 'EnableValueReadRewrite' -Value 1 -Type DWord -Force
        Write-OK 'EnableValueReadRewrite = 1 (RegNtPostQueryValueKey armado)'
        if ($Edid) {
            Set-ItemProperty -Path $paramsKey -Name 'EnableEdidValueRewrite' -Value 1 -Type DWord -Force
            Write-OK 'EnableEdidValueRewrite = 1'
            Write-Warn 'EDID kernel rewrite ativo: NAO rode spoof-edid-full.ps1 no mesmo deployment (double-spoof).'
        } else {
            Write-Info 'EnableEdidValueRewrite inalterado (default 0). Use -Edid so em deployment kernel-EDID-only.'
        }
        Write-Info 'Efeito imediato via tap RegNtPreSetValueKey (sem reboot). Gate por image name (rubinot*) vale.'
    }

    'DisableValue' {
        Write-Section 'Track D - Disable value-read handler (Phase 2)'
        Assert-DriverInstalled
        Set-ItemProperty -Path $paramsKey -Name 'EnableValueReadRewrite' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $paramsKey -Name 'EnableEdidValueRewrite' -Value 0 -Type DWord -Force
        Write-OK 'EnableValueReadRewrite = 0'
        Write-OK 'EnableEdidValueRewrite = 0'
        Write-Info 'Efeito imediato. Name-side (EnableRegCallback) permanece inalterado.'
    }

    'EnableSynth' {
        Write-Section 'Track D - Enable value-synth (v5.0.6 Phase 0 scaffolding)'
        Assert-DriverInstalled
        # Sanity: Phase 0 has no reader, but warn the operator if the
        # dependency gates are off - Phase 2 (which lands the reader) will
        # need EnableRegCallback + EnableValueReadRewrite both armed.
        $cur = Get-ItemProperty -Path $paramsKey -ErrorAction SilentlyContinue
        $regCb = if ($cur -and $cur.PSObject.Properties.Name -contains 'EnableRegCallback') { [int]$cur.EnableRegCallback } else { 0 }
        $vrw   = if ($cur -and $cur.PSObject.Properties.Name -contains 'EnableValueReadRewrite') { [int]$cur.EnableValueReadRewrite } else { 0 }
        if ($regCb -ne 1) { Write-Warn 'EnableRegCallback != 1 - o callback nao esta armado; Phase 2 vai precisar dele armado.' }
        if ($vrw   -ne 1) { Write-Warn 'EnableValueReadRewrite != 1 - value handler off; Phase 2 vai precisar dele armado tambem.' }
        Set-ItemProperty -Path $paramsKey -Name 'EnableValueSynth' -Value 1 -Type DWord -Force
        Write-OK 'EnableValueSynth = 1 (v5.0.6 Phase 0 scaffolding gate armed)'
        Write-Info 'Sem reader em Phase 0 - persistencia + hot-toggle validation so.'
        Write-Info 'Efeito imediato via tap RegNtPreSetValueKey. Phase 2 vai ler o gate quando synthesizer lands.'
    }

    'DisableSynth' {
        Write-Section 'Track D - Disable value-synth (v5.0.6)'
        Assert-DriverInstalled
        Set-ItemProperty -Path $paramsKey -Name 'EnableValueSynth' -Value 0 -Type DWord -Force
        Write-OK 'EnableValueSynth = 0'
        Write-Info 'Efeito imediato. Outros gates (EnableRegCallback, EnableValueReadRewrite, EnableEdidValueRewrite) inalterados.'
    }

    'EnableFsFilter' {
        Write-Section 'Track D - Enable filesystem minifilter scaffolding (v5.0.7 Phase 0)'
        Assert-DriverInstalled
        Set-ItemProperty -Path $paramsKey -Name 'EnableFsFilter' -Value 1 -Type DWord -Force
        Write-OK 'EnableFsFilter = 1 (v5.0.7 Phase 0 scaffolding gate armed)'
        Write-Info 'Sem reader em Phase 0 - IRP preops retornam FLT_PREOP_SUCCESS_NO_CALLBACK.'
        Write-Info 'Persistencia + hot-toggle validation so. Phase 1 vai ler o gate no PreCreate.'
        Write-Info 'FltRegisterFilter roda automaticamente no boot via workitem; verifique com'
        Write-Info '  -Diagnose (LastFsFilterStatus deve mostrar 04 ARM-OK, FsFilterInstanceCount >= 1).'
    }

    'DisableFsFilter' {
        Write-Section 'Track D - Disable filesystem minifilter scaffolding (v5.0.7)'
        Assert-DriverInstalled
        Set-ItemProperty -Path $paramsKey -Name 'EnableFsFilter' -Value 0 -Type DWord -Force
        Write-OK 'EnableFsFilter = 0'
        Write-Info 'Efeito imediato via tap. Nao desregistra o filtro (isso e Phase 1+).'
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
        Show-Val 'EnableValueReadRewrite'  '(0 ou ausente = value handler off)'
        Show-Val 'EnableEdidValueRewrite'  '(0 ou ausente = EDID rewrite off)'
        Show-Val 'RegCallbackSeed'
        Show-Val 'CallbackHitCount'      '(0 ou nenhum rewrite landou)'
        Show-Val 'CallbackInvokeCount'   '(0 ou callback nunca entrou)'
        Show-Val 'CallbackNameMissCount' '(0 ou nenhum invoke rejeitado)'
        Show-Val 'LastMissImageName'     '(nenhum miss registrado)'

        # v5.0.5 Phase 0/1: per-path-type breakdown (enum-name side)
        Write-Host ''
        Write-Host '  --- Enum-name hit counters (v5.0.5 Phase 0/1) ---' -ForegroundColor DarkGray
        Show-Val 'CallbackHit_SCSI'            '(nenhum SCSI rewrite)'
        Show-Val 'CallbackHit_PCI'             '(nenhum PCI rewrite)'
        Show-Val 'CallbackHit_USB'             '(nenhum USB rewrite)'
        Show-Val 'CallbackHit_HID'             '(nenhum HID rewrite)'
        Show-Val 'CallbackHit_AudioR'          '(nenhum Audio Render rewrite)'
        Show-Val 'CallbackHit_AudioC'          '(nenhum Audio Capture rewrite)'
        Show-Val 'CallbackHit_BTH'             '(nenhum BTH rewrite)'
        Show-Val 'CallbackHit_Storage'         '(nenhum STORAGE\Volume rewrite)'
        Show-Val 'CallbackNonRubiParentMatch'  '(nenhum non-rubi processo tocou nossos parents)'

        # v5.0.5 Phase 2: per-surface VALUE-read counters
        Write-Host ''
        Write-Host '  --- Value-read hit counters (v5.0.5 Phase 2) ---' -ForegroundColor DarkGray
        Show-Val 'CallbackValHit_SCSI'         '(nenhum value read SCSI engajado)'
        Show-Val 'CallbackValHit_PCI'          '(nenhum value read PCI engajado)'
        Show-Val 'CallbackValHit_BTH'          '(nenhum value read BTH engajado)'
        Show-Val 'CallbackValHit_Storage'      '(nenhum value read STORAGE engajado)'
        Show-Val 'CallbackValHit_Edid'         '(nenhum value read EDID engajado)'
        Show-Val 'CallbackNonRubiValueMatch'   '(nenhum non-rubi leu um value alvo)'
        Show-Val 'CallbackHitRingIndex'        '(ring buffer nunca escrito)'

        # v5.0.6 Phase 0: synthesizer scaffolding + measure-first counters.
        # SynthHit_* + Synth*Bail stay 0 in Phase 0 (Phase 2 wires bumps);
        # the 3 measure-first (LocationInfo/Paths/ContainerID) ARE wired
        # in Phase 0 - non-zero means EMAC reads that value name via
        # RegQueryValueEx on one of our classified parents.
        Write-Host ''
        Write-Host '  --- v5.0.6 Phase 0 scaffolding (SynthHit_* + SynthBail dormant; measure-first WIRED) ---' -ForegroundColor DarkGray
        Show-Val 'EnableValueSynth'                          '(0 ou ausente = synth gate off; Phase 2 lands the reader)'
        Show-Val 'CallbackSynthHit_SCSI_FriendlyName'        '(Phase 2)'
        Show-Val 'CallbackSynthHit_SCSI_DeviceDesc'          '(Phase 2)'
        Show-Val 'CallbackSynthHit_SCSI_Mfg'                 '(Phase 2)'
        Show-Val 'CallbackSynthHit_PCI_FriendlyName'         '(Phase 2)'
        Show-Val 'CallbackSynthHit_PCI_DeviceDesc'           '(Phase 2)'
        Show-Val 'CallbackSynthHit_PCI_Mfg'                  '(Phase 2)'
        Show-Val 'CallbackSynthHit_USB_FriendlyName'         '(Phase 2)'
        Show-Val 'CallbackSynthHit_HID_FriendlyName'         '(Phase 2)'
        Show-Val 'CallbackSynthHit_BTH_FriendlyName'         '(Phase 2)'
        Show-Val 'CallbackSynthTypeMismatchBail'             '(Phase 2)'
        Show-Val 'CallbackSynthOverflowBail'                 '(Phase 2)'
        Show-Val 'CallbackSynthSizeSanityBail'               '(Phase 2)'
        Show-Val 'CallbackSynthInventoryMissBail'            '(Phase 2)'
        Show-Val 'CallbackValHit_LocationInfo'               '(0 = EMAC nao le LocationInformation em parents classificados)'
        Show-Val 'CallbackValHit_LocationPaths'              '(0 = EMAC nao le LocationPaths)'
        Show-Val 'CallbackValHit_ContainerID'                '(0 = EMAC nao le ContainerID)'

        # v5.0.7 Phase 0: filesystem minifilter scaffolding. Phase 0 wires
        # ONLY FsFilterRegistered + FsFilterInstanceCount + LastFsFilterStatus;
        # the rest stay 0 until Phase 1 wires the PreCreate/PostDirCtl hide
        # + counter bumps.
        Write-Host ''
        Write-Host '  --- v5.0.7 Phase 0 scaffolding (Fs* counters dormant except InstanceCount + arm status) ---' -ForegroundColor DarkGray
        Show-Val 'EnableFsFilter'                            '(0 ou ausente = gate off; Phase 1 le no PreCreate)'
        Show-Val 'FsFilterRegistered'                        '(1 se FltRegisterFilter+FltStartFiltering ambos OK; 0 caso contrario)'
        Show-Val 'FsFilterInstanceCount'                     '(volumes atacheados; >=1 comprova bind ao filesystem stack)'
        Show-Val 'FsHideHitCount'                            '(dormant em P0; Phase 1 wira)'
        Show-Val 'FsFilterCreateHit'                         '(dormant em P0)'
        Show-Val 'FsFilterReadHit'                           '(dormant em P0)'
        Show-Val 'FsFilterDirCtlHit'                         '(dormant em P0)'
        Show-Val 'FsGateMissCount'                           '(dormant em P0)'
        Show-Val 'FsFilterAllocBail'                         '(dormant em P0)'
        Show-Val 'FsProbe_InstallDir'                        '(dormant em P0; Phase 1 measure-first)'
        Show-Val 'FsProbe_System32Drivers'                   '(dormant em P0; Phase 1 measure-first)'
        Show-Val 'FsProbe_CatRoot'                           '(dormant em P0; Phase 1 measure-first)'

        # LastFsFilterStatus decoded (v5.0.7 Phase 0 arm-worker breadcrumb).
        # Own tag set independent of tagTable (which decodes Cm callback path).
        $fsTagTable = @{
            0x00 = '(unset)'
            0x01 = 'INSTANCES-WRITE-FAIL (Zw* into Services\RstFlt\Instances)'
            0x02 = 'FLT-REGISTER-FAIL (FltRegisterFilter)'
            0x03 = 'FLT-START-FAIL (FltStartFiltering; filter unregistered)'
            0x04 = 'ARM-OK'
            0x05 = 'ARM-NULL-DRVOBJ (workitem lost the DrvObj pointer)'
            0x06 = 'MANDATORY-UNLOAD (FltMgr forced tear-down; state cleared)'
            0x07 = 'ARM-GATED-OFF (EnableFsFilter=0; arm intentionally skipped)'
        }
        $fsLast = $null
        if ($vals -and $vals.PSObject.Properties.Name -contains 'LastFsFilterStatus') {
            $fsLast = [uint32]$vals.LastFsFilterStatus
        }
        if ($null -eq $fsLast) {
            Write-Host ('  {0,-22}: (ausente - driver pre-v5.0.7 ou arm-worker nao rodou)' -f 'LastFsFilterStatus') -ForegroundColor DarkGray
        } else {
            $fsTag = [int](($fsLast -shr 24) -band 0xFF)
            $fsSt  = [int]($fsLast -band 0x00FFFFFF)
            $fsLabel = if ($fsTagTable.ContainsKey($fsTag)) { $fsTagTable[$fsTag] } else { ('unknown tag 0x{0:X2}' -f $fsTag) }
            Write-Host ('  {0,-22}: tag=0x{1:X2} status=0x{2:X6}  {3}' -f 'LastFsFilterStatus', $fsTag, $fsSt, $fsLabel) -ForegroundColor Cyan
        }

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

        # v5.0.5 Phase 0: ring buffer decode
        $ring = $null
        if ($vals -and $vals.PSObject.Properties.Name -contains 'HitRingBuffer') {
            $ring = $vals.HitRingBuffer
        }
        if ($null -ne $ring -and $ring.Length -ge 96) {
            $recSize = 96      # sizeof(TRACKD_HIT_RECORD) w/ MSVC x64 alignment
            # v5.0.6 Phase 0: ring size is now driver-side (128); derive from
            # the on-disk REG_BINARY length so a pre-v5.0.6 (16-slot / 1536-
            # byte) blob keeps decoding. Cap at a defensive maximum in case a
            # corrupted value ever surfaces a huge blob.
            $maxSlots = 2048
            $slotCount = [int]($ring.Length / $recSize)
            if ($slotCount -gt $maxSlots) { $slotCount = $maxSlots }
            $pathNames = @{
                0 = 'NONE   '; 1 = 'SCSI   '; 2 = 'PCI    ';
                3 = 'USB    '; 4 = 'HID    '; 5 = 'AudioR '; 6 = 'AudioC ';
                7 = 'BTH    '; 8 = 'Storage';  # v5.0.5 Phase 1 (wired)
                9 = 'EDID   '                  # v5.0.5 Phase 2 (value-only)
            }
            # v5.0.5 Phase 2: WasGated is now a kind byte, not a bool:
            #   0 = enum-side non-rubi parent match
            #   1 = enum-side gated rewrite landed
            #   2 = value-side gated engage (substring rewriter)
            #   3 = value-side non-rubi match
            #   4 = value-side gated engage via SYNTH (v5.0.6 Phase 2 OEM
            #       string synthesizer path; distinct from substring so
            #       ring forensics can bucket which path landed)
            $kindNames = @{ 0 = 'e/no '; 1 = 'e/YES'; 2 = 'v/YES'; 3 = 'v/no '; 4 = 'v/SYN' }
            # Windows-1252 preserves bytes >= 0x80 as printable characters
            # (matching how EPROCESS.ImageFileName renders in Windows tooling);
            # ASCII would substitute '?' for those bytes, defeating triage of
            # anomalous image names - exactly Phase 0's job.
            $ansiEnc = [Text.Encoding]::GetEncoding(1252)
            Write-Host ''
            Write-Host ('  --- Ring buffer (last {0} hits, physical slot order) ---' -f $slotCount) -ForegroundColor DarkGray
            Write-Host '  slot  timestamp                    image             type     kind   hash    child' -ForegroundColor DarkGray
            $anyValid = $false
            for ($i = 0; $i -lt $slotCount; $i++) {
                $off = $i * $recSize
                $ts  = [System.BitConverter]::ToInt64($ring, $off)
                if ($ts -eq 0) { continue }   # empty slot OR mid-write invalid
                $anyValid = $true
                # UTC + full date so records spanning midnight or from prior
                # sessions are unambiguous. Matches kernel-side KeQuerySystemTime
                # which returns UTC FILETIME ticks.
                $tsStr = try { [DateTime]::FromFileTimeUtc($ts).ToString('yyyy-MM-dd HH:mm:ss.fff') } catch { '(invalid)             ' }
                $img = $ansiEnc.GetString($ring, $off + 8, 16).TrimEnd([char]0)
                $pt  = [int]$ring[$off + 24]
                $wg  = [int]$ring[$off + 25]
                $hash = [System.BitConverter]::ToUInt16($ring, $off + 26)
                $child = [Text.Encoding]::Unicode.GetString($ring, $off + 28, 64).TrimEnd([char]0)
                $ptStr = $pathNames[$pt]
                if (-not $ptStr) { $ptStr = ('   ' + $pt + '   ') }
                $gStr = $kindNames[$wg]
                if (-not $gStr) { $gStr = ('  ' + $wg + '  ') }
                Write-Host ('   {0,2}  {1}   {2,-16}  {3}  {4}  0x{5:X4}  {6}' -f $i, $tsStr, $img, $ptStr, $gStr, $hash, $child) -ForegroundColor Cyan
            }
            if (-not $anyValid) {
                Write-Host ('   (todos os {0} slots vazios - nenhum hit ate agora)' -f $slotCount) -ForegroundColor DarkGray
            }
        } elseif ($null -ne $ring) {
            # v5.0.6 Phase 0: acceptable sizes are 1536 (pre-v5.0.6, 16 slots)
            # or 12288 (v5.0.6+, 128 slots); anything else is a schema drift.
            Write-Host ('  HitRingBuffer com tamanho inesperado ({0} bytes; esperava 1536 ou 12288)' -f $ring.Length) -ForegroundColor Yellow
        }

        Write-Section 'Tag legend'
        foreach ($k in ($tagTable.Keys | Sort-Object)) {
            Write-Host ('  0x{0:X2}  {1}' -f $k, $tagTable[$k]) -ForegroundColor DarkGray
        }

        Write-Section 'Interpretation (v5.0.4 + v5.0.5 Phase 0)'
        Write-Host '  InvokeCount=0                                       -> callback nao armado; inspecionar LastArmStatus' -ForegroundColor DarkGray
        Write-Host '  InvokeCount>0 & HitCount=0 & NameMissCount>0        -> callback fires mas name gate rejeita todos' -ForegroundColor DarkGray
        Write-Host '                                                         (LastMissImageName mostra quem dominou os misses)' -ForegroundColor DarkGray
        Write-Host '  InvokeCount>0 & HitCount>0                          -> callback opera; cruzar com check-consistency.ps1' -ForegroundColor DarkGray
        Write-Host '  LastMissImageName ~= rubinot* & NameMissCount>0     -> rubinot bateu no gate mas foi rejeitado pelo' -ForegroundColor DarkGray
        Write-Host '                                                         next-char guard (verificar leaf name real)' -ForegroundColor DarkGray
        Write-Host '  v5.0.5 Phase 0 diagnostics:' -ForegroundColor DarkGray
        Write-Host '    NonRubiParentMatch=0                              -> nenhum processo nao-rubi tocou nossos parents (gate OK)' -ForegroundColor DarkGray
        Write-Host '    NonRubiParentMatch>0 & ring mostra imgs nao-rubi  -> algum helper/service enumera HW; gate precisa broaden' -ForegroundColor DarkGray
        Write-Host '    Todos CallbackHit_XXX=0 & InvokeCount alto        -> EMAC usa RegOpenKey+RegQueryValueEx (nao RegEnumKeyEx);' -ForegroundColor DarkGray
        Write-Host '                                                         Phase 2 value handler resolve. Padrao esperado v5.0.5.' -ForegroundColor DarkGray
        Write-Host '  v5.0.5 Phase 2 diagnostics (value-read handler):' -ForegroundColor DarkGray
        Write-Host '    EnableValueReadRewrite=0                          -> value handler nao armado; rode -EnableValueRewrite' -ForegroundColor DarkGray
        Write-Host '    CallbackValHit_SCSI>0 (kind v/YES no ring)        -> rubinot leu HardwareID/etc SCSI; value rewrite engajou' -ForegroundColor DarkGray
        Write-Host '    ValHit_SCSI>0 & CallbackHit_SCSI=0                -> confirma o padrao by-name (o objetivo do Phase 2)' -ForegroundColor DarkGray
        Write-Host '    ValHit_BTH/Storage=0 apos sessao real            -> esses values nao carregam o token (esperado; addr/GUID' -ForegroundColor DarkGray
        Write-Host '                                                         vazam via instance-ID, nao via value)' -ForegroundColor DarkGray
        Write-Host '    NonRubiValueMatch>0                              -> processo non-rubi leu um value alvo; considerar gate' -ForegroundColor DarkGray
    }
}

exit 0
