#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Renomeia subchaves de instancia sob HKLM\SYSTEM\CurrentControlSet\Enum\
    USB\VID_*&PID_*\<instance> para sintetizar novos numeros de serie/instancia
    visiveis via RegOpenKey - Fase 5 GAP HWID (USB fingerprint).

.DESCRIPTION
    Reconnaissance (parallel-session recon 2026-08 + emac-recon-v2.md rev.3):
    EMAC (rubinot_dx.exe) executa 889 eventos RegOpenKey/RegQueryValueEx contra
    Enum\USB\* durante startup - a MAIOR superficie individual de fingerprint
    HWID coletada. Le ROOT_HUB30\<inst>, USB\VID_*&PID_*\<inst>\DeviceDesc,
    CompatibleIDs, FriendlyName, LocationInformation, ContainerID.

    EMAC eh 100% RegQueryValueEx-based: zero DeviceIoControl, zero WMI, zero
    SetupAPI direto contra devnode. Renomear a subchave de instancia rebalanceia
    a fingerprint sem que EMAC precise re-enumerar via CM_Get_Device_ID_List.

    Estrategia (mesmo padrao spoof-disk-registry.ps1 e spoof-audio-guids.ps1):
      1) reg.exe export do node de instancia inteiro
      2) regex-replace do nome de instancia (leaf name) por variante sintetica
         gerada via FNV-1a determinstico (seed do profile)
      3) regex-replace textual do nome antigo em HardwareID, CompatibleIDs,
         LocationInformation, ContainerID dentro do .reg
      4) reg.exe import + reg.exe delete do path antigo
      5) grava backup + mapping em C:\ProgramData\.hwcfg\

    CONVENCAO IMPORTANTE: NAO reescrevemos a subchave VID_XXXX&PID_XXXX (que
    identifica o driver a carregar - reescrever mata binding do driver e
    quebra o device). Reescrevemos SOMENTE o nome da instancia (leaf name)
    logo abaixo dela, que eh o campo tipicamente derivado do iSerialNumber
    do USB descriptor ou de um sinal PnP sintetico (formato "4&hex&0&NNNN").

    Cobertura (subchaves de Enum\USB consideradas):
      * VID_XXXX&PID_XXXX (device level) - PROCESSAR children (instances)
      * ROOT_HUB30 / ROOT_HUB20 (root hub controller) - SKIP (risco de PnP)
      * USBSTOR (storage) - SKIP (coberto por spoof-disk-registry.ps1)
      * Vid_xxxx (variante lowercase) - normalizar e processar
      * ClassGUID de instancia = HIDClass (mouse/teclado via USB) - SKIP,
        deixado para spoof-hid-ids.ps1 (que tem safety "last HID input").

    Whitelist ClassGUID (safe - renomear cosmeticamente):
      {36fc9e60-c465-11cf-8056-444553540000}  USB (composite hub/device)
      {ca3e7ab9-b4c3-4ae6-8251-579ef933890f}  Camera (Windows.Devices.Enumeration)
      {6bdd1fc6-810f-11d0-bec7-08002be2092f}  Image (webcam legacy)
      {4d36e96c-e325-11ce-bfc1-08002be10318}  Media (audio device via USB)
      {88bae032-5a81-49f0-bc3d-a4ff138216d6}  UsbPrinter

    Blacklist ClassGUID (SKIP):
      {745a17a0-74d3-11d0-b6fe-00a0c90f57da}  HIDClass  -> spoof-hid-ids.ps1
      {4d36e96b-e325-11ce-bfc1-08002be10318}  Keyboard  -> spoof-hid-ids.ps1
      {4d36e96f-e325-11ce-bfc1-08002be10318}  Mouse     -> spoof-hid-ids.ps1
      {4d36e97b-e325-11ce-bfc1-08002be10318}  SCSIAdapter -> boot risk
      {71a27cdd-812a-11d0-bec7-08002be2092f}  Volume -> boot risk

    Instancias com ClassGUID nao whitelisted (unknown) sao PULADAS por
    seguranca - preferimos under-coverage a quebrar hardware.

    Safety adicional (adotado de spoof-disk-registry.ps1):
      - Detecta USB boot device (Get-Volume SystemDrive -> Get-Disk -> se
        BusType USB, resolve ContainerID via Get-PnpDeviceProperty e adiciona
        ao set de ContainerIDs protegidos).
      - Detecta o mouse/teclado atualmente presente (Get-PnpDevice -Class
        Mouse/Keyboard onde Status=OK) e adiciona seus ContainerIDs ao set
        protegido. Toda instancia USB cujo ContainerID bata com um protegido
        eh pulada.
      - LocationInformation contendo "Boot" ou "System" -> SKIP.

    Determinismo:
      Seed FNV-1a lido de $prof.pci_hardwareid.randomize_seed (mesmo seed
      usado por spoof-pci-hardwareid.ps1 e spoof-network-ids.ps1). Rerun com
      mesmo profile = mesmo mapping. Se profile ausente, cai para GUID
      ephemera (mapping muda a cada run).

    CAVEAT PnP:
      Windows PnP Manager pode re-enumerar dispositivos USB em hot-plug e
      RECRIAR a subchave de instancia original (mesmo pattern documentado
      em emac-recon-v2.md:185-190 para Network Connection PnPInstanceId).
      Recomendacao: rodar este script como ULTIMO passo antes de abrir o
      cliente do jogo, e NAO hot-unplugar/plugar USB durante a sessao.
      Um reboot re-aplica o mapping via rerun (mapping persistido eh estavel).

    Uso:
      .\spoof-usb-ids.ps1              # aplica spoof
      .\spoof-usb-ids.ps1 -DryRun      # mostra plano sem escrever
      .\spoof-usb-ids.ps1 -Restore     # reverte via backup
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Restore
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"
$mappingPath = "C:\ProgramData\.hwcfg\usb-ids-mapping.json"
$backupPath  = "C:\ProgramData\.hwcfg\usb-ids-backup.json"
$usbRoot     = "HKLM\SYSTEM\CurrentControlSet\Enum\USB"
$usbRootPs   = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"

# ClassGUIDs whitelisted - renomeaveis com seguranca
$WhitelistClasses = @(
    '{36fc9e60-c465-11cf-8056-444553540000}',  # USB
    '{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}',  # Camera
    '{6bdd1fc6-810f-11d0-bec7-08002be2092f}',  # Image
    '{4d36e96c-e325-11ce-bfc1-08002be10318}',  # Media
    '{88bae032-5a81-49f0-bc3d-a4ff138216d6}'   # UsbPrinter
)

# ClassGUIDs blacklisted - NUNCA renomear
$BlacklistClasses = @(
    '{745a17a0-74d3-11d0-b6fe-00a0c90f57da}',  # HIDClass -> spoof-hid-ids.ps1
    '{4d36e96b-e325-11ce-bfc1-08002be10318}',  # Keyboard
    '{4d36e96f-e325-11ce-bfc1-08002be10318}',  # Mouse
    '{4d36e97b-e325-11ce-bfc1-08002be10318}',  # SCSIAdapter
    '{71a27cdd-812a-11d0-bec7-08002be2092f}'   # Volume
)

# ============================================================
#  Helpers
# ============================================================

function Invoke-Reg {
    param([string[]]$RegArgs)
    # PS 5.1 gotcha: com $ErrorActionPreference='Stop' no scope pai, `2>&1`
    # de nativo converte stderr em NativeCommandError e THROW mesmo quando
    # o exit code eh 0 (ex.: reg.exe pt-BR escreve "A operacao foi concluida
    # com exito" no stderr em SUCESSO). Isolamos com scope + Continue pref.
    $out = & {
        $ErrorActionPreference = 'Continue'
        & reg.exe @RegArgs 2>&1
    }
    if ($LASTEXITCODE -ne 0) {
        throw ("reg.exe " + ($RegArgs -join ' ') + " falhou (" + $LASTEXITCODE + "): " + ($out -join "`n"))
    }
    return $out
}

# FNV-1a 64bit deterministico - identico ao usado por spoof-pci-hardwareid.ps1
function Get-Fnv1a64Hash {
    param([string]$InputText)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
    $hash  = [System.Numerics.BigInteger]::Parse("14695981039346656037")
    $prime = [System.Numerics.BigInteger]::Parse("1099511628211")
    $mask  = [System.Numerics.BigInteger]::Parse("18446744073709551615")
    foreach ($b in $bytes) {
        $hash = $hash -bxor ([System.Numerics.BigInteger]$b)
        $hash = ($hash * $prime) -band $mask
    }
    return [uint64]$hash
}

# Gera N caracteres hex derivados de FNV(seed + salt). Repete o hash se
# precisar de mais que 16 chars (64bit hex = 16 chars).
function Get-DetHex {
    param([string]$Seed, [string]$Salt, [int]$Length)
    $out = ""
    $i = 0
    while ($out.Length -lt $Length) {
        $h = Get-Fnv1a64Hash -InputText ($Seed + "|" + $Salt + "|" + $i)
        $out += ("{0:x16}" -f $h)
        $i++
    }
    return $out.Substring(0, $Length)
}

# Gera nome sintetico para instancia USB preservando estrutura "&".
# Exemplos:
#   "4&2af66358&0&0001" -> "4&<8hex>&0&<4hex>"  (preserva N-alpha e sufixo)
#   "AABBCCDD"          -> "<8hex>"             (mesmo tamanho)
#   "6&1234abcd&0&2"    -> "6&<8hex>&0&<1hex>"
#
# Regra: componentes puramente numericos <= 4 chars sao preservados (indices
# de porta/interface), componentes hex maiores sao regenerados via FNV.
function New-SyntheticInstance {
    param([string]$OriginalName, [string]$Seed, [string]$ParentKey)
    if ([string]::IsNullOrWhiteSpace($OriginalName)) { return $OriginalName }
    $salt = $ParentKey + "|" + $OriginalName
    if ($OriginalName -notmatch '&') {
        # Nome monolitico (comum quando iSerialNumber real): regenera todo com hex de mesmo tamanho.
        $len = $OriginalName.Length
        return (Get-DetHex -Seed $Seed -Salt $salt -Length $len).ToUpper()
    }
    $parts = $OriginalName -split '&'
    $newParts = @()
    $idx = 0
    foreach ($p in $parts) {
        # Preserva componentes decimais curtos (indices de porta/hub/interface)
        if ($p -match '^\d{1,4}$') {
            $newParts += $p
        } elseif ($p.Length -gt 0) {
            $ln = $p.Length
            $newParts += (Get-DetHex -Seed $Seed -Salt ($salt + "|" + $idx) -Length $ln)
        } else {
            $newParts += ""
        }
        $idx++
    }
    return ($newParts -join '&')
}

# Le ClassGUID de uma subchave (retorna string em lower-case sem quotes, ou $null)
function Get-InstanceClassGuid {
    param([string]$InstancePathPs)
    try {
        $v = Get-ItemProperty -Path $InstancePathPs -Name "ClassGUID" -ErrorAction Stop
        return ([string]$v.ClassGUID).Trim().ToLower()
    } catch {
        return $null
    }
}

# Le LocationInformation de uma subchave (retorna string ou $null)
function Get-InstanceLocationInfo {
    param([string]$InstancePathPs)
    try {
        $v = Get-ItemProperty -Path $InstancePathPs -Name "LocationInformation" -ErrorAction Stop
        return [string]$v.LocationInformation
    } catch {
        return $null
    }
}

# Le ContainerID via cfgmgr32 (Get-PnpDeviceProperty). Historicamente a versao
# antiga tentava leitura direta em Properties\{fmtid}\<pid-hex>\(Default), mas
# a pid hex nao eh universal entre builds (Win7 vs Win8 vs Win10 divergiam
# entre \0002 e \0007 - ambos aparecem em documentacoes distintas). O caminho
# via cfgmgr32 normaliza e eh o mesmo usado por Get-ProtectedContainerIds,
# garantindo que os dois lados leem a mesma fonte de verdade.
function Get-InstanceContainerId {
    param([string]$InstancePathPs)
    # Derive InstanceId PnP a partir do path do registry.
    # Ex: "...\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_046D&PID_C077\5&2f34a9b&0&5"
    #     -> "USB\VID_046D&PID_C077\5&2f34a9b&0&5"
    try {
        $marker = "\Enum\"
        $idx = $InstancePathPs.IndexOf($marker)
        if ($idx -lt 0) { return $null }
        $instanceId = $InstancePathPs.Substring($idx + $marker.Length)
        $prop = Get-PnpDeviceProperty -InstanceId $instanceId -KeyName 'DEVPKEY_Device_ContainerId' -ErrorAction Stop
        if ($prop -and $prop.Data) { return ([string]$prop.Data).Trim().ToLower() }
    } catch {}
    return $null
}

# Coleta os ContainerIDs protegidos: boot device (se USB), todos os mice/keyboards Present.
function Get-ProtectedContainerIds {
    $protected = New-Object System.Collections.Generic.HashSet[string]

    # Boot volume - so protege se BusType USB
    try {
        $sd = $env:SystemDrive
        $letter = $sd.TrimEnd(':').TrimEnd('\')
        $part = Get-Partition -DriveLetter $letter -ErrorAction Stop
        $disk = $part | Get-Disk -ErrorAction Stop
        if ($disk.BusType -eq 'USB') {
            $wd = Get-CimInstance -ClassName Win32_DiskDrive -Filter ("Index=" + $disk.Number) -ErrorAction Stop
            if ($wd -and $wd.PNPDeviceID) {
                try {
                    $c = Get-PnpDeviceProperty -InstanceId $wd.PNPDeviceID -KeyName 'DEVPKEY_Device_ContainerId' -ErrorAction Stop
                    if ($c -and $c.Data) { [void]$protected.Add(([string]$c.Data).ToLower()) }
                } catch {}
            }
            Write-Warn "Boot volume esta em USB - ContainerID protegido"
        }
    } catch {
        Write-Warn ("Nao consegui inspecionar boot volume: " + $_.Exception.Message)
    }

    # Mice + Keyboards presentes. -PresentOnly (em vez de -Status OK) para pegar
    # tambem devices em Degraded/Unknown/Error; senao um mouse com driver mal-
    # aplicado ou keyboard com Code 10 nao entra na lista e o loop poderia
    # renomear a subchave USB do dongle dele.
    foreach ($cls in @('Mouse','Keyboard')) {
        try {
            $devs = Get-PnpDevice -Class $cls -PresentOnly -ErrorAction Stop
            foreach ($d in $devs) {
                try {
                    $c = Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_ContainerId' -ErrorAction Stop
                    if ($c -and $c.Data) { [void]$protected.Add(([string]$c.Data).ToLower()) }
                } catch {}
            }
        } catch {}
    }

    return $protected
}

# ============================================================
#  Per-device PnP pause/resume (handle-contention fix - Approach B)
#
#  reg.exe delete de HKLM\SYSTEM\CurrentControlSet\Enum\USB\<parent>\<inst>
#  falha com sharing violation quando PnP Manager mantem handle na subkey de
#  instancia (comportamento default do PnP Manager quando o device esta
#  arm e enumerado). Solucao: Disable-PnpDevice antes do rename (release do
#  handle); Enable-PnpDevice contra o NOVO InstanceId depois (o velho
#  InstanceId nao existe mais no Enum\USB apos rename bem-sucedido).
#
#  Trade-off conhecido: 2-5 segundos com o device sem driver (pause de
#  camera USB, pause de printer status, etc). Mouse/teclado sao BLINDADOS
#  pela lista Get-ProtectedContainerIds acima - nunca chegam aqui.
#
#  CAVEAT PnP:
#    Enable-PnpDevice contra o novo InstanceId as vezes falha porque o
#    Device Manager ainda associa InstanceId=velho ao device fisico. Sem
#    disparar `pnputil /scan-devices` (que pode recriar a subkey ORIGINAL
#    ao lado da fake - double-record obvio para EMAC), o device volta em
#    re-scan periodico do PnP ou por re-plug fisico. Log warn e siga.
# ============================================================

function Suspend-DeviceForRename {
    param([string]$InstanceId)
    # Retorna $true se disable teve efeito, $false caso contrario (device
    # ja disabled, device ausente, sem permissao). Nao lanca em erro para
    # nao interromper o loop - se falhar, tentamos o rename mesmo assim.
    try {
        Disable-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction Stop
        Write-Info ("  PnP disabled: " + $InstanceId)
        return $true
    } catch {
        Write-Warn ("  Disable-PnpDevice falhou (" + $InstanceId + "): " + $_.Exception.Message)
        Write-Warn "  Prosseguindo com rename - pode falhar com sharing violation"
        return $false
    }
}

function Resume-DeviceForRename {
    param([string]$InstanceId)
    # Tenta enable via InstanceId fornecido. Se falhar, warn e siga - o
    # device retorna em re-scan periodico do PnP ou por re-plug.
    try {
        Enable-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction Stop
        Write-Info ("  PnP re-enabled: " + $InstanceId)
    } catch {
        Write-Warn ("  Enable-PnpDevice falhou (" + $InstanceId + "): " + $_.Exception.Message)
        Write-Warn "  Device pode precisar re-plug fisico OU volta em re-scan PnP"
    }
}

# ============================================================
#  Boundary-safe rename dentro do .reg exportado
#
#  Substituir o nome de instancia via [regex]::Replace no arquivo inteiro eh
#  perigoso: instNames curtos/numericos podem casar dentro de LocationInformation
#  (ex.: "Port_#0005"), ParentIdPrefix, BusRelations, fragmentos de GUID, etc.,
#  causando corrupcao colateral silenciosa. Este helper aplica a substituicao
#  APENAS em:
#    (a) linhas de section header:  [HKLM\...\Enum\USB\<parentKey>\<instName>...]
#    (b) linhas de valor conhecidas: HardwareID, CompatibleIDs,
#         LocationInformation, ContainerID
#    (c) linhas de continuacao (backslash no fim) de um dos valores em (b),
#         para cobrir hex(7) multi-linha.
# ============================================================
function Rename-InstanceInReg {
    param(
        [string]$Content,
        [string]$ParentKey,
        [string]$OldInst,
        [string]$NewInst
    )
    if ([string]::IsNullOrEmpty($Content)) { return $Content }
    $escOld    = [regex]::Escape($OldInst)
    $escParent = [regex]::Escape($ParentKey)
    # Section header: linha comeca com '[HKEY_LOCAL_MACHINE\...\Enum\USB\<parent>\<inst>'
    # e termina em '\...]' ou ']'.
    $headerRe = '(?i)^\[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USB\\' + $escParent + '\\' + $escOld + '(\\|\])'
    # Value line: um dos fingerprint values conhecidos.
    $valueRe  = '(?i)^"(HardwareID|CompatibleIDs|LocationInformation|ContainerID)"='

    # Preserva os separadores de linha originais dividindo em linhas fisicas.
    $lines = $Content -split "`r`n", -1
    $out = New-Object System.Collections.Generic.List[string]
    $inTargetValue = $false
    foreach ($line in $lines) {
        $shouldReplace = $false
        if ($line -match $headerRe) {
            $shouldReplace = $true
            $inTargetValue = $false
        } elseif ($line -match $valueRe) {
            $shouldReplace = $true
            # Se termina em backslash, ha continuacao hex nas linhas seguintes.
            $inTargetValue = ($line.TrimEnd() -match '\\$')
        } elseif ($inTargetValue) {
            $shouldReplace = $true
            $inTargetValue = ($line.TrimEnd() -match '\\$')
        } else {
            $inTargetValue = $false
        }
        if ($shouldReplace) {
            $out.Add([regex]::Replace($line, $escOld, $NewInst, 'IgnoreCase'))
        } else {
            $out.Add($line)
        }
    }
    return ($out -join "`r`n")
}

# Parser leve de hex(7) (REG_MULTI_SZ UTF-16LE) dentro de conteudo .reg exportado.
# Retorna array de strings (sem terminador vazio) ou $null se nao encontrar.
# Usado como cross-check no spoof: garante que os valores HardwareID/CompatibleIDs
# no .reg exportado batem com $savedValues lidos via Get-ItemProperty antes de
# reescrever - defesa contra corrupcao/desalinhamento.
function Get-RegMultiSzFromReg {
    param([string]$Content, [string]$ValueName)
    if ([string]::IsNullOrEmpty($Content)) { return $null }
    $esc = [regex]::Escape($ValueName)
    # hex(7) pode se estender em multiplas linhas com '\' + CRLF + espacos.
    $pattern = '(?im)^"' + $esc + '"=hex\(7\):((?:[0-9a-fA-F]{2},?\s*\\?\s*)+)'
    $m = [regex]::Match($Content, $pattern)
    if (-not $m.Success) { return $null }
    $hex = $m.Groups[1].Value
    # Remove continuacoes, whitespace, virgulas
    $hex = ($hex -replace '[\\\r\n\s]', '')
    $tokens = @($hex -split ',')
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($t in $tokens) {
        if ($t -match '^[0-9a-fA-F]{2}$') {
            [void]$bytes.Add([byte]::Parse($t, [System.Globalization.NumberStyles]::HexNumber))
        }
    }
    if ($bytes.Count -eq 0) { return $null }
    $str = [System.Text.Encoding]::Unicode.GetString($bytes.ToArray())
    # MULTI_SZ: strings separadas por \0, terminadas por \0\0
    $parts = $str.TrimEnd([char]0) -split "`0"
    return @($parts | Where-Object { $_ -ne '' })
}

# ============================================================
#  Restore mode
# ============================================================
if ($Restore) {
    Write-Section "Restore de USB IDs"
    if (-not (Test-Path $backupPath)) {
        Write-Err ("Backup nao encontrado: " + $backupPath)
        exit 1
    }
    try {
        $bkp = Get-Content $backupPath -Raw | ConvertFrom-Json
    } catch {
        Write-Err ("Backup corrompido: " + $_.Exception.Message)
        exit 1
    }

    $restored = 0
    $failedRestore = 0
    foreach ($e in @($bkp.entries)) {
        $parentKey    = [string]$e.parent_key   # ex: VID_046D&PID_C077
        $origInst     = [string]$e.orig_instance
        $newInst      = [string]$e.new_instance
        $currentPathReg = "$usbRoot\$parentKey\$newInst"
        $origPathReg    = "$usbRoot\$parentKey\$origInst"
        $currentPathPs  = Join-Path (Join-Path $usbRootPs $parentKey) $newInst

        if (-not (Test-Path $currentPathPs)) {
            Write-Warn ("Instancia spoofada ausente: " + $parentKey + "\" + $newInst)
            continue
        }

        if ($DryRun) {
            Write-Info ("[DryRun] Restauraria: " + $parentKey + "\" + $newInst + " -> " + $origInst)
            continue
        }

        # InstanceIds completos para PnP suspend/resume. No Restore, o device
        # comeca com o NOME SPOOFADO ($newInst) e termina com o ORIGINAL ($origInst).
        $currentInstanceId  = "USB\" + $parentKey + "\" + $newInst
        $restoredInstanceId = "USB\" + $parentKey + "\" + $origInst
        $tmpFile = Join-Path $env:TEMP ("usb-restore-" + [guid]::NewGuid().ToString() + ".reg")
        $deviceWasSuspended = $false
        try {
            $deviceWasSuspended = Suspend-DeviceForRename -InstanceId $currentInstanceId

            [void](Invoke-Reg -RegArgs @("export", $currentPathReg, $tmpFile, "/y"))
            $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode

            # Reverte o nome de instancia SOMENTE em section headers e em value lines
            # conhecidas (HardwareID/CompatibleIDs/LocationInformation/ContainerID),
            # evitando substituicao colateral em Port_#XXXX, ParentIdPrefix, etc.
            $newContent = Rename-InstanceInReg -Content $content -ParentKey $parentKey -OldInst $newInst -NewInst $origInst

            Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline
            [void](Invoke-Reg -RegArgs @("import", $tmpFile))
            [void](Invoke-Reg -RegArgs @("delete", $currentPathReg, "/f"))

            # Restaura valores textuais originais se ainda existirem no backup
            $origPathPs = Join-Path (Join-Path $usbRootPs $parentKey) $origInst
            if ((Test-Path $origPathPs) -and $e.saved_values) {
                foreach ($vn in @('HardwareID','CompatibleIDs')) {
                    $arr = $e.saved_values.$vn
                    if ($arr) {
                        try { Set-ItemProperty -Path $origPathPs -Name $vn -Value @($arr) -Type MultiString -ErrorAction Stop } catch {}
                    }
                }
                foreach ($vn in @('LocationInformation','ContainerID','FriendlyName','DeviceDesc','Mfg')) {
                    $val = $e.saved_values.$vn
                    if ($null -ne $val) {
                        try { Set-ItemProperty -Path $origPathPs -Name $vn -Value $val -ErrorAction Stop } catch {}
                    }
                }
            }

            $restored++
            Write-OK ($parentKey + "\" + $newInst + " -> " + $origInst)
        } catch {
            Write-Err ("Falha restaurando " + $parentKey + "\" + $newInst + ": " + $_.Exception.Message)
            $failedRestore++
        } finally {
            if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
            if ($deviceWasSuspended) {
                # Prefer novo path (rename bem-sucedido) senao velho (rename falhou -
                # subkey original ainda existe). Test-Path decide.
                if (Test-Path (Join-Path (Join-Path $usbRootPs $parentKey) $origInst)) {
                    Resume-DeviceForRename -InstanceId $restoredInstanceId
                } else {
                    Resume-DeviceForRename -InstanceId $currentInstanceId
                }
            }
        }
    }

    if (-not $DryRun -and $restored -gt 0 -and $failedRestore -eq 0) {
        try { Remove-Item $backupPath -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item $mappingPath -Force -ErrorAction SilentlyContinue } catch {}
        Write-OK "Backup e mapping removidos"
    } elseif ($failedRestore -gt 0) {
        Write-Warn ("Backup preservado (" + $failedRestore + " falha(s) - rode novamente apos investigar)")
    }

    Write-Section "Resumo restore"
    Write-Host ("  Restauradas: " + $restored)        -ForegroundColor Cyan
    Write-Host ("  Falhas     : " + $failedRestore)   -ForegroundColor Cyan
    Write-Warn "PnP pode re-enumerar no proximo boot - reconferir com check-consistency.ps1"
    if ($failedRestore -gt 0) { exit 1 } else { exit 0 }
}

# ============================================================
#  Spoof mode
# ============================================================
Write-Section "Spoof de USB IDs (Enum\USB)"

# 1) Profile + seed
$seed = $null
if (Test-Path $profilePath) {
    try {
        $prof = Get-Content $profilePath -Raw | ConvertFrom-Json
        if ($prof.pci_hardwareid -and $prof.pci_hardwareid.randomize_seed) {
            $seed = [string]$prof.pci_hardwareid.randomize_seed
        }
    } catch {
        Write-Warn ("Profile corrompido: " + $_.Exception.Message)
    }
}
if ([string]::IsNullOrWhiteSpace($seed)) {
    $seed = [guid]::NewGuid().ToString('N')
    Write-Warn "Profile ausente/sem seed - usando seed ephemera (mapping mudara a cada run)"
} else {
    Write-OK ("Seed FNV: " + $seed.Substring(0,8) + "... (" + $seed.Length + " chars)")
}

# 2) Detectar ContainerIDs protegidos
Write-Section "Deteccao de ContainerIDs protegidos"
$protected = Get-ProtectedContainerIds
if ($protected.Count -eq 0) {
    Write-Info "Nenhum ContainerID USB protegido detectado (boot nao USB, sem mouse/kb USB)"
} else {
    Write-OK ("ContainerIDs protegidos: " + $protected.Count)
    foreach ($cid in $protected) { Write-Info ("  " + $cid) }
}

# 3) Enumerar Enum\USB
if (-not (Test-Path $usbRootPs)) {
    Write-Err ("Path nao existe: " + $usbRootPs)
    exit 1
}

$allDevKeys = @(Get-ChildItem -Path $usbRootPs -ErrorAction SilentlyContinue)
$vidKeys = @($allDevKeys | Where-Object {
    $n = $_.PSChildName
    ($n -match '^(?i)VID_[0-9A-F]{4}&PID_[0-9A-F]{4}(&MI_[0-9A-F]{2})?$')
})

# Detecta composite parents (VID&PID com filhos MI_XX ao lado no mesmo nivel).
# usbccgp.sys linka parent<->children via BaseContainerId, LocationInformation
# Port_#XXXX.Hub_#YYYY, e PDO paths embutidos no registry dos filhos. Renomear
# somente o parent quebra os filhos porque a subkey referenciada some.
# Estrategia: pular o parent VID&PID inteiro quando qualquer MI_XX irmao existir.
$compositeParents = New-Object System.Collections.Generic.HashSet[string]
foreach ($k in $allDevKeys) {
    $nm = $k.PSChildName
    if ($nm -match '^(?i)(VID_[0-9A-F]{4}&PID_[0-9A-F]{4})&MI_[0-9A-F]{2}$') {
        [void]$compositeParents.Add($matches[1].ToUpper())
    }
}

$skippedRootHub = @($allDevKeys | Where-Object { $_.PSChildName -match '^(?i)ROOT_HUB' }).Count
$skippedUsbstor = @($allDevKeys | Where-Object { $_.PSChildName -eq 'USBSTOR' }).Count

Write-OK ("Devices VID&PID candidatos: " + $vidKeys.Count)
if ($skippedRootHub -gt 0) { Write-Info ("Root hubs pulados: " + $skippedRootHub) }
if ($skippedUsbstor -gt 0) { Write-Info ("USBSTOR pulado (coberto por spoof-disk-registry): " + $skippedUsbstor) }
if ($compositeParents.Count -gt 0) { Write-Info ("Composite parents detectados (parents com filhos MI_XX): " + $compositeParents.Count) }

if ($vidKeys.Count -eq 0) {
    Write-Warn "Nenhum device VID_*&PID_* encontrado - nada a fazer"
    exit 0
}

# 4) Carregar mapping anterior (estabilidade em reruns)
$existingMap = @{}
if (Test-Path $mappingPath) {
    try {
        $prev = Get-Content $mappingPath -Raw | ConvertFrom-Json
        foreach ($p in $prev.PSObject.Properties) { $existingMap[$p.Name] = $p.Value }
        Write-OK ("Mapping anterior carregado: " + $existingMap.Count + " entrada(s)")
    } catch {
        Write-Warn ("Falha lendo mapping anterior: " + $_.Exception.Message)
    }
}

# 5) Processar cada device
$backupEntries = @()
$newMapping    = @{}
$processed     = 0
$failed        = 0
$skippedHid       = 0
$skippedProt      = 0
$skippedClass     = 0
$skippedBoot      = 0
$skippedOther     = 0
$skippedComposite = 0

foreach ($dev in $vidKeys) {
    $parentKey = $dev.PSChildName
    $devPathPs = $dev.PSPath

    # Fix atomicidade composite: pula parent VID&PID inteiro quando ele tem
    # filhos MI_XX. Renomear apenas o parent quebraria os filhos porque a
    # subkey de referencia (BaseContainerId/PDO path) desaparece.
    if ($parentKey -match '^(?i)VID_[0-9A-F]{4}&PID_[0-9A-F]{4}$' -and $compositeParents.Contains($parentKey.ToUpper())) {
        Write-Warn ($parentKey + " - composite parent (tem MI_XX irmaos), pulando familia inteira para evitar quebrar filhos")
        $skippedComposite++
        continue
    }

    $instances = @()
    try { $instances = @(Get-ChildItem -Path $devPathPs -ErrorAction Stop) } catch {}
    if ($instances.Count -eq 0) {
        Write-Info ($parentKey + " - sem instancias, pulando")
        continue
    }

    foreach ($inst in $instances) {
        $instName   = $inst.PSChildName
        $instPathPs = $inst.PSPath
        $mapKey     = $parentKey + "\" + $instName

        # Skip se ja spoofada (mapping anterior)
        $alreadySpoofed = $false
        foreach ($mk in $existingMap.Keys) {
            $mv = $existingMap[$mk]
            if ($mv.new_instance -and $mv.parent_key -and $mv.parent_key -eq $parentKey -and $mv.new_instance -eq $instName) {
                $alreadySpoofed = $true; break
            }
        }
        if ($alreadySpoofed) {
            Write-Info ($mapKey + " - ja spoofada em run anterior, pulando")
            continue
        }

        # Le ClassGUID
        $cg = Get-InstanceClassGuid -InstancePathPs $instPathPs
        if ([string]::IsNullOrWhiteSpace($cg)) {
            Write-Warn ($mapKey + " - sem ClassGUID legivel, pulando por seguranca")
            $skippedOther++
            continue
        }

        # Blacklist -> skip
        if ($BlacklistClasses -contains $cg) {
            if ($cg -eq '{745a17a0-74d3-11d0-b6fe-00a0c90f57da}' -or
                $cg -eq '{4d36e96b-e325-11ce-bfc1-08002be10318}' -or
                $cg -eq '{4d36e96f-e325-11ce-bfc1-08002be10318}') {
                Write-Info ($mapKey + " - HID/Mouse/Keyboard (delegado a spoof-hid-ids.ps1)")
                $skippedHid++
            } else {
                Write-Info ($mapKey + " - Class " + $cg + " blacklisted")
                $skippedClass++
            }
            continue
        }

        # Whitelist check
        if (-not ($WhitelistClasses -contains $cg)) {
            Write-Info ($mapKey + " - Class " + $cg + " nao whitelisted, pulando por seguranca")
            $skippedClass++
            continue
        }

        # ContainerID protegido?
        $cid = Get-InstanceContainerId -InstancePathPs $instPathPs
        if ($cid -and $protected.Contains($cid)) {
            Write-Warn ($mapKey + " - ContainerID protegido (" + $cid + "), pulando")
            $skippedProt++
            continue
        }

        # LocationInformation contendo Boot/System?
        $loc = Get-InstanceLocationInfo -InstancePathPs $instPathPs
        if ($loc -and ($loc -match '(?i)Boot' -or $loc -match '(?i)System')) {
            Write-Warn ($mapKey + " - LocationInformation suspeito ('" + $loc + "'), pulando")
            $skippedBoot++
            continue
        }

        # Gerar nome sintetico
        $newInst = New-SyntheticInstance -OriginalName $instName -Seed $seed -ParentKey $parentKey
        if ($newInst -eq $instName) {
            Write-Info ($mapKey + " - sintetico igual ao original, pulando")
            continue
        }
        if (Test-Path (Join-Path (Join-Path $usbRootPs $parentKey) $newInst)) {
            Write-Warn ($mapKey + " - destino " + $newInst + " ja existe, pulando")
            $skippedOther++
            continue
        }

        # Coletar valores para backup textual
        $savedValues = [ordered]@{
            HardwareID          = $null
            CompatibleIDs       = $null
            LocationInformation = $null
            ContainerID         = $null
            FriendlyName        = $null
            DeviceDesc          = $null
            Mfg                 = $null
        }
        try {
            $props = Get-ItemProperty -Path $instPathPs -ErrorAction Stop
            if ($props.PSObject.Properties.Name -contains 'HardwareID')          { $savedValues.HardwareID          = @($props.HardwareID) }
            if ($props.PSObject.Properties.Name -contains 'CompatibleIDs')       { $savedValues.CompatibleIDs       = @($props.CompatibleIDs) }
            if ($props.PSObject.Properties.Name -contains 'LocationInformation') { $savedValues.LocationInformation = [string]$props.LocationInformation }
            if ($props.PSObject.Properties.Name -contains 'ContainerID')         { $savedValues.ContainerID         = [string]$props.ContainerID }
            if ($props.PSObject.Properties.Name -contains 'FriendlyName')        { $savedValues.FriendlyName        = [string]$props.FriendlyName }
            if ($props.PSObject.Properties.Name -contains 'DeviceDesc')          { $savedValues.DeviceDesc          = [string]$props.DeviceDesc }
            if ($props.PSObject.Properties.Name -contains 'Mfg')                 { $savedValues.Mfg                 = [string]$props.Mfg }
        } catch {}

        if ($DryRun) {
            Write-Info ("[DryRun] " + $mapKey + "  ->  " + $parentKey + "\" + $newInst)
            continue
        }

        # Rename via export/replace/import/delete
        $oldPathReg = "$usbRoot\$parentKey\$instName"
        $newPathReg = "$usbRoot\$parentKey\$newInst"
        # InstanceIds completos para PnP suspend/resume. Comeca com nome ORIGINAL
        # ($instName) e termina com nome SPOOFADO ($newInst).
        $oldInstanceId = "USB\" + $parentKey + "\" + $instName
        $newInstanceId = "USB\" + $parentKey + "\" + $newInst
        $tmpFile = Join-Path $env:TEMP ("usb-swap-" + [guid]::NewGuid().ToString() + ".reg")
        $deviceWasSuspended = $false
        try {
            $deviceWasSuspended = Suspend-DeviceForRename -InstanceId $oldInstanceId

            [void](Invoke-Reg -RegArgs @("export", $oldPathReg, $tmpFile, "/y"))
            $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode

            # Cross-check antes de reescrever: os HardwareID/CompatibleIDs no .reg
            # exportado devem bater com $savedValues lidos via Get-ItemProperty.
            # Divergencia -> reg export capturou estado diferente (device re-enumerado
            # entre leitura live e export). Abortar por seguranca em vez de gravar
            # bytes inconsistentes.
            foreach ($vn in @('HardwareID','CompatibleIDs')) {
                $liveArr = $savedValues.$vn
                if ($null -eq $liveArr) { continue }
                $regArr = Get-RegMultiSzFromReg -Content $content -ValueName $vn
                if ($null -eq $regArr) { continue }
                $liveJoin = ((@($liveArr)) -join "`0")
                $regJoin  = ((@($regArr))  -join "`0")
                if ($liveJoin -ne $regJoin) {
                    throw ("Sanity cross-check falhou para " + $vn + ": .reg export divergente do live registry")
                }
            }

            # Substitui nome de instancia APENAS em section headers e value lines
            # conhecidas (HardwareID/CompatibleIDs/LocationInformation/ContainerID).
            # Evita corrupcao colateral em Port_#XXXX, ParentIdPrefix, GUID frags, etc.
            $newContent = Rename-InstanceInReg -Content $content -ParentKey $parentKey -OldInst $instName -NewInst $newInst

            # Sanity: o nome de instancia original nao pode mais existir em section
            # headers ou value lines conhecidas do .reg apos o rename.
            $verifyContent = Rename-InstanceInReg -Content $newContent -ParentKey $parentKey -OldInst $instName -NewInst "__DETECT__"
            if ($verifyContent -ne $newContent) {
                throw "Sanity check falhou: instancia original ainda referenciada apos rename"
            }

            Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline
            [void](Invoke-Reg -RegArgs @("import", $tmpFile))

            # Retry-com-backoff no delete: PnP libera handle da subkey de forma
            # assincrona mesmo apos Disable-PnpDevice retornar. 3 tentativas x 100ms.
            $deleteOk = $false
            $lastErr  = $null
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                try {
                    [void](Invoke-Reg -RegArgs @("delete", $oldPathReg, "/f"))
                    $deleteOk = $true
                    break
                } catch {
                    $lastErr = $_
                    if ($attempt -lt 3) { Start-Sleep -Milliseconds 100 }
                }
            }
            if (-not $deleteOk) {
                throw ("delete do original falhou apos 3 tentativas: " + $lastErr.Exception.Message)
            }

            $backupEntries += [pscustomobject]@{
                parent_key    = $parentKey
                orig_instance = $instName
                new_instance  = $newInst
                class_guid    = $cg
                container_id  = $cid
                saved_values  = $savedValues
            }
            $newMapping[$mapKey] = [pscustomobject]@{
                parent_key   = $parentKey
                new_instance = $newInst
                class_guid   = $cg
            }
            $processed++
            Write-OK ($mapKey + "  ->  " + $parentKey + "\" + $newInst)
        } catch {
            Write-Err ("Falha spoof " + $mapKey + ": " + $_.Exception.Message)
            $failed++

            # Rollback: se o fake foi importado mas o delete do original falhou,
            # apaga o fake para evitar cascata fake-of-fake no proximo run e para
            # nao deixar registry com AMBAS subkeys convivendo (deteccao trivial).
            $fakePathPs = Join-Path (Join-Path $usbRootPs $parentKey) $newInst
            $origPathPsHere = Join-Path (Join-Path $usbRootPs $parentKey) $instName
            if ((Test-Path $fakePathPs) -and (Test-Path $origPathPsHere)) {
                try {
                    [void](Invoke-Reg -RegArgs @('delete', $newPathReg, '/f'))
                    Write-Warn ("Rollback do fake OK: " + $parentKey + "\" + $newInst)
                } catch {
                    Write-Warn ("Rollback do fake tambem falhou: " + $_.Exception.Message)
                }
            }
        } finally {
            if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
            if ($deviceWasSuspended) {
                # Prefer novo path (rename bem-sucedido) senao velho (rename falhou
                # ou foi feito rollback). Test-Path decide qual InstanceId existe.
                if (Test-Path (Join-Path (Join-Path $usbRootPs $parentKey) $newInst)) {
                    Resume-DeviceForRename -InstanceId $newInstanceId
                } else {
                    Resume-DeviceForRename -InstanceId $oldInstanceId
                }
            }
        }
    }
}

# 6) Persistir backup + mapping (merge com anterior)
if (-not $DryRun -and $processed -gt 0) {
    Write-Section "Persistindo backup e mapping"

    $dir = Split-Path $backupPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    # Merge backup
    $mergedEntries = @()
    if (Test-Path $backupPath) {
        try {
            $prevBkp = Get-Content $backupPath -Raw | ConvertFrom-Json
            foreach ($e in @($prevBkp.entries)) {
                $stillInNew = $false
                foreach ($ne in $backupEntries) {
                    if ($ne.parent_key -eq $e.parent_key -and $ne.orig_instance -eq $e.orig_instance) {
                        $stillInNew = $true; break
                    }
                }
                if (-not $stillInNew) { $mergedEntries += $e }
            }
        } catch {}
    }
    $mergedEntries += $backupEntries
    $bkpObj = [pscustomobject]@{ generated_at = (Get-Date).ToString('o'); entries = $mergedEntries }

    $tmpBkp = $backupPath + ".tmp"
    $bkpObj | ConvertTo-Json -Depth 10 | Set-Content -Path $tmpBkp -Encoding UTF8
    Move-Item -Path $tmpBkp -Destination $backupPath -Force
    Write-OK ("Backup salvo em: " + $backupPath)

    # Merge mapping
    foreach ($k in $existingMap.Keys) {
        if (-not $newMapping.ContainsKey($k)) { $newMapping[$k] = $existingMap[$k] }
    }
    $tmpMap = $mappingPath + ".tmp"
    $newMapping | ConvertTo-Json -Depth 6 | Set-Content -Path $tmpMap -Encoding UTF8
    Move-Item -Path $tmpMap -Destination $mappingPath -Force
    Write-OK ("Mapping salvo em: " + $mappingPath)
}

# 7) Resumo
Write-Section "Resumo"
Write-Host ("  Instancias renomeadas          : " + $processed)        -ForegroundColor Cyan
Write-Host ("  Falhas                         : " + $failed)           -ForegroundColor Cyan
Write-Host ("  Puladas (HID/mouse/keyboard)   : " + $skippedHid)       -ForegroundColor Cyan
Write-Host ("  Puladas (ContainerID protegido): " + $skippedProt)      -ForegroundColor Cyan
Write-Host ("  Puladas (Class blacklist/misc) : " + $skippedClass)     -ForegroundColor Cyan
Write-Host ("  Puladas (boot/system hint)     : " + $skippedBoot)      -ForegroundColor Cyan
Write-Host ("  Puladas (composite parent)     : " + $skippedComposite) -ForegroundColor Cyan
Write-Host ("  Puladas (outros)               : " + $skippedOther)     -ForegroundColor Cyan
if ($DryRun) { Write-Warn "DryRun ativo - nenhuma escrita feita" }
Write-Host ""
Write-Warn "PnP manager pode RE-ENUMERAR e recriar as instancias originais em hot-plug USB."
Write-Warn "Recomendacao: rodar este script como ULTIMO passo antes do jogo,"
Write-Warn "e NAO hot-plugar/unplugar USB durante a sessao."
Write-Info "Para reverter: .\spoof-usb-ids.ps1 -Restore"
if ($failed -gt 0) { exit 1 } else { exit 0 }
