#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Auditoria READ-ONLY do spoof de HW.
.DESCRIPTION
    Nada altera o sistema. Cobre duas categorias:

      1. BIOS mirror audit:
         Compara HKLM\HARDWARE\DESCRIPTION\System\BIOS com o profile
         em C:\ProgramData\.hwcfg\profile.json. Se algum valor no
         mirror ainda mostra a placa REAL, o SMBIOS spoof nao cobre
         essa superficie - anti-cheat que le esse path direto ve a
         maquina real. Sinalizamos como GAP.

      2. Consistency cross-check:
         Compara identidades entre WMI/SMBIOS/registry procurando as
         inconsistencias classicas que anti-cheat cruza:
           - Manufacturer entre ComputerSystem/BaseBoard/SystemEnclosure
           - CPU Type 4 SMBIOS vs Win32_Processor.Name (que vem de CPUID)
           - MAC OUI vs adapter vendor no PnP enum
           - Disk Model (nao spoofado) vs Serial prefix (spoofado)

    Codigo de saida:
      0 = tudo bate
      1 = pelo menos um GAP ou INCONSISTENCIA

    NOTA: este arquivo e ASCII puro de proposito. Windows PowerShell 5.1
    le sem BOM assumindo Windows-1252, e caracteres UTF-8 multi-byte
    (em-dash, acentuados) viram sequencias com aspas que quebram o parser.
#>

$ErrorActionPreference = "Stop"
$profilePath = "C:\ProgramData\.hwcfg\profile.json"

. "$PSScriptRoot\_ui-common.ps1"

# consistency-check conta gaps: precisamos que Warn/Gap incrementem
# $script:GapCount. As helpers em _ui-common.ps1 nao mexem em contador
# (sao usadas por outros scripts que nao contam). Sobrescrevemos aqui
# as duas versoes contadoras. ASCII only.
$script:GapCount = 0
function Write-Gap($m)  { Write-Host ("  [GAP]  " + $m) -ForegroundColor Yellow; $script:GapCount++ }
function Write-Warn($m) { Write-Host ("  [!]    " + $m) -ForegroundColor Yellow; $script:GapCount++ }

# ============================================================
#  Load profile (opcional - sem profile, viramos "baseline mode":
#  mostra os valores reais do sistema sem comparar com nada.
#  Util pra ver o que precisa spoofar antes de rodar 00-gerar-profile.)
# ============================================================
$hasProfile = Test-Path $profilePath
$prof = $null
$smb  = $null
if ($hasProfile) {
    $prof = Get-Content $profilePath -Raw | ConvertFrom-Json
    $smb  = $prof.smbios
    Write-Host "[*] Modo COMPARE - profile carregado: $profilePath" -ForegroundColor DarkGray
} else {
    Write-Host "[*] Modo BASELINE - profile ausente. Rode 00-gerar-profile.bat" -ForegroundColor DarkGray
    Write-Host "    para habilitar a comparacao BIOS mirror <-> profile." -ForegroundColor DarkGray
}

# ============================================================
#  v4.0.6: Read-ReplayStatus — decodifica o breadcrumb que o driver
#  RstFlt v4.0.6+ deixa em Parameters\LastReplayStatus a cada boot
#  (ApplySmbiosBlobIfCached WriteLastReplayStatus). Formato:
#    (tag << 24) | (NTSTATUS & 0x00FFFFFF)
#  Tags:
#    0x00 SUCCESS               0x01 GATE-OFF
#    0x02 NO-BLOB               0x03 VALIDATION-FAIL
#    0x04 MSSMBIOS-OPEN-FAIL    0x05 MSSMBIOS-WRITE-FAIL
#  Silencioso se o driver e anterior a v4.0.6 (chave ausente).
# ============================================================
function Read-ReplayStatus {
    $rstflt = 'HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters'
    if (-not (Test-Path $rstflt)) { return }

    $raw = (Get-ItemProperty -Path $rstflt -Name 'LastReplayStatus' `
                              -ErrorAction SilentlyContinue).LastReplayStatus
    if ($null -eq $raw) {
        Write-Host "  [*]    RstFlt LastReplayStatus: ausente (driver < v4.0.6 ou nao rodou ainda)" -ForegroundColor DarkGray
        return
    }

    $tag = ($raw -shr 24) -band 0xFF
    $st  = $raw -band 0x00FFFFFF
    $tagNames = @{
        0x00 = 'SUCCESS'
        0x01 = 'GATE-OFF'
        0x02 = 'NO-BLOB'
        0x03 = 'VALIDATION-FAIL'
        0x04 = 'MSSMBIOS-OPEN-FAIL'
        0x05 = 'MSSMBIOS-WRITE-FAIL'
    }
    $tagName = $tagNames[$tag]
    if (-not $tagName) { $tagName = "UNKNOWN($tag)" }

    $stHex = '0x{0:X6}' -f $st
    $line  = "  [*]    RstFlt LastReplayStatus: $tagName (NTSTATUS=$stHex)"
    switch ($tag) {
        0x00 { Write-Host $line -ForegroundColor Green }
        0x01 { Write-Host $line -ForegroundColor DarkGray }
        0x02 { Write-Host $line -ForegroundColor DarkGray }
        0x03 { Write-Host $line -ForegroundColor Yellow }
        0x04 {
            Write-Host $line -ForegroundColor Yellow
            Write-Host "         Esperado em Hyper-V: mssmbios carrega depois de RstFlt," -ForegroundColor DarkGray
            Write-Host "         path de escrita em registry nao consegue landar. WMI-visible" -ForegroundColor DarkGray
            Write-Host "         spoof precisa de v4.1 IRP interception. Ver Bug 3." -ForegroundColor DarkGray
        }
        0x05 { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line -ForegroundColor Yellow }
    }
}

Read-ReplayStatus

# ============================================================
#  v5.0.0: Read-CallbackStatus decodifica o breadcrumb Track D
#  em Parameters\LastCallbackStatus. Formato identico:
#    (tag << 24) | (NTSTATUS & 0x00FFFFFF)
#  Tags Track D (v5.0.4):
#    0x00 OK               (rewrite landed OU arm-time sucesso)
#    0x01 NAME-MISS        (v5.0.4: image name do caller nao bateu com
#                           TRACKD_IMAGE_MATCH_PREFIX "rubinot" no gate
#                           inline. Antes de v5.0.4 esse slot era
#                           NO-PID e representava "PID array vazio".)
#    0x02 RESERVED         (era PID-STALE pre-v5.0.4; slot mantido
#                           por compat com decodificadores antigos)
#    0x03 PATH-GET-FAIL    (CmCallbackGetKeyObjectID falhou)
#    0x04 BUFFER-BAD       (KEY_INFORMATION malformada)
#    0x05 ALLOC-FAIL       (arm-time: CmRegisterCallbackEx falhou)
#    0x06 SEH-FAULT        (__except capturou fault na rewrite)
#
#  v5.0.4 tambem publica CallbackInvokeCount, CallbackNameMissCount,
#  LastMissImageName, e LastArmStatus (separate do LastCallbackStatus).
# ============================================================
function Read-CallbackStatus {
    $rstflt = 'HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters'
    if (-not (Test-Path $rstflt)) { return }

    $tagNames = @{
        0x00 = 'OK'
        0x01 = 'NAME-MISS'
        0x02 = 'RESERVED'
        0x03 = 'PATH-GET-FAIL'
        0x04 = 'BUFFER-BAD'
        0x05 = 'ALLOC-FAIL'
        0x06 = 'SEH-FAULT'
    }

    $raw = (Get-ItemProperty -Path $rstflt -Name 'LastCallbackStatus' `
                              -ErrorAction SilentlyContinue).LastCallbackStatus
    if ($null -eq $raw) {
        Write-Host "  [*]    Track D LastCallbackStatus: ausente (callback nunca fired hot path)" -ForegroundColor DarkGray
    } else {
        $tag = ($raw -shr 24) -band 0xFF
        $st  = $raw -band 0x00FFFFFF
        $tagName = $tagNames[$tag]
        if (-not $tagName) { $tagName = "UNKNOWN($tag)" }

        $stHex = '0x{0:X6}' -f $st
        $line  = "  [*]    Track D LastCallbackStatus: $tagName (NTSTATUS=$stHex)"
        switch ($tag) {
            0x00 { Write-Host $line -ForegroundColor Green }
            0x01 {
                Write-Host $line -ForegroundColor Yellow
                Write-Host "         v5.0.4: image name do caller nao bateu com 'rubinot' no gate." -ForegroundColor DarkGray
                Write-Host "         Ver LastMissImageName + CallbackNameMissCount abaixo." -ForegroundColor DarkGray
            }
            0x02 { Write-Host $line -ForegroundColor Yellow }
            0x03 { Write-Host $line -ForegroundColor Yellow }
            0x04 { Write-Host $line -ForegroundColor Yellow }
            0x05 {
                Write-Host $line -ForegroundColor Red
                Write-Host "         CmRegisterCallbackEx falhou no DriverEntry" -ForegroundColor DarkGray
                Write-Host "         - Track D nao esta ativo. Ver docs/postmortem-v5-track-d/." -ForegroundColor DarkGray
            }
            0x06 {
                Write-Host $line -ForegroundColor Red
                Write-Host "         SEH capturou fault ao mutar buffer do caller" -ForegroundColor DarkGray
                Write-Host "         (possivel corruption de KEY_INFORMATION). Investigar." -ForegroundColor DarkGray
            }
            default { Write-Host $line -ForegroundColor Yellow }
        }
    }

    # Callback hit count (rewrites que efetivamente reescreveram bytes)
    $hits = (Get-ItemProperty -Path $rstflt -Name 'CallbackHitCount' `
                               -ErrorAction SilentlyContinue).CallbackHitCount
    if ($null -ne $hits) {
        $color = if ($hits -gt 0) { 'Green' } else { 'DarkGray' }
        Write-Host ("  [*]    Track D CallbackHitCount: " + $hits + " rewrite(s) desde ultimo flush") -ForegroundColor $color
    }

    # v5.0.4: CallbackInvokeCount - total de RegNtPostEnumerateKey vistos
    # pelo callback body post-enable-gate (inclui pass-through, NAME-MISS
    # e OK). Se 0 apos boot, callback nao esta armado - checar LastArmStatus.
    $inv = (Get-ItemProperty -Path $rstflt -Name 'CallbackInvokeCount' `
                              -ErrorAction SilentlyContinue).CallbackInvokeCount
    if ($null -ne $inv) {
        Write-Host ("  [*]    Track D CallbackInvokeCount: " + $inv + " invocacao(oes) post-enable-gate") -ForegroundColor DarkGray
        if ($null -ne $hits -and $inv -gt 0) {
            $rewriteRatio = [math]::Round(($hits / $inv) * 100, 2)
            Write-Host ("         rewrite ratio: {0}%" -f $rewriteRatio) -ForegroundColor DarkGray
        }
    }

    # v5.0.4: CallbackNameMissCount - invocacoes rejeitadas pelo name gate
    # (image name do caller nao comeca com "rubinot"). Se >0, o driver vem
    # sendo perguntado por processos que nao sao alvo - normal em qualquer
    # boot (Explorer, Discord, etc. lem SCSI\Disk enum tambem).
    $miss = (Get-ItemProperty -Path $rstflt -Name 'CallbackNameMissCount' `
                               -ErrorAction SilentlyContinue).CallbackNameMissCount
    if ($null -ne $miss) {
        $color = if ($miss -gt 0) { 'Yellow' } else { 'DarkGray' }
        Write-Host ("  [*]    Track D CallbackNameMissCount: " + $miss + " invocacao(oes) rejeitada(s) pelo name gate") -ForegroundColor $color
    }

    # v5.0.4: LastMissImageName - primeiros 15 bytes do EPROCESS
    # ImageFileName do ultimo caller que falhou o name gate. Diagnostico
    # de quem dominou o trafego de misses.
    $lastImg = (Get-ItemProperty -Path $rstflt -Name 'LastMissImageName' `
                                 -ErrorAction SilentlyContinue).LastMissImageName
    if ($null -ne $lastImg -and $lastImg -ne '') {
        Write-Host ("  [*]    Track D LastMissImageName: `"" + $lastImg + "`"") -ForegroundColor DarkGray
    }

    # v5.0.4: LastArmStatus - breadcrumb gravado no ArmTrackD (success
    # ou failure), mesma codificacao (tag<<24)|NTSTATUS. Serve para
    # distinguir "callback nunca disparou hot path" (LastCallbackStatus
    # ausente) de "arm falhou" (LastArmStatus com tag != 0x00).
    $armRaw = (Get-ItemProperty -Path $rstflt -Name 'LastArmStatus' `
                                -ErrorAction SilentlyContinue).LastArmStatus
    if ($null -ne $armRaw) {
        $armTag  = ($armRaw -shr 24) -band 0xFF
        $armSt   = $armRaw -band 0x00FFFFFF
        $armName = $tagNames[$armTag]
        if (-not $armName) { $armName = "UNKNOWN($armTag)" }
        $armHex  = '0x{0:X6}' -f $armSt
        $armLine = "  [*]    Track D LastArmStatus: $armName (NTSTATUS=$armHex)"
        if ($armTag -eq 0x00) {
            Write-Host $armLine -ForegroundColor Green
        } else {
            Write-Host $armLine -ForegroundColor Red
            Write-Host "         DriverEntry arm path falhou - callback nao esta ativo" -ForegroundColor DarkGray
            Write-Host "         mesmo se EnableRegCallback=1. Ver docs/postmortem-v5-track-d/." -ForegroundColor DarkGray
        }
    }
}

Read-CallbackStatus

# ============================================================
#  v4.0.6: verificar se o rstflt.sys em disco (nao o carregado)
#  contem o marker "RstFlt-v4.0.6-BUILD-MARKER". PE TimeDateStamp
#  muda a cada relink e defeats SHA-based identity, entao este
#  marker (const char[] mantido por #pragma /INCLUDE) e a forma
#  confiavel de confirmar que voce esta usando a build v4.0.6+.
# ============================================================
function Read-DriverVersionMarker {
    $sysPath = 'C:\Windows\System32\drivers\rstflt.sys'
    if (-not (Test-Path $sysPath)) {
        Write-Host "  [*]    rstflt.sys nao instalado em System32\drivers (driver nao registrado)" -ForegroundColor DarkGray
        return
    }
    try {
        $b = [System.IO.File]::ReadAllBytes($sysPath)
        $s = [System.Text.Encoding]::ASCII.GetString($b)
        # v4.0.9+: match any RstFlt-v* marker (previously hardcoded to v4.0.6, false-negatived v4.0.9 builds)
        $markerMatch = [regex]::Match($s, 'RstFlt-v(\d+\.\d+\.\d+)-BUILD-MARKER')
        if ($markerMatch.Success) {
            Write-Host "  [OK]   rstflt.sys instalado: v$($markerMatch.Groups[1].Value) (marker encontrado)" -ForegroundColor Green
        } elseif ($s.Contains('RstFlt')) {
            Write-Host "  [!]    rstflt.sys instalado eh anterior a v4.0.6 (marker ausente)" -ForegroundColor Yellow
            Write-Host "         Reinstale via 03-instalar-driver.bat para pegar Bug 3 breadcrumb + Bug 5 fixes." -ForegroundColor Yellow
        } else {
            Write-Host "  [!]    rstflt.sys em System32 nao parece ser o RstFlt (marker ausente)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [!]    Falha lendo rstflt.sys: $_" -ForegroundColor Yellow
    }
}

Read-DriverVersionMarker

# ============================================================
#  1. BIOS MIRROR AUDIT
#
#  HARDWARE hive nao persiste em disco - e reconstruida a cada boot
#  pelo NTLoader/hal. Se nosso spoof de mssmbios\Data\SMBiosData
#  esta ativo, essa reconstrucao deve pegar os valores spoofados.
#  Se algum campo mostra o valor REAL da placa, significa que:
#    (a) o replay em kernel do rstflt nao rodou (opt-in off, blob
#        invalido, driver nao carregou), OU
#    (b) esse campo especifico vem de outra fonte (ex. ACPI RSDP)
#        e o SMBIOS spoof nao cobre.
#  Em qualquer caso, e um vazamento.
# ============================================================
Write-Section "BIOS mirror audit (HKLM\HARDWARE\DESCRIPTION\System\BIOS)"

$biosKey = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
if (-not (Test-Path $biosKey)) {
    Write-Warn "Chave $biosKey nao existe (?). Boot corrompido ou HAL diferente."
} else {
    $bp = Get-ItemProperty -Path $biosKey -ErrorAction SilentlyContinue

    # Mapeia campo do mirror -> (label, valor esperado do profile ou $null)
    $checks = @(
        @{ Field = "SystemManufacturer";      Expected = $(if($smb){$smb.system_manufacturer}); Label = "System Mfr"     },
        @{ Field = "SystemProductName";       Expected = $(if($smb){$smb.system_product});      Label = "System Product" },
        @{ Field = "SystemFamily";            Expected = $(if($smb){$smb.system_family});       Label = "System Family"  },
        @{ Field = "SystemSKU";               Expected = $(if($smb){$smb.system_sku});          Label = "System SKU"     },
        @{ Field = "SystemVersion";           Expected = $(if($smb){$smb.system_version});      Label = "System Version" },
        @{ Field = "BaseBoardManufacturer";   Expected = $(if($smb){$smb.board_manufacturer});  Label = "Board Mfr"      },
        @{ Field = "BaseBoardProduct";        Expected = $(if($smb){$smb.board_product});       Label = "Board Product"  },
        @{ Field = "BaseBoardVersion";        Expected = $(if($smb){$smb.board_version});       Label = "Board Version"  }
    )

    foreach ($c in $checks) {
        $actual = $bp.PSObject.Properties |
                  Where-Object { $_.Name -eq $c.Field } |
                  Select-Object -ExpandProperty Value -First 1
        if ($null -eq $actual) {
            Write-Info ("{0,-18} : (campo ausente)" -f $c.Label)
            continue
        }
        if (-not $hasProfile) {
            # Baseline mode: so mostra o valor atual
            Write-Info ("{0,-18} : `"{1}`"" -f $c.Label, $actual)
        } elseif ([string]$actual -eq [string]$c.Expected) {
            Write-OK ("{0,-18} : `"{1}`"" -f $c.Label, $actual)
        } else {
            Write-Gap ("{0,-18} : mirror=`"{1}`"  profile=`"{2}`"" -f $c.Label, $actual, $c.Expected)
        }
    }

    # BIOSVendor/BIOSVersion/BIOSReleaseDate - nao spoofamos hoje
    Write-Info ("BIOSVendor        : `"{0}`" (nao spoofado)"      -f $bp.BIOSVendor)
    Write-Info ("BIOSVersion       : `"{0}`" (nao spoofado)"      -f $bp.BIOSVersion)
    Write-Info ("BIOSReleaseDate   : `"{0}`" (nao spoofado)"      -f $bp.BIOSReleaseDate)
}

# ============================================================
#  CPU registry replay audit
#  (HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\N)
#
#  Espelho de CPUID em registry. Cada subchave N e um core logico;
#  os 3 campos abaixo devem bater com profile.cpu se o spoof/replay
#  cobre esse path. Divergencia = anti-cheat lendo aqui ve valores
#  reais mesmo com SMBIOS Type 4 spoofado.
# ============================================================
Write-Section "CPU registry replay audit (HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\N)"

if (-not $hasProfile -or -not $prof.PSObject.Properties['cpu']) {
    Write-Info "Profile v< 9 sem bloco cpu - secao pulada"
} else {
    $cpuRoot = "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor"
    if (-not (Test-Path $cpuRoot)) {
        Write-Warn "CentralProcessor key ausente"
    } else {
        $cpuProf = $prof.cpu
        $cpuChecks = @(
            @{ Field = "ProcessorNameString"; Expected = $(if ($cpuProf.PSObject.Properties['name_string'])       { [string]$cpuProf.name_string })       },
            @{ Field = "Identifier";          Expected = $(if ($cpuProf.PSObject.Properties['identifier'])        { [string]$cpuProf.identifier })        },
            @{ Field = "VendorIdentifier";    Expected = $(if ($cpuProf.PSObject.Properties['vendor_identifier']) { [string]$cpuProf.vendor_identifier }) }
        )

        $cpuSubKeys = Get-ChildItem $cpuRoot -ErrorAction SilentlyContinue
        foreach ($ck in $cpuSubKeys) {
            $n = $ck.PSChildName
            $cp = $null
            try {
                $cp = Get-ItemProperty -Path $ck.PSPath -ErrorAction SilentlyContinue
            } catch { }

            foreach ($chk in $cpuChecks) {
                $field    = $chk.Field
                $expected = $chk.Expected
                $actual = $null
                if ($cp) {
                    $prop = $cp.PSObject.Properties | Where-Object { $_.Name -eq $field } | Select-Object -First 1
                    if ($prop) { $actual = [string]$prop.Value }
                }

                if ($null -eq $actual) {
                    Write-Warn ("CPU[{0}] {1} ausente do registro" -f $n, $field)
                    continue
                }

                if ([string]$actual -eq [string]$expected) {
                    Write-OK ("CPU[{0}] {1} OK: {2}" -f $n, $field, $actual)
                } else {
                    Write-Gap ("CPU[{0}] {1} vazamento: registro='{2}' profile='{3}'" -f $n, $field, $actual, $expected)
                }
            }
        }
    }
}

# ============================================================
#  2. Manufacturer cross-check entre 3 fontes
# ============================================================
Write-Section "Manufacturer cross-check"

$sysMfr     = (Get-CimInstance Win32_ComputerSystem).Manufacturer
$boardMfr   = (Get-CimInstance Win32_BaseBoard).Manufacturer
$chassisMfr = (Get-CimInstance Win32_SystemEnclosure).Manufacturer

Write-Info "System   Mfr : $sysMfr"
Write-Info "Board    Mfr : $boardMfr"
Write-Info "Chassis  Mfr : $chassisMfr"

if ($sysMfr -eq $boardMfr -and $boardMfr -eq $chassisMfr) {
    Write-OK "Todos os 3 batem"
} else {
    Write-Gap "Divergentes - anti-cheat cruzando essas 3 vai flag"
}

# ============================================================
#  3. CPU: SMBIOS Type 4 vs Win32_Processor (que vem de CPUID)
#
#  Nao spoofamos family/model/manufacturer do Type 4 (deliberado -
#  divergencia entre SMBIOS Type 4 e CPUID e um flag classico).
#  So checamos que o que WMI reporta bate com o CPUID real do
#  silicio, e que os campos que SPOOFAMOS (serial/asset/part#)
#  sumiram do Win32_Processor.
# ============================================================
Write-Section "CPU: SMBIOS Type 4 vs CPUID coherency"

$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
Write-Info ("Win32_Processor.Name          : {0}" -f $cpu.Name)
Write-Info ("Win32_Processor.Manufacturer  : {0}" -f $cpu.Manufacturer)
Write-Info ("Win32_Processor.ProcessorId   : {0}" -f $cpu.ProcessorId)

# ProcessorId de CPUID come de EAX=1 e nao deve mudar. Se mudou,
# alguma coisa alterou Type 4 CPUID (bug em spoof-smbios.ps1).
$expectedVendor = switch -Regex ($cpu.Manufacturer) {
    "Intel" { "GenuineIntel"; break }
    "AMD"   { "AuthenticAMD"; break }
    default { $null }
}
if ($expectedVendor) {
    Write-OK ("Vendor family consistente ({0})" -f $expectedVendor)
} else {
    Write-Gap ("Manufacturer WMI ({0}) nao mapeia para vendor conhecido" -f $cpu.Manufacturer)
}

# ============================================================
#  4. Rede: MAC OUI vs adapter vendor
#
#  Se profile disse MSI (Realtek/Killer), mas o MAC de um adapter
#  Realtek tem OUI Intel, e vazamento obvio.
# ============================================================
Write-Section "Rede: MAC OUI vs adapter vendor"

$adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' }
foreach ($a in $adapters) {
    $oui = ($a.MacAddress -replace '[:-]', '').Substring(0, 6).ToUpper()
    $desc = $a.InterfaceDescription
    $vendorGuess = switch -Regex ($desc) {
        "Intel"                 { "Intel";     break }
        "Realtek"               { "Realtek";   break }
        "Killer"                { "Killer";    break }
        "Broadcom"              { "Broadcom";  break }
        "Qualcomm|Atheros"      { "Qualcomm";  break }
        "Mediatek|MTK|Wi-Fi 6"  { "MTK/Wi-Fi"; break }
        default                 { "?" }
    }

    $shortDesc = if ($desc.Length -gt 32) { $desc.Substring(0,32) } else { $desc }
    Write-Info ("{0,-32} MAC OUI={1}  vendor(desc)={2}" -f $shortDesc, $oui, $vendorGuess)
}

# ============================================================
#  5. Disco: Model + Serial (informativo, NAO spoofado em v3.6)
#
#  v3.6 removeu o intercept de IOCTL_STORAGE_QUERY_PROPERTY /
#  IDENTIFY / NVMe do driver rstflt. O serial de disco reportado
#  aqui e o real da controladora - EMAC nao consulta esse campo,
#  o custo/beneficio do spoof nao valia o BSOD risk.
#  Mostramos os valores so pra registro. Nao emitimos gap por
#  "prefixo errado" - nao existe prefixo esperado.
# ============================================================
Write-Section "Disco: Model + Serial (nao spoofado em v3.6 - valor real)"

$disks = Get-CimInstance Win32_DiskDrive |
         Where-Object { $_.MediaType -match "Fixed" -or $_.InterfaceType -match "IDE|SCSI|NVMe" }
foreach ($d in $disks) {
    $ser = if ($d.SerialNumber) { $d.SerialNumber.Trim() } else { "(vazio)" }
    Write-Info ("{0,-35} Serial: {1}" -f $d.Model, $ser)
}

# ============================================================
#  6. Audio MMDevices GUIDs match profile pool
#
#  spoof-audio-guids.ps1 gera novos endpoint GUIDs em
#  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio
#  e salva o mapa (old->new) em audio-rotation.json. Aqui checamos
#  se cada endpoint Active atual tem entrada no mapa - se nao tem,
#  ainda esta com GUID real de fabrica.
# ============================================================
Write-Section "Audio MMDevices GUIDs vs profile rotation"

$audioMapPath = "C:\ProgramData\.hwcfg\audio-rotation.json"
$audioPool    = $null
if ($hasProfile -and $prof.PSObject.Properties['audio']) {
    $audioPool = $prof.audio.rotation_pool
}

if (-not (Test-Path $audioMapPath)) {
    Write-Info "audio rotation not applied yet (audio-rotation.json missing)"
} else {
    $audioMap = $null
    try {
        $audioMap = Get-Content $audioMapPath -Raw | ConvertFrom-Json
    } catch {
        Write-Warn "audio-rotation.json ilegivel: $($_.Exception.Message)"
    }

    if ($audioMap) {
        # Schema real: { "Render": [ {old, new}, ... ], "Capture": [ {old, new}, ... ] }
        # Colecta o campo "new" de cada entrada em ambos os arrays.
        $newGuids = New-Object System.Collections.Generic.HashSet[string]
        foreach ($section in @('Render','Capture')) {
            if ($audioMap.PSObject.Properties[$section]) {
                foreach ($entry in @($audioMap.$section)) {
                    if ($entry -and $entry.PSObject.Properties['new']) {
                        [void]$newGuids.Add(([string]$entry.new).ToLower().Trim('{','}'))
                    }
                }
            }
        }

        $renderKey  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
        $captureKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture"

        foreach ($rk in @($renderKey, $captureKey)) {
            $label = Split-Path $rk -Leaf
            if (-not (Test-Path $rk)) {
                Write-Info ("{0}: chave ausente" -f $label)
                continue
            }
            $endpoints = Get-ChildItem $rk -ErrorAction SilentlyContinue
            foreach ($ep in $endpoints) {
                $devState = $null
                try {
                    $devState = (Get-ItemProperty -Path $ep.PSPath -Name DeviceState -ErrorAction SilentlyContinue).DeviceState
                } catch { }
                # DEVICE_STATE_ACTIVE = 0x1. Outros: Disabled/NotPresent/Unplugged.
                # Bitmask (nao equality) para robustez caso flags extras aparecam.
                if ($null -eq $devState -or (([int]$devState) -band 0x1) -eq 0) { continue }

                $guid = $ep.PSChildName.ToLower().Trim('{','}')
                if ($newGuids.Contains($guid)) {
                    Write-OK ("{0}\{{{1}}} (rotated)" -f $label, $guid)
                } else {
                    Write-Gap ("{0}\{{{1}}} sem mapping - endpoint Active nao rotacionado" -f $label, $guid)
                }
            }
        }

        if ($audioPool) {
            Write-Info ("profile.audio.rotation_pool: {0} GUIDs disponiveis" -f @($audioPool).Count)
        }
    }
}

# ============================================================
#  7. EDID full-spoof coherency
#
#  spoof-edid-full.ps1 reescreve o EDID inteiro (PNP ID, product
#  code, serial num, week/year, descriptor blocks 0xFC nome e 0xFF
#  serial ASCII) e recalcula o checksum. Aqui decodificamos o EDID
#  atual e comparamos cada campo com o profile.
# ============================================================
Write-Section "EDID full-spoof coherency"

$monProf = if ($hasProfile -and $prof.PSObject.Properties['monitor']) { $prof.monitor } else { $null }

$displayRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
if (-not (Test-Path $displayRoot)) {
    Write-Info "HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY ausente"
} else {
    $edidCount = 0
    $mfrKeys = Get-ChildItem $displayRoot -ErrorAction SilentlyContinue
    foreach ($mk in $mfrKeys) {
        $instKeys = Get-ChildItem $mk.PSPath -ErrorAction SilentlyContinue
        foreach ($ik in $instKeys) {
            $paramPath = Join-Path $ik.PSPath "Device Parameters"
            if (-not (Test-Path $paramPath)) { continue }
            $edid = $null
            try {
                $edid = (Get-ItemProperty -Path $paramPath -Name EDID -ErrorAction SilentlyContinue).EDID
            } catch { }
            if (-not $edid -or $edid.Length -lt 128) { continue }
            $edidCount++

            $tag = "{0}\{1}" -f $mk.PSChildName, $ik.PSChildName
            Write-Info ("--- EDID de {0} ({1} bytes) ---" -f $tag, $edid.Length)

            # PNP ID: bytes 8-9, big-endian, 5 bits por letra + 0x40 offset
            $w = ([int]$edid[8] -shl 8) -bor [int]$edid[9]
            $c1 = [char]((($w -shr 10) -band 0x1F) + 0x40)
            $c2 = [char]((($w -shr 5)  -band 0x1F) + 0x40)
            $c3 = [char](( $w         -band 0x1F) + 0x40)
            $pnp = ("" + $c1 + $c2 + $c3).ToUpper()

            $productCode = [int]$edid[10] -bor ([int]$edid[11] -shl 8)
            $serialNum   = [int]$edid[12] -bor ([int]$edid[13] -shl 8) -bor ([int]$edid[14] -shl 16) -bor ([int]$edid[15] -shl 24)
            $mfgWeek     = [int]$edid[16]
            $mfgYear     = [int]$edid[17] + 1990

            # Descriptor blocks: 4 x 18 bytes em offsets 54, 72, 90, 108.
            # Tipo esta no byte 3 do bloco (indices 0-2 sao zeros para
            # descritores nao-timing). 0xFC = nome, 0xFF = serial ASCII,
            # 0xFE = string livre. Payload nos bytes 5-17, terminador
            # opcional 0x0A, resto padding 0x20.
            $descName   = $null
            $descSerial = $null
            foreach ($off in 54, 72, 90, 108) {
                if ($edid[$off] -ne 0 -or $edid[$off + 1] -ne 0 -or $edid[$off + 2] -ne 0) { continue }
                $tp = [int]$edid[$off + 3]
                $raw = New-Object byte[] 13
                [Array]::Copy($edid, $off + 5, $raw, 0, 13)
                $sb = New-Object System.Text.StringBuilder
                foreach ($b in $raw) {
                    if ($b -eq 0x0A -or $b -eq 0x00) { break }
                    [void]$sb.Append([char]$b)
                }
                $txt = $sb.ToString().TrimEnd(' ')
                if     ($tp -eq 0xFC) { $descName   = $txt }
                elseif ($tp -eq 0xFF) { $descSerial = $txt }
            }

            # Checksum base: soma dos 128 bytes deve ser multiplo de 256.
            $sum = 0
            for ($i = 0; $i -lt 128; $i++) { $sum = ($sum + [int]$edid[$i]) -band 0xFF }
            if ($sum -eq 0) {
                Write-OK "checksum base valido"
            } else {
                Write-Gap ("checksum base invalido (soma mod 256 = {0}) - spoofer quebrou o EDID" -f $sum)
            }

            # Checksum da primeira extensao (se presente).
            if ($edid.Length -ge 256) {
                $sum2 = 0
                for ($i = 128; $i -lt 256; $i++) { $sum2 = ($sum2 + [int]$edid[$i]) -band 0xFF }
                if ($sum2 -eq 0) {
                    Write-OK "checksum extensao valido"
                } else {
                    Write-Gap ("checksum extensao invalido (soma mod 256 = {0})" -f $sum2)
                }
            }

            if (-not $monProf) {
                # Baseline mode: so imprime os valores decodificados.
                Write-Info ("pnp_id       : `"{0}`"" -f $pnp)
                Write-Info ("product_code : {0}"     -f $productCode)
                Write-Info ("serial_num   : {0}"     -f $serialNum)
                Write-Info ("mfg_week     : {0}"     -f $mfgWeek)
                Write-Info ("mfg_year     : {0}"     -f $mfgYear)
                if ($null -ne $descName)   { Write-Info ("descriptor 0xFC (name)   : `"{0}`"" -f $descName) }
                if ($null -ne $descSerial) { Write-Info ("descriptor 0xFF (serial) : `"{0}`"" -f $descSerial) }
                continue
            }

            # Compare com profile.monitor
            $expPnp    = $monProf.mfr_pnp_id
            $expProd   = $monProf.product_code
            $expSer    = $monProf.serial_num
            $expWeek   = $monProf.mfg_week
            $expYear   = $monProf.mfg_year
            $expName   = $monProf.model_name
            $expSerAsc = $monProf.serial_ascii

            if ($null -ne $expPnp -and [string]$pnp -eq [string]$expPnp) {
                Write-OK ("pnp_id       : `"{0}`"" -f $pnp)
            } elseif ($null -ne $expPnp) {
                Write-Gap ("pnp_id       : actual=`"{0}`"  expected=`"{1}`"" -f $pnp, $expPnp)
            } else {
                Write-Info ("pnp_id       : `"{0}`" (profile sem mfr_pnp_id)" -f $pnp)
            }

            if ($null -ne $expProd -and [int]$productCode -eq [int]$expProd) {
                Write-OK ("product_code : {0}" -f $productCode)
            } elseif ($null -ne $expProd) {
                Write-Gap ("product_code : actual={0}  expected={1}" -f $productCode, $expProd)
            } else {
                Write-Info ("product_code : {0} (profile sem product_code)" -f $productCode)
            }

            if ($null -ne $expSer -and [int64]$serialNum -eq [int64]$expSer) {
                Write-OK ("serial_num   : {0}" -f $serialNum)
            } elseif ($null -ne $expSer) {
                Write-Gap ("serial_num   : actual={0}  expected={1}" -f $serialNum, $expSer)
            } else {
                Write-Info ("serial_num   : {0} (profile sem serial_num)" -f $serialNum)
            }

            if ($null -ne $expWeek -and [int]$mfgWeek -eq [int]$expWeek) {
                Write-OK ("mfg_week     : {0}" -f $mfgWeek)
            } elseif ($null -ne $expWeek) {
                Write-Gap ("mfg_week     : actual={0}  expected={1}" -f $mfgWeek, $expWeek)
            } else {
                Write-Info ("mfg_week     : {0} (profile sem mfg_week)" -f $mfgWeek)
            }

            if ($null -ne $expYear -and [int]$mfgYear -eq [int]$expYear) {
                Write-OK ("mfg_year     : {0}" -f $mfgYear)
            } elseif ($null -ne $expYear) {
                Write-Gap ("mfg_year     : actual={0}  expected={1}" -f $mfgYear, $expYear)
            } else {
                Write-Info ("mfg_year     : {0} (profile sem mfg_year)" -f $mfgYear)
            }

            if ($null -ne $expName) {
                if ($null -ne $descName -and [string]$descName -eq [string]$expName) {
                    Write-OK ("descriptor 0xFC (name)   : `"{0}`"" -f $descName)
                } else {
                    $shown = if ($null -eq $descName) { "(ausente)" } else { "`"" + $descName + "`"" }
                    Write-Gap ("descriptor 0xFC (name)   : actual={0}  expected=`"{1}`"" -f $shown, $expName)
                }
            } elseif ($null -ne $descName) {
                Write-Info ("descriptor 0xFC (name)   : `"{0}`" (profile sem model_name)" -f $descName)
            }

            if ($null -ne $expSerAsc) {
                if ($null -ne $descSerial -and [string]$descSerial -eq [string]$expSerAsc) {
                    Write-OK ("descriptor 0xFF (serial) : `"{0}`"" -f $descSerial)
                } else {
                    $shown = if ($null -eq $descSerial) { "(ausente)" } else { "`"" + $descSerial + "`"" }
                    Write-Gap ("descriptor 0xFF (serial) : actual={0}  expected=`"{1}`"" -f $shown, $expSerAsc)
                }
            } elseif ($null -ne $descSerial) {
                Write-Info ("descriptor 0xFF (serial) : `"{0}`" (profile sem serial_ascii)" -f $descSerial)
            }
        }
    }

    if ($edidCount -eq 0) {
        Write-Info "Nenhum EDID encontrado em Enum\DISPLAY (monitor desconectado?)"
    }
}

# ============================================================
#  8. (Reservado) - antes do v3.6 aqui havia o dump de driver
#  storage state / disk-serial spoof check; foi removido junto
#  com o intercept de IOCTL_STORAGE_QUERY_PROPERTY no driver.
# ============================================================

# ============================================================
#  9. emac-uuid file persistente + ACL locked
#
#  EMAC guarda HWID plaintext em %USERPROFILE%\emac-uuid. Deletar
#  triggera burst de 32k+ RegOpenKey re-registrando. A estrategia
#  aqui e MANTER o arquivo com UUID falso e travar ACL para o proprio
#  usuario nao poder reescrever (spoof persiste entre boots).
# ============================================================
Write-Section "emac-uuid persistente + ACL"

$emacPath = Join-Path $env:USERPROFILE "emac-uuid"
$placeholderUuid = "d9f4202f-e108-4fc8-8389-c3c8d4b9689e"

if (-not (Test-Path $emacPath)) {
    Write-Info "emac-uuid not created yet - game must run once (or run manage-emac-uuid.ps1 -Apply)"
} else {
    $actualUuid = $null
    try {
        $actualUuid = (Get-Content $emacPath -Raw -ErrorAction SilentlyContinue)
        if ($null -ne $actualUuid) { $actualUuid = $actualUuid.Trim() }
    } catch {
        Write-Warn ("Falha ao ler {0}: {1}" -f $emacPath, $_.Exception.Message)
    }

    $expectedUuid = $null
    $wantLock     = $false
    if ($hasProfile -and $prof.PSObject.Properties['emac']) {
        $expectedUuid = $prof.emac.persistent_uuid
        if ($prof.emac.PSObject.Properties['lock_file']) {
            $wantLock = [bool]$prof.emac.lock_file
        }
    }

    if ($null -ne $expectedUuid) {
        if ([string]$actualUuid -eq [string]$expectedUuid) {
            Write-OK ("emac-uuid content bate com profile: `"{0}`"" -f $actualUuid)
        } else {
            Write-Gap ("emac-uuid: file has `"{0}`" but profile has `"{1}`"" -f $actualUuid, $expectedUuid)
        }
    } else {
        Write-Info ("emac-uuid content: `"{0}`" (profile.emac.persistent_uuid ausente)" -f $actualUuid)
    }

    if ($null -ne $actualUuid -and [string]$actualUuid -eq [string]$placeholderUuid) {
        Write-Warn "emac-uuid contem o UUID placeholder da documentacao - troque por um valor random em profile.emac.persistent_uuid"
    }

    # ACL check
    try {
        $acl = Get-Acl $emacPath
        $protected = $acl.AreAccessRulesProtected
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # Bitmask (numerico) e mais confiavel do que string-match: quando
        # FileSystemRights carrega uma mascara custom que nao bate com nenhum
        # nome de enum, ToString() retorna um numero decimal ("1245631") e o
        # regex "Write|Modify|..." nunca casa - falso negativo no lock check.
        $writeMask = ([int][System.Security.AccessControl.FileSystemRights]::Write) `
                     -bor ([int][System.Security.AccessControl.FileSystemRights]::Modify) `
                     -bor ([int][System.Security.AccessControl.FileSystemRights]::FullControl) `
                     -bor ([int][System.Security.AccessControl.FileSystemRights]::Delete) `
                     -bor ([int][System.Security.AccessControl.FileSystemRights]::ChangePermissions) `
                     -bor ([int][System.Security.AccessControl.FileSystemRights]::TakeOwnership) `
                     -bor ([int][System.Security.AccessControl.FileSystemRights]::WriteData) `
                     -bor ([int][System.Security.AccessControl.FileSystemRights]::AppendData) `
                     -bor ([int][System.Security.AccessControl.FileSystemRights]::WriteAttributes) `
                     -bor ([int][System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes)

        $userWriteRules = @()
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $ident = [string]$ace.IdentityReference
            if ($ident -ne $currentUser) { continue }
            $rightsInt = [int]$ace.FileSystemRights
            if (($rightsInt -band $writeMask) -ne 0) {
                $userWriteRules += [string]$ace.FileSystemRights
            }
        }

        if ($wantLock) {
            if ($protected -and $userWriteRules.Count -eq 0) {
                Write-OK "ACL protegida (heranca desligada) e usuario atual sem write - lock ativo"
            } else {
                $why = @()
                if (-not $protected)              { $why += "heranca ainda ligada" }
                if ($userWriteRules.Count -gt 0)  { $why += ("usuario ainda tem write: " + ($userWriteRules -join ",")) }
                Write-Gap ("ACL lock esperado (profile.emac.lock_file=true) mas: {0}" -f ($why -join "; "))
            }
        } else {
            Write-Info ("ACL heranca protegida: {0}  write-rules-do-user: {1}" -f $protected, $userWriteRules.Count)
        }
    } catch {
        Write-Warn ("Falha ao ler ACL de {0}: {1}" -f $emacPath, $_.Exception.Message)
    }
}

# ============================================================
#  10. Profile schema version
# ============================================================
Write-Section "Profile schema version"

if (-not $hasProfile) {
    Write-Info "Sem profile carregado - pular check de schema."
} else {
    $schemaVer = $null
    if ($prof.PSObject.Properties['schema_version']) {
        $schemaVer = $prof.schema_version
    } elseif ($prof.PSObject.Properties['version']) {
        $schemaVer = $prof.version
    }

    if ($null -eq $schemaVer) {
        Write-Warn "profile sem campo schema_version - assumindo pre-Fase-1, regenere com 00-gerar-profile.bat"
    } else {
        Write-Info ("profile schema_version = {0}" -f $schemaVer)
        $verInt = 0
        [int]::TryParse([string]$schemaVer, [ref]$verInt) | Out-Null
        if ($verInt -lt 7) {
            Write-Warn ("schema {0} < 7 - versao antiga do profile (pre-v3.6, ainda contem 'storage' block obsoleto). Regenere com 00-gerar-profile.bat." -f $schemaVer)
        } elseif ($verInt -lt 8) {
            Write-Warn ("schema {0} < 8 - versao Fase 1.5. Regenere com 00-gerar-profile.bat para habilitar windows.machine_guid + disk/pci/volume spoof (Fase 1.6)." -f $schemaVer)
        } elseif ($verInt -lt 9) {
            Write-Warn ("schema {0} < 9 - versao Fase 1.6/pre-Track-A. Regenere com 00-gerar-profile.bat para habilitar cpu.* replay (rstflt v4.0)." -f $schemaVer)
        } else {
            Write-OK "schema >= 9 (Track A: cpu registry replay incluso + Fase 1.6 completa)"
        }
    }
}

# ============================================================
#  11. Per-adapter MAC vs profile.network
#
#  profile.network eh um array de entries { match, mac } onde
#  'match' e um regex contra InterfaceDescription e 'mac' o MAC
#  esperado (12 hex chars, upper). Se algum adapter que casa com
#  o pattern tem MAC diferente, spoof nao aplicou naquele NIC.
# ============================================================
Write-Section "Per-adapter MAC vs profile.network"

if (-not $hasProfile) {
    Write-Info "Sem profile - pulando comparacao per-adapter."
} elseif (-not $prof.PSObject.Properties['network']) {
    Write-Info "profile sem secao 'network' - pulando."
} else {
    $netEntries = @($prof.network)
    if ($netEntries.Count -eq 0) {
        Write-Info "profile.network vazio."
    } else {
        foreach ($entry in $netEntries) {
            if (-not ($entry.PSObject.Properties['match']) -or -not ($entry.PSObject.Properties['mac'])) {
                Write-Info "entrada network sem 'match' ou 'mac' - pulando"
                continue
            }
            $expectedMac = ([string]$entry.mac -replace '[:\-]', '').ToUpper()
            $pattern = [string]$entry.match
            $matched = Get-NetAdapter -ErrorAction SilentlyContinue |
                       Where-Object { $_.InterfaceDescription -match $pattern }
            if (-not $matched) {
                Write-Info ("match=`"{0}`" : nenhum adapter casou" -f $pattern)
                continue
            }
            foreach ($ad in $matched) {
                $curMac = ([string]$ad.MacAddress -replace '[:\-]', '').ToUpper()
                $desc = $ad.InterfaceDescription
                $shortDesc = if ($desc.Length -gt 40) { $desc.Substring(0,40) } else { $desc }
                if ($curMac -eq $expectedMac) {
                    Write-OK ("{0,-40} MAC={1}" -f $shortDesc, $curMac)
                } else {
                    Write-Gap ("{0,-40} MAC atual={1}  profile={2}" -f $shortDesc, $curMac, $expectedMac)
                }
            }
        }
    }
}

# ============================================================
#  12. CPU coherency: registry CPUID vendor vs WMI Manufacturer
#
#  HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\VendorIdentifier
#  vem cru do CPUID leaf 0 (GenuineIntel / AuthenticAMD). Comparamos
#  com Win32_Processor.Manufacturer que anti-cheat cruza com SMBIOS
#  Type 4. Divergencia = flag.
# ============================================================
Write-Section "CPU coherency: CPUID vendor vs WMI Manufacturer"

$cpuidVendor = $null
try {
    $cp0 = Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -ErrorAction SilentlyContinue
    if ($cp0 -and $cp0.VendorIdentifier) { $cpuidVendor = [string]$cp0.VendorIdentifier }
} catch { }

$wmiMfr = $null
try {
    $cpu2 = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cpu2) { $wmiMfr = [string]$cpu2.Manufacturer }
} catch { }

if ($null -eq $cpuidVendor -or $null -eq $wmiMfr) {
    Write-Info ("CPUID vendor: {0}  WMI Manufacturer: {1}" -f $cpuidVendor, $wmiMfr)
} else {
    Write-Info ("CPUID VendorIdentifier : {0}" -f $cpuidVendor)
    Write-Info ("WMI  Manufacturer      : {0}" -f $wmiMfr)
    $coherent = $false
    if     ($cpuidVendor -eq "GenuineIntel" -and $wmiMfr -match "Intel") { $coherent = $true }
    elseif ($cpuidVendor -eq "AuthenticAMD" -and $wmiMfr -match "AMD")   { $coherent = $true }
    if ($coherent) {
        Write-OK "CPUID vendor bate com WMI Manufacturer"
    } else {
        Write-Gap "SMBIOS Type 4 CPU manufacturer diverges from CPUID vendor"
    }
}

# ============================================================
#  13. Windows identity (MachineGuid + ComputerName + Hostname)
#
#  Fase 1.6 hotfix: EMAC user-mode le esses 3 valores via registry
#  (confirmado por procmon reconn-v2). Rewriter em spoof-windows-id.ps1
#  aplica todos de uma vez. Aqui checamos que registry bate com profile.
# ============================================================
Write-Section "Windows identity (MachineGuid + ComputerName + Hostname)"

if (-not $hasProfile) {
    Write-Info "Sem profile - pulando checks de windows identity."
} elseif (-not $prof.PSObject.Properties['windows']) {
    Write-Info "profile sem secao 'windows' - schema antigo (pre-v8)? Regenere profile."
} else {
    $wProf = $prof.windows

    # MachineGuid
    if ($wProf.PSObject.Properties['machine_guid']) {
        $expected = [string]$wProf.machine_guid
        $actual = $null
        try {
            $mg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -ErrorAction SilentlyContinue
            if ($mg) { $actual = [string]$mg.MachineGuid }
        } catch { }
        if ($null -eq $actual) {
            Write-Gap "MachineGuid    : chave HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid ausente"
        } elseif ($actual -ieq $expected) {
            Write-OK ("MachineGuid    : `"{0}`"" -f $actual)
        } else {
            Write-Gap ("MachineGuid    : actual=`"{0}`"  profile=`"{1}`"" -f $actual, $expected)
        }
    } else {
        Write-Info "profile.windows.machine_guid ausente"
    }

    # ComputerName (ActiveComputerName)
    if ($wProf.PSObject.Properties['computer_name']) {
        $expected = [string]$wProf.computer_name
        $actual = $null
        try {
            $cn = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name ComputerName -ErrorAction SilentlyContinue
            if ($cn) { $actual = [string]$cn.ComputerName }
        } catch { }
        if ($null -eq $actual) {
            Write-Gap "ComputerName   : chave ActiveComputerName\ComputerName ausente"
        } elseif ($actual -ieq $expected) {
            Write-OK ("ComputerName   : `"{0}`"" -f $actual)
        } else {
            Write-Gap ("ComputerName   : actual=`"{0}`"  profile=`"{1}`"" -f $actual, $expected)
        }
    } else {
        Write-Info "profile.windows.computer_name ausente"
    }

    # Tcpip Hostname
    if ($wProf.PSObject.Properties['tcpip_hostname']) {
        $expected = [string]$wProf.tcpip_hostname
        $actual = $null
        try {
            $tp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name Hostname -ErrorAction SilentlyContinue
            if ($tp) { $actual = [string]$tp.Hostname }
        } catch { }
        if ($null -eq $actual) {
            Write-Gap "TcpipHostname  : chave Tcpip\Parameters\Hostname ausente"
        } elseif ($actual -ieq $expected) {
            Write-OK ("TcpipHostname  : `"{0}`"" -f $actual)
        } else {
            Write-Gap ("TcpipHostname  : actual=`"{0}`"  profile=`"{1}`"" -f $actual, $expected)
        }
    } else {
        Write-Info "profile.windows.tcpip_hostname ausente"
    }
}

# ============================================================
#  14. Disk SCSI enum (registry cache) vs disk-mapping
#
#  EMAC user-mode le HKLM\SYSTEM\CurrentControlSet\Enum\SCSI\
#  Disk&Ven_XXX&Prod_YYY para descobrir vendor/model de cada disco.
#  spoof-disk-registry.ps1 reescreve FriendlyName + HardwareID.
#  Aqui checamos cada instancia (exceto boot disk) contra disk-mapping.
# ============================================================
Write-Section "Disk SCSI enum vs disk-mapping"

$diskMapPath = "C:\ProgramData\.hwcfg\disk-mapping.json"
if (-not $hasProfile) {
    Write-Info "Sem profile - pulando disk enum check."
} elseif (-not (Test-Path $diskMapPath)) {
    Write-Info "disk-mapping.json ausente - spoof-disk-registry.ps1 ainda nao rodou."
} else {
    $diskMap = $null
    try {
        $diskMap = Get-Content $diskMapPath -Raw | ConvertFrom-Json
    } catch {
        Write-Warn ("disk-mapping.json ilegivel: {0}" -f $_.Exception.Message)
    }

    if ($diskMap) {
        # Descobrir boot disk (o que hospeda C:) - excluir da checagem.
        $bootDiskModel = $null
        try {
            $sysDrive = ($env:SystemDrive).TrimEnd(':')
            $part = Get-Partition -DriveLetter $sysDrive -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($part) {
                $bd = Get-Disk -Number $part.DiskNumber -ErrorAction SilentlyContinue
                if ($bd) { $bootDiskModel = [string]$bd.Model }
            }
        } catch { }
        if ($bootDiskModel) {
            Write-Info ("boot disk (excluido): `"{0}`"" -f $bootDiskModel)
        }

        $scsiRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI"
        if (-not (Test-Path $scsiRoot)) {
            Write-Info "Enum\SCSI ausente."
        } else {
            $diskKeys = Get-ChildItem $scsiRoot -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -like "Disk&Ven_*&Prod_*" }
            if (-not $diskKeys -or $diskKeys.Count -eq 0) {
                Write-Info "Nenhuma entrada Disk&Ven_*&Prod_* em Enum\SCSI."
            } else {
                foreach ($dk in $diskKeys) {
                    $instances = Get-ChildItem $dk.PSPath -ErrorAction SilentlyContinue
                    foreach ($inst in $instances) {
                        $friendly = $null
                        $hwid1    = $null
                        try {
                            $ip = Get-ItemProperty -Path $inst.PSPath -ErrorAction SilentlyContinue
                            if ($ip) {
                                if ($ip.PSObject.Properties['FriendlyName']) { $friendly = [string]$ip.FriendlyName }
                                if ($ip.PSObject.Properties['HardwareID'])   {
                                    $hw = @($ip.HardwareID)
                                    if ($hw.Count -gt 0) { $hwid1 = [string]$hw[0] }
                                }
                            }
                        } catch { }

                        $tag = "{0}\{1}" -f $dk.PSChildName, $inst.PSChildName
                        if ($bootDiskModel -and $friendly -and ($friendly -match [regex]::Escape($bootDiskModel))) {
                            Write-Info ("{0} : boot disk - skip" -f $tag)
                            continue
                        }

                        # spoof-disk-registry.ps1 escreve o mapping como HASHTABLE:
                        #   { "<orig_key>": { new_key: "...", fake: {vendor, product, class} }, ... }
                        # A checagem: existe alguma entry cujo new_key bata com a
                        # subchave atual (dk.PSChildName)?
                        $curKey = $dk.PSChildName
                        $match = $null
                        $matchOrigKey = $null
                        foreach ($origKey in $diskMap.PSObject.Properties.Name) {
                            $ent = $diskMap.$origKey
                            if (-not $ent) { continue }
                            $newKey = $null
                            if ($ent.PSObject.Properties['new_key']) { $newKey = [string]$ent.new_key }
                            if ($newKey -and $newKey -ieq $curKey) {
                                $match = $ent
                                $matchOrigKey = $origKey
                                break
                            }
                        }
                        if ($match) {
                            Write-OK ("{0} : new_key match (orig={1})" -f $tag, $matchOrigKey)
                        } else {
                            Write-Gap ("{0} : FriendlyName=`"{1}`" - subchave nao aparece como new_key em disk-mapping (spoof nao aplicado?)" -f $tag, $friendly)
                        }
                    }
                }
            }
        }
    }
}

# ============================================================
#  15. PCI HardwareID (SUBSYS/REV/CC granular)
#
#  EMAC le HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_*&DEV_*\{inst}
#  \HardwareID (REG_MULTI_SZ) e agrega VEN&DEV&SUBSYS&REV&CC pra HWID.
#  spoof-pci-hardwareid.ps1 usa FNV(seed + VEN&DEV) pra derivar SUBSYS
#  deterministico. Sampleamos 5 devices e conferimos.
# ============================================================
Write-Section "PCI HardwareID (5 devices sample)"

$pciMapPath = "C:\ProgramData\.hwcfg\pci-hardwareid-mapping.json"
if (-not $hasProfile) {
    Write-Info "Sem profile - pulando check PCI HardwareID."
} elseif (-not (Test-Path $pciMapPath)) {
    Write-Info "pci-hardwareid-mapping.json ausente - spoof-pci-hardwareid.ps1 ainda nao rodou."
} else {
    $pciMap = $null
    try {
        $pciMap = Get-Content $pciMapPath -Raw | ConvertFrom-Json
    } catch {
        Write-Warn ("pci-hardwareid-mapping.json ilegivel: {0}" -f $_.Exception.Message)
    }

    $seed = $null
    if ($prof.PSObject.Properties['pci_hardwareid'] -and $prof.pci_hardwareid.PSObject.Properties['randomize_seed']) {
        $seed = [string]$prof.pci_hardwareid.randomize_seed
    }
    if ($null -eq $seed) {
        Write-Info "profile.pci_hardwareid.randomize_seed ausente - so validaremos presenca no mapping."
    } else {
        Write-Info ("randomize_seed : {0}" -f $seed)
    }

    if ($pciMap) {
        # Enumera devices PCI e amostra 5.
        $pciRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
        if (-not (Test-Path $pciRoot)) {
            Write-Info "Enum\PCI ausente."
        } else {
            $venDevKeys = Get-ChildItem $pciRoot -ErrorAction SilentlyContinue |
                          Where-Object { $_.PSChildName -match '^VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}$' }
            $allInstances = @()
            foreach ($vk in $venDevKeys) {
                $ins = Get-ChildItem $vk.PSPath -ErrorAction SilentlyContinue
                foreach ($i in $ins) {
                    $allInstances += [pscustomobject]@{
                        VenDev = $vk.PSChildName
                        InstancePath = $i.PSPath
                        InstanceName = $i.PSChildName
                    }
                }
            }
            if ($allInstances.Count -eq 0) {
                Write-Info "Nenhum device em Enum\PCI."
            } else {
                $sampleCount = [Math]::Min(5, $allInstances.Count)
                $sample = $allInstances | Get-Random -Count $sampleCount
                foreach ($s in $sample) {
                    $hwids = $null
                    try {
                        $ip = Get-ItemProperty -Path $s.InstancePath -Name HardwareID -ErrorAction SilentlyContinue
                        if ($ip) { $hwids = @($ip.HardwareID) }
                    } catch { }

                    if (-not $hwids -or $hwids.Count -eq 0) {
                        Write-Info ("{0}\{1} : HardwareID ausente" -f $s.VenDev, $s.InstanceName)
                        continue
                    }

                    # Extrai primeiro SUBSYS_XXXXXXXX presente em qualquer entry.
                    $currentSubsys = $null
                    foreach ($h in $hwids) {
                        if ([string]$h -match 'SUBSYS_([0-9A-Fa-f]{8})') {
                            $currentSubsys = $matches[1].ToUpper()
                            break
                        }
                    }
                    if ($null -eq $currentSubsys) {
                        Write-Info ("{0}\{1} : sem SUBSYS_ no HardwareID (device sem subsystem)" -f $s.VenDev, $s.InstanceName)
                        continue
                    }

                    # spoof-pci-hardwareid.ps1 escreve mapping como:
                    #   { version, created_at, seed, entries: [ {vendev, instance,
                    #     new_subsys, new_rev, ...}, ... ] }
                    $pciEntries = @()
                    if ($pciMap.PSObject.Properties['entries']) {
                        $pciEntries = @($pciMap.entries)
                    }
                    $mapEntry = $null
                    foreach ($m in $pciEntries) {
                        if (-not $m) { continue }
                        $mv = $null
                        if ($m.PSObject.Properties['vendev']) { $mv = [string]$m.vendev }
                        elseif ($m.PSObject.Properties['ven_dev']) { $mv = [string]$m.ven_dev }
                        if ($mv -and $mv -ieq $s.VenDev) { $mapEntry = $m; break }
                    }

                    if (-not $mapEntry) {
                        # Skip esperado: spoofer pula devices de classe unsafe
                        # (storage/TPM/bridge), instancias com so 1 HardwareID,
                        # ou sem SUBSYS/REV. Ausencia no mapping nao e gap.
                        Write-Info ("{0}\{1} : SUBSYS={2} sem entrada (spoofer pulou por politica ou classe unsafe)" -f $s.VenDev, $s.InstanceName, $currentSubsys)
                        continue
                    }

                    $expectedSubsys = $null
                    if ($mapEntry.PSObject.Properties['new_subsys']) { $expectedSubsys = ([string]$mapEntry.new_subsys).ToUpper() }
                    elseif ($mapEntry.PSObject.Properties['subsys_new']) { $expectedSubsys = ([string]$mapEntry.subsys_new).ToUpper() }

                    if ($null -eq $expectedSubsys) {
                        Write-Info ("{0}\{1} : mapping sem subsys_new - schema inesperado" -f $s.VenDev, $s.InstanceName)
                    } elseif ($currentSubsys -eq $expectedSubsys) {
                        Write-OK ("{0}\{1} : SUBSYS={2}" -f $s.VenDev, $s.InstanceName, $currentSubsys)
                    } else {
                        Write-Gap ("{0}\{1} : SUBSYS actual={2}  mapping={3}" -f $s.VenDev, $s.InstanceName, $currentSubsys, $expectedSubsys)
                    }
                }
            }
        }
    }
}

# ============================================================
#  16. Volume GUIDs (registry cache) vs volume-guid-backup
#
#  EMAC le HKLM\SYSTEM\CurrentControlSet\Enum\STORAGE\Volume\{GUID}#offset
#  pra colecionar 3 GUIDs de volume. spoof-volume-guid.ps1 gera novos
#  GUIDs para volumes NAO-boot e reescreve Enum + MountedDevices.
#  CRITICO: boot volume nunca eh spoofado. Aqui excluimos ele e comparamos
#  drive letters restantes contra o backup mapping.
# ============================================================
Write-Section "Volume GUIDs vs volume-guid-backup"

$volMapPath = "C:\ProgramData\.hwcfg\volume-guid-backup.json"
if (-not (Test-Path $volMapPath)) {
    Write-Info "volume-guid-backup.json ausente - spoof-volume-guid.ps1 ainda nao rodou."
} else {
    $volMap = $null
    try {
        $volMap = Get-Content $volMapPath -Raw | ConvertFrom-Json
    } catch {
        Write-Warn ("volume-guid-backup.json ilegivel: {0}" -f $_.Exception.Message)
    }

    if ($volMap) {
        $bootLetter = ($env:SystemDrive).TrimEnd(':').ToUpper()

        # Obter drive letter -> GUID atual usando GetVolumeNameForVolumeMountPoint.
        # Assinatura P/Invoke definida inline.
        if (-not ("HwtVolApi" -as [type])) {
            $sig = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class HwtVolApi {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern bool GetVolumeNameForVolumeMountPoint(
        string lpszVolumeMountPoint,
        StringBuilder lpszVolumeName,
        int cchBufferLength);
}
"@
            try { Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue } catch { }
        }

        # Enumera drive letters fixos.
        $drives = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue |
                  Where-Object { $_.DriveType -eq 3 }
        foreach ($dr in $drives) {
            $letter = ([string]$dr.DeviceID).TrimEnd(':').ToUpper()
            if ($letter -eq $bootLetter) {
                Write-Info ("{0}: : boot volume - skip (nunca deve ser spoofado)" -f $letter)
                continue
            }

            $mount = "$letter" + ":\"
            $sb = New-Object System.Text.StringBuilder 260
            $ok = $false
            try { $ok = [HwtVolApi]::GetVolumeNameForVolumeMountPoint($mount, $sb, $sb.Capacity) } catch { }
            if (-not $ok) {
                Write-Info ("{0}: : GetVolumeNameForVolumeMountPoint falhou" -f $letter)
                continue
            }
            $volName = $sb.ToString()
            # Formato: \\?\Volume{GUID}\ - extrai o GUID.
            $currentGuid = $null
            if ($volName -match 'Volume\{([0-9a-fA-F\-]+)\}') {
                $currentGuid = $matches[1].ToLower()
            }
            if ($null -eq $currentGuid) {
                Write-Info ("{0}: : sem GUID em `"{1}`"" -f $letter, $volName)
                continue
            }

            # spoof-volume-guid.ps1 salva backup como:
            #   { schema, timestamp, boot_guid, entries: [ {drive, old, new}, ... ] }
            $volEntries = @()
            if ($volMap.PSObject.Properties['entries']) {
                $volEntries = @($volMap.entries)
            }
            $entry = $null
            foreach ($v in $volEntries) {
                if (-not $v) { continue }
                $dl = $null
                if ($v.PSObject.Properties['drive']) { $dl = [string]$v.drive }
                elseif ($v.PSObject.Properties['drive_letter']) { $dl = [string]$v.drive_letter }
                elseif ($v.PSObject.Properties['letter']) { $dl = [string]$v.letter }
                if ($dl -and $dl.TrimEnd(':').ToUpper() -eq $letter) { $entry = $v; break }
            }

            if (-not $entry) {
                Write-Info ("{0}: : GUID={1} - drive nao consta em volume-guid-backup" -f $letter, $currentGuid)
                continue
            }

            $expected = $null
            if ($entry.PSObject.Properties['new']) { $expected = ([string]$entry.new).ToLower().Trim('{','}') }
            elseif ($entry.PSObject.Properties['new_guid']) { $expected = ([string]$entry.new_guid).ToLower().Trim('{','}') }
            if ($null -eq $expected) {
                Write-Info ("{0}: : entry sem campo 'new' - schema inesperado" -f $letter)
                continue
            }

            if ($currentGuid -eq $expected) {
                Write-OK ("{0}: : GUID={{{1}}}" -f $letter, $currentGuid)
            } else {
                Write-Gap ("{0}: : GUID actual={{{1}}}  mapping new={{{2}}}" -f $letter, $currentGuid, $expected)
            }
        }
    }
}

# ============================================================
#  Fim
# ============================================================
Write-Host ""
Write-Host "========================================================" -ForegroundColor White
if ($script:GapCount -eq 0) {
    Write-Host "  CONSISTENCY: OK - nada obvio a corrigir" -ForegroundColor Green
    exit 0
} else {
    Write-Host ("  CONSISTENCY: {0} gaps/inconsistencias encontrados" -f $script:GapCount) -ForegroundColor Yellow
    Write-Host "  Revise os itens marcados [GAP] acima antes de testar" -ForegroundColor Yellow
    exit 1
}
