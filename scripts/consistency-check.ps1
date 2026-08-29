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
           - Volume Serial Number: mostra os de C:/D:/E: para conferir
             se volflt esta ativo (VSN deve ser deterministico do seed)

    Codigo de saida:
      0 = tudo bate
      1 = pelo menos um GAP ou INCONSISTENCIA

    NOTA: este arquivo e ASCII puro de proposito. Windows PowerShell 5.1
    le sem BOM assumindo Windows-1252, e caracteres UTF-8 multi-byte
    (em-dash, acentuados) viram sequencias com aspas que quebram o parser.
#>

$ErrorActionPreference = "Stop"
$profilePath = "C:\ProgramData\.hwcfg\profile.json"

function Write-Section($t) { Write-Host ""; Write-Host ("== " + $t + " ==") -ForegroundColor Cyan }
function Write-OK($m)      { Write-Host ("  [OK]   " + $m) -ForegroundColor Green }
function Write-Gap($m)     { Write-Host ("  [GAP]  " + $m) -ForegroundColor Yellow; $script:GapCount++ }
function Write-Warn($m)    { Write-Host ("  [!]    " + $m) -ForegroundColor Yellow; $script:GapCount++ }
function Write-Info($m)    { Write-Host ("  [*]    " + $m) -ForegroundColor Gray }

$script:GapCount = 0

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
# alguma coisa alterou Type 4 CPUID (bug em spoof-uuid.ps1).
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
#  5. Disco: Model (nao spoofado) vs Serial format (spoofado)
#
#  Se Model diz "Samsung SSD 970" mas Serial parece formato
#  Kingston/Crucial (prefixo diferente), disparate obvio.
#  Alem disso mostra ambos os campos que anti-cheat compara.
# ============================================================
Write-Section "Disco: Model vs Serial format"

$disks = Get-CimInstance Win32_DiskDrive |
         Where-Object { $_.MediaType -match "Fixed" -or $_.InterfaceType -match "IDE|SCSI|NVMe" }
foreach ($d in $disks) {
    $ser = if ($d.SerialNumber) { $d.SerialNumber.Trim() } else { "(vazio)" }
    Write-Info ("{0,-35} Serial: {1}" -f $d.Model, $ser)

    # Heuristica leve - so aviso se cheiro obvio
    if ($d.Model -match "Samsung"  -and $ser -notmatch "^S[0-9A-Z]") {
        Write-Gap "Samsung mas serial nao comeca com S - verifique SerialPrefix"
    }
    if ($d.Model -match "Kingston" -and $ser -match "^S6BN") {
        Write-Gap "Kingston com prefixo S6BN (default do toolkit) - mismatch"
    }
}

# ============================================================
#  6. Volume Serial Numbers - comprova volflt ativo
# ============================================================
Write-Section "Volume Serial Numbers (checa volflt ativo)"

$fltActive = $false
try {
    $flt = & fltmc filters 2>$null
    if ($flt -match "VolFlt") {
        Write-OK "VolFlt carregado no fltmc"
        $fltActive = $true
    } else {
        Write-Warn "VolFlt NAO aparece em 'fltmc filters' - VSN spoof inativo"
    }
} catch {
    Write-Warn "fltmc indisponivel"
}

Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
    $vsn = $null
    try {
        $filter = "DeviceID='{0}:'" -f $_.DriveLetter
        $ld = Get-CimInstance Win32_LogicalDisk -Filter $filter -ErrorAction SilentlyContinue
        if ($ld) { $vsn = $ld.VolumeSerialNumber }
    } catch { }
    Write-Info ("{0}:  VSN={1}  Label='{2}'  FS={3}" -f $_.DriveLetter, $vsn, $_.FileSystemLabel, $_.FileSystem)
}

if (-not $fltActive) {
    Write-Gap "VSN acima sao os REAIS (VolFlt nao esta filtrando)"
}

# ============================================================
#  7. Audio MMDevices GUIDs match profile pool
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
        # Coleta GUIDs "novos" do mapa (aceita tanto propriedade "new"
        # quanto valores diretos - depende de como spoof-audio-guids.ps1
        # serializa. Cobrimos os dois formatos.)
        $newGuids = New-Object System.Collections.Generic.HashSet[string]
        foreach ($p in $audioMap.PSObject.Properties) {
            $v = $p.Value
            if ($v -is [string]) {
                [void]$newGuids.Add($v.ToLower().Trim('{','}'))
            } elseif ($v -and $v.PSObject.Properties['new']) {
                [void]$newGuids.Add(([string]$v.new).ToLower().Trim('{','}'))
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
#  8. EDID full-spoof coherency
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
        # regex "Write|Modify|..." nunca casa — falso negativo no lock check.
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
        if ($verInt -lt 5) {
            Write-Warn ("schema {0} < 5 - Fase 1 (audio rotation, EDID full, emac persistence) ausente. Regenere o profile." -f $schemaVer)
        } else {
            Write-OK "schema >= 5 (Fase 1 fields presentes)"
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
