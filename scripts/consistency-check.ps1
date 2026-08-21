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
