#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Reescreve entradas Enum\SCSI\Disk&Ven_*&Prod_* no registro para spoofar
    marca/modelo dos drives visiveis para EMAC (Fase 1.6 - GAP HWID).

.DESCRIPTION
    Reconnaissance v2: EMAC (user-mode) le HKLM\SYSTEM\CurrentControlSet\
    Enum\SCSI\Disk&Ven_<vendor>&Prod_<model>\<instance> via RegOpenKey +
    RegQueryValue. O nome da SUBCHAVE ("Disk&Ven_KINGSTON&Prod_SA400S3")
    ja carrega vendor+model - portanto reescrever apenas FriendlyName nao
    resolve. Precisamos renomear a propria chave (export -> replace no
    .reg -> import -> delete antigo), mesmo padrao de spoof-audio-guids.

    Fonte dos fakes: $prof.disk.drives (pool de {vendor, model}).
    Mapeamento persistido em C:\ProgramData\.hwcfg\disk-mapping.json
    para que reruns produzam o mesmo mapping (evita drift).
    Backup dos valores originais em disk-registry-backup.json para -Restore.

    PROTECAO CRITICA: NAO tocamos no disco de boot (aquele que contem C:).
    Reescrever o Enum\SCSI da unidade de boot pode deixar o Windows
    incapaz de reencontrar o volume de sistema no proximo boot. Detectamos
    o disco de boot via Get-Partition -DriveLetter C | Get-Disk e
    ignoramos suas subchaves SCSI.

    RISCO PnP: O Plug-and-Play manager pode re-enumerar o dispositivo
    ao proximo boot e RECRIAR a subchave original. Recomendacao ao
    usuario: rodar este script como ultimo passo antes de abrir o cliente
    do jogo, apos o reboot final da rotina de spoof. Alternativamente,
    agendar como tarefa em -AtStartup delayed 60s.

    Uso:
      .\spoof-disk-registry.ps1              # aplica spoof
      .\spoof-disk-registry.ps1 -DryRun      # mostra plano sem escrever
      .\spoof-disk-registry.ps1 -Restore     # reverte via backup
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Restore
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"

$profilePath  = "C:\ProgramData\.hwcfg\profile.json"
$mappingPath  = "C:\ProgramData\.hwcfg\disk-mapping.json"
$backupPath   = "C:\ProgramData\.hwcfg\disk-registry-backup.json"
$scsiRoot     = "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"
$scsiRootPs   = "HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI"

# ============================================================
#  Helpers
# ============================================================

function Invoke-Reg {
    param([string[]]$RegArgs)
    $out = & reg.exe @RegArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("reg.exe " + ($RegArgs -join ' ') + " falhou (" + $LASTEXITCODE + "): " + ($out -join "`n"))
    }
    return $out
}

# Ex: "Disk&Ven_KINGSTON&Prod_SA400S3" -> @{ Vendor="KINGSTON"; Product="SA400S3" }
function Parse-DiskKeyName {
    param([string]$KeyName)
    if ($KeyName -match '^Disk&Ven_(.+?)&Prod_(.+)$') {
        return [pscustomobject]@{ Vendor = $Matches[1]; Product = $Matches[2] }
    }
    return $null
}

# Normaliza um string vendor/model para o formato usado no Enum\SCSI:
#   - espacos viram underscore
#   - so ASCII imprimivel; tudo fora vira "_"
#   - Windows tipicamente maiuscula, mas preservamos entrada do profile
function Normalize-ScsiToken {
    param([string]$S)
    if ([string]::IsNullOrWhiteSpace($S)) { return "UNKNOWN" }
    $s = $S -replace '\s+','_'
    $s = -join ($s.ToCharArray() | ForEach-Object {
        if ([int][char]$_ -ge 32 -and [int][char]$_ -le 126 -and $_ -notin @('\','/','&','?','*',':','<','>','|','"','[',']')) { $_ } else { '_' }
    })
    return $s
}

# Descobre o numero do disco fisico que contem o boot volume.
# Usa $env:SystemDrive (autoritativo) em vez de 'C' hard-coded — Windows
# instalado em D:/E: (Windows-To-Go, dual-boot rescue) tem SystemDrive != C:.
function Get-BootDiskNumber {
    try {
        $sd = $env:SystemDrive
        if ([string]::IsNullOrWhiteSpace($sd)) { throw "SystemDrive nao definido" }
        $letter = $sd.TrimEnd(':').TrimEnd('\')
        $part = Get-Partition -DriveLetter $letter -ErrorAction Stop
        $disk = $part | Get-Disk -ErrorAction Stop
        return [int]$disk.Number
    } catch {
        Write-Warn ("Nao consegui identificar disco de boot: " + $_.Exception.Message)
        return $null
    }
}

# Mapeia PSChildName do Enum\SCSI (ex: "Disk&Ven_KINGSTON&Prod_SA400S3") -> lista de numeros de disco fisicos.
# Windows expoe o mapping via propriedade DEVPKEY_Device_InstanceId no MSFT_Disk (Get-Disk).
# Comparamos SCSI\Disk&Ven_...&Prod_..._<instance> do MSFT_Disk.Path com nossas subchaves.
function Get-DiskNumberMap {
    $map = @{}
    try {
        $disks = Get-Disk -ErrorAction Stop
    } catch {
        return $map
    }
    foreach ($d in $disks) {
        $pnp = $null
        try { $pnp = (Get-CimInstance -Namespace root/Microsoft/Windows/Storage -ClassName MSFT_Disk -Filter ("Number=" + $d.Number) -ErrorAction Stop).PSComputerName } catch {}
        # Preferimos o campo Path/Location; caemos em FriendlyName se necessario.
        $loc = $d.Location
        $friendly = $d.FriendlyName
        # Location tipicamente contem "SCSI\Disk&Ven_XXX&Prod_YYY\..." ou "PCI(...)#SCSI(...)".
        if ($loc -match 'Disk&Ven_(.+?)&Prod_([^\\#]+)') {
            $keyName = "Disk&Ven_" + $Matches[1] + "&Prod_" + $Matches[2]
            if (-not $map.ContainsKey($keyName)) { $map[$keyName] = @() }
            $map[$keyName] += [int]$d.Number
        }
    }
    return $map
}

# ============================================================
#  Restore mode
# ============================================================
if ($Restore) {
    Write-Section "Restore de disk registry"
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

    $bootDisk = Get-BootDiskNumber
    if ($null -ne $bootDisk) { Write-Info ("Disco de boot: #" + $bootDisk + " (protegido)") }

    $restored = 0
    foreach ($e in @($bkp.entries)) {
        $currentKey = $e.new_key  # nome da subchave apos spoof (ex: Disk&Ven_SEAGATE&Prod_ST2000)
        $origKey    = $e.orig_key # nome original
        $currentPathReg = "$scsiRoot\$currentKey"
        $origPathReg    = "$scsiRoot\$origKey"

        if (-not (Test-Path (Join-Path $scsiRootPs $currentKey))) {
            Write-Warn ("Subchave spoofada ausente (ja restaurada ou nao existe): " + $currentKey)
            continue
        }

        if ($DryRun) {
            Write-Info ("[DryRun] Restauraria: " + $currentKey + " -> " + $origKey)
            continue
        }

        $tmpFile = Join-Path $env:TEMP ("disk-restore-" + [guid]::NewGuid().ToString() + ".reg")
        try {
            [void](Invoke-Reg -RegArgs @("export", $currentPathReg, $tmpFile, "/y"))
            $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode

            # Replace no path da chave e nos valores textuais que carregam vendor/product.
            # Substituicao case-insensitive por regex, tokens escapados.
            $escCurKey = [regex]::Escape($currentKey)
            $newContent = [regex]::Replace($content, $escCurKey, $origKey, 'IgnoreCase')

            # Tambem restaurar tokens vendor/product isolados (aparecem em HardwareID/CompatibleIDs)
            $curParsed = Parse-DiskKeyName $currentKey
            $origParsed = Parse-DiskKeyName $origKey
            if ($curParsed -and $origParsed) {
                $escVen  = [regex]::Escape("Ven_" + $curParsed.Vendor)
                $escProd = [regex]::Escape("Prod_" + $curParsed.Product)
                $newContent = [regex]::Replace($newContent, $escVen,  ("Ven_"  + $origParsed.Vendor),  'IgnoreCase')
                $newContent = [regex]::Replace($newContent, $escProd, ("Prod_" + $origParsed.Product), 'IgnoreCase')
            }

            Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline
            [void](Invoke-Reg -RegArgs @("import", $tmpFile))
            [void](Invoke-Reg -RegArgs @("delete", $currentPathReg, "/f"))

            # Restaurar FriendlyName/DeviceDesc originais (podem nao ter batido no replace textual
            # se a string tinha caracteres nao presentes no key name).
            $origKeyPs = Join-Path $scsiRootPs $origKey
            foreach ($instance in @($e.instances)) {
                $instPath = Join-Path $origKeyPs $instance.name
                if (-not (Test-Path $instPath)) { continue }
                foreach ($vname in @("FriendlyName","DeviceDesc","Mfg")) {
                    $v = $instance.$vname
                    if ($null -ne $v) {
                        try { Set-ItemProperty -Path $instPath -Name $vname -Value $v -ErrorAction Stop } catch {}
                    }
                }
                if ($instance.HardwareID) {
                    try { Set-ItemProperty -Path $instPath -Name "HardwareID" -Value @($instance.HardwareID) -Type MultiString -ErrorAction Stop } catch {}
                }
                if ($instance.CompatibleIDs) {
                    try { Set-ItemProperty -Path $instPath -Name "CompatibleIDs" -Value @($instance.CompatibleIDs) -Type MultiString -ErrorAction Stop } catch {}
                }
            }

            $restored++
            Write-OK ("Restaurado: " + $currentKey + " -> " + $origKey)
        } catch {
            Write-Err ("Falha restaurando " + $currentKey + ": " + $_.Exception.Message)
        } finally {
            if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
        }
    }

    if (-not $DryRun -and $restored -gt 0) {
        try {
            $bakPath = $backupPath + ".bak"
            if (Test-Path $bakPath) { Remove-Item $bakPath -Force -ErrorAction SilentlyContinue }
            Move-Item -Path $backupPath -Destination $bakPath -Force
            Remove-Item $bakPath -Force -ErrorAction SilentlyContinue
        } catch { Remove-Item $backupPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $mappingPath) { Remove-Item $mappingPath -Force -ErrorAction SilentlyContinue }
        Write-OK ("Backup e mapping removidos")
    }

    Write-Section "Resumo restore"
    Write-Host ("  Restaurados: " + $restored) -ForegroundColor Cyan
    Write-Warn "PnP pode re-enumerar no proximo boot - reconferir com check-consistency.ps1"
    exit 0
}

# ============================================================
#  Spoof mode
# ============================================================
Write-Section "Spoof de disk registry (Enum\SCSI)"

# 1) Carregar profile
if (-not (Test-Path $profilePath)) {
    Write-Err ("Profile nao encontrado: " + $profilePath)
    Write-Err "Rode generate-profile.ps1 primeiro."
    exit 1
}
try {
    $prof = Get-Content $profilePath -Raw | ConvertFrom-Json
} catch {
    Write-Err ("Profile corrompido: " + $_.Exception.Message)
    exit 1
}

$profVer = 0
if ($prof.PSObject.Properties['version']) {
    [int]::TryParse([string]$prof.version, [ref]$profVer) | Out-Null
}
if ($profVer -lt 8) {
    Write-Err ("Profile schema v" + $profVer + " nao contem bloco disk.drives (v8+).")
    Write-Err "Regenere com generate-profile.ps1 -Generate."
    exit 1
}

$drivesPool = @()
if ($prof.disk -and $prof.disk.drives) {
    $drivesPool = @($prof.disk.drives)
}
if ($drivesPool.Count -eq 0) {
    Write-Err "Profile nao contem disk.drives - regenere o profile (schema v8+)."
    exit 1
}
Write-OK ("Pool de drives no profile: " + $drivesPool.Count + " entrada(s)")

# 2) Detectar disco de boot (protegido)
$bootDisk = Get-BootDiskNumber
if ($null -eq $bootDisk) {
    Write-Err "Nao consegui identificar disco de boot - abortando por seguranca."
    Write-Err "Sem isso, spoof pode corromper o volume de sistema."
    exit 1
}
Write-OK ("Disco de boot: #" + $bootDisk + " (sera PROTEGIDO)")

# 3) Mapping subchave SCSI -> lista de numeros de disco fisicos
$diskNumMap = Get-DiskNumberMap
if ($diskNumMap.Count -eq 0) {
    Write-Warn "Nao consegui mapear subchaves SCSI para numeros de disco fisicos."
    Write-Warn "Sem esse mapping nao podemos detectar o disco de boot por subchave - abortando."
    exit 1
}

# 3.1) Sanity: o boot disk PRECISA aparecer em pelo menos uma entrada do mapping.
# Se nao aparece, Get-Disk.Location nao retornou padrao Disk&Ven_*&Prod_* para o
# boot disk (NVMe muitas vezes reporta so PCIROOT#PCI#NVME). Sem essa entrada,
# o filtro "physNums -contains $bootDisk" nunca dispara e o boot disk fica em
# risco de ser reescrito. Melhor abortar do que arriscar brick.
$bootDiskMapped = $false
foreach ($physList in $diskNumMap.Values) {
    if (@($physList) -contains $bootDisk) { $bootDiskMapped = $true; break }
}
if (-not $bootDiskMapped) {
    Write-Err ("Disco de boot (#" + $bootDisk + ") NAO aparece em Get-DiskNumberMap.")
    Write-Err "Provavelmente NVMe cujo Get-Disk.Location nao expoe Disk&Ven_*&Prod_*."
    Write-Err "Sem essa entrada, nao podemos garantir que o disco de boot seja preservado."
    Write-Err "Abortando por seguranca."
    exit 1
}

# 4) Enumerar subchaves Disk&Ven_*&Prod_*
$allKeys = @()
if (Test-Path $scsiRootPs) {
    $allKeys = @(Get-ChildItem -Path $scsiRootPs -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like "Disk&Ven_*&Prod_*" })
}
if ($allKeys.Count -eq 0) {
    Write-Warn "Nenhuma subchave Disk&Ven_*&Prod_* encontrada em Enum\SCSI"
    exit 0
}
Write-OK ("Subchaves SCSI candidatas: " + $allKeys.Count)

# 5) Carregar mapping anterior (para estabilidade em reruns)
$existingMap = @{}
if (Test-Path $mappingPath) {
    try {
        $prev = Get-Content $mappingPath -Raw | ConvertFrom-Json
        foreach ($p in $prev.PSObject.Properties) {
            $existingMap[$p.Name] = $p.Value
        }
        Write-OK ("Mapping anterior carregado: " + $existingMap.Count + " entrada(s)")
    } catch {
        Write-Warn ("Falha lendo mapping anterior: " + $_.Exception.Message)
    }
}

# 6) Round-robin index sobre o pool
$poolIndex = 0
function Get-Next-FakeDrive {
    $d = $drivesPool[$script:poolIndex % $drivesPool.Count]
    $script:poolIndex++
    return $d
}

# 7) Processar cada subchave
$backupEntries = @()
$newMapping    = @{}
$skippedBoot   = 0
$skippedOther  = 0
$processed     = 0

foreach ($k in $allKeys) {
    $keyName = $k.PSChildName
    $keyPathPs  = $k.PSPath
    $keyPathReg = "$scsiRoot\$keyName"

    # Skip se este key ja e resultado de spoof anterior (nao re-spoofar)
    $alreadySpoofed = $false
    foreach ($entryName in $existingMap.Keys) {
        $entryVal = $existingMap[$entryName]
        if ($entryVal.new_key -and $entryVal.new_key.ToString().ToLower() -eq $keyName.ToLower()) {
            $alreadySpoofed = $true
            break
        }
    }
    if ($alreadySpoofed) {
        Write-Info ($keyName + " - ja spoofada em run anterior, pulando")
        continue
    }

    # Descobrir numeros de disco fisicos ligados a esta subchave
    $physNums = @()
    if ($diskNumMap.ContainsKey($keyName)) { $physNums = @($diskNumMap[$keyName]) }

    if ($physNums.Count -eq 0) {
        Write-Warn ($keyName + " - sem mapping para disco fisico; PULANDO por seguranca")
        $skippedOther++
        continue
    }

    if ($physNums -contains $bootDisk) {
        Write-Warn ($keyName + " - contem disco de BOOT (#" + $bootDisk + "); PULANDO")
        $skippedBoot++
        continue
    }

    # Coletar valores originais de todas as instancias (subchaves) sob este keyName
    $instances = @()
    $instanceItems = @()
    try { $instanceItems = @(Get-ChildItem -Path $keyPathPs -ErrorAction Stop) } catch {}
    foreach ($inst in $instanceItems) {
        $props = $null
        try { $props = Get-ItemProperty -Path $inst.PSPath -ErrorAction Stop } catch {}
        $obj = [pscustomobject]@{
            name          = $inst.PSChildName
            FriendlyName  = $null
            DeviceDesc    = $null
            Mfg           = $null
            HardwareID    = @()
            CompatibleIDs = @()
        }
        if ($props) {
            if ($props.PSObject.Properties.Name -contains 'FriendlyName')  { $obj.FriendlyName  = $props.FriendlyName }
            if ($props.PSObject.Properties.Name -contains 'DeviceDesc')    { $obj.DeviceDesc    = $props.DeviceDesc }
            if ($props.PSObject.Properties.Name -contains 'Mfg')           { $obj.Mfg           = $props.Mfg }
            if ($props.PSObject.Properties.Name -contains 'HardwareID')    { $obj.HardwareID    = @($props.HardwareID) }
            if ($props.PSObject.Properties.Name -contains 'CompatibleIDs') { $obj.CompatibleIDs = @($props.CompatibleIDs) }
        }
        $instances += $obj
    }

    # Escolher drive fake do pool. Profile emite {vendor, product, class}.
    $fake = Get-Next-FakeDrive
    $fakeVendorRaw  = [string]$fake.vendor
    $fakeProductRaw = [string]$fake.product
    # Vendor pode legitimamente ser "" para NVMe (pool reflete que NVMe real
    # tem Ven_ vazio). Nao normalizamos "" -> "UNKNOWN": isso viraria uma
    # fingerprint distinctive "Disk&Ven_UNKNOWN&Prod_*" comum a todos os
    # usuarios do toolkit. Se vazio, keyName sai "Disk&Ven_&Prod_X" que e
    # o formato real de NVMe.
    if ([string]::IsNullOrEmpty($fakeVendorRaw)) {
        $fakeVendor = ""
    } else {
        $fakeVendor = Normalize-ScsiToken $fakeVendorRaw
    }
    $fakeProduct = Normalize-ScsiToken $fakeProductRaw
    $newKeyName  = "Disk&Ven_" + $fakeVendor + "&Prod_" + $fakeProduct
    $newKeyPathReg = "$scsiRoot\$newKeyName"

    if ($newKeyName.ToLower() -eq $keyName.ToLower()) {
        Write-Info ($keyName + " - fake identico ao original; pulando")
        continue
    }

    if (Test-Path (Join-Path $scsiRootPs $newKeyName)) {
        Write-Warn ("Destino ja existe: " + $newKeyName + " - PULANDO para evitar merge")
        $skippedOther++
        continue
    }

    $origParsed = Parse-DiskKeyName $keyName
    if (-not $origParsed) {
        Write-Warn ("Nao consegui parse: " + $keyName + " - pulando")
        $skippedOther++
        continue
    }

    if ($DryRun) {
        Write-Info ("[DryRun] " + $keyName + "  ->  " + $newKeyName)
        foreach ($i in $instances) {
            Write-Info ("           inst=" + $i.name + "  FriendlyName='" + $i.FriendlyName + "'")
        }
        continue
    }

    # Executa rename via export/replace/import/delete (padrao spoof-audio-guids)
    $tmpFile = Join-Path $env:TEMP ("disk-swap-" + [guid]::NewGuid().ToString() + ".reg")
    try {
        [void](Invoke-Reg -RegArgs @("export", $keyPathReg, $tmpFile, "/y"))
        $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode

        # Substituicoes:
        # 1) O key path completo (usa keyName no path)
        $escKey  = [regex]::Escape($keyName)
        # 2) Tokens Ven_X e Prod_Y isolados (aparecem em HardwareID/CompatibleIDs
        #    tanto no formato SCSI\Disk&Ven_...&Prod_... quanto em outras strings)
        $escVen  = [regex]::Escape("Ven_"  + $origParsed.Vendor)
        $escProd = [regex]::Escape("Prod_" + $origParsed.Product)

        $newContent = [regex]::Replace($content,    $escKey,  $newKeyName,               'IgnoreCase')
        $newContent = [regex]::Replace($newContent, $escVen,  ("Ven_"  + $fakeVendor),   'IgnoreCase')
        $newContent = [regex]::Replace($newContent, $escProd, ("Prod_" + $fakeProduct),  'IgnoreCase')

        # 3) FriendlyName tipicamente "KINGSTON SA400S3" (com espaco). Substituir
        #    ocorrencias textuais do vendor original e do product original (com
        #    underscores convertidos para espacos) por versoes fake.
        #    Usamos word-boundary (\b) para evitar colisoes: "HP" nao pode
        #    substituir "HPQC001" e "WDC" nao substitui parte de "WDC=..."
        #    em strings de ContainerID/Location/Class. Ainda case-insensitive.
        $origVendorSpaced  = $origParsed.Vendor  -replace '_',' '
        $origProductSpaced = $origParsed.Product -replace '_',' '
        $fakeVendorSpaced  = $fakeVendorRaw
        $fakeProductSpaced = $fakeProductRaw
        if ($origVendorSpaced  -and $fakeVendorSpaced) {
            $pat = '\b' + [regex]::Escape($origVendorSpaced) + '\b'
            $newContent = [regex]::Replace($newContent, $pat, $fakeVendorSpaced, 'IgnoreCase')
        }
        if ($origProductSpaced -and $fakeProductSpaced) {
            $pat = '\b' + [regex]::Escape($origProductSpaced) + '\b'
            $newContent = [regex]::Replace($newContent, $pat, $fakeProductSpaced, 'IgnoreCase')
        }

        # Sanity: o key path original nao pode mais existir literal no .reg
        if ([regex]::IsMatch($newContent, $escKey, 'IgnoreCase')) {
            throw "Sanity check falhou: key name original ainda presente apos replace."
        }

        Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline
        [void](Invoke-Reg -RegArgs @("import", $tmpFile))
        [void](Invoke-Reg -RegArgs @("delete", $keyPathReg, "/f"))

        # Registrar no backup e mapping
        $backupEntries += [pscustomobject]@{
            orig_key  = $keyName
            new_key   = $newKeyName
            instances = $instances
        }
        $newMapping[$keyName] = [pscustomobject]@{
            new_key = $newKeyName
            fake    = $fake
        }
        $processed++
        Write-OK ($keyName + "  ->  " + $newKeyName)
    } catch {
        Write-Err ("Falha spoof " + $keyName + ": " + $_.Exception.Message)
    } finally {
        if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
    }
}

# 8) Persistir backup + mapping (merge com anterior)
if (-not $DryRun -and $processed -gt 0) {
    Write-Section "Persistindo backup e mapping"

    $dir = Split-Path $backupPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    # Merge backup: se existe backup anterior, preservar entradas antigas para keys nao re-processadas
    $mergedEntries = @()
    if (Test-Path $backupPath) {
        try {
            $prevBkp = Get-Content $backupPath -Raw | ConvertFrom-Json
            foreach ($e in @($prevBkp.entries)) {
                $stillInNew = $false
                foreach ($ne in $backupEntries) {
                    if ($ne.orig_key -eq $e.orig_key) { $stillInNew = $true; break }
                }
                if (-not $stillInNew) { $mergedEntries += $e }
            }
        } catch {}
    }
    $mergedEntries += $backupEntries
    $bkpObj = [pscustomobject]@{ generated_at = (Get-Date).ToString('o'); entries = $mergedEntries }

    $tmpBkp = $backupPath + ".tmp"
    $bkpObj | ConvertTo-Json -Depth 8 | Set-Content -Path $tmpBkp -Encoding UTF8
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

# 9) Resumo
Write-Section "Resumo"
Write-Host ("  Subchaves processadas    : " + $processed)      -ForegroundColor Cyan
Write-Host ("  Puladas (disco de boot)  : " + $skippedBoot)    -ForegroundColor Cyan
Write-Host ("  Puladas (outros motivos) : " + $skippedOther)   -ForegroundColor Cyan
if ($DryRun) {
    Write-Warn "DryRun ativo - nenhuma escrita feita"
}
Write-Host ""
Write-Warn "PnP manager pode RE-ENUMERAR e recriar as subchaves originais no proximo boot."
Write-Warn "Recomendacao: rode este script como ULTIMO passo, apos o reboot final,"
Write-Warn "imediatamente antes de abrir o cliente do jogo."
Write-Info ("Para reverter: .\spoof-disk-registry.ps1 -Restore")
exit 0
