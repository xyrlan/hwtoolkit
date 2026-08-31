#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Renomeia instance IDs de dispositivos HID em Enum\HID\VID_*&PID_*[&Col*]
    para spoofar identidade HID visivel para EMAC (Fase 1.6 - GAP HWID).

.DESCRIPTION
    Reconnaissance v2 (docs/emac-hwid-recon.md rev.3): rubinot_dx.exe leu
    54 vezes chaves HKLM\SYSTEM\CurrentControlSet\Enum\HID\VID_*&PID_*[&Col*]
    via RegQueryValueEx. O nome da SUBCHAVE VID_YYYY&PID_XXXX ja identifica
    o dispositivo pelo hardware ID; o nome da INSTANCE (ex: "7&12ab34cd&0&0000")
    identifica a instancia fisica plugada. Aqui reescrevemos APENAS o nome da
    subchave-folha (instance), preservando o pai VID&PID intacto. O que muda
    ao EMAC eh o identificador de instancia unico por-maquina.

    Padrao de rename identico ao spoof-disk-registry.ps1:
      reg.exe export -> substituicao textual do instance name -> reg.exe import
      -> reg.exe delete da chave antiga.

    Fonte da aleatoriedade: FNV-1a 64bit de (seed + instance path original),
    seed vindo de $prof.pci_hardwareid.randomize_seed (32 hex chars).
    Reruns produzem o MESMO nome novo para a mesma entrada (deterministico).

    ============================================================
    ORDEM NO PIPELINE - importante:
    ============================================================
    HID eh filho de USB no PnP tree. Se spoof-usb-ids.ps1 renomear um
    USB parent, o Plug-and-Play manager REGENERA os children HID,
    invalidando o backup deste script. Duas ordens seguras:

      OPCAO A (preferida, ordem recomendada em 04b-aplicar-hwid-emac.bat):
        1) spoof-hid-ids.ps1     <-- ESTE script primeiro
        2) spoof-usb-ids.ps1
        Motivo: HID nao regenera USB parents, mas USB regenera HID children.

      OPCAO B (se por algum motivo USB precisar rodar antes):
        1) spoof-usb-ids.ps1
        2) reboot (aguardar PnP re-enumerar)
        3) spoof-hid-ids.ps1
        Motivo: sem reboot, PnP ainda nao reconstruiu os HID children
        e este script vai enumerar as chaves velhas.

    ============================================================
    PROTECAO CRITICA - MOUSE E TECLADO:
    ============================================================
    Renomear a instancia HID do mouse/teclado que o Windows esta USANDO
    AGORA torna o input inutilizavel no proximo boot ate reinstalacao PnP.
    Guarda-corpos:

      1) Enumeramos Get-PnpDevice -Class Mouse -Status OK e
         Get-PnpDevice -Class Keyboard -Status OK. Para cada dispositivo
         presente, extraimos a instance folha do InstanceId
         (ex: HID\VID_046D&PID_C077\7&12ab34cd&0&0000 -> "7&12ab34cd&0&0000")
         e adicionamos a lista de PROTECAO. Nunca renomeamos essas.

      2) Complementamos com Get-CimInstance Win32_PointingDevice e
         Win32_Keyboard (cobre casos onde Get-PnpDevice reporta a interface
         mas nao a instance HID literal).

      3) Se Get-PnpDevice falhar (WMI corrompido, servico desabilitado)
         para Mouse OU Keyboard, ABORTAMOS o script inteiro. Melhor nao
         fazer nada do que arriscar bricar o teclado/mouse do usuario.

      4) Se a maquina tem exatamente 1 (uma) instance de mouse OU 1 de
         teclado, PULAMOS aquela classe inteira - sem redundancia de
         input, nao ha margem para errar.

      5) ClassGUID {5d624f94-8850-40c3-a3fa-a4fd2080baf3} = HIDClass
         (parent class subkey), skipamos - nao eh device real.

      6) ClassGUID de Sensor {5175d334-c371-4806-b3ba-71fd53c9258d} ou
         Mouse {4d36e96f-e325-11ce-bfc1-08002be10318} tambem PULAMOS -
         superficies de input alternativas que poderiam comprometer
         usabilidade. Touch screens vivem sob HIDClass, ja coberto em (5).

    Uso:
      .\spoof-hid-ids.ps1              # aplica spoof
      .\spoof-hid-ids.ps1 -DryRun      # mostra plano sem escrever
      .\spoof-hid-ids.ps1 -Restore     # reverte via backup
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Restore
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"

$profilePath  = "C:\ProgramData\.hwcfg\profile.json"
$mappingPath  = "C:\ProgramData\.hwcfg\hid-ids-mapping.json"
$backupPath   = "C:\ProgramData\.hwcfg\hid-ids-backup.json"
$hidRoot      = "HKLM\SYSTEM\CurrentControlSet\Enum\HID"
$hidRootPs    = "HKLM:\SYSTEM\CurrentControlSet\Enum\HID"

# ClassGUIDs que nunca devemos tocar (superficies de input)
# Defesa em profundidade: mesmo com filtro Get-PnpDevice, um device removido
# (mouse/teclado desconectado) escaparia do filtro dinamico e cairia no spoof.
# Blacklist cobre tanto Mouse quanto Keyboard pra fechar essa lacuna.
$blacklistClassGuidsLower = @(
    '{745a17a0-74d3-11d0-b6fe-00a0c90f57da}',   # HIDClass (parent, nao device)
    '{5175d334-c371-4806-b3ba-71fd53c9258d}',   # Sensor
    '{4d36e96f-e325-11ce-bfc1-08002be10318}',   # Mouse (input)
    '{4d36e96b-e325-11ce-bfc1-08002be10318}'    # Keyboard (input) - defesa contra device removido
)

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

# FNV-1a 64bit - deterministico, mesmo padrao de spoof-pci-hardwareid.ps1.
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

# Gera um bloco hex determinstico de tamanho $Len (chars) para substituir a
# porcao aleatoria de um instance name (tipicamente o 2o campo).
function Get-DeterministicHex {
    param([string]$Seed, [string]$Salt, [int]$Len)
    if ($Len -le 0) { return "" }
    $sb = New-Object System.Text.StringBuilder
    $round = 0
    while ($sb.Length -lt $Len) {
        $h = Get-Fnv1a64Hash -InputText ("HID|" + $Seed + "|" + $Salt + "|" + $round)
        [void]$sb.Append(("{0:x16}" -f $h))
        $round++
    }
    $s = $sb.ToString().Substring(0, $Len)
    # Manter caixa original: instance IDs sao tipicamente lowercase.
    return $s
}

# Recebe um instance name (ex: "7&12ab34cd&0&0000") e gera um novo determinstico
# preservando shape. Estrategia: casar o 2o campo (bloco hex longo) e trocar so ele.
# Preserva prefixo/sufixos, incluindo eventual "&Col04" ao final.
function New-FakeInstanceName {
    param([string]$Original, [string]$Seed, [string]$Salt)
    # Padrao esperado: <digit(s)>&<hex+>&<digit(s)>&<tail>
    if ($Original -match '^(\d+)&([0-9a-fA-F]+)&(\d+)&(.+)$') {
        $p1   = $Matches[1]
        $mid  = $Matches[2]
        $p3   = $Matches[3]
        $tail = $Matches[4]
        $newMid = Get-DeterministicHex -Seed $Seed -Salt ($Salt + "|mid") -Len $mid.Length
        # Se o mid original era uppercase, uppercase o novo. Heuristica simples.
        if ($mid -cmatch '[A-F]' -and $mid -cnotmatch '[a-f]') { $newMid = $newMid.ToUpper() }
        return ($p1 + "&" + $newMid + "&" + $p3 + "&" + $tail)
    }
    # Padrao alternativo: <digit>&<hex+>&<tail>
    if ($Original -match '^(\d+)&([0-9a-fA-F]+)&(.+)$') {
        $p1 = $Matches[1]; $mid = $Matches[2]; $tail = $Matches[3]
        $newMid = Get-DeterministicHex -Seed $Seed -Salt ($Salt + "|mid2") -Len $mid.Length
        if ($mid -cmatch '[A-F]' -and $mid -cnotmatch '[a-f]') { $newMid = $newMid.ToUpper() }
        return ($p1 + "&" + $newMid + "&" + $tail)
    }
    # Formato desconhecido - nao rename para nao arriscar quebrar semantica.
    return $null
}

# Extrai a instance folha de um InstanceId completo do PnP.
# Ex: "HID\VID_046D&PID_C077&COL01\7&12ab34cd&0&0000" -> "7&12ab34cd&0&0000"
function Get-InstanceLeaf {
    param([string]$InstanceId)
    if ([string]::IsNullOrWhiteSpace($InstanceId)) { return $null }
    $idx = $InstanceId.LastIndexOf('\')
    if ($idx -lt 0) { return $InstanceId }
    return $InstanceId.Substring($idx + 1)
}

# Colhe as leaf instances de todas as instancias PnP de uma classe.
# Retorna @() ou lanca se Get-PnpDevice falhar.
function Get-ProtectedInstances {
    param([string]$Class)
    $out = @()
    $devs = @()
    try {
        $devs = @(Get-PnpDevice -Class $Class -Status OK -ErrorAction Stop)
    } catch {
        throw ("Get-PnpDevice -Class " + $Class + " falhou: " + $_.Exception.Message)
    }
    foreach ($d in $devs) {
        $id = [string]$d.InstanceId
        # So nos importa se comeca com "HID\" - outras interfaces (KEYBOARD\,
        # ACPI\PNP0303, etc) nao estao em Enum\HID.
        if ($id -like 'HID\*') {
            $leaf = Get-InstanceLeaf $id
            if ($leaf) { $out += $leaf.ToLower() }
        }
    }
    return $out
}

# Complementa com WMI Win32_PointingDevice / Win32_Keyboard (PNPDeviceID).
function Get-ProtectedInstancesFromWmi {
    param([string]$WmiClass)
    $out = @()
    try {
        $items = @(Get-CimInstance -ClassName $WmiClass -ErrorAction Stop)
    } catch {
        return $out
    }
    foreach ($i in $items) {
        $id = [string]$i.PNPDeviceID
        if ($id -like 'HID\*') {
            $leaf = Get-InstanceLeaf $id
            if ($leaf) { $out += $leaf.ToLower() }
        }
    }
    return $out
}

# Le ClassGUID de uma subchave (ou "" se nao houver).
function Get-InstanceClassGuid {
    param([string]$InstanceKeyPsPath)
    try {
        $ip = Get-ItemProperty -Path $InstanceKeyPsPath -Name ClassGUID -ErrorAction Stop
        if ($ip) { return ([string]$ip.ClassGUID).ToLower() }
    } catch {}
    return ""
}

# ============================================================
#  Restore mode
# ============================================================
if ($Restore) {
    Write-Section "Restore de HID IDs"
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
    foreach ($e in @($bkp.entries)) {
        $vidPidKey    = $e.vidpid_key      # ex: "VID_046D&PID_C077&Col01"
        $currentInst  = $e.new_instance    # nome da subchave apos spoof
        $origInst     = $e.orig_instance   # nome original
        $parentPs     = Join-Path $hidRootPs $vidPidKey
        $curPathReg   = "$hidRoot\$vidPidKey\$currentInst"
        $curPathPs    = Join-Path $parentPs $currentInst
        $origPathPs   = Join-Path $parentPs $origInst

        if (-not (Test-Path $parentPs)) {
            Write-Warn ("Parent VID&PID ausente (device removido?): " + $vidPidKey)
            continue
        }
        if (-not (Test-Path $curPathPs)) {
            Write-Warn ("Instance spoofada ausente: " + $vidPidKey + "\" + $currentInst)
            continue
        }
        if (Test-Path $origPathPs) {
            Write-Warn ("Original ja re-existe (PnP re-enumerou): " + $vidPidKey + "\" + $origInst)
            continue
        }

        if ($DryRun) {
            Write-Info ("[DryRun] Restauraria: " + $vidPidKey + "\" + $currentInst + " -> " + $origInst)
            continue
        }

        $tmpFile = Join-Path $env:TEMP ("hid-restore-" + [guid]::NewGuid().ToString() + ".reg")
        try {
            [void](Invoke-Reg -RegArgs @("export", $curPathReg, $tmpFile, "/y"))
            $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode

            $escCur = [regex]::Escape($currentInst)
            $newContent = [regex]::Replace($content, $escCur, $origInst, 'IgnoreCase')

            Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline
            [void](Invoke-Reg -RegArgs @("import", $tmpFile))
            [void](Invoke-Reg -RegArgs @("delete", $curPathReg, "/f"))

            $restored++
            Write-OK ("Restaurado: " + $vidPidKey + "\" + $currentInst + " -> " + $origInst)
        } catch {
            Write-Err ("Falha restaurando " + $currentInst + ": " + $_.Exception.Message)
        } finally {
            if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
        }
    }

    if (-not $DryRun -and $restored -gt 0) {
        try {
            Remove-Item $backupPath -Force -ErrorAction SilentlyContinue
            if (Test-Path $mappingPath) { Remove-Item $mappingPath -Force -ErrorAction SilentlyContinue }
            Write-OK "Backup e mapping removidos"
        } catch {}
    }

    Write-Section "Resumo restore"
    Write-Host ("  Restaurados: " + $restored) -ForegroundColor Cyan
    Write-Warn "PnP pode re-enumerar no proximo boot - reconferir com check-consistency.ps1"
    exit 0
}

# ============================================================
#  Spoof mode
# ============================================================
Write-Section "Spoof de HID IDs (Enum\HID)"

# 1) Carregar profile + seed
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

if (-not $prof.pci_hardwareid) {
    Write-Err "Profile nao contem bloco 'pci_hardwareid' (usado para seed). Regenere."
    exit 1
}
$seed = [string]$prof.pci_hardwareid.randomize_seed
if ([string]::IsNullOrWhiteSpace($seed) -or $seed -notmatch '^[0-9a-fA-F]{32}$') {
    Write-Err "randomize_seed ausente ou invalido no profile - regenere."
    exit 1
}
Write-OK ("Seed carregado (" + $seed.Length + " chars)")

# 2) Coletar leaf instances protegidas (mouse + keyboard).
#    ABORT se qualquer classe falhar - melhor nao mexer do que arriscar input.
$protectedMice = @()
$protectedKbs  = @()
try {
    $protectedMice = Get-ProtectedInstances -Class "Mouse"
} catch {
    Write-Err ("Nao consegui enumerar mouses via Get-PnpDevice: " + $_.Exception.Message)
    Write-Err "Abortando - risco de tornar mouse inutilizavel."
    exit 1
}
try {
    $protectedKbs = Get-ProtectedInstances -Class "Keyboard"
} catch {
    Write-Err ("Nao consegui enumerar teclados via Get-PnpDevice: " + $_.Exception.Message)
    Write-Err "Abortando - risco de tornar teclado inutilizavel."
    exit 1
}

# Complementa via WMI (cobre alguns HID compostos que Get-PnpDevice reporta na
# interface KEYBOARD\ ao inves de HID\).
$protectedMice += Get-ProtectedInstancesFromWmi -WmiClass "Win32_PointingDevice"
$protectedKbs  += Get-ProtectedInstancesFromWmi -WmiClass "Win32_Keyboard"

$protectedMice = @($protectedMice | Sort-Object -Unique)
$protectedKbs  = @($protectedKbs  | Sort-Object -Unique)

Write-OK ("Mouse instances protegidas : " + $protectedMice.Count)
foreach ($m in $protectedMice) { Write-Info ("  proteg mouse : " + $m) }
Write-OK ("Keyb instances protegidas  : " + $protectedKbs.Count)
foreach ($k in $protectedKbs)  { Write-Info ("  proteg keyb  : " + $k) }

# Guarda-corpo #4: se so tem 1 mouse OU 1 keyboard, pula essa classe inteira
# adicionando um marcador. Como toda instance dessa classe esta em $protectedMice
# ou $protectedKbs, ela ja sera pulada. Nada a fazer explicitamente aqui alem
# de LOGAR - a decisao efetiva ocorre no loop (skip por match em protegido).
if ($protectedMice.Count -le 1) {
    Write-Warn "Apenas 1 mouse presente - nenhuma redundancia; qualquer HID de mouse sera pulado."
}
if ($protectedKbs.Count -le 1) {
    Write-Warn "Apenas 1 teclado presente - nenhuma redundancia; qualquer HID de keyboard sera pulado."
}

$protectedAll = @(@() + $protectedMice + $protectedKbs | Sort-Object -Unique)

# 3) Enumerar subchaves Enum\HID\VID_*&PID_*[&Col*]
if (-not (Test-Path $hidRootPs)) {
    Write-Warn ("HID root nao encontrado: " + $hidRootPs)
    exit 0
}
$vidPidKeys = @(Get-ChildItem -Path $hidRootPs -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}(&Col[0-9A-Fa-f]+)?$' })

if ($vidPidKeys.Count -eq 0) {
    Write-Warn "Nenhuma subchave VID_*&PID_* encontrada em Enum\HID"
    exit 0
}
Write-OK ("VID&PID subkeys encontradas: " + $vidPidKeys.Count)

# 4) Carregar mapping anterior
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

# 5) Processar
$backupEntries = @()
$newMapping    = @{}
$skippedInput  = 0
$skippedClass  = 0
$skippedOther  = 0
$skippedSpoofed= 0
$processed     = 0

foreach ($vk in $vidPidKeys) {
    $vidPidName = $vk.PSChildName
    $vidPidPs   = $vk.PSPath

    # Enumerar instancias dentro deste VID&PID
    $instItems = @()
    try { $instItems = @(Get-ChildItem -Path $vidPidPs -ErrorAction Stop) } catch { continue }

    foreach ($inst in $instItems) {
        $instName   = $inst.PSChildName
        $instPathPs = $inst.PSPath
        $instPathReg = "$hidRoot\$vidPidName\$instName"
        $mapKey = $vidPidName + "\" + $instName

        # Skip se ja spoofada em run anterior (o new_instance bate com nome atual)
        $alreadySpoofed = $false
        foreach ($entryName in $existingMap.Keys) {
            $entryVal = $existingMap[$entryName]
            if ($entryVal.new_instance -and $entryVal.vidpid_key -eq $vidPidName -and `
                $entryVal.new_instance.ToString().ToLower() -eq $instName.ToLower()) {
                $alreadySpoofed = $true; break
            }
        }
        if ($alreadySpoofed) {
            Write-Info ($mapKey + " - ja spoofada, pulando")
            $skippedSpoofed++
            continue
        }

        # Skip se instance esta na lista protegida (mouse ou keyboard presente)
        if ($protectedAll -contains $instName.ToLower()) {
            Write-Warn ($mapKey + " - INPUT ATIVO (mouse/keyboard); PULANDO")
            $skippedInput++
            continue
        }

        # Skip por ClassGUID blacklistado
        $cg = Get-InstanceClassGuid -InstanceKeyPsPath $instPathPs
        if ($cg -and $blacklistClassGuidsLower -contains $cg) {
            Write-Warn ($mapKey + " - ClassGUID " + $cg + " (input surface); PULANDO")
            $skippedClass++
            continue
        }

        # Gerar novo instance name deterministico
        $newInst = New-FakeInstanceName -Original $instName -Seed $seed -Salt $mapKey
        if ([string]::IsNullOrEmpty($newInst)) {
            Write-Warn ($mapKey + " - formato de instance desconhecido; PULANDO")
            $skippedOther++
            continue
        }
        if ($newInst.ToLower() -eq $instName.ToLower()) {
            Write-Info ($mapKey + " - novo nome identico ao original; pulando")
            $skippedOther++
            continue
        }
        $newInstPathPs = Join-Path $vidPidPs $newInst
        if (Test-Path $newInstPathPs) {
            Write-Warn ($mapKey + " - destino " + $newInst + " ja existe; PULANDO")
            $skippedOther++
            continue
        }

        if ($DryRun) {
            Write-Info ("[DryRun] " + $mapKey + "  ->  " + $newInst)
            continue
        }

        $tmpFile = Join-Path $env:TEMP ("hid-swap-" + [guid]::NewGuid().ToString() + ".reg")
        try {
            [void](Invoke-Reg -RegArgs @("export", $instPathReg, $tmpFile, "/y"))
            $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode

            # Substituicao textual do instance name no conteudo do .reg. Preservamos
            # tudo o mais (parent path VID&PID, ClassGUID, HardwareID etc).
            $escInst = [regex]::Escape($instName)
            $newContent = [regex]::Replace($content, $escInst, $newInst, 'IgnoreCase')

            if ([regex]::IsMatch($newContent, $escInst, 'IgnoreCase')) {
                throw "Sanity check falhou: instance name original ainda presente apos replace."
            }

            Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline
            [void](Invoke-Reg -RegArgs @("import", $tmpFile))
            [void](Invoke-Reg -RegArgs @("delete", $instPathReg, "/f"))

            $backupEntries += [pscustomobject]@{
                vidpid_key    = $vidPidName
                orig_instance = $instName
                new_instance  = $newInst
            }
            $newMapping[$mapKey] = [pscustomobject]@{
                vidpid_key    = $vidPidName
                new_instance  = $newInst
            }
            $processed++
            Write-OK ($mapKey + "  ->  " + $newInst)
        } catch {
            Write-Err ("Falha spoof " + $mapKey + ": " + $_.Exception.Message)
        } finally {
            if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
        }
    }
}

# 6) Persistir backup + mapping (merge)
if (-not $DryRun -and $processed -gt 0) {
    Write-Section "Persistindo backup e mapping"

    $dir = Split-Path $backupPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $mergedEntries = @()
    if (Test-Path $backupPath) {
        try {
            $prevBkp = Get-Content $backupPath -Raw | ConvertFrom-Json
            foreach ($e in @($prevBkp.entries)) {
                $stillInNew = $false
                foreach ($ne in $backupEntries) {
                    if ($ne.vidpid_key -eq $e.vidpid_key -and $ne.orig_instance -eq $e.orig_instance) {
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
    $bkpObj | ConvertTo-Json -Depth 6 | Set-Content -Path $tmpBkp -Encoding UTF8
    Move-Item -Path $tmpBkp -Destination $backupPath -Force
    Write-OK ("Backup salvo em: " + $backupPath)

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
Write-Host ("  Instancias processadas       : " + $processed)       -ForegroundColor Cyan
Write-Host ("  Puladas (input ativo m/kb)   : " + $skippedInput)    -ForegroundColor Cyan
Write-Host ("  Puladas (ClassGUID input)    : " + $skippedClass)    -ForegroundColor Cyan
Write-Host ("  Puladas (ja spoofada)        : " + $skippedSpoofed)  -ForegroundColor Cyan
Write-Host ("  Puladas (outros motivos)     : " + $skippedOther)    -ForegroundColor Cyan
if ($DryRun) {
    Write-Warn "DryRun ativo - nenhuma escrita feita"
}
Write-Host ""
Write-Warn "PnP manager pode RE-ENUMERAR e recriar as instancias originais no proximo boot."
Write-Warn "Rodar spoof-hid-ids.ps1 ANTES de spoof-usb-ids.ps1 (HID e filho de USB no tree)."
Write-Info ("Para reverter: .\spoof-hid-ids.ps1 -Restore")
exit 0
