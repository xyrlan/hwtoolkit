#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Rotaciona Volume GUIDs de VOLUMES NAO-BOOT no registry - GAP #3d.

.DESCRIPTION
    Reconnaissance v2 confirmou que EMAC (user-mode) le no minimo 3 Volume
    GUIDs em:
      HKLM\SYSTEM\CurrentControlSet\Enum\STORAGE\Volume\{GUID}#offset
    E cada volume tambem esta indexado em:
      HKLM\SYSTEM\MountedDevices
        \??\Volume{GUID}     (REG_BINARY: signature+offset ou GPT GUID)
        \DosDevices\D:       (mesmo REG_BINARY, apontando pro mesmo volume)

    O GUID de volume identifica o volume de forma persistente entre reboots
    e faz parte da fingerprint de storage. Rotacionar => outra fingerprint.

    == PERIGO EXTREMO ==
    O volume onde Windows esta instalado (tipicamente C:) tem seu GUID
    referenciado pelo BCD (Boot Configuration Data). Reescrever o GUID
    do volume boot QUEBRA o boot - o Windows nao consegue localizar
    system32 ao iniciar. Este script:
      1) Detecta rigorosamente qual eh o volume boot via
         Get-Partition -DriveLetter C -> AccessPaths.
      2) Detecta System Reserved / EFI System Partition (Type='System'
         ou GPT type GUID conhecido) e recusa-se a tocar.
      3) So opera em volumes que TENHAM DriveLetter (D, E, F...) e que
         NAO sejam boot nem system.
      4) Se qualquer verificacao falhar, ABORTA - refuse to run.

    Notas de consistencia:
      - MountedDevices contem TAMBEM \DosDevices\D: apontando para o
         mesmo REG_BINARY. Se so trocarmos a subchave \??\Volume{GUID}
         sem atualizar \DosDevices\X:, a proxima reboot pode reatribuir
         letras ou marcar volumes como offline. Ambos precisam trocar
         atomically.
      - REG_BINARY em MountedDevices varia entre discos MBR (12 bytes:
         4B signature + 8B offset) e GPT (24 bytes: "DMIO:ID:" + 16B
         GPT partition GUID). NAO alteramos o valor binario - a semantica
         "qual volume fisico" precisa continuar identica. Apenas
         renomeamos a chave \??\Volume{OLD} -> \??\Volume{NEW}.
      - Reboot obrigatorio: MountedDevices e lido pelo mountmgr durante
         boot. Ate reiniciar, o Windows continua servindo os GUIDs antigos.
      - Storage Volume enum subkeys (Enum\STORAGE\Volume\{GUID}#offset)
         podem exigir take-ownership para escrita (SYSTEM tem full, TrustedInstaller
         as vezes protege). Este script tenta o rename direto e reporta se falhar
         sem parar - a chave STORAGE\Volume as vezes se recria sozinha no proximo
         boot com o novo GUID vindo do MountedDevices.

    Uso:
      .\spoof-volume-guid.ps1              # rotaciona (com prompt)
      .\spoof-volume-guid.ps1 -DryRun      # so mostra o que faria
      .\spoof-volume-guid.ps1 -Restore     # reverte via volume-guid-backup.json
      .\spoof-volume-guid.ps1 -Yes         # pula prompt (nao recomendado)
#>

[CmdletBinding()]
param(
    [switch]$Restore,
    [switch]$DryRun,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"

$profilePath  = "C:\ProgramData\.hwcfg\profile.json"
$backupPath   = "C:\ProgramData\.hwcfg\volume-guid-backup.json"
$mountedDevPs = "HKLM:\SYSTEM\MountedDevices"
$mountedDevReg= "HKLM\SYSTEM\MountedDevices"
$storVolPs    = "HKLM:\SYSTEM\CurrentControlSet\Enum\STORAGE\Volume"
$storVolReg   = "HKLM\SYSTEM\CurrentControlSet\Enum\STORAGE\Volume"

$guidRegex = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'

function New-Guid-Str {
    return ("{" + ([guid]::NewGuid().ToString()) + "}").ToLower()
}

function Invoke-Reg {
    param([string[]]$RegArgs)
    $out = & reg.exe @RegArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("reg.exe " + ($RegArgs -join ' ') + " falhou (" + $LASTEXITCODE + "): " + ($out -join "`n"))
    }
    return $out
}

# ============================================================
#  Safety: identify boot volume GUID
# ============================================================
function Get-BootDriveLetter {
    # $env:SystemDrive e a fonte autoritativa. Windows-To-Go / dual boot
    # podem instalar em D:, E:, etc — usar 'C' hard-coded quebraria a
    # deteccao de boot volume nesses cenarios.
    $sd = $env:SystemDrive
    if ([string]::IsNullOrWhiteSpace($sd)) { return $null }
    return $sd.TrimEnd(':').TrimEnd('\')
}

function Get-BootVolumeGuid {
    # AccessPaths do boot drive contem entradas tipo:
    #   C:\
    #   \\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\
    $bootLetter = Get-BootDriveLetter
    if ($null -eq $bootLetter) { return $null }
    try {
        $bootPart = Get-Partition -DriveLetter $bootLetter -ErrorAction Stop
    } catch {
        return $null
    }
    if ($null -eq $bootPart) { return $null }
    foreach ($ap in $bootPart.AccessPaths) {
        if ($ap -match ('\\\\\?\\Volume(' + $guidRegex + ')\\')) {
            return $matches[1].ToLower()
        }
    }
    return $null
}

# Identifica volumes system-reserved / EFI. Retorna array de GUIDs (lower) a excluir.
function Get-SystemPartitionGuids {
    $blacklist = @{}
    try {
        # Blacklist inclui:
        #   - System partition (EFI/System Reserved): Type='System' ou GptType EFI
        #   - Recovery partition: GptType {de94bba4-...} ou IsHidden
        #   - MSR (Microsoft Reserved): GptType {e3c9e316-...}
        $recoveryGpt = '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
        $efiGpt      = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        $msrGpt      = '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
        $sysParts = Get-Partition -ErrorAction Stop | Where-Object {
            $_.Type -eq 'System' -or `
            $_.Type -eq 'Recovery' -or `
            $_.IsSystem -eq $true -or `
            $_.IsHidden -eq $true -or `
            $_.GptType -eq $efiGpt -or `
            $_.GptType -eq $recoveryGpt -or `
            $_.GptType -eq $msrGpt
        }
        foreach ($sp in $sysParts) {
            foreach ($ap in $sp.AccessPaths) {
                if ($ap -match ('\\\\\?\\Volume(' + $guidRegex + ')\\')) {
                    $blacklist[$matches[1].ToLower()] = $true
                }
            }
        }
    } catch {
        # Fail-stop: sem essa lista, uma particao de sistema/recovery/MSR
        # com drive letter atribuida (comum em oficinas de imaging que
        # mapeiam R:) pode ser reescrita e quebrar WinRE.
        throw "Nao consegui enumerar particoes de sistema (Get-Partition falhou): $($_.Exception.Message). Abortando por seguranca."
    }

    # Fallback / redundancia: volumes sem drive letter frequentemente sao
    # system/recovery. Vamos marcar TODOS os \??\Volume{...} do MountedDevices
    # que nao tenham \DosDevices\X: correspondente como "sem letra" e excluir.
    return @($blacklist.Keys)
}

# Enumera candidates: volumes com drive letter, nao-C, nao-system.
function Get-CandidateVolumes {
    param(
        [string]$BootGuid,
        [string[]]$SystemGuids
    )
    $candidates = @()
    $bootLetter = Get-BootDriveLetter
    if ($null -eq $bootLetter) { return @() }
    try {
        $vols = Get-Volume -ErrorAction Stop | Where-Object {
            $_.DriveLetter -and ([string]$_.DriveLetter).ToUpper() -ne $bootLetter.ToUpper()
        }
    } catch {
        return @()
    }
    foreach ($v in $vols) {
        # Get-Volume nao expõe o GUID diretamente em todas as versoes; usar Get-Partition -Volume $v
        $guid = $null
        try {
            $part = Get-Partition -Volume $v -ErrorAction Stop | Select-Object -First 1
            if ($part) {
                foreach ($ap in $part.AccessPaths) {
                    if ($ap -match ('\\\\\?\\Volume(' + $guidRegex + ')\\')) {
                        $guid = $matches[1].ToLower()
                        break
                    }
                }
            }
        } catch {
            $guid = $null
        }
        if ($null -eq $guid) { continue }
        if ($guid -eq $BootGuid) { continue }
        if ($SystemGuids -contains $guid) { continue }

        $candidates += [pscustomobject]@{
            DriveLetter = [string]$v.DriveLetter
            OldGuid     = $guid
            FileSystem  = $v.FileSystem
            SizeGB      = [math]::Round($v.Size / 1GB, 1)
        }
    }
    return $candidates
}

# ============================================================
#  Renaming primitives
# ============================================================

# Scan pra referencias externas ao OLD Volume GUID. Se page file, DOS Devices
# links, ou qualquer service armazenou \??\Volume{OLD}\... como caminho, rewrite
# quebra silenciosamente esses subsistemas. Abortar preserva boot funcionando.
function Test-VolumeGuidReferences {
    param([string]$OldGuid)
    $needle = "\??\Volume$OldGuid"
    $found = @()
    $paths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    )
    foreach ($p in $paths) {
        if (-not (Test-Path $p)) { continue }
        try {
            $ip = Get-ItemProperty -Path $p -ErrorAction Stop
            foreach ($prop in $ip.PSObject.Properties) {
                if ($prop.Name -like 'PS*') { continue }
                $val = $prop.Value
                if ($null -eq $val) { continue }
                # Val pode ser string ou string[]
                $strs = @()
                if ($val -is [string]) { $strs += $val }
                elseif ($val -is [System.Array]) { foreach ($v in $val) { if ($v -is [string]) { $strs += $v } } }
                foreach ($s in $strs) {
                    if ($s -and $s.ToLower().Contains($needle.ToLower())) {
                        $found += ("{0}\{1}" -f $p, $prop.Name)
                    }
                }
            }
        } catch {}
    }
    return $found
}

# Renomeia \??\Volume{OLD} -> \??\Volume{NEW} em HKLM\SYSTEM\MountedDevices
# preservando o REG_BINARY exato. Tambem sincroniza \DosDevices\X: se existir
# entry apontando pro mesmo binary — mountmgr precisa que ambos os lados
# batam (\??\Volume{GUID} e \DosDevices\X: com mesmo REG_BINARY) para o
# volume ficar online com a letra atribuida.
function Rename-MountedDeviceEntry {
    param(
        [string]$OldGuid,
        [string]$NewGuid,
        [string]$DriveLetter    # opcional; usado pra encontrar \DosDevices\X:
    )
    $oldValueName = "\??\Volume$OldGuid"
    $newValueName = "\??\Volume$NewGuid"

    $md = Get-ItemProperty -Path $mountedDevPs -Name $oldValueName -ErrorAction Stop
    $bin = $md.$oldValueName
    if ($null -eq $bin -or ([byte[]]$bin).Length -eq 0) {
        throw "MountedDevices nao contem '$oldValueName' (ou valor vazio)"
    }

    # Cria novo value
    New-ItemProperty -Path $mountedDevPs -Name $newValueName -Value $bin -PropertyType Binary -Force | Out-Null
    # Remove antigo
    Remove-ItemProperty -Path $mountedDevPs -Name $oldValueName -Force
    Write-Info ("MountedDevices: " + $oldValueName + " -> " + $newValueName)

    # Sanity re-write \DosDevices\X: com mesmo binary — garante que mountmgr
    # nao reatribua letra caso a reconciliacao com STORAGE\Volume falhe.
    if (-not [string]::IsNullOrWhiteSpace($DriveLetter)) {
        $letter = ([string]$DriveLetter).TrimEnd(':').TrimEnd('\').ToUpper()
        if ($letter.Length -eq 1) {
            $dosName = "\DosDevices\$letter" + ":"
            try {
                $cur = Get-ItemProperty -Path $mountedDevPs -Name $dosName -ErrorAction Stop
                $curBin = $cur.$dosName
                if ($null -ne $curBin -and ([byte[]]$curBin).Length -gt 0) {
                    # Rewrite same value (defensivo): forca mountmgr a re-hash na proxima leitura
                    New-ItemProperty -Path $mountedDevPs -Name $dosName -Value $curBin -PropertyType Binary -Force | Out-Null
                    Write-Info ("MountedDevices: refreshed " + $dosName)
                }
            } catch {}
        }
    }
}

# Renomeia subchaves Enum\STORAGE\Volume\{OLD}#offset -> {NEW}#offset.
# Usa export -> sed replace -> import -> delete (mesmo padrao do audio script).
# Falha aqui NAO e fatal - o mountmgr recria a chave no proximo boot.
function Rename-StorageVolumeSubkeys {
    param(
        [string]$OldGuid,
        [string]$NewGuid
    )
    if (-not (Test-Path $storVolPs)) {
        Write-Info "Enum\STORAGE\Volume nao existe - pulando"
        return
    }
    $storSubkeys = Get-ChildItem -Path $storVolPs -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -like ($OldGuid + "*")
    }
    if ($null -eq $storSubkeys -or @($storSubkeys).Count -eq 0) {
        Write-Info ("Nenhuma subchave Enum\STORAGE\Volume para " + $OldGuid)
        return
    }
    $escaped = [regex]::Escape($OldGuid)
    foreach ($m in $storSubkeys) {
        $oldName = $m.PSChildName
        $newName = [regex]::Replace($oldName, $escaped, $NewGuid, 'IgnoreCase')
        if ($newName -eq $oldName) { continue }
        $oldPath = "$storVolReg\$oldName"
        $newPath = "$storVolReg\$newName"
        $tmpFile = Join-Path $env:TEMP ("volguid-swap-" + [guid]::NewGuid().ToString() + ".reg")
        try {
            try {
                [void](Invoke-Reg -RegArgs @("export", $oldPath, $tmpFile, "/y"))
            } catch {
                Write-Warn ("Nao consegui exportar " + $oldPath + " (permissao?): " + $_.Exception.Message)
                continue
            }
            $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode
            $newContent = [regex]::Replace($content, $escaped, $NewGuid, 'IgnoreCase')
            if ([regex]::IsMatch($newContent, $escaped, 'IgnoreCase')) {
                Write-Warn ("Sanity falhou: GUID antigo ainda no arquivo apos replace (" + $oldName + ")")
                continue
            }
            Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline
            try {
                [void](Invoke-Reg -RegArgs @("import", $tmpFile))
                [void](Invoke-Reg -RegArgs @("delete", $oldPath, "/f"))
                Write-OK ("Enum\STORAGE\Volume: " + $oldName + " -> " + $newName)
            } catch {
                # Fail-stop: se STORAGE\Volume nao aceita rewrite (ACL TrustedInstaller,
                # hive protegido), o boot pode ficar split-brain apos reboot. Melhor
                # abortar aqui e reverter MountedDevices no chamador.
                throw ("Import/delete falhou para " + $oldName + ": " + $_.Exception.Message)
            }
        } finally {
            if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
        }
    }
}

# ============================================================
#  Restore mode
# ============================================================
if ($Restore) {
    Write-Section "Restore de Volume GUIDs"
    if (-not (Test-Path $backupPath)) {
        Write-Err ("Backup nao encontrado: " + $backupPath)
        exit 1
    }
    try {
        $bak = Get-Content $backupPath -Raw | ConvertFrom-Json
    } catch {
        Write-Err ("Backup corrompido: " + $_.Exception.Message)
        exit 1
    }

    # Restore SEMPRE aplica cada entrada — se um bug anterior spoofou o boot
    # volume, restore e a UNICA forma de o usuario desbrickar. Filtrar por
    # "new == boot atual" nesse cenario deixaria o usuario preso.
    # Validamos apenas o FORMATO dos GUIDs pra recusar backup corrompido.
    $restored = 0
    foreach ($e in @($bak.entries)) {
        $old = ([string]$e.old).ToLower()
        $new = ([string]$e.new).ToLower()
        if ($old -notmatch ('^' + $guidRegex + '$') -or $new -notmatch ('^' + $guidRegex + '$')) {
            Write-Err ("Backup entry com GUID malformado (old='" + $old + "' new='" + $new + "') - PULANDO por seguranca")
            continue
        }
        Write-Info ("Reverter " + $new + " -> " + $old + " (letter " + $e.drive + ")")
        try {
            Rename-MountedDeviceEntry -OldGuid $new -NewGuid $old -DriveLetter $e.drive
            try {
                Rename-StorageVolumeSubkeys -OldGuid $new -NewGuid $old
            } catch {
                Write-Warn ("Restore STORAGE\Volume falhou (nao fatal): " + $_.Exception.Message)
            }
            $restored++
            Write-OK ("Revertido " + $e.drive + ": " + $new + " -> " + $old)
        } catch {
            Write-Err ("Falha revertendo " + $e.drive + ": " + $_.Exception.Message)
        }
    }

    try {
        $bakOld = $backupPath + ".bak"
        if (Test-Path $bakOld) { Remove-Item $bakOld -Force -ErrorAction SilentlyContinue }
        Move-Item -Path $backupPath -Destination $bakOld -Force
        Remove-Item $bakOld -Force -ErrorAction SilentlyContinue
    } catch {
        Remove-Item $backupPath -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host ("Total revertido: " + $restored) -ForegroundColor Cyan
    Write-Warn "REBOOT obrigatorio para MountedDevices ter efeito"
    exit 0
}

# ============================================================
#  Rotate mode
# ============================================================
Write-Section "Spoof de Volume GUIDs (STORAGE + MountedDevices)"

# Passo 1: descobrir boot volume - se falhar, ABORTA
$bootGuid = Get-BootVolumeGuid
if ($null -eq $bootGuid) {
    Write-Err "Nao consegui identificar volume boot via Get-Partition -DriveLetter C"
    Write-Err "Recusando-se a rodar - risco de brickar boot"
    exit 1
}
Write-OK ("Boot volume detectado: " + $bootGuid + " (SERA PRESERVADO)")

# Passo 2: descobrir system partitions (EFI/System Reserved) - excluir
$sysGuids = Get-SystemPartitionGuids
if ($sysGuids.Count -gt 0) {
    foreach ($sg in $sysGuids) {
        Write-Info ("System partition detectada: " + $sg + " (sera preservada)")
    }
}

# Passo 3: candidatos
$candidates = Get-CandidateVolumes -BootGuid $bootGuid -SystemGuids $sysGuids
if ($candidates.Count -eq 0) {
    Write-Warn "Nenhum volume nao-boot com drive letter encontrado - nada a fazer"
    exit 0
}

Write-Section "Volumes candidatos"
foreach ($c in $candidates) {
    Write-Host ("  " + $c.DriveLetter + ":  " + $c.OldGuid + "  [" + $c.FileSystem + " " + $c.SizeGB + " GB]") -ForegroundColor Gray
}

# Passo 4: carregar pool do profile
$rotationPool = @()
if (Test-Path $profilePath) {
    try {
        $prof = Get-Content $profilePath -Raw | ConvertFrom-Json
        $profVer = 0
        if ($prof.PSObject.Properties['version']) {
            [int]::TryParse([string]$prof.version, [ref]$profVer) | Out-Null
        }
        if ($profVer -lt 8) {
            Write-Warn ("Profile schema v" + $profVer + " sem bloco volume - vou gerar GUIDs on the fly (nao deterministico entre reruns)")
        }
        if ($prof.volume -and $prof.volume.rotation_pool) {
            $rotationPool = @($prof.volume.rotation_pool)
            Write-OK ("Pool do profile: " + $rotationPool.Count + " GUID(s)")
        } else {
            Write-Warn "profile.volume.rotation_pool ausente - vou gerar GUIDs on the fly"
        }
    } catch {
        Write-Warn ("Falha lendo profile: " + $_.Exception.Message)
    }
} else {
    Write-Warn ("Profile ausente (" + $profilePath + ") - vou gerar GUIDs on the fly")
}

# Passo 5: carregar backup anterior (mapping estavel entre runs)
$existingEntries = @()
if (Test-Path $backupPath) {
    try {
        $prev = Get-Content $backupPath -Raw | ConvertFrom-Json
        if ($prev.entries) { $existingEntries = @($prev.entries) }
        Write-OK ("Backup anterior carregado: " + $existingEntries.Count + " entry(ies)")
    } catch {
        Write-Warn ("Backup anterior corrompido - ignorando: " + $_.Exception.Message)
    }
}

# Guardar quem ja foi consumido do pool
$consumed = @{}
foreach ($e in $existingEntries) { $consumed[$e.new.ToLower()] = $true }
$poolCursor = 0

function Get-Next-New-Guid {
    param([string]$OldGuid, [string]$DriveLetter)
    # Reuse por drive letter + old
    foreach ($e in $existingEntries) {
        if ($e.old.ToLower() -eq $OldGuid.ToLower() -and $e.drive -eq $DriveLetter) {
            return $e.new.ToLower()
        }
    }
    while ($script:poolCursor -lt $rotationPool.Count) {
        $cand = $rotationPool[$script:poolCursor].ToLower()
        $script:poolCursor++
        if (-not $consumed.ContainsKey($cand)) {
            $consumed[$cand] = $true
            return $cand
        }
    }
    $g = (New-Guid-Str)
    $consumed[$g] = $true
    return $g
}

# Passo 6: montar plano (old -> new) e detectar drift (candidato ja rotacionado)
$plan = @()
foreach ($c in $candidates) {
    $oldGuidLower = $c.OldGuid.ToLower()
    # Se este OldGuid ja aparece como .new em backup anterior, ja foi rotacionado - pular
    $alreadyRotated = $false
    foreach ($e in $existingEntries) {
        if ($e.new.ToLower() -eq $oldGuidLower) {
            $alreadyRotated = $true
            break
        }
    }
    if ($alreadyRotated) {
        Write-Info ($c.DriveLetter + ": " + $c.OldGuid + " - ja rotacionado em run anterior, pulando")
        continue
    }

    $newGuid = Get-Next-New-Guid -OldGuid $oldGuidLower -DriveLetter $c.DriveLetter
    # Guard extra: novo GUID NAO pode colidir com boot
    if ($newGuid -eq $bootGuid) {
        Write-Err ("Novo GUID gerado colide com boot (" + $newGuid + ") - abortando")
        exit 1
    }
    $plan += [pscustomobject]@{
        Drive       = $c.DriveLetter
        Old         = $oldGuidLower
        New         = $newGuid
        FileSystem  = $c.FileSystem
    }
}

if ($plan.Count -eq 0) {
    Write-Warn "Nada a rotacionar (todos ja rotacionados ou nenhum candidato)"
    exit 0
}

# Passo 7: apresentar plano
Write-Section "Plano"
foreach ($p in $plan) {
    Write-Host ("  " + $p.Drive + ":  " + $p.Old + "  ->  " + $p.New) -ForegroundColor Yellow
}

if ($DryRun) {
    Write-Host ""
    Write-Warn "DryRun: nada foi alterado"
    exit 0
}

# Passo 8: confirmacao explicita
if (-not $Yes) {
    Write-Host ""
    Write-Warn "Este script vai rewrite Volume GUIDs de volumes NAO-BOOT."
    $listaDrives = ($plan | ForEach-Object { $_.Drive + ":" }) -join ", "
    Write-Warn ("Volumes que serao alterados: " + $listaDrives)
    Write-Warn "REBOOT obrigatorio depois. Se o rewrite for incompleto, drive letters"
    Write-Warn "podem ser reatribuidas ou volumes marcados offline no proximo boot."
    Write-Warn "TESTE EM VM antes de usar em maquina de producao."
    Write-Host ""
    $ans = Read-Host "Continua? (S/N)"
    if ($ans.Trim().ToUpper() -ne "S") {
        Write-Info "Cancelado pelo usuario"
        exit 0
    }
}

# Passo 9: preparar diretorio backup
$backupDir = Split-Path $backupPath -Parent
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}

# Passo 10: executar plano - MountedDevices PRIMEIRO (autoritativo pro mountmgr).
# Em cada iteracao: (a) atualiza MountedDevices, (b) tenta Enum\STORAGE (pode falhar).
# Persiste cada entrada individualmente para garantir backup atomico mesmo se meio
# do loop falhar.
Write-Section "Executando"

# Merge com entries anteriores nao afetadas
$mergedEntries = @{}
foreach ($e in $existingEntries) {
    $key = $e.drive + "|" + $e.old.ToLower()
    $mergedEntries[$key] = [pscustomobject]@{
        drive = $e.drive
        old   = $e.old.ToLower()
        new   = $e.new.ToLower()
    }
}

$ok = 0
$fail = 0
foreach ($p in $plan) {
    Write-Info ("[" + $p.Drive + ":] " + $p.Old + " -> " + $p.New)

    # Pre-check: se OLD GUID aparece em pagefile / Session Manager, abortar
    # sem tocar registry — spoof quebraria pagefile/env vars apos reboot.
    $refs = Test-VolumeGuidReferences -OldGuid $p.Old
    if ($refs.Count -gt 0) {
        $fail++
        Write-Err ("[" + $p.Drive + ":] PULANDO - GUID referenciado por:")
        foreach ($r in $refs) { Write-Err ("    " + $r) }
        Write-Err ("    Rewrite quebraria esses subsistemas apos reboot.")
        continue
    }

    $mountedDone = $false
    try {
        Rename-MountedDeviceEntry -OldGuid $p.Old -NewGuid $p.New -DriveLetter $p.Drive
        $mountedDone = $true

        # STORAGE\Volume rewrite agora e FAIL-STOP. Se falhar, revertemos
        # MountedDevices pra evitar split-brain no proximo boot.
        Rename-StorageVolumeSubkeys -OldGuid $p.Old -NewGuid $p.New

        # AMBOS os lados funcionaram - persistir backup
        $key = $p.Drive + "|" + $p.Old
        $mergedEntries[$key] = [pscustomobject]@{
            drive = $p.Drive
            old   = $p.Old
            new   = $p.New
        }
        $bakObj = [pscustomobject]@{
            schema     = 1
            timestamp  = (Get-Date).ToString("o")
            boot_guid  = $bootGuid
            entries    = @($mergedEntries.Values)
        }
        $tmpBak = $backupPath + ".tmp"
        $bakObj | ConvertTo-Json -Depth 5 | Set-Content -Path $tmpBak -Encoding UTF8
        Move-Item -Path $tmpBak -Destination $backupPath -Force

        $ok++
        Write-OK ("[" + $p.Drive + ":] rewrite completo")
    } catch {
        $fail++
        Write-Err ("[" + $p.Drive + ":] FALHA: " + $_.Exception.Message)
        # Rollback MountedDevices se ja tinha rewrite mas STORAGE falhou
        if ($mountedDone) {
            try {
                Rename-MountedDeviceEntry -OldGuid $p.New -NewGuid $p.Old -DriveLetter $p.Drive
                Write-Warn ("[" + $p.Drive + ":] rollback MountedDevices " + $p.New + " -> " + $p.Old)
            } catch {
                Write-Err ("[" + $p.Drive + ":] ROLLBACK FALHOU: " + $_.Exception.Message + " - REBOOT PARA WinRE E RESTORE MANUAL")
            }
        }
    }
}

# ============================================================
#  Summary
# ============================================================
Write-Section "Resumo"
Write-Host ("  Volumes rotacionados: " + $ok) -ForegroundColor Cyan
Write-Host ("  Falhas             : " + $fail) -ForegroundColor Cyan
Write-Host ("  Backup em          : " + $backupPath) -ForegroundColor Cyan
Write-Host ""
if ($ok -gt 0) {
    Write-Warn "REBOOT OBRIGATORIO para MountedDevices ter efeito."
    Write-Warn "Drive letters D:, E:, ... podem ser reatribuidas ou ficar offline"
    Write-Warn "temporariamente no primeiro boot. Se um volume ficar offline:"
    Write-Warn "  1) Abrir diskmgmt.msc"
    Write-Warn "  2) Botao direito no volume -> 'Change Drive Letter and Paths'"
    Write-Warn "  3) Re-adicionar a letra"
    Write-Info ("Para reverter: .\spoof-volume-guid.ps1 -Restore")
}
if ($fail -gt 0) { exit 1 }
exit 0
