#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Rotaciona GUIDs de endpoints de audio (MMDevices) - GAP #3a.

.DESCRIPTION
    Reconnaissance: EMAC (e outros anti-cheats) coletam os GUIDs dos
    endpoints em:
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{GUID}
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\{GUID}
    Cada {GUID} identifica UM endpoint (speakers, headset, mic) de forma
    persistente entre reboots. Anti-cheat hasheia esse conjunto e usa como
    parte da fingerprint. Rotacionar => outra fingerprint.

    Notas de consistencia:
      - Os GUIDs de MMDevices sao per-install (nao vem do driver nem do HW).
        Podemos reescrever livremente desde que atualizemos referencias.
      - Windows Audio Session (WASAPI) resolve DefaultEndpoint antes de
        renderizar/capturar. Esse valor e REG_BINARY de 16 bytes com o GUID
        em forma binaria - precisamos atualizar se apontar para um endpoint
        rotacionado.
      - Chaves em ...\Audio\PolicyConfig\PropertyStore\* usam a string
        "{0.0.X.00000000}.{GUID}" como identificador do endpoint. Fazemos
        uma varredura restrita ao subtree Audio\ e reescrevemos matches.
      - Software terceiro (Voicemeeter, Discord audio device pinning, OBS,
        equalizers) pode cachear o GUID antigo. Depois de rotacionar, o
        usuario pode precisar re-selecionar o device uma vez.

    Perigo:
      - So processamos strings de GUID via regex escape.
      - So reescrevemos subchaves cujo path bate estritamente com o padrao
        de endpoint (Render/Capture) ou esta sob Audio\ - nunca escrevemos
        em keys fora dessa arvore. FxProperties (que carrega blobs binarios
        parecidos com GUIDs) e preservado pelo pipeline export/replace de
        texto: a representacao em .reg de REG_BINARY e hex,byte,byte,byte
        e nao casa com o padrao "{xxxxxxxx-xxxx-...}".

    Uso:
      .\spoof-audio-guids.ps1              # rotaciona endpoints ATIVOS
      .\spoof-audio-guids.ps1 -Restore     # reverte via audio-rotation.json
#>

[CmdletBinding()]
param(
    [switch]$Restore
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"

$profilePath  = "C:\ProgramData\.hwcfg\profile.json"
$mappingPath  = "C:\ProgramData\.hwcfg\audio-rotation.json"
$mmRoot       = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio"
$mmRootPs     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio"
$audioRootPs  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio"

# Regex para GUID no formato registry {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
$guidRegex = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'

function New-Guid-Str {
    return ("{" + ([guid]::NewGuid().ToString()) + "}").ToLower()
}

function Get-EndpointState {
    param([string]$RegPath)
    # RegPath eh no formato PS: HKLM:\SOFTWARE\...\Render\{guid}
    try {
        $v = Get-ItemProperty -Path $RegPath -Name "DeviceState" -ErrorAction Stop
        return [uint32]$v.DeviceState
    } catch {
        # Sem DeviceState => tratar como ATIVO (endpoint valido nao gravou o valor ainda)
        return [uint32]1
    }
}

function Format-StateName {
    param([uint32]$State)
    switch ($State) {
        1 { return "ACTIVE" }
        2 { return "DISABLED" }
        4 { return "NOTPRESENT" }
        8 { return "UNPLUGGED" }
        default { return ("0x{0:X}" -f $State) }
    }
}

# Converte string GUID -> byte[16] no formato "Microsoft" (mixed-endian: primeiros 3 grupos little-endian)
function Guid-To-Bytes {
    param([string]$G)
    $clean = $G.Trim('{','}')
    return ([guid]::Parse($clean)).ToByteArray()
}

function Bytes-To-Guid {
    param([byte[]]$B)
    if ($B.Length -ne 16) { return $null }
    return ("{" + (New-Object System.Guid(,$B)).ToString() + "}").ToLower()
}

# Rewrite DefaultEndpoint / DefaultCaptureVoiceDevice / etc: valores REG_BINARY 16 bytes
function Update-DefaultEndpoint {
    param(
        [string]$RolePath,   # PS path (Render ou Capture)
        [hashtable]$Map      # old-guid-string(lower) -> new-guid-string(lower)
    )
    if (-not (Test-Path $RolePath)) { return }
    $props = Get-ItemProperty -Path $RolePath -ErrorAction SilentlyContinue
    if ($null -eq $props) { return }

    # PSCustomObject: iterar propriedades procurando por REG_BINARY de 16 bytes
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
        $val = $p.Value
        if ($val -is [byte[]] -and $val.Length -eq 16) {
            $asGuid = Bytes-To-Guid -B $val
            if ($null -ne $asGuid -and $Map.ContainsKey($asGuid)) {
                $newG    = $Map[$asGuid]
                $newBytes = Guid-To-Bytes -G $newG
                Set-ItemProperty -Path $RolePath -Name $p.Name -Value $newBytes -Type Binary
                Write-Info ("DefaultEndpoint '{0}' {1} -> {2}" -f $p.Name, $asGuid, $newG)
            }
        }
    }
}

# Executa reg.exe capturando output e checando exit code
function Invoke-Reg {
    param([string[]]$RegArgs)
    $out = & reg.exe @RegArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("reg.exe " + ($RegArgs -join ' ') + " falhou (" + $LASTEXITCODE + "): " + ($out -join "`n"))
    }
    return $out
}

# Renomeia uma chave: export -> sed replace no arquivo -> import -> delete antigo.
# So substitui strings de GUID (regex escapada). Blobs REG_BINARY nao contem
# a representacao string, sao "hex:xx,xx,..." no .reg, entao ficam intactos.
function Rename-EndpointKey {
    param(
        [string]$RegBase,   # "HKLM\...\Render" (formato reg.exe)
        [string]$OldGuid,   # "{...}"
        [string]$NewGuid    # "{...}"
    )
    $oldPath = "$RegBase\$OldGuid"
    $newPath = "$RegBase\$NewGuid"
    $tmpFile = Join-Path $env:TEMP ("audio-swap-" + [guid]::NewGuid().ToString() + ".reg")

    try {
        [void](Invoke-Reg -RegArgs @("export", $oldPath, $tmpFile, "/y"))

        # reg.exe grava em UTF-16 LE com BOM. Preservar encoding.
        $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode

        # Substituir toda ocorrencia da string do GUID antigo. Case-insensitive porque
        # o registry as vezes retorna maiusculo, as vezes minusculo.
        $escaped = [regex]::Escape($OldGuid)
        $newContent = [regex]::Replace($content, $escaped, $NewGuid, 'IgnoreCase')

        # Sanity: NAO devem existir mais matches do GUID antigo dentro do arquivo.
        if ([regex]::IsMatch($newContent, $escaped, 'IgnoreCase')) {
            throw "Sanity check falhou: GUID antigo ainda presente apos replace."
        }

        Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline

        [void](Invoke-Reg -RegArgs @("import", $tmpFile))
        [void](Invoke-Reg -RegArgs @("delete", $oldPath, "/f"))
    } finally {
        if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
    }
}

# Varre subchaves sob HKLM\...\Audio\ (PolicyConfig etc) procurando referencias
# string ao GUID antigo em NOMES DE SUBCHAVE, e recria com o novo GUID.
# Restrito ao subtree para nao mexer em nada global.
function Rewrite-Audio-References {
    param(
        [hashtable]$Map  # old -> new (todos lowercase)
    )
    $audioRootReg = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio"
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio")) {
        return
    }

    # reg query /s lista tudo. Filtramos linhas que sejam PATHS de subchave contendo algum GUID antigo.
    $lines = & reg.exe query $audioRootReg /s /f "{" /k 2>$null
    if ($LASTEXITCODE -ne 0) { return }

    foreach ($old in $Map.Keys) {
        $new = $Map[$old]
        $escaped = [regex]::Escape($old)
        foreach ($line in $lines) {
            $trim = $line.Trim()
            if ($trim -notlike "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio\*") { continue }
            if (-not [regex]::IsMatch($trim, $escaped, 'IgnoreCase')) { continue }

            # Guard duplo: precisa realmente comecar com o path de Audio
            $regPath = $trim -replace '^HKEY_LOCAL_MACHINE\\','HKLM\'

            # Nao mexer nas proprias chaves de Render/Capture endpoint - ja foram tratadas.
            if ($regPath -match '\\MMDevices\\Audio\\(Render|Capture)\\\{[0-9A-Fa-f-]+\}$') { continue }

            $newRegPath = [regex]::Replace($regPath, $escaped, $new, 'IgnoreCase')
            if ($newRegPath -eq $regPath) { continue }

            # Guard triplo: newRegPath TAMBEM tem que estar sob Audio\
            if ($newRegPath -notlike 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio\*') { continue }

            $tmpFile = Join-Path $env:TEMP ("audio-ref-" + [guid]::NewGuid().ToString() + ".reg")
            try {
                $r = & reg.exe export $regPath $tmpFile /y 2>&1
                if ($LASTEXITCODE -ne 0) { continue }
                $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode
                $newContent = [regex]::Replace($content, $escaped, $new, 'IgnoreCase')
                Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline
                $r = & reg.exe import $tmpFile 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $r = & reg.exe delete $regPath /f 2>&1
                    Write-Info ("Ref reescrita: " + $regPath)
                }
            } catch {
                Write-Warn ("Falha reescrevendo " + $regPath + ": " + $_.Exception.Message)
            } finally {
                if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}

# ============================================================
#  Restore mode
# ============================================================
if ($Restore) {
    Write-Section "Restore de audio GUIDs"
    if (-not (Test-Path $mappingPath)) {
        Write-Err ("Mapping nao encontrado: " + $mappingPath)
        exit 1
    }
    try {
        $map = Get-Content $mappingPath -Raw | ConvertFrom-Json
    } catch {
        Write-Err ("Mapping corrompido: " + $_.Exception.Message)
        Write-Err ("Remova manualmente {0} e reaplique se necessario." -f $mappingPath)
        exit 1
    }

    $totalRestored = 0
    $reverseMap = @{}  # new -> old (para atualizar DefaultEndpoint)

    foreach ($role in @("Render","Capture")) {
        $entries = $map.$role
        if ($null -eq $entries) { continue }
        Write-Info ("Role " + $role + ": " + $entries.Count + " mapping(s)")
        foreach ($e in $entries) {
            $old = $e.old.ToLower()
            $new = $e.new.ToLower()
            $regBase = "$mmRoot\$role"
            $currentPath = Join-Path $mmRootPs ($role + "\" + $new)
            if (-not (Test-Path $currentPath)) {
                Write-Warn ("Endpoint " + $new + " ausente - pulando restore desta entrada")
                continue
            }
            try {
                # Reverte: renomeia NEW -> OLD
                Rename-EndpointKey -RegBase $regBase -OldGuid $new -NewGuid $old
                $reverseMap[$new] = $old
                $totalRestored++
                Write-OK ("Restaurado " + $role + ": " + $new + " -> " + $old)
            } catch {
                Write-Err ("Falha restaurando " + $new + ": " + $_.Exception.Message)
            }
        }
    }

    # DefaultEndpoint reverso
    foreach ($role in @("Render","Capture")) {
        $rolePath = Join-Path $mmRootPs $role
        Update-DefaultEndpoint -RolePath $rolePath -Map $reverseMap
    }

    # Refs sob Audio\
    if ($reverseMap.Count -gt 0) {
        Rewrite-Audio-References -Map $reverseMap
    }

    # Atomic delete: rename para .bak antes de remover (se algo falhar durante,
    # o mapping original nao fica truncado no meio).
    try {
        $bakPath = $mappingPath + ".bak"
        if (Test-Path $bakPath) { Remove-Item $bakPath -Force -ErrorAction SilentlyContinue }
        Move-Item -Path $mappingPath -Destination $bakPath -Force
        Remove-Item $bakPath -Force -ErrorAction SilentlyContinue
        Write-OK ("Mapping removido: " + $mappingPath)
    } catch {
        Remove-Item $mappingPath -Force -ErrorAction SilentlyContinue
        Write-OK ("Mapping removido: " + $mappingPath)
    }

    # AudioEndpointBuilder cacheia o enumeration de MMDevices. Reinicia-lo
    # (com -Force pra levar dependentes junto: AudioSrv) forca o Windows a
    # reler os endpoints do registry. Restart-Service -Force reinicia
    # servicos dependentes automaticamente.
    try {
        Restart-Service -Name AudioEndpointBuilder -Force -ErrorAction Stop
        Write-OK "Servico AudioEndpointBuilder reiniciado (AudioSrv como dependente)"
    } catch {
        Write-Warn ("Nao consegui reiniciar AudioEndpointBuilder: " + $_.Exception.Message)
        try {
            Restart-Service -Name AudioSrv -Force -ErrorAction Stop
            Write-OK "Fallback: AudioSrv reiniciado"
        } catch {
            Write-Warn ("Nao consegui reiniciar AudioSrv: " + $_.Exception.Message)
        }
    }

    Write-Host ""
    Write-Host ("Total restaurado: " + $totalRestored) -ForegroundColor Cyan
    exit 0
}

# ============================================================
#  Rotate mode
# ============================================================
Write-Section "Spoof de audio GUIDs (MMDevices)"

# Carregar profile (opcional para pool - podemos gerar on the fly)
$rotationPool = @()
if (Test-Path $profilePath) {
    try {
        $prof = Get-Content $profilePath -Raw | ConvertFrom-Json
        if ($prof.audio -and $prof.audio.rotation_pool) {
            $rotationPool = @($prof.audio.rotation_pool)
            Write-OK ("Pool do profile: " + $rotationPool.Count + " GUID(s)")
        } else {
            Write-Warn "Profile nao tem audio.rotation_pool - vou gerar GUIDs on the fly"
        }
    } catch {
        Write-Warn ("Falha lendo profile: " + $_.Exception.Message)
    }
} else {
    Write-Warn ("Profile ausente (" + $profilePath + ") - vou gerar GUIDs on the fly")
}

# Carregar mapping existente (para runs repetidas serem estaveis)
$existingMap = @{ Render = @(); Capture = @() }
if (Test-Path $mappingPath) {
    try {
        $prev = Get-Content $mappingPath -Raw | ConvertFrom-Json
        foreach ($role in @("Render","Capture")) {
            if ($prev.$role) { $existingMap[$role] = @($prev.$role) }
        }
        Write-OK ("Mapping anterior carregado (" +
                  $existingMap.Render.Count + " Render, " +
                  $existingMap.Capture.Count + " Capture)")
    } catch {
        Write-Warn ("Falha lendo mapping anterior: " + $_.Exception.Message)
    }
}

# Indice do pool: quais GUIDs ja foram consumidos por mappings anteriores
$consumed = @{}
foreach ($role in @("Render","Capture")) {
    foreach ($e in $existingMap[$role]) { $consumed[$e.new.ToLower()] = $true }
}
$poolCursor = 0

function Get-Next-New-Guid {
    param([string]$OldGuid)
    # Reuse: se este old ja foi mapeado antes, retorna o mesmo new
    foreach ($role in @("Render","Capture")) {
        foreach ($e in $existingMap[$role]) {
            if ($e.old.ToLower() -eq $OldGuid.ToLower()) {
                return $e.new.ToLower()
            }
        }
    }
    # Nova alocacao: tenta pool primeiro
    while ($script:poolCursor -lt $rotationPool.Count) {
        $cand = $rotationPool[$script:poolCursor].ToLower()
        $script:poolCursor++
        if (-not $consumed.ContainsKey($cand)) {
            $consumed[$cand] = $true
            return $cand
        }
    }
    # Pool esgotado: gera on the fly
    $g = (New-Guid-Str)
    $consumed[$g] = $true
    return $g
}

# Coletar endpoints ativos por role
$newMap = @{ Render = @(); Capture = @() }
$sessionMap = @{}  # old -> new (usado nesta sessao para DefaultEndpoint e refs)

foreach ($role in @("Render","Capture")) {
    Write-Section ("Role: " + $role)
    $roleRootPs  = Join-Path $mmRootPs $role
    $roleRootReg = "$mmRoot\$role"

    if (-not (Test-Path $roleRootPs)) {
        Write-Warn ($role + " nao existe - pulando")
        continue
    }

    $endpoints = Get-ChildItem -Path $roleRootPs -ErrorAction SilentlyContinue
    if ($null -eq $endpoints -or $endpoints.Count -eq 0) {
        Write-Info "Nenhum endpoint encontrado"
        continue
    }

    $poolExhaustedWarned = $false

    foreach ($ep in $endpoints) {
        $oldGuid = $ep.PSChildName
        if ($oldGuid -notmatch ('^' + $guidRegex + '$')) {
            Write-Info ("Subchave nao-GUID ignorada: " + $oldGuid)
            continue
        }
        $oldGuidLower = $oldGuid.ToLower()

        $stateVal = Get-EndpointState -RegPath $ep.PSPath
        $stateName = Format-StateName -State $stateVal

        # DEVICE_STATE_ACTIVE = 0x1. Windows tipicamente seta exatamente 1 flag,
        # mas usamos bitmask (nao equality) para robustez caso um flag extra apareca.
        if (($stateVal -band 0x1) -eq 0) {
            Write-Info ("[" + $stateName + "] " + $oldGuid + " - pulando (nao ACTIVE)")
            continue
        }

        # Anti-drift: se este oldGuid ja e um GUID rotacionado em runs anteriores
        # (ou seja, aparece como .new no existingMap), pula. Sem isso, rerodar
        # o script produz novo GUID a cada execucao e -Restore so desfaz o ultimo.
        # (Usa variavel loop dedicada — NAO reutilizar $role do foreach externo.)
        $alreadyRotated = $false
        foreach ($checkRole in @("Render","Capture")) {
            foreach ($e in $existingMap[$checkRole]) {
                if ($e.new.ToLower() -eq $oldGuidLower) {
                    $alreadyRotated = $true
                    break
                }
            }
            if ($alreadyRotated) { break }
        }
        if ($alreadyRotated) {
            Write-Info ("[ACTIVE] " + $oldGuid + " - ja rotacionado em run anterior, pulando")
            continue
        }

        $newGuid = Get-Next-New-Guid -OldGuid $oldGuidLower
        if ($null -eq $newGuid) {
            if (-not $poolExhaustedWarned) {
                Write-Warn "Pool esgotado nesta role - parando rotacao"
                $poolExhaustedWarned = $true
            }
            break
        }

        try {
            Rename-EndpointKey -RegBase $roleRootReg -OldGuid $oldGuid -NewGuid $newGuid
            $newMap[$role] += [pscustomobject]@{ old = $oldGuidLower; new = $newGuid }
            $sessionMap[$oldGuidLower] = $newGuid
            Write-OK ("[" + $stateName + "] " + $oldGuid + " -> " + $newGuid)
        } catch {
            Write-Err ("Falha rotacionando " + $oldGuid + ": " + $_.Exception.Message)
        }
    }
}

# Persistir mapping (merge com anterior por role/old)
Write-Section "Persistindo mapping"

$mergedMap = @{ Render = @(); Capture = @() }
foreach ($role in @("Render","Capture")) {
    $seen = @{}
    # Novos primeiro
    foreach ($e in $newMap[$role]) {
        $seen[$e.old] = $e
    }
    # Depois preserva os anteriores nao sobrescritos
    foreach ($e in $existingMap[$role]) {
        if (-not $seen.ContainsKey($e.old.ToLower())) {
            $seen[$e.old.ToLower()] = [pscustomobject]@{ old = $e.old.ToLower(); new = $e.new.ToLower() }
        }
    }
    $mergedMap[$role] = @($seen.Values)
}

# Garantir diretorio
$mappingDir = Split-Path $mappingPath -Parent
if (-not (Test-Path $mappingDir)) {
    New-Item -ItemType Directory -Path $mappingDir -Force | Out-Null
}

# Atomic write: escreve em tmp e move (mesmo padrao de generate-profile.ps1)
$tmpMap = $mappingPath + ".tmp"
$mergedMap | ConvertTo-Json -Depth 5 | Set-Content -Path $tmpMap -Encoding UTF8
Move-Item -Path $tmpMap -Destination $mappingPath -Force
Write-OK ("Mapping salvo em: " + $mappingPath)

# ============================================================
#  Atualizar DefaultEndpoint (REG_BINARY 16 bytes)
# ============================================================
if ($sessionMap.Count -gt 0) {
    Write-Section "Atualizando DefaultEndpoint"
    foreach ($role in @("Render","Capture")) {
        $rolePath = Join-Path $mmRootPs $role
        Update-DefaultEndpoint -RolePath $rolePath -Map $sessionMap
    }

    Write-Section "Reescrevendo referencias sob Audio\"
    Rewrite-Audio-References -Map $sessionMap
}

# ============================================================
#  Restart servico
# ============================================================
Write-Section "Restart do servico Windows Audio"
# AudioEndpointBuilder e o servico que enumera/cacheia MMDevices do registry.
# Reinicia-lo com -Force leva junto AudioSrv (que depende dele), forcando o
# Windows a reler os enderecos dos endpoints rotacionados. So reiniciar
# AudioSrv nao invalida o cache do enumerator.
try {
    Restart-Service -Name AudioEndpointBuilder -Force -ErrorAction Stop
    Write-OK "AudioEndpointBuilder reiniciado (AudioSrv como dependente)"
} catch {
    Write-Warn ("Nao consegui reiniciar AudioEndpointBuilder: " + $_.Exception.Message)
    try {
        Restart-Service -Name AudioSrv -Force -ErrorAction Stop
        Write-OK "Fallback: AudioSrv reiniciado"
    } catch {
        Write-Warn ("Nao consegui reiniciar AudioSrv (pode precisar de logout): " + $_.Exception.Message)
    }
}

# ============================================================
#  Summary
# ============================================================
Write-Section "Resumo"
$rc = $newMap.Render.Count
$cc = $newMap.Capture.Count
Write-Host ("  Render rotacionados : " + $rc) -ForegroundColor Cyan
Write-Host ("  Capture rotacionados: " + $cc) -ForegroundColor Cyan
if (($rc + $cc) -eq 0) {
    Write-Warn "Nenhum endpoint foi rotacionado - verifique se ha devices ACTIVE"
    exit 1
}
Write-Host ""
Write-Info "Software de audio terceiro pode precisar reconfiguracao"
Write-Info ("Para reverter: .\spoof-audio-guids.ps1 -Restore")
exit 0
