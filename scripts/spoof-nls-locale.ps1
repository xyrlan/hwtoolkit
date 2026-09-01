#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Spoof deterministico dos valores de
      HKLM:\SYSTEM\CurrentControlSet\Control\Nls\ExtendedLocale
      HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CustomLocale

.DESCRIPTION
    Reconhecimento EMAC v2 (docs/emac-recon-v2.md) reporta que o cliente EMAC
    faz ~2 leituras nessas chaves (volume baixo, provavelmente enumeracao de
    subvalores como parte do fingerprint de sistema).

    Estrategia CONSERVADORA (nao destrutiva):
      - NAO modifica nem apaga entradas existentes (rewriter de LCIDs de
        locales conhecidos como "en-US", "pt-BR" quebraria a NLS API pra
        qualquer coisa que le esses mesmos valores - Explorer, apps de
        Office, formatadores de data, etc).
      - APENAS ADICIONA 1 entrada nova por chave, com:
          * name  = "hw-<xx>"  <xx> derivado de FNV1a(seed | "NLS-NAME|<key>")
          * value = escolhido de um pool pequeno de strings LCID plausiveis
                    (padrao Windows: "LCID_HEX:SORTKEY_HEX")
      - Nomes tem prefixo "hw-" pra facilmente identificar entradas nossas
        no dump. Restore apaga exatamente pelo prefixo + nome registrado no
        backup.

    O que este script NAO toca (proposital):
      - Nenhum valor pre-existente em ExtendedLocale ou CustomLocale.
      - Nenhum valor em outras subchaves de Control\Nls (CodePage, Language,
        Locale, etc). Essas sao consumidas pelo boot loader / kernel NLS
        subsystem e alterar quebra APIs em cascata.
      - Nenhum registry de UserLocale/system locale de perfil.

    Determinismo:
      - seed lido de $prof.pci_hardwareid.randomize_seed (mesmo padrao dos
        outros spoofers - spoof-pci-hardwareid, spoof-usb-ids, spoof-hid-ids,
        spoof-network-pnpid).
      - Se profile ou seed ausente, script recusa (exit 1) - evita "spoof
        efemero" acidental que gera nomes diferentes a cada arm.

.PARAMETER Apply
    Le seed do profile, salva backup (uma vez), adiciona 1 entrada em cada
    chave. Idempotente: se a entrada com o nome derivado ja existe, apenas
    reescreve o value (permite re-arm depois de rotacao de pool).

.PARAMETER Restore
    Le C:\ProgramData\.hwcfg\nls-locale-backup.json e apaga as entradas
    listadas em added_names_extended / added_names_custom.

.PARAMETER Show
    Mostra os valores atuais de cada chave + valores derivados do profile +
    conteudo do backup. Nao escreve nada.
#>

[CmdletBinding(DefaultParameterSetName='Apply')]
param(
    [Parameter(ParameterSetName='Apply')]   [switch]$Apply,
    [Parameter(ParameterSetName='Restore')] [switch]$Restore,
    [Parameter(ParameterSetName='Show')]    [switch]$Show,
    # -DryRun sem ParameterSetName = valido em qualquer modo (__AllParameterSets).
    # 08b-rollback-userland.bat injeta -DryRun em todos os -Restore quando --dry-run;
    # sem esse switch, CmdletBinding rejeita e o rollback falha com FAIL(nls-locale)
    # em vez de preview limpo.
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"
$backupPath  = "C:\ProgramData\.hwcfg\nls-locale-backup.json"

$extendedPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\ExtendedLocale"
$customPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CustomLocale"

# Pool small e propositalmente plausivel. Cada string segue o formato
# "<LCID hex 4>:<sortkey hex 8>" que o Windows usa nativamente pra
# entradas nessas chaves. Sao todos LCIDs reais - se EMAC comparar
# contra tabela conhecida, nada fica marcado como "invalido".
$lcidPool = @(
    "0409:00000409",  # en-US
    "0416:00000416",  # pt-BR
    "040a:0000040a",  # es-ES tradicional
    "040c:0000040c",  # fr-FR
    "0407:00000407"   # de-DE
)

# ============================================================
#  Helpers
# ============================================================

# FNV-1a 64bit deterministico (mesmo helper de spoof-network-pnpid.ps1).
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

function Get-DerivedName {
    param([string]$Seed, [string]$KeyTag)
    $h = Get-Fnv1a64Hash -InputText ("NLS-NAME|" + $Seed + "|" + $KeyTag)
    $suffix = ("{0:x2}" -f [byte]($h -band 0xFF))
    return ("hw-" + $suffix)
}

function Get-DerivedValue {
    param([string]$Seed, [string]$KeyTag)
    $h = Get-Fnv1a64Hash -InputText ("NLS-VAL|" + $Seed + "|" + $KeyTag)
    $idx = [int]($h % [uint64]$lcidPool.Length)
    return $lcidPool[$idx]
}

function Get-KeyValueMap {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @{} }
    $map = @{}
    $item = Get-Item -Path $Path -ErrorAction Stop
    foreach ($n in $item.GetValueNames()) {
        if ([string]::IsNullOrEmpty($n)) { continue }
        $map[$n] = [string]$item.GetValue($n)
    }
    return $map
}

# ============================================================
#  Header
# ============================================================
Write-Host ""
Write-Host "=== Spoof NLS ExtendedLocale / CustomLocale ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Adiciona 1 entrada 'hw-<xx>' em cada chave (nao apaga nada)." -ForegroundColor Gray
Write-Host "  EMAC v2 recon: ~2 leituras nessas chaves." -ForegroundColor Gray
Write-Host ""

# ============================================================
#  Load profile + seed
# ============================================================
$seed = $null
if (Test-Path $profilePath) {
    try {
        $prof = Get-Content $profilePath -Raw | ConvertFrom-Json
        if ($prof.pci_hardwareid -and $prof.pci_hardwareid.randomize_seed) {
            $candidate = [string]$prof.pci_hardwareid.randomize_seed
            if ($candidate -match '^[0-9a-fA-F]{32}$') {
                $seed = $candidate.ToLower()
            } else {
                Write-Warn ("randomize_seed em formato invalido (esperado 32 hex): '{0}' - usando seed ephemeral" -f $candidate)
            }
        } else {
            Write-Warn "profile.pci_hardwareid.randomize_seed ausente - usando seed ephemeral"
        }
    } catch {
        Write-Warn ("Falha lendo profile.json: {0} - usando seed ephemeral" -f $_.Exception.Message)
    }
} else {
    Write-Warn "Profile nao encontrado - usando seed ephemeral (reruns produzirao valores diferentes)"
    Write-Warn "Para consistencia entre reruns, rode: .\generate-profile.ps1 -Generate"
}
if (-not $seed) {
    $seed = ([guid]::NewGuid().ToString('N')).ToLower()
    Write-Info ("Seed ephemeral gerado: {0}" -f $seed)
}

# Valores derivados (mesmos em Show, Apply e Restore-check).
$extName  = Get-DerivedName  -Seed $seed -KeyTag "ExtendedLocale"
$extValue = Get-DerivedValue -Seed $seed -KeyTag "ExtendedLocale"
$cusName  = Get-DerivedName  -Seed $seed -KeyTag "CustomLocale"
$cusValue = Get-DerivedValue -Seed $seed -KeyTag "CustomLocale"

$mode = $PSCmdlet.ParameterSetName
if (-not ($Apply -or $Restore -or $Show)) { $mode = 'Apply' }

# ============================================================
#  DISPATCH: Show
# ============================================================
if ($mode -eq 'Show') {
    Write-Section "ExtendedLocale (valores atuais)"
    $map = Get-KeyValueMap $extendedPath
    if ($map.Count -eq 0) { Write-Warn "chave vazia ou ausente." }
    foreach ($k in ($map.Keys | Sort-Object)) { Write-Info ("{0} = {1}" -f $k, $map[$k]) }

    Write-Section "CustomLocale (valores atuais)"
    $map = Get-KeyValueMap $customPath
    if ($map.Count -eq 0) { Write-Warn "chave vazia ou ausente." }
    foreach ($k in ($map.Keys | Sort-Object)) { Write-Info ("{0} = {1}" -f $k, $map[$k]) }

    Write-Section "Derivado do profile (seed = $seed)"
    Write-Info ("ExtendedLocale : {0} = {1}" -f $extName, $extValue)
    Write-Info ("CustomLocale   : {0} = {1}" -f $cusName, $cusValue)

    Write-Section "Backup"
    if (Test-Path $backupPath) {
        Write-OK ("Existe: {0}" -f $backupPath)
        $bk = Get-Content $backupPath -Raw | ConvertFrom-Json
        Write-Info ("  added_names_extended : {0}" -f (($bk.added_names_extended) -join ', '))
        Write-Info ("  added_names_custom   : {0}" -f (($bk.added_names_custom)   -join ', '))
    } else {
        Write-Warn "Sem backup ainda (primeiro -Apply cria)."
    }

    Write-Host ""
    Write-Host "=== Fim ===" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# ============================================================
#  DISPATCH: Restore
# ============================================================
if ($mode -eq 'Restore') {
    Write-Section "Restore (apaga entradas registradas no backup)"
    if (-not (Test-Path $backupPath)) {
        Write-Err "Backup nao encontrado em $backupPath"
        Write-Err "Nada a restaurar."
        exit 1
    }
    $bk = Get-Content $backupPath -Raw | ConvertFrom-Json

    $removed = 0
    foreach ($n in @($bk.added_names_extended)) {
        if ([string]::IsNullOrEmpty($n)) { continue }
        if ($DryRun) {
            Write-Info ("[DryRun] ExtendedLocale : removeria '{0}'" -f $n)
            continue
        }
        try {
            Remove-ItemProperty -Path $extendedPath -Name $n -Force -ErrorAction Stop
            Write-OK ("ExtendedLocale : removido '{0}'" -f $n)
            $removed++
        } catch {
            Write-Warn ("ExtendedLocale : '{0}' ja ausente ({1})" -f $n, $_.Exception.Message)
        }
    }
    foreach ($n in @($bk.added_names_custom)) {
        if ([string]::IsNullOrEmpty($n)) { continue }
        if ($DryRun) {
            Write-Info ("[DryRun] CustomLocale   : removeria '{0}'" -f $n)
            continue
        }
        try {
            Remove-ItemProperty -Path $customPath -Name $n -Force -ErrorAction Stop
            Write-OK ("CustomLocale   : removido '{0}'" -f $n)
            $removed++
        } catch {
            Write-Warn ("CustomLocale   : '{0}' ja ausente ({1})" -f $n, $_.Exception.Message)
        }
    }

    Write-Host ""
    if ($DryRun) {
        Write-Info "DryRun ativo - nenhuma escrita feita"
    } else {
        Write-Info ("Total removido: {0}" -f $removed)
    }
    Write-Host "=== Fim ===" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# ============================================================
#  DISPATCH: Apply (default)
# ============================================================
Write-Section "Apply (adiciona entradas derivadas do seed)"

if (-not (Test-Path $extendedPath)) {
    Write-Err "$extendedPath nao existe - Windows corrompido? Abortando."
    exit 1
}
if (-not (Test-Path $customPath)) {
    Write-Err "$customPath nao existe - Windows corrompido? Abortando."
    exit 1
}

# Backup UMA VEZ. Guarda dump completo dos valores originais (referencia
# forense) + a lista de nomes que ADICIONAMOS (usada por -Restore).
if (-not (Test-Path $backupPath)) {
    $backupDir = Split-Path $backupPath -Parent
    if (-not (Test-Path $backupDir) -and -not $DryRun) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }

    $bkObj = [ordered]@{
        created_utc            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        seed                   = $seed
        added_names_extended   = @($extName)
        added_names_custom     = @($cusName)
        original_extended_dump = Get-KeyValueMap $extendedPath
        original_custom_dump   = Get-KeyValueMap $customPath
    }
    $json = $bkObj | ConvertTo-Json -Depth 5
    if ($DryRun) {
        Write-Info ("[DryRun] Criaria backup em: {0}" -f $backupPath)
    } else {
        $tmp = "$backupPath.tmp"
        Set-Content -Path $tmp -Value $json -Encoding UTF8 -Force
        Move-Item -Path $tmp -Destination $backupPath -Force
        Write-OK ("Backup criado: {0}" -f $backupPath)
    }
} else {
    Write-Info ("Backup ja existe (preservado): {0}" -f $backupPath)
}

# Guard: entrada derivada NUNCA pode colidir com nome pre-existente
# (evita clobber acidental caso a maquina tenha uma entrada real
# chamada "hw-XX" por acaso - improvavel mas checado).
$extMap = Get-KeyValueMap $extendedPath
if ($extMap.ContainsKey($extName)) {
    $existing = $extMap[$extName]
    if ($existing -ne $extValue) {
        Write-Warn ("ExtendedLocale ja tem '{0}' = '{1}' - reescrevendo pra '{2}'." -f $extName, $existing, $extValue)
    }
}
$cusMap = Get-KeyValueMap $customPath
if ($cusMap.ContainsKey($cusName)) {
    $existing = $cusMap[$cusName]
    if ($existing -ne $cusValue) {
        Write-Warn ("CustomLocale ja tem '{0}' = '{1}' - reescrevendo pra '{2}'." -f $cusName, $existing, $cusValue)
    }
}

# Grava as duas entradas (New-ItemProperty com -Force = upsert).
if ($DryRun) {
    Write-Info ("[DryRun] ExtendedLocale : escreveria '{0}' = '{1}'" -f $extName, $extValue)
    Write-Info ("[DryRun] CustomLocale   : escreveria '{0}' = '{1}'" -f $cusName, $cusValue)
} else {
    New-ItemProperty -Path $extendedPath -Name $extName -Value $extValue -PropertyType String -Force | Out-Null
    Write-OK ("ExtendedLocale : {0} = {1}" -f $extName, $extValue)

    New-ItemProperty -Path $customPath -Name $cusName -Value $cusValue -PropertyType String -Force | Out-Null
    Write-OK ("CustomLocale   : {0} = {1}" -f $cusName, $cusValue)
}

Write-Host ""
Write-Info "EMAC le esses valores on-demand - vale ja no proximo start do cliente."
Write-Info "Reboot NAO e necessario (nenhum cache in-kernel dessas chaves)."
Write-Host ""
Write-Info ("Para reverter:    .\spoof-nls-locale.ps1 -Restore")
Write-Info ("Para inspecionar: .\spoof-nls-locale.ps1 -Show")
Write-Host ""
Write-Host "=== Fim ===" -ForegroundColor Cyan
Write-Host ""
exit 0
