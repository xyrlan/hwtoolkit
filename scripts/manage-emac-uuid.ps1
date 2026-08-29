#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Gerencia o arquivo de cache do EMAC anti-cheat (~\emac-uuid).
.DESCRIPTION
    O EMAC anti-cheat mantem um cache persistente em
    C:\Users\<user>\emac-uuid contendo um UUID v4 ASCII de 36 bytes.
    Esse arquivo funciona como "assinatura" da instalacao. Quando ele
    existe e nao muda entre boots, o cliente reusa o UUID e nao
    dispara re-registro no servidor.

    Reconhecimento observado: se o arquivo desaparece, o cliente
    dispara uma cascata de re-registro (~32k RegOpenKey queries +
    varios POSTs pra endpoints Vultr/Cloudflare). Esse burst e visivel
    a nivel de rede e telemetria - nao queremos disparar do nada.

    Estrategia deste script:
      - Manter um UUID FAKE persistente vindo do profile.
      - Opcionalmente travar o arquivo via ACL (read-only pra user),
        pra impedir que o proprio cliente sobrescreva com o UUID real
        que ele coletaria da nossa maquina.
      - Rotacionar so quando o operador quiser (-Fresh), gravando o
        novo UUID no profile pra manter a "single source of truth".

    Modos:
      -Apply    (default) escreve persistent_uuid do profile no arquivo
                e aplica ACL se profile.emac.lock_file == true.
      -Fresh    Gera novo UUID v4, atualiza profile.json in-place,
                reescreve o arquivo e reaplica ACL.
      -Restore  Remove a ACL restritiva (volta a heranca padrao).
                Use antes de desinstalar / trocar de conta / permitir
                que o cliente escreva de novo.
      -Show     So mostra o conteudo atual, a ACL e se bate com o profile.

    IMPORTANTE: nao negamos SYSTEM. Alguns componentes de AV/telemetria
    precisam ler o arquivo. So restringimos WRITE/DELETE do usuario.
#>

[CmdletBinding(DefaultParameterSetName='Apply')]
param(
    [Parameter(ParameterSetName='Apply')]   [switch]$Apply,
    [Parameter(ParameterSetName='Fresh')]   [switch]$Fresh,
    [Parameter(ParameterSetName='Restore')] [switch]$Restore,
    [Parameter(ParameterSetName='Show')]    [switch]$Show
)

$ErrorActionPreference = "Stop"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"

# Detecta contexto SYSTEM: $env:USERPROFILE resolveria para
# C:\Windows\system32\config\systemprofile, e o arquivo escrito la nao
# corresponde ao cache real do jogador em C:\Users\<name>\emac-uuid.
# Se o toolkit for chamado via scheduled task ou servico, o arquivo real
# ficaria dessincronizado e o EMAC dispararia burst de re-registro.
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isSystemContext = $currentIdentity.IsSystem
if ($isSystemContext) {
    Write-Host ""
    Write-Host "  [X] ERRO: rodando como SYSTEM (LocalSystem)." -ForegroundColor Red
    Write-Host "  [X] Este script precisa rodar como o USUARIO INTERATIVO do jogo," -ForegroundColor Red
    Write-Host "  [X] senao %USERPROFILE% aponta pra C:\Windows\system32\config\systemprofile" -ForegroundColor Red
    Write-Host "  [X] e o emac-uuid real (em C:\Users\<jogador>\) nao seria atualizado." -ForegroundColor Red
    Write-Host "  [X] Rode este .bat/.ps1 com clique-direito 'Executar como administrador'" -ForegroundColor Red
    Write-Host "  [X] a partir da sessao do jogador — NUNCA de scheduled task rodando como SYSTEM." -ForegroundColor Red
    exit 2
}

$emacPath    = Join-Path $env:USERPROFILE "emac-uuid"

# UUID que aparece na documentacao de reconhecimento como placeholder.
# Se o profile ainda tem esse valor, o operador nunca gerou um proprio.
$placeholderUuid = "d9f4202f-e108-4fc8-8389-c3c8d4b9689e"

function Write-Section($t) { Write-Host ""; Write-Host ("== " + $t + " ==") -ForegroundColor Cyan }
function Write-OK($m)      { Write-Host ("  [OK]   " + $m) -ForegroundColor Green }
function Write-Info($m)    { Write-Host ("  [*]    " + $m) -ForegroundColor Gray }
function Write-Warn($m)    { Write-Host ("  [!]    " + $m) -ForegroundColor Yellow }
function Write-Err($m)     { Write-Host ("  [X]    " + $m) -ForegroundColor Red }

# ============================================================
#  AVISO DE RECONHECIMENTO
# ============================================================
Write-Host ""
Write-Host "=== EMAC UUID cache manager ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  AVISO: apagar ~\emac-uuid dispara registro completo de HW" -ForegroundColor Yellow
Write-Host "  no cliente EMAC (~32k RegOpenKey queries + POSTs pra"       -ForegroundColor Yellow
Write-Host "  endpoints Vultr/Cloudflare desconhecidos)."                  -ForegroundColor Yellow
Write-Host "  Mantenha esse arquivo. So rotacione com -Fresh E depois"    -ForegroundColor Yellow
Write-Host "  de um reset completo de spoof de HW."                        -ForegroundColor Yellow
Write-Host ""

# ============================================================
#  CARREGAR PROFILE
# ============================================================
if (-not (Test-Path $profilePath)) {
    Write-Err "Profile nao encontrado em $profilePath"
    Write-Err "Rode primeiro:  .\hwprofile.ps1 -Generate"
    exit 1
}

$profileObj = Get-Content $profilePath -Raw | ConvertFrom-Json

if (-not $profileObj.PSObject.Properties['emac']) {
    Write-Err "Profile nao tem secao 'emac'. Regenere com a versao nova"
    Write-Err "do hwprofile.ps1 que emite emac.persistent_uuid + emac.lock_file."
    exit 1
}

$emacCfg = $profileObj.emac

if (-not $emacCfg.PSObject.Properties['persistent_uuid'] -or `
    [string]::IsNullOrWhiteSpace($emacCfg.persistent_uuid)) {
    Write-Err "profile.emac.persistent_uuid vazio."
    exit 1
}

$profileUuid = [string]$emacCfg.persistent_uuid
$lockFile    = [bool]$emacCfg.lock_file

# Sanity: UUID valido (36 chars, formato 8-4-4-4-12)
if ($profileUuid -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    Write-Err "profile.emac.persistent_uuid nao esta no formato UUID (36 chars)."
    Write-Err "Valor atual: '$profileUuid'"
    exit 1
}

# Sanity: nao usar o placeholder do documento
if ($profileUuid -ieq $placeholderUuid) {
    Write-Warn "profile.emac.persistent_uuid == placeholder do doc de reconhecimento"
    Write-Warn "($placeholderUuid)."
    Write-Warn "Isso e o valor de exemplo da documentacao, NAO um UUID gerado."
    Write-Warn "Rode com -Fresh pra gerar um proprio antes de aplicar."
}

Write-Info "Profile:    $profilePath"
Write-Info "Arquivo:    $emacPath"
Write-Info "UUID cfg:   $profileUuid"
Write-Info "Lock ACL:   $lockFile"

# ============================================================
#  HELPERS
# ============================================================

function Get-CurrentUserSid {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().User
}

function Test-EmacRunning {
    # Retorna true se algum processo com "emac" no nome estiver rodando.
    # Reescrever emac-uuid enquanto o cliente esta ativo pode disparar o
    # burst de re-registro (o cliente detecta tamper e recomeca a coleta).
    $procs = @(Get-Process -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -match '(?i)emac' })
    return ($procs.Count -gt 0)
}

function Write-EmacFile {
    param([string]$Path, [string]$Uuid)

    if (Test-EmacRunning) {
        Write-Warn "Detectei processo com 'emac' no nome ativo. Reescrever o cache"
        Write-Warn "agora pode disparar burst de re-registro no cliente."
        Write-Warn "Feche o jogo/cliente EMAC antes de rodar este script."
        throw "EMAC client aparentemente em execucao - abortando escrita."
    }

    # Se o arquivo esta com ACL restritiva, o proprio admin corrente
    # pode nao conseguir sobrescrever - remove primeiro.
    if (Test-Path $Path) {
        try {
            # Remove read-only attribute se existir
            $item = Get-Item -Path $Path -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReadOnly) {
                $item.Attributes = $item.Attributes -bxor [IO.FileAttributes]::ReadOnly
            }
        } catch {}

        # Se a ACL bloqueia write pro admin, restaura heranca padrao antes.
        try {
            Reset-EmacFileAcl -Path $Path
        } catch {}
    }

    # 36 bytes ASCII, SEM BOM, SEM newline final.
    # Retry curto caso o arquivo esteja momentaneamente com share-mode restrito
    # (WriteAllBytes throws IOException nesse caso).
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Uuid)
    $attempts = 0
    $maxAttempts = 3
    while ($true) {
        try {
            [System.IO.File]::WriteAllBytes($Path, $bytes)
            break
        } catch [System.IO.IOException] {
            $attempts++
            if ($attempts -ge $maxAttempts) { throw }
            Start-Sleep -Milliseconds 250
        }
    }
}

function Reset-EmacFileAcl {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    $acl = Get-Acl -Path $Path

    # Passo 1: remove todas as regras explicitas nao-herdadas (senao a
    # read-only-user do Lock-EmacFileAcl anterior sobrevive e mascara as
    # regras herdadas que autorizam escrita).
    $existingRules = @($acl.Access | Where-Object { -not $_.IsInherited })
    foreach ($r in $existingRules) {
        [void]$acl.RemoveAccessRule($r)
    }

    # Passo 2: reativa heranca. Segundo parametro = $false descarta regras
    # explicitas preservadas (nao ha razao pra manter cache das regras que
    # acabamos de remover).
    $acl.SetAccessRuleProtection($false, $false)

    Set-Acl -Path $Path -AclObject $acl
}

function Lock-EmacFileAcl {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Arquivo nao existe pra travar: $Path"
    }

    $userSid   = Get-CurrentUserSid
    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)

    $acl = Get-Acl -Path $Path

    # Break inheritance + descarta regras herdadas (nao mantem copia).
    $acl.SetAccessRuleProtection($true, $false)

    # Limpa qualquer regra remanescente.
    $existing = @($acl.Access)
    foreach ($r in $existing) {
        [void]$acl.RemoveAccessRule($r)
    }

    # User corrente: READ + READ_ATTRIBUTES + SYNCHRONIZE (sem write, sem delete)
    $userRights = [System.Security.AccessControl.FileSystemRights]::Read -bor `
                  [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor `
                  [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes -bor `
                  [System.Security.AccessControl.FileSystemRights]::Synchronize
    $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $userSid, $userRights,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($userRule)

    # Admins: FullControl (pra permitir -Restore / -Fresh no futuro)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $adminsSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($adminRule)

    # SYSTEM: FullControl (NAO negamos - AV/telemetria pode precisar ler)
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $systemSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($systemRule)

    Set-Acl -Path $Path -AclObject $acl
}

function Show-EmacState {
    param([string]$Path, [string]$ExpectedUuid)

    Write-Section "Estado atual"

    if (-not (Test-Path $Path)) {
        Write-Warn "Arquivo nao existe: $Path"
        Write-Warn "Se o cliente EMAC rodar agora, vai disparar registro completo."
        return
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    Write-Info ("Tamanho: {0} bytes" -f $bytes.Length)

    if ($bytes.Length -ne 36) {
        Write-Warn "Tamanho != 36. Formato inesperado."
    }

    $content = [System.Text.Encoding]::ASCII.GetString($bytes)
    Write-Info "Conteudo: $content"

    if ($content -ieq $ExpectedUuid) {
        Write-OK "Bate com profile.emac.persistent_uuid"
    } else {
        Write-Warn "NAO bate com o profile."
        Write-Warn "  esperado: $ExpectedUuid"
        Write-Warn "  no disco: $content"
    }

    Write-Section "ACL"
    $acl = Get-Acl -Path $Path
    Write-Info ("Owner:               {0}" -f $acl.Owner)
    Write-Info ("Herdando (protected: {0})" -f $acl.AreAccessRulesProtected)
    foreach ($rule in $acl.Access) {
        $line = "  {0,-40} {1,-6} {2}" -f $rule.IdentityReference, $rule.AccessControlType, $rule.FileSystemRights
        Write-Host $line -ForegroundColor DarkGray
    }
}

# ============================================================
#  DISPATCH
# ============================================================
$mode = $PSCmdlet.ParameterSetName
if (-not ($Apply -or $Fresh -or $Restore -or $Show)) {
    $mode = 'Apply'
}

switch ($mode) {

    'Show' {
        Show-EmacState -Path $emacPath -ExpectedUuid $profileUuid
        break
    }

    'Restore' {
        Write-Section "Restore (remove ACL restritiva)"
        if (-not (Test-Path $emacPath)) {
            Write-Warn "Arquivo nao existe, nada pra restaurar."
        } else {
            Reset-EmacFileAcl -Path $emacPath
            Write-OK "ACL voltou pra heranca padrao. Cliente EMAC pode escrever de novo."
        }
        break
    }

    'Fresh' {
        Write-Section "Fresh (gerar novo UUID + atualizar profile)"

        # Gera UUID v4 via .NET (rand cripto)
        $newUuid = [guid]::NewGuid().ToString().ToLower()
        Write-Info "Novo UUID: $newUuid"

        # Ordem importa: escreve o arquivo emac PRIMEIRO. Se falhar (disk full,
        # ACL bug, path invalido), o profile fica intacto com UUID antigo e
        # o cliente EMAC nao ve dessincronia. So atualiza o profile depois
        # do arquivo assentar.
        Write-EmacFile -Path $emacPath -Uuid $newUuid
        Write-OK "Arquivo reescrito: $emacPath"

        # Atualiza profile in-place (escrita atomica: tmp + Move-Item para
        # nao expor JSON truncado a leitores concorrentes).
        $profileObj.emac.persistent_uuid = $newUuid
        $jsonOut = $profileObj | ConvertTo-Json -Depth 10
        $tmpPath = "$profilePath.tmp"
        Set-Content -Path $tmpPath -Value $jsonOut -Encoding UTF8 -Force
        Move-Item -Path $tmpPath -Destination $profilePath -Force
        Write-OK "profile.json atualizado (emac.persistent_uuid = $newUuid)"

        if ($lockFile) {
            Lock-EmacFileAcl -Path $emacPath
            Write-OK "ACL restritiva reaplicada (user=read-only, admin=full, system=full)"
        } else {
            Write-Info "lock_file=false no profile, ACL padrao mantida."
        }

        Show-EmacState -Path $emacPath -ExpectedUuid $newUuid
        break
    }

    default {
        # Apply
        Write-Section "Apply (escreve persistent_uuid do profile)"
        Write-EmacFile -Path $emacPath -Uuid $profileUuid
        Write-OK "Arquivo gravado: $emacPath"

        if ($lockFile) {
            Lock-EmacFileAcl -Path $emacPath
            Write-OK "ACL restritiva aplicada (user=read-only, admin=full, system=full)"
        } else {
            Write-Info "lock_file=false no profile, ACL padrao (arquivo escrivel pelo user)."
        }

        Show-EmacState -Path $emacPath -ExpectedUuid $profileUuid
    }
}

Write-Host ""
Write-Host "=== Fim ===" -ForegroundColor Cyan
Write-Host ""
