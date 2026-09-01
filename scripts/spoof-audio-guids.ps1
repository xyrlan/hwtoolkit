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

# ============================================================
#  MMDevices ACL escalation
#
#  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\
#  Render|Capture roots: owner = NT AUTHORITY\SYSTEM, ACL grants
#  TrustedInstaller FullControl but Administrators only SetValue +
#  ReadKey. reg.exe import/delete fails because Admin lacks
#  CreateSubKey + Delete. Take ownership + grant Admin FullControl
#  (with ContainerInherit so subkey endpoints inherit) BEFORE the
#  endpoint iteration loop.
#
#  Pattern mirrors _smbios-common.ps1 (Take-SmbiosDataOwnership /
#  Grant-SmbiosDataWrite). SeTakeOwnershipPrivilege and
#  SeRestorePrivilege are enabled explicitly via P/Invoke because
#  they are present-but-disabled on the elevated admin token.
#
#  NOTE: ownership is NOT restored to TrustedInstaller afterwards.
#  Leaving the roots Admin-writable is acceptable on a daily-driver
#  host; restoring the original SD is complex and out of scope here.
# ============================================================

if (-not ([System.Management.Automation.PSTypeName]'HwToolkit.Priv').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace HwToolkit {
    public static class Priv {
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID { public uint LowPart; public int HighPart; }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState, uint bufLen, IntPtr prev, IntPtr retLen);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);
        public static void Enable(string name) {
            IntPtr token = IntPtr.Zero;
            // TOKEN_ADJUST_PRIVILEGES (0x20) | TOKEN_QUERY (0x8)
            if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try {
                LUID luid;
                if (!LookupPrivilegeValue(null, name, out luid))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                TOKEN_PRIVILEGES tp;
                tp.PrivilegeCount = 1;
                tp.Privileges.Luid = luid;
                tp.Privileges.Attributes = 2; // SE_PRIVILEGE_ENABLED
                if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                int err = Marshal.GetLastWin32Error();
                if (err != 0) // ERROR_NOT_ALL_ASSIGNED
                    throw new System.ComponentModel.Win32Exception(err);
            } finally {
                CloseHandle(token);
            }
        }
    }
}
"@
}

function Enable-OwnershipPrivileges {
    foreach ($p in @("SeTakeOwnershipPrivilege","SeRestorePrivilege")) {
        try {
            [HwToolkit.Priv]::Enable($p)
        } catch {
            Write-Warn ("Nao consegui habilitar " + $p + ": " + $_.Exception.Message)
        }
    }
}

function Take-MMDevicesOwnership {
    param([string]$SubKey)  # e.g. SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render
    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $SubKey,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::TakeOwnership
    )
    if ($null -eq $regKey) { throw ("OpenSubKey(TakeOwnership) retornou null para " + $SubKey) }
    try {
        $acl = $regKey.GetAccessControl()
        # Usar SID direto (S-1-5-32-544 = BUILTIN\Administrators, universal cross-locale)
        # em vez de NTAccount por nome, que falha em Windows pt-BR ("Administradores").
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null
        )
        $acl.SetOwner($adminSid)
        $regKey.SetAccessControl($acl)
    } finally {
        $regKey.Close()
    }
}

function Grant-MMDevicesWrite {
    param([string]$SubKey)
    Take-MMDevicesOwnership -SubKey $SubKey
    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $SubKey,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions
    )
    if ($null -eq $regKey) { throw ("OpenSubKey(ChangePermissions) retornou null para " + $SubKey) }
    try {
        $acl = $regKey.GetAccessControl()
        # ContainerInherit para que endpoints (subkeys) herdem o FullControl -
        # reg.exe delete precisa disso na subkey do endpoint especifico.
        # SID direto (S-1-5-32-544) cross-locale-safe.
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null
        )
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $adminSid,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.SetAccessRule($rule)
        $regKey.SetAccessControl($acl)
    } finally {
        $regKey.Close()
    }
}

function Ensure-MMDevicesWritable {
    # Escala privilegio + ownership + ACL dos dois roots antes de qualquer
    # reg.exe import/delete. Idempotente - re-executar nao quebra nada.
    Enable-OwnershipPrivileges
    foreach ($role in @("Render","Capture")) {
        $sub = "SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\" + $role
        try {
            Grant-MMDevicesWrite -SubKey $sub
            Write-OK ("Ownership+ACL escalados: MMDevices\Audio\" + $role)
        } catch {
            Write-Warn ("Falha escalando ACL de MMDevices\Audio\" + $role + ": " + $_.Exception.Message)
        }
    }
    Write-Warn "Ownership do MMDevices nao sera restaurado a TrustedInstaller (Admin-writable persiste)"
}

# ============================================================
#  Audio-stack pause/resume (handle-contention fix - Approach A)
#
#  Mesmo com ACL escalada, AudioSrv/AudioEndpointBuilder podem
#  manter HANDLES abertos nas subkeys HKLM\...\MMDevices\Audio\
#  Render|Capture\{GUID}. reg.exe delete falha com sharing
#  violation. Solucao: parar AudioEndpointBuilder ANTES do
#  rename loop (o -Force cascateia para AudioSrv que depende
#  dele) e reiniciar em finally, garantindo restauracao mesmo
#  em erro / exit no meio do script.
#
#  Trade-off conhecido: 3-8 segundos sem audio. AudioSrv
#  reconstroi MMDevices ao voltar - se detectar mismatch entre
#  endpoint GUID modificado e hardware, PODE regenerar GUIDs
#  originais (regressao silenciosa). Precisa validacao empirica
#  pos-restart via check-consistency.ps1.
# ============================================================

function Stop-AudioStack {
    # Retorna lista dos servicos que ESTE script parou (para nao mexer
    # em servicos que ja estavam Stopped pelo usuario/dependencies).
    $stopped = @()
    try {
        $svc = Get-Service -Name AudioEndpointBuilder -ErrorAction Stop
        if ($svc.Status -eq 'Running') {
            # -Force cascateia dependents (AudioSrv). Nao usar 2>&1 aqui:
            # Stop-Service e cmdlet PS, nao nativo, entao NativeCommandError
            # nao aplica.
            Stop-Service -Name AudioEndpointBuilder -Force -ErrorAction Stop
            # Confirmar que parou de fato antes de prosseguir. Windows as vezes
            # retorna do Stop-Service enquanto o servico ainda esta em StopPending.
            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
            $stopped += 'AudioEndpointBuilder'
            Write-OK "AudioEndpointBuilder parado (AudioSrv em cascata)"
        } else {
            Write-Info ("AudioEndpointBuilder ja em " + $svc.Status + " - sem acao")
        }
    } catch {
        Write-Warn ("Nao consegui parar AudioEndpointBuilder: " + $_.Exception.Message)
        Write-Warn "Prosseguindo mesmo assim - reg.exe delete pode falhar com sharing violation"
    }
    return ,$stopped   # comma prefix forca retorno como array (mesmo para 0/1 elemento)
}

function Start-AudioStack {
    param([string[]]$Services)
    # Sobe AudioEndpointBuilder; Windows sobe AudioSrv automaticamente via
    # dependencia declarada. Se $Services vazio, ainda checa e sobe se
    # encontrar Stopped - defensivo caso Stop tenha cascateado sem gravar
    # em $Services.
    foreach ($s in @('AudioEndpointBuilder','AudioSrv')) {
        try {
            $svc = Get-Service -Name $s -ErrorAction Stop
            if ($svc.Status -ne 'Running') {
                Start-Service -Name $s -ErrorAction Stop
                # Espera transicao Running (evita return prematuro pre-endpoints-visiveis)
                $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
                Write-OK ($s + " iniciado")
            } else {
                Write-Info ($s + " ja em Running - sem acao")
            }
        } catch {
            Write-Warn ("Nao consegui iniciar " + $s + ": " + $_.Exception.Message)
        }
    }
}

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

# Varredura de valores REG_BINARY 16 bytes numa chave especifica (nao recursiva).
# Usado tanto na raiz Render/Capture quanto nos filhos Role0/Role1/Role2.
function Scan-DefaultEndpointsInKey {
    param(
        [string]$RegPath,    # PS path exato da chave a inspecionar
        [hashtable]$Map      # old-guid-string(lower) -> new-guid-string(lower)
    )
    if (-not (Test-Path $RegPath)) { return }
    $props = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
    if ($null -eq $props) { return }

    # PSCustomObject: iterar propriedades procurando por REG_BINARY de 16 bytes
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
        $val = $p.Value
        if ($val -is [byte[]] -and $val.Length -eq 16) {
            $asGuid = Bytes-To-Guid -B $val
            if ($null -ne $asGuid -and $Map.ContainsKey($asGuid)) {
                $newG     = $Map[$asGuid]
                $newBytes = Guid-To-Bytes -G $newG
                Set-ItemProperty -Path $RegPath -Name $p.Name -Value $newBytes -Type Binary
                Write-Info ("DefaultEndpoint '{0}' em '{1}' {2} -> {3}" -f $p.Name, $RegPath, $asGuid, $newG)
            }
        }
    }
}

# Rewrite DefaultEndpoint / DefaultCaptureVoiceDevice / etc: valores REG_BINARY 16 bytes.
# Em Windows 10/11 tipicos, os valores DefaultEndpoint / DefaultCaptureVoiceDevice /
# DefaultCaptureCommunicationsDevice vivem em Render\Role0 / Capture\Role0 (um nivel
# abaixo do RolePath). Varremos raiz E filhos diretos (Role0/Role1/Role2) para cobrir
# ambos os layouts observados. Nao descemos mais fundo: WASAPI nao usa netos.
function Update-DefaultEndpoint {
    param(
        [string]$RolePath,   # PS path (Render ou Capture)
        [hashtable]$Map      # old-guid-string(lower) -> new-guid-string(lower)
    )
    if (-not (Test-Path $RolePath)) { return }

    # 1) Varredura na raiz (comportamento pre-existente; alguns builds mantem valores aqui).
    Scan-DefaultEndpointsInKey -RegPath $RolePath -Map $Map

    # 2) Varredura em subchaves diretas (Role0, Role1, Role2, ...) onde tipicamente
    #    ficam os REG_BINARY DefaultEndpoint/DefaultCaptureVoiceDevice/etc.
    $children = @()
    try {
        $children = Get-ChildItem -Path $RolePath -ErrorAction Stop
    } catch {
        return
    }
    foreach ($child in $children) {
        Scan-DefaultEndpointsInKey -RegPath $child.PSPath -Map $Map
    }
}

# Executa reg.exe capturando output e checando exit code
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

    # reg query /s lista tudo. GOTCHA pt-BR (v4.0.x): sob $ErrorActionPreference='Stop'
    # do escopo pai, `& reg.exe ... 2>&1` converte a mensagem localizada de sucesso
    # em stderr ("A operacao foi concluida com exito") em NativeCommandError e THROW,
    # engolindo pelo try/catch e mascarando sucesso como falha. USAR Invoke-Reg
    # (definido acima) que isola o EAP='Continue' em scope local. Para o query
    # inicial (aceita zero resultados) reproduzimos o mesmo padrao inline.
    $queryOut = & {
        $ErrorActionPreference = 'Continue'
        & reg.exe query $audioRootReg /s /f "{" /k 2>&1
    }
    if ($LASTEXITCODE -ne 0) { return }
    # $queryOut pode conter tanto linhas de path quanto ErrorRecords stringificados
    # do stderr (mensagem localizada). Filtramos so as linhas que comecam com
    # HKEY_LOCAL_MACHINE\ - as demais sao ruido do stderr localizado.
    $lines = @($queryOut | ForEach-Object { [string]$_ } | Where-Object { $_ -like 'HKEY_LOCAL_MACHINE\*' })

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
                # Via Invoke-Reg (que blinda contra NativeCommandError pt-BR).
                # Se qualquer etapa falhar, a excecao propaga para o catch abaixo
                # com mensagem util contendo exit code + output real.
                [void](Invoke-Reg -RegArgs @("export", $regPath, $tmpFile, "/y"))
                $content = Get-Content -Path $tmpFile -Raw -Encoding Unicode
                $newContent = [regex]::Replace($content, $escaped, $new, 'IgnoreCase')
                Set-Content -Path $tmpFile -Value $newContent -Encoding Unicode -NoNewline
                [void](Invoke-Reg -RegArgs @("import", $tmpFile))
                [void](Invoke-Reg -RegArgs @("delete", $regPath, "/f"))
                Write-Info ("Ref reescrita: " + $regPath)
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

    # Cheque cedo: sem mapping, nao vale pagar downtime de audio pra
    # descobrir isso. exit direto (sem entrar no try/finally).
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

    Write-Section "Pausando AudioEndpointBuilder (release de handles nas subkeys)"
    $audioStoppedByUs = Stop-AudioStack

    # try/finally: Start-AudioStack DEVE rodar mesmo em erro ou exit no meio,
    # senao o usuario fica sem audio ate reboot. PS 5.1 fires finally em
    # `exit` de dentro de try (verificado empiricamente).
    try {
        Ensure-MMDevicesWritable

        $totalRestored = 0
        $failedRestore = 0   # hard failures (throws) - endpoints marcados 'ausente' NAO contam
        $reverseMap = @{}    # new -> old (para atualizar DefaultEndpoint)

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
                    # Soft skip - endpoint ja foi embora (PnP re-enumerou, ou nunca chegou
                    # a ser spoofado). NAO conta como falha - nao ha o que restaurar.
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
                    $failedRestore++
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

        # Deleta mapping SO se zero falhas duras. Uma unica sharing violation
        # (ex.: AudioSrv regenerando GUID ao voltar - risco documentado) sem
        # essa guarda perderia o mapeamento new->old para SEMPRE, deixando o
        # endpoint permanentemente spoofado sem caminho de reversao.
        if ($failedRestore -gt 0) {
            Write-Warn ("Mapping preservado em " + $mappingPath)
            Write-Warn ($failedRestore + " falha(s) - investigue e re-execute -Restore")
        } else {
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
        }

        Write-Host ""
        Write-Host ("Total restaurado: " + $totalRestored + " / falhas: " + $failedRestore) -ForegroundColor Cyan
    } finally {
        Write-Section "Retomando AudioEndpointBuilder"
        Start-AudioStack -Services $audioStoppedByUs
    }
    exit 0
}

# ============================================================
#  Rotate mode
# ============================================================
Write-Section "Spoof de audio GUIDs (MMDevices)"

Write-Section "Pausando AudioEndpointBuilder (release de handles nas subkeys)"
$audioStoppedByUs = Stop-AudioStack

# try/finally: Start-AudioStack DEVE rodar mesmo em erro ou `exit N` no meio,
# senao o usuario fica sem audio ate reboot. Bloco DESINDENTADO deliberadamente
# para manter o diff minimo; o try engloba tudo ate o `} finally { ... }`
# proximo ao final do arquivo. Verificado: PS 5.1 fires finally em `exit N`
# dentro de try.
try {

Ensure-MMDevicesWritable

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
        # (Usa variavel loop dedicada - NAO reutilizar $role do foreach externo.)
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
#  Summary (ainda dentro do try - se `exit 1` disparar aqui, o finally
#  abaixo garante Start-AudioStack antes de terminar o script)
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

} finally {
    # Retoma AudioEndpointBuilder (e AudioSrv em cascata por dependencia
    # declarada). AudioEndpointBuilder reenumera MMDevices lendo o registry
    # ja rotacionado - se detectar mismatch com hardware fisico, pode
    # regenerar GUIDs originais silenciosamente (revalidar com
    # check-consistency.ps1 pos-run).
    Write-Section "Retomando AudioEndpointBuilder"
    Start-AudioStack -Services $audioStoppedByUs
}

Write-Host ""
Write-Info "Software de audio terceiro pode precisar reconfiguracao"
Write-Info ("Para reverter: .\spoof-audio-guids.ps1 -Restore")
exit 0
