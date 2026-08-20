#Requires -RunAsAdministrator
# ============================================================
#  SMBIOS Spoofer v2 — UUID + Strings (Types 1, 2, 3)
#
#  Le valores do profile centralizado e modifica:
#    - Type 1 (System):    UUID, Manufacturer, Product, Serial
#    - Type 2 (Baseboard): Manufacturer, Product, Serial
#    - Type 3 (Chassis):   Manufacturer, Serial, Asset Tag
#
#  Rebuild completo do blob para suportar strings de tamanho
#  diferente do original.
# ============================================================

param(
    [switch]$InstallTask,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"
$keyPath     = "SYSTEM\CurrentControlSet\Services\mssmbios\Data"
$taskName    = "SpoofSMBIOS"

# ---- Funcoes de output ----
function Write-OK($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Info($msg)  { Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Warn($msg)  { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "  [X] $msg" -ForegroundColor Red }

# ============================================================
#  Uninstall mode
# ============================================================
if ($Uninstall) {
    Write-Host "`n=== Removendo SMBIOS Spoof ===" -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    # Tenta o nome antigo tambem
    Unregister-ScheduledTask -TaskName "SpoofUUID" -Confirm:$false -ErrorAction SilentlyContinue
    Write-OK "Tarefa agendada removida"

    # Limpar blob cacheado do driver (replay em kernel)
    $driverParams = "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters"
    if (Test-Path $driverParams) {
        try {
            Remove-ItemProperty -Path $driverParams -Name "SmbiosBlob" -ErrorAction SilentlyContinue
            Write-OK "SmbiosBlob removido do driver (sem mais replay em kernel)"
        } catch {}
    }
    Write-Host "  Reinicie o PC para restaurar os valores originais.`n"
    exit 0
}

# ============================================================
#  Banner
# ============================================================
Write-Host ""
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host "    SMBIOS Spoofer v2 (Profile-Based)" -ForegroundColor Cyan
Write-Host "    Types 1 + 2 + 3 — Manufacturer Consistente" -ForegroundColor Cyan
Write-Host "  ============================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
#  Step 1: Carregar profile
# ============================================================
Write-Info "Carregando profile de $profilePath..."

if (-not (Test-Path $profilePath)) {
    Write-Err "Profile nao encontrado!"
    Write-Err "Rode primeiro:  .\hwprofile.ps1 -Generate"
    exit 1
}

$profile = Get-Content $profilePath -Raw | ConvertFrom-Json
$smb = $profile.smbios

Write-OK "Profile carregado (v$($profile.version))"
Write-Info "Target: $($smb.board_manufacturer) / $($smb.board_product)"

# ============================================================
#  SMBIOS Parsing Functions
# ============================================================

function Parse-SmbiosStructures {
    param([byte[]]$Blob, [int]$StartOffset)

    $structures = [System.Collections.ArrayList]::new()
    $offset = $StartOffset

    while ($offset -lt $Blob.Length - 2) {
        $type = $Blob[$offset]
        $len  = $Blob[$offset + 1]
        if ($len -lt 4) { break }

        # Extrair area formatada
        $formatted = New-Object byte[] $len
        [Array]::Copy($Blob, $offset, $formatted, 0, [Math]::Min($len, $Blob.Length - $offset))

        # Ler string table
        $strOffset = $offset + $len
        $strings   = [System.Collections.ArrayList]::new()
        $nextOffset = $strOffset

        if ($strOffset -ge $Blob.Length) { break }

        if ($Blob[$strOffset] -eq 0) {
            # String table vazia — pular double null
            $nextOffset = $strOffset + 1
            if ($nextOffset -lt $Blob.Length -and $Blob[$nextOffset] -eq 0) {
                $nextOffset++
            }
        } else {
            $pos = $strOffset
            while ($pos -lt $Blob.Length) {
                $strEnd = $pos
                while ($strEnd -lt $Blob.Length -and $Blob[$strEnd] -ne 0) {
                    $strEnd++
                }
                if ($strEnd -eq $pos) {
                    # Null vazio = fim da string table
                    $nextOffset = $pos + 1
                    break
                }
                $str = [System.Text.Encoding]::ASCII.GetString($Blob, $pos, $strEnd - $pos)
                [void]$strings.Add($str)
                $pos = $strEnd + 1
            }
            if ($pos -ge $Blob.Length) {
                $nextOffset = $Blob.Length
            }
        }

        [void]$structures.Add([PSCustomObject]@{
            Type      = $type
            Length    = $len
            Formatted = $formatted
            Strings   = $strings
        })

        $offset = $nextOffset
    }

    return ,$structures
}

function Build-SmbiosBlob {
    param([byte[]]$Header, $Structures)

    $result = [System.Collections.Generic.List[byte]]::new()
    $result.AddRange([byte[]]$Header)

    foreach ($s in $Structures) {
        $result.AddRange([byte[]]$s.Formatted)

        if ($s.Strings.Count -eq 0) {
            $result.Add(0)
            $result.Add(0)
        } else {
            foreach ($str in $s.Strings) {
                if ([string]::IsNullOrEmpty($str)) { $str = " " }
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($str)
                $result.AddRange($bytes)
                $result.Add(0)
            }
            $result.Add(0)
        }
    }

    return ,$result.ToArray()
}

function Set-StructureString {
    param($Structure, [int]$StringIndex, [string]$NewValue)

    if ($StringIndex -le 0) { return }
    $idx = $StringIndex - 1

    while ($Structure.Strings.Count -le $idx) {
        [void]$Structure.Strings.Add("Default string")
    }
    $Structure.Strings[$idx] = $NewValue
}

function ConvertTo-SmbiosUuidBytes {
    param([string]$UuidString)

    # Parse GUID "AABBCCDD-EEFF-GGHH-IIJJ-KKLLMMNNOOPP"
    $guid = [System.Guid]::Parse($UuidString)
    $bytes = $guid.ToByteArray()
    # .NET Guid.ToByteArray() already uses mixed-endian:
    #   bytes 0-3: little-endian dword (first group)
    #   bytes 4-5: little-endian word (second group)
    #   bytes 6-7: little-endian word (third group)
    #   bytes 8-15: big-endian (last two groups)
    # This matches SMBIOS format exactly
    return $bytes
}

# ============================================================
#  Step 2: Take ownership da chave do registro
# ============================================================
Write-Info "Tomando ownership da chave mssmbios\Data..."

try {
    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $keyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::TakeOwnership
    )
    $acl = $regKey.GetAccessControl()
    $admin = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"
    $acl.SetOwner($admin)
    $regKey.SetAccessControl($acl)
    $regKey.Close()
    Write-OK "Ownership obtido"
} catch {
    Write-Err "Falha ao tomar ownership: $_"
    exit 1
}

# ============================================================
#  Step 3: Permissao de escrita
# ============================================================
Write-Info "Concedendo permissao de escrita..."

try {
    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $keyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions
    )
    $acl = $regKey.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $admin, "FullControl", "Allow"
    )
    $acl.SetAccessRule($rule)
    $regKey.SetAccessControl($acl)
    $regKey.Close()
    Write-OK "Permissao concedida"
} catch {
    Write-Err "Falha ao conceder permissao: $_"
    exit 1
}

# ============================================================
#  Step 4: Ler SMBiosData
# ============================================================
Write-Info "Lendo SMBiosData..."

$data = (Get-ItemProperty -Path "HKLM:\$keyPath" -Name "SMBiosData").SMBiosData
Write-OK "Blob lido: $($data.Length) bytes"

# ============================================================
#  Step 5: Parsear blob SMBIOS
# ============================================================
Write-Info "Parseando estruturas SMBIOS..."

$header = New-Object byte[] 8
[Array]::Copy($data, 0, $header, 0, 8)

$structures = Parse-SmbiosStructures -Blob $data -StartOffset 8
Write-OK "Encontradas $($structures.Count) estruturas"

$modifiedTypes = @()

# ============================================================
#  Step 6: Modificar Type 1 (System Information)
# ============================================================
$type1 = $structures | Where-Object { $_.Type -eq 1 } | Select-Object -First 1

if ($type1) {
    Write-Info "Modificando Type 1 (System Information)..."

    # Strings: [4]=Mfr, [5]=Product, [6]=Version, [7]=Serial
    Set-StructureString $type1 $type1.Formatted[4] $smb.system_manufacturer
    Set-StructureString $type1 $type1.Formatted[5] $smb.system_product
    Set-StructureString $type1 $type1.Formatted[6] $smb.system_version
    Set-StructureString $type1 $type1.Formatted[7] $smb.system_serial

    # UUID nos bytes 8-23 do formatted area
    $uuidBytes = ConvertTo-SmbiosUuidBytes -UuidString $smb.uuid
    for ($i = 0; $i -lt 16; $i++) {
        $type1.Formatted[8 + $i] = $uuidBytes[$i]
    }

    # SKU (offset 25 -> requer Length >= 26) e Family (offset 26 -> Length >= 27)
    if ($type1.Length -ge 26 -and $smb.system_sku) {
        Set-StructureString $type1 $type1.Formatted[25] $smb.system_sku
    }
    if ($type1.Length -ge 27 -and $smb.system_family) {
        Set-StructureString $type1 $type1.Formatted[26] $smb.system_family
    }

    $modifiedTypes += "Type 1 (System)"

    Write-Info "  Novo UUID: $($smb.uuid)"
    Write-Info "  Manufacturer: $($smb.system_manufacturer)"
    Write-Info "  Product: $($smb.system_product)"
    Write-OK "Type 1 modificado"
} else {
    Write-Warn "Type 1 nao encontrado no blob!"
}

# ============================================================
#  Step 7: Modificar Type 2 (Baseboard)
# ============================================================
$type2 = $structures | Where-Object { $_.Type -eq 2 } | Select-Object -First 1

if ($type2) {
    Write-Info "Modificando Type 2 (Baseboard)..."

    # Strings: [4]=Mfr, [5]=Product, [6]=Version, [7]=Serial, [8]=AssetTag
    Set-StructureString $type2 $type2.Formatted[4] $smb.board_manufacturer
    Set-StructureString $type2 $type2.Formatted[5] $smb.board_product
    Set-StructureString $type2 $type2.Formatted[6] $smb.board_version
    Set-StructureString $type2 $type2.Formatted[7] $smb.board_serial
    if ($type2.Length -ge 9) {
        Set-StructureString $type2 $type2.Formatted[8] $smb.board_asset_tag
    }

    $modifiedTypes += "Type 2 (Baseboard)"

    Write-Info "  Manufacturer: $($smb.board_manufacturer)"
    Write-Info "  Product: $($smb.board_product)"
    Write-Info "  Serial: $($smb.board_serial)"
    Write-OK "Type 2 modificado"
} else {
    Write-Warn "Type 2 nao encontrado no blob!"
}

# ============================================================
#  Step 8: Modificar Type 3 (Chassis)
# ============================================================
$type3 = $structures | Where-Object { $_.Type -eq 3 } | Select-Object -First 1

if ($type3) {
    Write-Info "Modificando Type 3 (Chassis)..."

    # [4]=Mfr(str), [5]=ChassisType(byte!), [6]=Version(str), [7]=Serial(str), [8]=AssetTag(str)
    Set-StructureString $type3 $type3.Formatted[4] $smb.chassis_manufacturer

    # Chassis Type e um BYTE, nao string index!
    $type3.Formatted[5] = [byte]$smb.chassis_type

    Set-StructureString $type3 $type3.Formatted[6] $smb.chassis_version
    Set-StructureString $type3 $type3.Formatted[7] $smb.chassis_serial
    if ($type3.Length -ge 9) {
        Set-StructureString $type3 $type3.Formatted[8] $smb.chassis_asset_tag
    }

    $modifiedTypes += "Type 3 (Chassis)"

    Write-Info "  Manufacturer: $($smb.chassis_manufacturer)"
    Write-OK "Type 3 modificado"
} else {
    Write-Warn "Type 3 nao encontrado no blob!"
}

# ============================================================
#  Step 9: Reconstruir blob
# ============================================================
Write-Info "Reconstruindo blob SMBIOS..."

$newData = Build-SmbiosBlob -Header $header -Structures $structures
Write-OK "Novo blob: $($newData.Length) bytes (original: $($data.Length) bytes)"

# ============================================================
#  Step 10: Escrever no registro
# ============================================================
Write-Info "Escrevendo SMBiosData modificado..."

try {
    Set-ItemProperty -Path "HKLM:\$keyPath" -Name "SMBiosData" -Value $newData -Type Binary
    Write-OK "SMBiosData atualizado!"
} catch {
    Write-Err "Falha ao escrever: $_"
    exit 1
}

# ============================================================
#  Step 10b: Cachear blob para o driver replay em kernel
#
#  O driver RstFlt v3.3+ ao carregar em DriverEntry copia este blob
#  para mssmbios\Data\SMBiosData, garantindo que a identidade
#  spoofada esteja em pe antes de winmgmt/anti-cheat rodarem.
#  Substitui a antiga tarefa agendada boot-time (que sofria race).
# ============================================================
$driverParams = "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters"
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt") {
    try {
        if (-not (Test-Path $driverParams)) {
            New-Item -Path $driverParams -Force | Out-Null
        }
        Set-ItemProperty -Path $driverParams -Name "SmbiosBlob" -Value $newData -Type Binary
        Write-OK "Blob cacheado para replay em kernel ($($newData.Length) bytes)"
        Write-Info "O driver aplicara este blob a cada boot antes de winmgmt subir"
    } catch {
        Write-Warn "Falha ao cachear blob para o driver: $_"
        Write-Warn "Replay em kernel nao funcionara - use -InstallTask como fallback"
    }
} else {
    Write-Warn "Driver RstFlt nao instalado - sem replay em kernel"
    Write-Warn "Instale o driver (03-instalar-driver.bat) para persistencia sem race"
}

# ============================================================
#  Step 11: Reiniciar WMI
# ============================================================
Write-Info "Reiniciando WMI para aplicar..."
Restart-Service winmgmt -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# ============================================================
#  Step 12: Verificar
# ============================================================
Write-Host ""
Write-Host "  === VERIFICACAO ===" -ForegroundColor White

$uuid      = (Get-CimInstance Win32_ComputerSystemProduct).UUID
$boardMfr  = (Get-CimInstance Win32_BaseBoard).Manufacturer
$boardProd = (Get-CimInstance Win32_BaseBoard).Product
$boardSer  = (Get-CimInstance Win32_BaseBoard).SerialNumber
$chassisMfr = (Get-CimInstance Win32_SystemEnclosure).Manufacturer
$sysMfr    = (Get-CimInstance Win32_ComputerSystem).Manufacturer

Write-Info "UUID WMI:        $uuid"
Write-Info "System Mfr:      $sysMfr"
Write-Info "Board Mfr:       $boardMfr"
Write-Info "Board Product:   $boardProd"
Write-Info "Board Serial:    $boardSer"
Write-Info "Chassis Mfr:     $chassisMfr"

# Checagem de consistencia
$allMatch = ($boardMfr -eq $chassisMfr)
if ($allMatch) {
    Write-OK "Fabricantes CONSISTENTES entre Board e Chassis!"
} else {
    Write-Warn "Fabricantes inconsistentes - pode precisar de reboot"
}

if ($uuid -ne "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" -and $uuid.Length -gt 10) {
    Write-OK "UUID aplicado"
} else {
    Write-Warn "UUID pode precisar de reboot para refletir"
}

# ============================================================
#  Step 13: Tarefa agendada (opcional)
# ============================================================
if ($InstallTask) {
    Write-Host ""
    Write-Info "Criando tarefa agendada para persistir entre reboots..."

    # Remove tarefa antiga se existir
    Unregister-ScheduledTask -TaskName "SpoofUUID" -Confirm:$false -ErrorAction SilentlyContinue

    $scriptPath = $MyInvocation.MyCommand.Path
    $action   = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $trigger  = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-OK "Tarefa '$taskName' criada - roda a cada boot como SYSTEM"
}

# ============================================================
#  Resumo
# ============================================================
Write-Host ""
Write-Host "  ============================================" -ForegroundColor Green
Write-Host "    CONCLUIDO!" -ForegroundColor Green
Write-Host "  ============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Estruturas modificadas:" -ForegroundColor White
foreach ($t in $modifiedTypes) {
    Write-Host "    - $t" -ForegroundColor Green
}
Write-Host ""
Write-Host "  Para instalar a tarefa de boot:" -ForegroundColor White
Write-Host "    .\spoof-uuid.ps1 -InstallTask" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Para remover tudo:" -ForegroundColor White
Write-Host "    .\spoof-uuid.ps1 -Uninstall" -ForegroundColor Yellow
Write-Host ""
