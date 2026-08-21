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
    [switch]$Uninstall,
    # v3.4: por padrao setamos EnableSmbiosReplay=1 no driver DEPOIS de
    # verificar via WMI. -DisableKernelReplay pula esse passo (util para
    # depurar boot loop suspeito de vir do replay em kernel).
    [switch]$DisableKernelReplay
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

    # Limpar blob cacheado + flag opt-in do driver (replay em kernel)
    $driverParams = "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters"
    if (Test-Path $driverParams) {
        try {
            Remove-ItemProperty -Path $driverParams -Name "SmbiosBlob"          -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $driverParams -Name "EnableSmbiosReplay"  -ErrorAction SilentlyContinue
            Write-OK "SmbiosBlob + opt-in flag removidos (sem mais replay em kernel)"
        } catch {}

        # v3.4: restaurar SMBiosData original se o driver salvou backup
        try {
            $orig = Get-ItemProperty -Path $driverParams -Name "OrigSmbiosData" -ErrorAction Stop
            if ($orig.OrigSmbiosData -and $orig.OrigSmbiosData.Length -gt 32) {
                Set-ItemProperty -Path "HKLM:\$keyPath" -Name "SMBiosData" -Value $orig.OrigSmbiosData -Type Binary
                Write-OK "SMBiosData restaurado do backup ($($orig.OrigSmbiosData.Length) bytes)"
                Remove-ItemProperty -Path $driverParams -Name "OrigSmbiosData" -ErrorAction SilentlyContinue
            }
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

    # [4]=Mfr(str), [5]=ChassisType(byte!), [6]=Version(str), [7]=Serial(str),
    # [8]=AssetTag(str). Layout depois disso e variavel (bootup state, thermal
    # state, security state, oem defined 4 bytes, height, num power cords,
    # contained element count, contained elems...). SKUNumber e o ultimo
    # string index e a distancia depende de contained_element_count *
    # contained_element_record_length. Formula: offset 0x11 + n*m onde
    # n=Formatted[0x13] e m=Formatted[0x14].
    Set-StructureString $type3 $type3.Formatted[4] $smb.chassis_manufacturer

    # Chassis Type e um BYTE, nao string index!
    $type3.Formatted[5] = [byte]$smb.chassis_type

    Set-StructureString $type3 $type3.Formatted[6] $smb.chassis_version
    Set-StructureString $type3 $type3.Formatted[7] $smb.chassis_serial
    if ($type3.Length -ge 9) {
        Set-StructureString $type3 $type3.Formatted[8] $smb.chassis_asset_tag
    }

    # SKUNumber (Type 3, spec 2.7+): offset 0x11 + contained*len.
    # So mexer se o SMBIOS local expor esse campo (Length grande o bastante).
    if ($smb.PSObject.Properties.Name -contains "chassis_sku" -and $smb.chassis_sku) {
        $containedN   = if ($type3.Length -ge 0x14) { [int]$type3.Formatted[0x13] } else { 0 }
        $containedLen = if ($type3.Length -ge 0x15) { [int]$type3.Formatted[0x14] } else { 0 }
        $skuOff       = 0x11 + ($containedN * $containedLen)
        if ($type3.Length -gt $skuOff) {
            Set-StructureString $type3 $type3.Formatted[$skuOff] $smb.chassis_sku
            Write-Info "  Chassis SKU: $($smb.chassis_sku) @ off=0x$($skuOff.ToString('X2'))"
        }
    }

    $modifiedTypes += "Type 3 (Chassis)"

    Write-Info "  Manufacturer: $($smb.chassis_manufacturer)"
    Write-OK "Type 3 modificado"
} else {
    Write-Warn "Type 3 nao encontrado no blob!"
}

# ============================================================
#  Step 8b: Modificar Type 4 (Processor Information) — STRINGS ONLY
#
#  Layout Type 4 (SMBIOS 2.0+): [4]=SocketDesignation(str), [5]=ProcType(byte),
#  [6]=ProcFamily(byte), [7]=ProcManufacturer(str), [8..15]=ProcessorID(qword),
#  [16]=ProcVersion(str), ... [32]=SerialNumber(str), [33]=AssetTag(str),
#  [34]=PartNumber(str). Nao mexer em bytes 5-15 — sao familia/ID que vem do
#  silicio (CPUID) e trocar aqui cria inconsistencia entre SMBIOS Type 4 e
#  Win32_Processor.ProcessorId, que anti-cheats cruzam.
# ============================================================
$type4 = $structures | Where-Object { $_.Type -eq 4 } | Select-Object -First 1

if ($type4) {
    Write-Info "Modificando Type 4 (Processor) — apenas string fields..."

    if ($type4.Length -ge 33 -and $smb.PSObject.Properties.Name -contains "processor_serial" -and $smb.processor_serial) {
        Set-StructureString $type4 $type4.Formatted[32] $smb.processor_serial
    }
    if ($type4.Length -ge 34 -and $smb.PSObject.Properties.Name -contains "processor_asset_tag" -and $smb.processor_asset_tag) {
        Set-StructureString $type4 $type4.Formatted[33] $smb.processor_asset_tag
    }
    if ($type4.Length -ge 35 -and $smb.PSObject.Properties.Name -contains "processor_part_num" -and $smb.processor_part_num) {
        Set-StructureString $type4 $type4.Formatted[34] $smb.processor_part_num
    }

    $modifiedTypes += "Type 4 (Processor strings)"
    Write-OK "Type 4 modificado (CPUID/family intactos)"
} else {
    Write-Warn "Type 4 nao encontrado no blob!"
}

# ============================================================
#  Step 8c: Modificar Type 11 (OEM Strings)
#
#  Layout Type 11: [4]=Count(byte). Depois disso, strings enumeradas 1..Count
#  na string table. Anti-cheats leem via Win32_OEMStringArray. Se o profile
#  diz MSI mas a maquina real e Dell, essa area vaza service tag Dell.
#  Sobrescrevemos com strings genericas.
# ============================================================
$type11 = $structures | Where-Object { $_.Type -eq 11 } | Select-Object -First 1

if ($type11 -and $smb.PSObject.Properties.Name -contains "oem_strings" -and $smb.oem_strings) {
    Write-Info "Modificando Type 11 (OEM Strings)..."

    $count = [int]$type11.Formatted[4]
    if ($count -gt 0) {
        for ($i = 0; $i -lt $count; $i++) {
            $newVal = if ($i -lt $smb.oem_strings.Count) { $smb.oem_strings[$i] } else { "Default string" }
            # Type 11 nao carrega indices — strings sao lidas em ordem 1..Count.
            # A ordem de $type11.Strings ja mapeia 1..N na tabela de string.
            while ($type11.Strings.Count -le $i) {
                [void]$type11.Strings.Add("Default string")
            }
            $type11.Strings[$i] = $newVal
        }
        $modifiedTypes += "Type 11 (OEM Strings, $count)"
        Write-Info "  OEM Strings sobrescritas ($count)"
        Write-OK "Type 11 modificado"
    } else {
        Write-Info "  Count=0 — nada a modificar"
    }
} elseif (-not $type11) {
    Write-Info "Type 11 ausente do blob — nada a fazer (nao e vazamento em si)"
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
#  Fluxo v3.4:
#   - Cache do blob e feito AGORA (para o driver ter em maos).
#   - Opt-in flag (EnableSmbiosReplay=1) e setado APENAS DEPOIS
#     da verificacao WMI abaixo (Step 12) confirmar que o blob
#     nao quebrou consultas basicas. Isso evita repetir o BSOD
#     onde um blob quebrado ficava cacheado e era reaplicado a
#     cada boot pelo driver, brickando o Windows.
#   - -DisableKernelReplay pula tudo isso.
# ============================================================
$driverParams   = "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters"
$driverInstalled = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt"
$cachedBlob     = $false

if ($DisableKernelReplay) {
    Write-Warn "-DisableKernelReplay: replay em kernel NAO sera armado"
    if ($driverInstalled -and (Test-Path $driverParams)) {
        Remove-ItemProperty -Path $driverParams -Name "SmbiosBlob"         -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $driverParams -Name "EnableSmbiosReplay" -ErrorAction SilentlyContinue
    }
} elseif ($driverInstalled) {
    try {
        if (-not (Test-Path $driverParams)) {
            New-Item -Path $driverParams -Force | Out-Null
        }
        # v3.4: DESLIGA opt-in flag ANTES de cachear o novo blob.
        # Se algo falhar entre aqui e a verificacao WMI, o driver
        # NAO vai aplicar o blob no proximo boot (opt-in ausente).
        Set-ItemProperty -Path $driverParams -Name "EnableSmbiosReplay" -Value 0 -Type DWord
        Set-ItemProperty -Path $driverParams -Name "SmbiosBlob"         -Value $newData -Type Binary
        $cachedBlob = $true
        Write-OK "Blob cacheado ($($newData.Length) bytes) — opt-in ainda OFF"
        Write-Info "Opt-in sera ligado apos a verificacao WMI abaixo"
    } catch {
        Write-Warn "Falha ao cachear blob para o driver: $_"
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
#  Step 12b: Armar opt-in do replay em kernel (v3.4)
#
#  So chegamos aqui se todas as queries WMI acima retornaram sem
#  travar/lancar. Isso e o sinal mais forte que temos, ainda em
#  runtime, de que o blob que acabamos de gravar em mssmbios\Data
#  nao vai brickar o parser em boots subsequentes. Agora sim
#  ligamos o flag que autoriza o driver a re-aplicar no boot.
# ============================================================
if ($cachedBlob) {
    $wmiOk = ($null -ne $uuid -and $uuid.Length -gt 10 -and
              $null -ne $boardMfr -and $boardMfr.Length -gt 0 -and
              $null -ne $sysMfr   -and $sysMfr.Length   -gt 0)

    if ($wmiOk) {
        try {
            Set-ItemProperty -Path $driverParams -Name "EnableSmbiosReplay" -Value 1 -Type DWord
            Write-OK "Replay em kernel ARMADO (EnableSmbiosReplay=1)"
            Write-Info "Driver aplicara o blob a cada boot antes de winmgmt"
        } catch {
            Write-Warn "Falha ao armar opt-in: $_"
        }
    } else {
        Write-Warn "WMI nao respondeu limpo — replay em kernel NAO armado"
        Write-Warn "Blob fica cacheado mas o driver ignora sem EnableSmbiosReplay=1"
    }
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
