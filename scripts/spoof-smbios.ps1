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
    [switch]$DisableKernelReplay,
    # v4.0.6: switches mutuamente exclusivos para isolar Bug 4 (crash em
    # ~52-56s post-arm). Sem eles, um teste "so CPU" arma EnableCpuReplay
    # a mao SEM limpar EnableSmbiosReplay=1 do run anterior, contaminando
    # a evidencia. Com estes switches o operador consegue medir SMBIOS-only
    # ou CPU-only de verdade.
    #   -SmbiosOnly: limpa CpuStrings/EnableCpuReplay antes; pula Step 10c.
    #   -CpuOnly:    limpa SmbiosBlob/EnableSmbiosReplay/OrigSmbiosData
    #                antes; pula Steps 4-10b; arma EnableCpuReplay=1 no fim.
    [switch]$SmbiosOnly,
    [switch]$CpuOnly
)

if ($SmbiosOnly -and $CpuOnly) {
    Write-Host "[!] -SmbiosOnly e -CpuOnly sao mutuamente exclusivos." -ForegroundColor Red
    exit 1
}

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\_ui-common.ps1"
. "$PSScriptRoot\_smbios-common.ps1"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"
$keyPath     = "SYSTEM\CurrentControlSet\Services\mssmbios\Data"
$taskName    = "SpoofSMBIOS"

# ============================================================
#  Uninstall mode
# ============================================================
if ($Uninstall) {
    Write-Host "`n=== Removendo SMBIOS Spoof ===" -ForegroundColor Yellow

    # Garantir permissao de escrita em mssmbios\Data ANTES de tentar restaurar.
    # Sem isso, Set-ItemProperty abaixo pode falhar com Access Denied silenciosamente
    # (o try/catch downgrade para warning e o usuario pensa que restaurou).
    try {
        Grant-SmbiosDataWrite
        Write-OK "ACL de mssmbios\Data ajustada para restore"
    } catch {
        Write-Warn "Falha ao ajustar ACL de mssmbios\Data: $_"
        Write-Warn "Restore da SMBIOS abaixo pode falhar. Rode como Admin com ownership."
    }

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
        } catch { Write-Warn "Falha ao restaurar: $_" }

        # v3.7+: limpar cache de CpuStrings do driver
        try {
            Remove-ItemProperty -Path $driverParams -Name "CpuStrings" -ErrorAction SilentlyContinue
            Write-OK "CpuStrings removido do cache do driver"
        } catch { Write-Warn "Falha ao remover CpuStrings: $_" }

        # v3.4: restaurar SMBiosData original se o driver salvou backup
        try {
            $orig = Get-ItemProperty -Path $driverParams -Name "OrigSmbiosData" -ErrorAction Stop
            if ($orig.OrigSmbiosData -and $orig.OrigSmbiosData.Length -gt 32) {
                Set-ItemProperty -Path "HKLM:\$keyPath" -Name "SMBiosData" -Value $orig.OrigSmbiosData -Type Binary
                Write-OK "SMBiosData restaurado do backup ($($orig.OrigSmbiosData.Length) bytes)"
                Remove-ItemProperty -Path $driverParams -Name "OrigSmbiosData" -ErrorAction SilentlyContinue
            }
        } catch { Write-Warn "Falha ao restaurar: $_" }
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
    Write-Err "Rode primeiro:  .\generate-profile.ps1 -Generate"
    exit 1
}

$prof = Get-Content $profilePath -Raw | ConvertFrom-Json
$smb = $prof.smbios

Write-OK "Profile carregado (v$($prof.version))"
Write-Info "Target: $($smb.board_manufacturer) / $($smb.board_product)"

# ============================================================
#  v4.0.6 (Bug 4 postmortem):
#  Se o operador pediu -SmbiosOnly ou -CpuOnly, limpar a chave da
#  OUTRA replay para nao contaminar a evidencia. O bug 4 (crash em
#  52-56s post-arm) foi observado com "mesmo timing para SMBIOS e
#  CPU independentes", mas na verdade nenhum script nunca escreveu
#  EnableCpuReplay — operador ligava a mao SEM limpar EnableSmbios-
#  Replay=1 do run anterior, entao "CPU-only" era SMBIOS+CPU. Estes
#  switches dao isolamento REAL entre as duas replays.
# ============================================================
$driverParams   = "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters"
$driverInstalled = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt"

if ($SmbiosOnly -and $driverInstalled -and (Test-Path $driverParams)) {
    Write-Info "-SmbiosOnly: limpando CpuStrings + EnableCpuReplay do driver..."
    Remove-ItemProperty -Path $driverParams -Name "CpuStrings"      -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $driverParams -Name "EnableCpuReplay" -ErrorAction SilentlyContinue
    Write-OK "CPU replay path limpo (arma SMBIOS apenas)"
}

if ($CpuOnly) {
    Write-Info "-CpuOnly: pulando SMBIOS inteiro, limpando estado SMBIOS do driver..."
    if ($driverInstalled -and (Test-Path $driverParams)) {
        Remove-ItemProperty -Path $driverParams -Name "SmbiosBlob"         -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $driverParams -Name "EnableSmbiosReplay" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $driverParams -Name "OrigSmbiosData"     -ErrorAction SilentlyContinue
        Write-OK "SMBIOS replay path limpo"
    }
    if (-not $driverInstalled) {
        Write-Err "Driver RstFlt nao instalado — -CpuOnly precisa do driver."
        exit 1
    }
    if (-not ($prof.PSObject.Properties.Name -contains "cpu" -and $prof.cpu)) {
        Write-Err "Profile v< 9 (sem bloco cpu) — -CpuOnly requer profile v9+."
        exit 1
    }
    if (-not (Test-Path $driverParams)) { New-Item -Path $driverParams -Force | Out-Null }
    $cpuNameStr = [string]$prof.cpu.name_string
    $cpuIdent   = [string]$prof.cpu.identifier
    $cpuVendor  = [string]$prof.cpu.vendor_identifier
    Set-ItemProperty -Path $driverParams -Name "CpuStrings" `
        -Value @($cpuNameStr, $cpuIdent, $cpuVendor) -Type MultiString
    Set-ItemProperty -Path $driverParams -Name "EnableCpuReplay" -Value 1 -Type DWord
    Write-OK "CpuStrings + EnableCpuReplay=1 armados"
    Write-Info "  name_string:       $cpuNameStr"
    Write-Info "  identifier:        $cpuIdent"
    Write-Info "  vendor_identifier: $cpuVendor"
    Write-Host ""
    Write-Host "  === Estado final Parameters ===" -ForegroundColor White
    Get-ItemProperty -Path $driverParams -ErrorAction SilentlyContinue |
        Select-Object EnableSmbiosReplay, EnableCpuReplay, `
                      @{n='SmbiosBlob';    e={if ($_.SmbiosBlob){"$($_.SmbiosBlob.Length) bytes"} else {'(absent)'}}}, `
                      @{n='CpuStrings';    e={if ($_.CpuStrings){"$($_.CpuStrings.Count) strings"} else {'(absent)'}}}, `
                      @{n='OrigSmbiosData';e={if ($_.OrigSmbiosData){"$($_.OrigSmbiosData.Length) bytes"} else {'(absent)'}}} |
        Format-List
    Write-Host ""
    Write-Host "  Reboot para o driver aplicar CpuStrings no proximo boot." -ForegroundColor Green
    exit 0
}

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
        # Nota: $len vem do byte array so vale 0-255. $Blob.Length - $offset
        # e int e pode passar de 255 em blobs SMBIOS reais (>= 256 bytes,
        # ou seja, praticamente qualquer BIOS moderno). Sem o cast [int],
        # [Math]::Min resolve pro overload (byte, byte) e faz overflow
        # tentando converter 1028 (ou o que for) pra byte. Descoberto
        # rodando este spoofer pela primeira vez no VM (blob 1036 bytes,
        # StartOffset 8 -> Length-offset = 1028 > 255). Bugado desde v3.x
        # mas ninguem viu porque Phase 7 nunca completou em campo ate v4.0.4.
        $formatted = New-Object byte[] $len
        [Array]::Copy($Blob, $offset, $formatted, 0, [Math]::Min([int]$len, $Blob.Length - $offset))

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

    # v4.0.10 hardening: recomputar o DWORD LE de raw-table-size no
    # wrapper mssmbios (bytes 4-7). O firmware original devolve o
    # wrapper com esse campo apontando pro tamanho do raw SMBIOS que
    # vem logo depois; se a gente reemite strings de tamanho diferente,
    # o total muda e o campo antigo passa a mentir. Isso NAO era a
    # causa raiz do 0x03 VALIDATION-FAIL (o validador do driver nunca
    # le esse campo — usa DataLength do REG_BINARY), mas o mssmbios
    # ler o wrapper stale pode causar over-read/under-read do raw
    # table na hora do consumo. Ver docs/postmortem-v4-phase5/
    # incident-v410-smbios-validator-scan-window.md secao "Latent bugs".
    #
    # Assume wrapper de 8 bytes (Used21CallingMethod, Major, Minor,
    # DmiRev, RawSize DWORD LE). Se o Header passado tem tamanho
    # diferente de 8, pula esse fix — layout desconhecido.
    if ($Header.Length -eq 8 -and $result.Count -ge 8) {
        $rawLen = $result.Count - 8
        $result[4] = [byte]($rawLen -band 0xFF)
        $result[5] = [byte](($rawLen -shr 8)  -band 0xFF)
        $result[6] = [byte](($rawLen -shr 16) -band 0xFF)
        $result[7] = [byte](($rawLen -shr 24) -band 0xFF)
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
#  Step 2+3: ownership + write permission em mssmbios\Data
# ============================================================
Write-Info "Ajustando ACL de mssmbios\Data (owner + FullControl para Administrators)..."

try {
    Grant-SmbiosDataWrite
    Write-OK "ACL ajustada"
} catch {
    Write-Err "Falha ao ajustar ACL: $_"
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
    # contained_element_record_length. Formula: offset 0x15 + n*m onde
    # n=Formatted[0x13] e m=Formatted[0x14].
    Set-StructureString $type3 $type3.Formatted[4] $smb.chassis_manufacturer

    # Chassis Type e um BYTE, nao string index!
    $type3.Formatted[5] = [byte]$smb.chassis_type

    Set-StructureString $type3 $type3.Formatted[6] $smb.chassis_version
    Set-StructureString $type3 $type3.Formatted[7] $smb.chassis_serial
    if ($type3.Length -ge 9) {
        Set-StructureString $type3 $type3.Formatted[8] $smb.chassis_asset_tag
    }

    # SKUNumber (Type 3, spec 2.7+): offset 0x15 + contained*len.
    # So mexer se o SMBIOS local expor esse campo (Length grande o bastante).
    if ($smb.PSObject.Properties.Name -contains "chassis_sku" -and $smb.chassis_sku) {
        $containedN   = if ($type3.Length -ge 0x14) { [int]$type3.Formatted[0x13] } else { 0 }
        $containedLen = if ($type3.Length -ge 0x15) { [int]$type3.Formatted[0x14] } else { 0 }
        $skuOff       = 0x15 + ($containedN * $containedLen)
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
#  Fluxo v4.0.6 (Bug 3+5 postmortem):
#   - Cache do blob e feito AGORA (para o driver ter em maos).
#   - Opt-in flag (EnableSmbiosReplay=1) e setado APENAS SE o
#     SmbiosBlob for cacheado com sucesso ($cachedBlob=true).
#     Validacao real ocorre no proximo boot, dentro do driver
#     (ValidateSmbiosBlob rejeita blob malformado sem tocar
#     mssmbios\Data; OrigSmbiosData ficou de backup).
#   - Removido gate WMI que existia em v3.4-v4.0.5: WMI serve do
#     cache in-kernel do mssmbios (populado do firmware ACPI/RSMB),
#     nao do registry, entao a query nunca observou o blob que
#     escrevemos. Ver Bug 3 no postmortem v4.0.5.
#   - -DisableKernelReplay pula tudo isso.
# ============================================================
# $driverParams / $driverInstalled ja definidos no topo (v4.0.6 switch handling).
$cachedBlob     = $false

if ($DisableKernelReplay) {
    Write-Warn "-DisableKernelReplay: replay em kernel NAO sera armado"
    if ($driverInstalled -and (Test-Path $driverParams)) {
        Remove-ItemProperty -Path $driverParams -Name "SmbiosBlob"         -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $driverParams -Name "EnableSmbiosReplay" -ErrorAction SilentlyContinue
        # v3.7+: tambem limpar CpuStrings — todo replay em kernel esta desligado
        Remove-ItemProperty -Path $driverParams -Name "CpuStrings"         -ErrorAction SilentlyContinue
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
#  Step 10c: Cachear strings de CPU (name_string / identifier /
#  vendor_identifier) no driver para spoof estatico via registry.
#
#  So faz sentido se:
#    - Driver esta instalado (senao nao ha quem consuma o cache)
#    - Profile tem bloco cpu (v9+)
#    - -DisableKernelReplay nao esta setado (mesma logica dos
#      passos anteriores: se o usuario desligou replay para
#      depurar, tambem nao queremos empilhar spoof de CPU)
#    - -SmbiosOnly nao esta setado (v4.0.6 isolamento Bug 4)
# ============================================================
if ($driverInstalled -and -not $DisableKernelReplay -and -not $SmbiosOnly) {
    if ($prof.PSObject.Properties.Name -contains "cpu" -and $prof.cpu) {
        $cpuNameStr = [string]$prof.cpu.name_string
        $cpuIdent   = [string]$prof.cpu.identifier
        $cpuVendor  = [string]$prof.cpu.vendor_identifier

        try {
            if (-not (Test-Path $driverParams)) {
                New-Item -Path $driverParams -Force | Out-Null
            }
            Set-ItemProperty -Path $driverParams -Name "CpuStrings" `
                -Value @($cpuNameStr, $cpuIdent, $cpuVendor) -Type MultiString
            Write-OK "CpuStrings gravado no cache do driver (3 valores)"

            $trunc = {
                param($s)
                if ($null -eq $s) { return "" }
                if ($s.Length -gt 60) { return $s.Substring(0, 60) + "..." }
                return $s
            }
            Write-Info "  name_string:       $(& $trunc $cpuNameStr)"
            Write-Info "  identifier:        $(& $trunc $cpuIdent)"
            Write-Info "  vendor_identifier: $(& $trunc $cpuVendor)"
        } catch {
            Write-Warn "Falha ao gravar CpuStrings no driver: $_"
        }
    } else {
        Write-Info "Profile v< 9 - pulando CpuStrings"
    }
}

# ============================================================
#  Step 11: Snapshot WMI (informacional; NAO valida spoof)
#
#  v4.0.6 (postmortem v4.0.5 Bug 5+3):
#    - REMOVIDO Restart-Service winmgmt -Force: bloqueia 60+s pela
#      cascata SCM de 15+ dependentes (Winrm, ProfSvc, Themes,
#      wuauserv, wscsvc, Schedule, ...) e ao voltar deixa canais
#      RPC ainda em recovery, gerando RPC_E_CALL_CANCELED nas
#      Get-CimInstance seguintes.
#    - REMOVIDO gate $wmiOk: por Bug 3 (mssmbios serve WMI a partir
#      de um cache in-kernel populado do firmware ACPI/RSMB, NAO do
#      registro), essa query nunca observou o blob que acabamos de
#      gravar. O "gate" era placebo — sempre passava.
#    - Query mantida como INFORMACIONAL, com -OperationTimeoutSec
#      para nao ter chance de travar. Validacao REAL do blob acontece
#      no proximo boot, dentro do driver (ValidateSmbiosBlob).
#    - Ver: docs/postmortem-v4-phase5/incident-v405-vm-pipeline-validation.md
# ============================================================
Write-Host ""
Write-Host "  === WMI atual (cache in-kernel do mssmbios; NAO valida spoof) ===" -ForegroundColor White

$wmiOpts = @{ OperationTimeoutSec = 5; ErrorAction = 'SilentlyContinue' }
try {
    Write-Info "UUID:          $((Get-CimInstance Win32_ComputerSystemProduct @wmiOpts).UUID)"
    Write-Info "System Mfr:    $((Get-CimInstance Win32_ComputerSystem       @wmiOpts).Manufacturer)"
    Write-Info "Board Mfr:     $((Get-CimInstance Win32_BaseBoard            @wmiOpts).Manufacturer)"
    Write-Info "Board Prod:    $((Get-CimInstance Win32_BaseBoard            @wmiOpts).Product)"
    Write-Info "Chassis Mfr:   $((Get-CimInstance Win32_SystemEnclosure      @wmiOpts).Manufacturer)"
} catch {
    Write-Warn "Query WMI falhou (nao bloqueia arming): $_"
}
Write-Warn "Valores acima refletem o cache in-kernel do mssmbios (populado do"
Write-Warn "firmware no boot), NAO o blob que acabamos de escrever. Validacao"
Write-Warn "real do blob acontece no proximo boot, dentro do driver."

# ============================================================
#  Step 12: Armar opt-in do replay em kernel (v4.0.6)
#
#  Sem gate de WMI (Bug 3): se o blob esta cacheado com sucesso
#  em Parameters ($cachedBlob=true) e o driver esta instalado,
#  autorizamos o replay no proximo boot. Validacao FINAL do blob
#  e ValidateSmbiosBlob() no driver, que rejeita blob malformado
#  sem tocar mssmbios\Data, com backup em OrigSmbiosData.
#  -DisableKernelReplay honrado explicitamente.
# ============================================================
if ($DisableKernelReplay) {
    Write-Info "-DisableKernelReplay: NAO armando EnableSmbiosReplay"
} elseif ($cachedBlob) {
    try {
        Set-ItemProperty -Path $driverParams -Name "EnableSmbiosReplay" -Value 1 -Type DWord
        Write-OK  "Replay em kernel ARMADO (EnableSmbiosReplay=1)"
        Write-Warn "NOTA v4.0.6: em Hyper-V esta cadeia esta comprovadamente"
        Write-Warn "INEFICAZ contra WMI Win32_ComputerSystemProduct/BaseBoard/etc"
        Write-Warn "-- mssmbios serve do cache in-kernel populado do firmware,"
        Write-Warn "nao do registro. Bare-metal pode ter comportamento diferente."
        Write-Warn "Ver docs/postmortem-v4-phase5/incident-v405-vm-pipeline-validation.md"
        Write-Warn "e docs/roadmap-v41-wmi-intercept.md."
    } catch {
        Write-Warn "Falha ao armar opt-in: $_"
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
Write-Host "    .\spoof-smbios.ps1 -InstallTask" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Para remover tudo:" -ForegroundColor White
Write-Host "    .\spoof-smbios.ps1 -Uninstall" -ForegroundColor Yellow
Write-Host ""
