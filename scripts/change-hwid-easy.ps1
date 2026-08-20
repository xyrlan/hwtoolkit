#Requires -RunAsAdministrator
# ============================================================
#  HWID Changer v3 — Profile-Based
#
#  Le valores do profile centralizado em vez de gerar random.
#  Correcoes sobre v1/v2:
#    - MAC usa OUI real (sem bit LA)
#    - Product ID no formato correto (5-5-7-5)
#    - Valores estaveis entre execucoes (mesmo profile)
#    - EDID monitor serial spoofing (bytes 12-15 bloco 0)
# ============================================================

$ErrorActionPreference = "Stop"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"

# ---- Carregar profile ----
Write-Host ""
Write-Host "=== HWID Changer v3 (Profile-Based) ===" -ForegroundColor Cyan

if (-not (Test-Path $profilePath)) {
    Write-Host "  [X] Profile nao encontrado!" -ForegroundColor Red
    Write-Host "  [X] Rode primeiro:  .\hwprofile.ps1 -Generate" -ForegroundColor Red
    Write-Host ""
    Read-Host "Pressione Enter para fechar"
    exit 1
}

$profile = Get-Content $profilePath -Raw | ConvertFrom-Json
$win = $profile.windows
$net = $profile.network

Write-Host "  [OK] Profile carregado (v$($profile.version))" -ForegroundColor Green
Write-Host ""

# ============================================================
#  BACKUP DOS VALORES ATUAIS
# ============================================================
Write-Host "=== BACKUP DOS VALORES ATUAIS ===" -ForegroundColor Cyan

$oldGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$oldSqm  = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient" -Name MachineId).MachineId
$oldPid  = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductId).ProductId
Write-Host "  Machine GUID:       $oldGuid"
Write-Host "  SQM Machine ID:     $oldSqm"
Write-Host "  Windows Product ID: $oldPid"

# ============================================================
#  1. Machine GUID
# ============================================================
$newGuid = $win.machine_guid
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -Value $newGuid
Write-Host ""
Write-Host "[OK] Machine GUID" -ForegroundColor Green
Write-Host "  Antes: $oldGuid"
Write-Host "  Agora: $newGuid"

# ============================================================
#  2. SQM Machine ID
# ============================================================
$newSqm = $win.sqm_machine_id
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient" -Name MachineId -Value $newSqm
Write-Host ""
Write-Host "[OK] SQM Machine ID" -ForegroundColor Green
Write-Host "  Antes: $oldSqm"
Write-Host "  Agora: $newSqm"

# ============================================================
#  3. Windows Product ID (formato correto: 00330-80000-XXXXXXX-AAXXX)
# ============================================================
$newPid = $win.product_id
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductId -Value $newPid
Write-Host ""
Write-Host "[OK] Windows Product ID" -ForegroundColor Green
Write-Host "  Antes: $oldPid"
Write-Host "  Agora: $newPid"
Write-Host "  Formato: 5-5-7-5 (OEM padrao)" -ForegroundColor DarkGray

# ============================================================
#  4. MAC Addresses (usando OUI real do profile)
# ============================================================
$netKey  = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
$changed = 0

$items = Get-ChildItem $netKey -ErrorAction SilentlyContinue
foreach ($item in $items) {
    $desc = $null
    try {
        $desc = (Get-ItemProperty -Path $item.PSPath -Name DriverDesc -ErrorAction Stop).DriverDesc
    } catch {
        continue
    }

    # Procurar match no profile
    foreach ($adapter in $net) {
        if ($desc -match $adapter.match) {
            $oldMac = "(padrao de fabrica)"
            try {
                $oldMac = (Get-ItemProperty -Path $item.PSPath -Name NetworkAddress -ErrorAction Stop).NetworkAddress
            } catch {}

            $newMac = $adapter.mac
            Set-ItemProperty -Path $item.PSPath -Name NetworkAddress -Value $newMac

            # Formatar MAC para display
            $macDisplay = ($newMac -replace '(.{2})', '$1:').TrimEnd(':')
            $oui = $newMac.Substring(0, 6)

            # Verificar que NAO tem bit LA
            $firstByte = [Convert]::ToByte($oui.Substring(0, 2), 16)
            $isLA = ($firstByte -band 0x02) -ne 0
            $ouiNote = if ($isLA) { "(AVISO: bit LA setado!)" } else { "(OUI real - nao detectavel)" }

            Write-Host ""
            Write-Host "[OK] MAC - $desc" -ForegroundColor Green
            Write-Host "  Antes: $oldMac"
            Write-Host "  Agora: $macDisplay $ouiNote"
            $changed++
            break
        }
    }
}

if ($changed -eq 0) {
    Write-Host ""
    Write-Host "[!] Nenhum adaptador correspondente encontrado no profile" -ForegroundColor Yellow
    Write-Host "    Adapters no profile:" -ForegroundColor Yellow
    foreach ($a in $net) {
        Write-Host "      match: $($a.match)" -ForegroundColor DarkGray
    }
} else {
    Write-Host ""
    Write-Host "[!] Reinicie os adaptadores para aplicar os novos MACs:" -ForegroundColor Yellow
    Write-Host "  Get-NetAdapter | Where-Object { `$_.InterfaceDescription -match 'Intel.*I219|Realtek.*2.5GbE' } | Restart-NetAdapter -Confirm:`$false"
}

# ============================================================
#  5. EDID Monitor Serial (bytes 12-15 do bloco 0)
# ============================================================

$edidChanged = 0

if ($profile.monitor -and $profile.monitor.edid_serial) {
    $edidHex = $profile.monitor.edid_serial
    # Converter hex string para 4 bytes
    $edidBytes = @()
    for ($i = 0; $i -lt 8; $i += 2) {
        $edidBytes += [Convert]::ToByte($edidHex.Substring($i, 2), 16)
    }

    Write-Host ""
    Write-Host "=== EDID MONITOR SERIAL ===" -ForegroundColor Cyan
    Write-Host "  Serial do profile: $edidHex" -ForegroundColor Gray

    $displayRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"

    if (Test-Path $displayRegPath) {
        $vendors = Get-ChildItem $displayRegPath -ErrorAction SilentlyContinue
        foreach ($vendor in $vendors) {
            $instances = Get-ChildItem $vendor.PSPath -ErrorAction SilentlyContinue
            foreach ($instance in $instances) {
                $devParamsPath = Join-Path $instance.PSPath "Device Parameters"
                if (-not (Test-Path $devParamsPath)) { continue }

                try {
                    $edidRaw = (Get-ItemProperty -Path $devParamsPath -Name "EDID" -ErrorAction Stop).EDID
                } catch {
                    continue
                }

                if ($edidRaw -isnot [byte[]]) { continue }
                if ($edidRaw.Length -lt 128) { continue }

                # Guardar serial antigo
                $oldSerial = "{0:X2}{1:X2}{2:X2}{3:X2}" -f $edidRaw[12], $edidRaw[13], $edidRaw[14], $edidRaw[15]

                # Modificar bytes 12-15 (serial de fabricação)
                $edidRaw[12] = $edidBytes[0]
                $edidRaw[13] = $edidBytes[1]
                $edidRaw[14] = $edidBytes[2]
                $edidRaw[15] = $edidBytes[3]

                # Recalcular checksum do bloco 0 (byte 127)
                # Checksum = valor que faz sum(bytes[0..127]) mod 256 == 0
                $sum = 0
                for ($b = 0; $b -lt 127; $b++) {
                    $sum += $edidRaw[$b]
                }
                $edidRaw[127] = (256 - ($sum % 256)) % 256

                # Escrever EDID modificado de volta
                Set-ItemProperty -Path $devParamsPath -Name "EDID" -Value $edidRaw -Type Binary

                $monitorId = $vendor.PSChildName + "\" + $instance.PSChildName
                Write-Host ""
                Write-Host "[OK] EDID - $monitorId" -ForegroundColor Green
                Write-Host "  Serial antes: $oldSerial"
                Write-Host "  Serial agora: $edidHex"
                $edidChanged++
            }
        }
    }

    if ($edidChanged -eq 0) {
        Write-Host ""
        Write-Host "[!] Nenhum monitor com EDID encontrado no registro" -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "[+] $edidChanged monitor(es) EDID modificado(s)" -ForegroundColor Green
        Write-Host "    Reboot necessario para efeito." -ForegroundColor DarkGray
    }
} else {
    Write-Host ""
    Write-Host "[!] Seção monitor.edid_serial ausente no profile (v2?)" -ForegroundColor Yellow
    Write-Host "    Rode hwprofile.ps1 -Generate para gerar com suporte a EDID." -ForegroundColor Yellow
}

# ============================================================
#  RESUMO
# ============================================================
Write-Host ""
Write-Host "=== CONCLUIDO ===" -ForegroundColor Cyan
Write-Host "  Identificadores alterados com sucesso."
Write-Host "  Todos os valores vem do profile centralizado."
Write-Host "  Rodar novamente aplica os MESMOS valores (estavel)."
Write-Host "  Reinicie o PC para efeito completo."
Write-Host ""
Read-Host "Pressione Enter para fechar"
