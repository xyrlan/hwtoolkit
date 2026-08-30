#Requires -RunAsAdministrator
# ============================================================
#  HWID Changer v3.6 (schema v7) - Profile-Based
#
#  Escopo reduzido em v3.5.1:
#    - Somente MAC addresses (OUI real, sem bit LA).
#    - Machine GUID / SQM Machine ID / Product ID REMOVIDOS
#      (Fase 1.5): EMAC nao le esses campos, e re-escrever
#      cria diff detectavel contra o baseline do Windows sem
#      qualquer beneficio de anti-fingerprint.
#    - EDID serial partial REMOVIDO: spoof-edid-full.ps1
#      cobre isso com bloco 0xFF + descritores completos.
# ============================================================

$ErrorActionPreference = "Stop"

$profilePath = "C:\ProgramData\.hwcfg\profile.json"

# ---- Carregar profile ----
Write-Host ""
Write-Host "=== HWID Changer v3.6 (Profile-Based) ===" -ForegroundColor Cyan

if (-not (Test-Path $profilePath)) {
    Write-Host "  [X] Profile nao encontrado!" -ForegroundColor Red
    Write-Host "  [X] Rode primeiro:  .\generate-profile.ps1 -Generate" -ForegroundColor Red
    Write-Host ""
    Read-Host "Pressione Enter para fechar"
    exit 1
}

$prof = Get-Content $profilePath -Raw | ConvertFrom-Json
$net = $prof.network

# Schema version guard (v3.6 = schema v7; ainda aceita v6 legado)
$profVer = 0
if ($prof.PSObject.Properties['version']) {
    [int]::TryParse([string]$prof.version, [ref]$profVer) | Out-Null
}
Write-Host "  [OK] Profile carregado (v$profVer)" -ForegroundColor Green
if ($profVer -lt 6) {
    Write-Host "  [!] Profile schema v$profVer detectado; recomendado v7+ (v3.6)." -ForegroundColor Yellow
    Write-Host "  [!] Campos legado (windows.*) sao ignorados; regenere com 00-gerar-profile.bat." -ForegroundColor Yellow
} elseif ($profVer -eq 6) {
    Write-Host "  [i] Profile v6 legado — ainda funciona, mas regenere para v7 quando puder." -ForegroundColor DarkGray
}
if (-not $net) {
    Write-Host "  [X] Profile nao contem bloco 'network' - regenere o profile." -ForegroundColor Red
    Read-Host "Pressione Enter para fechar"
    exit 1
}
Write-Host ""

# ============================================================
#  MAC Addresses (usando OUI real do profile)
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
#  RESUMO
# ============================================================
Write-Host ""
Write-Host "=== CONCLUIDO ===" -ForegroundColor Cyan
Write-Host "  MAC addresses alterados a partir do profile."
Write-Host "  Rodar novamente aplica os MESMOS valores (estavel)."
Write-Host "  Reinicie os adaptadores (ou o PC) para efeito."
Write-Host ""
Read-Host "Pressione Enter para fechar"
