#Requires -RunAsAdministrator
# ============================================================
#  HWID Changer v3.7 (schema v8) - Profile-Based
#
#  Escopo em v3.7 (Fase 1.6):
#    - Somente MAC addresses (OUI real, sem bit LA).
#    - Machine GUID / ComputerName / TCPIP Hostname REINSERIDOS
#      em v3.7 mas aplicados por spoof-windows-id.ps1 (nao aqui).
#    - SQM Machine ID / Product ID NAO restaurados (recon v2
#      confirmou zero leituras EMAC).
#    - EDID serial partial REMOVIDO: spoof-edid-full.ps1
#      cobre isso com bloco 0xFF + descritores completos.
#
#  v4.0.5: -NoPause switch adicionado. Sem ele, os 3 Read-Host
#  no fim de cada exit path travam o batch parent 04-aplicar-hwid.bat
#  (quando invocado do PS shell) causando o batch abortar antes de
#  rodar os proximos 7 spoofers. Descoberto em VM validation
#  session 2026-08-30. O batch caller agora passa -NoPause; use
#  standalone sem a flag pra ter o comportamento pre-v4.0.5.
# ============================================================

param(
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"

function Wait-Enter {
    if (-not $NoPause) {
        Wait-Enter
    }
}

$profilePath = "C:\ProgramData\.hwcfg\profile.json"

# ---- Carregar profile ----
Write-Host ""
Write-Host "=== HWID Changer v3.7 (Profile-Based) ===" -ForegroundColor Cyan

if (-not (Test-Path $profilePath)) {
    Write-Host "  [X] Profile nao encontrado!" -ForegroundColor Red
    Write-Host "  [X] Rode primeiro:  .\generate-profile.ps1 -Generate" -ForegroundColor Red
    Write-Host ""
    Wait-Enter
    exit 1
}

$prof = Get-Content $profilePath -Raw | ConvertFrom-Json
$net = $prof.network

# Schema version guard (v3.7 = schema v8; ainda aceita v6/v7 legado)
$profVer = 0
if ($prof.PSObject.Properties['version']) {
    [int]::TryParse([string]$prof.version, [ref]$profVer) | Out-Null
}
Write-Host "  [OK] Profile carregado (v$profVer)" -ForegroundColor Green
if ($profVer -lt 6) {
    Write-Host "  [!] Profile schema v$profVer detectado; recomendado v8+ (v3.7)." -ForegroundColor Yellow
    Write-Host "  [!] Regenere com 00-gerar-profile.bat para habilitar Fase 1.6." -ForegroundColor Yellow
} elseif ($profVer -lt 8) {
    Write-Host "  [i] Profile v$profVer legado — ainda funciona, mas regenere para v8 para Fase 1.6." -ForegroundColor DarkGray
}
if (-not $net) {
    Write-Host "  [X] Profile nao contem bloco 'network' - regenere o profile." -ForegroundColor Red
    Wait-Enter
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
Wait-Enter
