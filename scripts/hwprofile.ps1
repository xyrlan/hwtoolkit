#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Gerador centralizado de perfil de hardware para o toolkit de spoofing.
.DESCRIPTION
    Gera um conjunto completo e CONSISTENTE de identificadores falsos de hardware,
    salva em um perfil JSON, e escreve o seed do driver no registro.
    Todos os outros scripts (change-hwid-easy.ps1, spoof-uuid.ps1, e o driver kernel)
    devem ler deste perfil ao invés de gerar valores aleatórios independentemente.
.NOTES
    Localização do perfil: C:\ProgramData\.hwcfg\profile.json
    Schema v5 — adiciona audio (rotation pool de GUIDs), monitor EDID completo,
    e emac (UUID persistente falso).
#>

param(
    [switch]$Generate,    # Gerar novo perfil
    [switch]$Show,        # Exibir perfil atual
    [switch]$Validate,    # Validar consistência do perfil
    [switch]$WriteDriver, # Escrever valores do driver no registro (após instalar o driver)
    [int]$BoardIndex = 0, # 1-based; se >0, pula o menu interativo de placa
    [string]$Socket = ""  # opcional; se setado, pula deteccao automatica de socket
)

$ErrorActionPreference = "Stop"

# ============================================================
#  Constantes e configuração
# ============================================================

$ProfileDir  = "C:\ProgramData\.hwcfg"
$ProfilePath = Join-Path $ProfileDir "profile.json"

# ============================================================
#  Banco de dados de hardware compatível
# ============================================================

$HardwareDB = @{
    "LGA1200" = @{
        CpuPattern = "i[3579]-10[0-9]{2}|i[3579]-11[0-9]{2}"
        Boards = @(
            @{ Manufacturer = "Micro-Star International Co., Ltd."; Product = "MAG Z490 TOMAHAWK (MS-7C80)"; Version = "1.0" }
            @{ Manufacturer = "ASUSTeK COMPUTER INC.";              Product = "PRIME Z490-A";                  Version = "Rev 1.xx" }
            @{ Manufacturer = "Gigabyte Technology Co., Ltd.";      Product = "Z490 AORUS MASTER";             Version = "x.x" }
            @{ Manufacturer = "ASRock";                              Product = "Z490 Steel Legend";              Version = "" }
            @{ Manufacturer = "Micro-Star International Co., Ltd."; Product = "MPG Z490 GAMING EDGE WIFI (MS-7C79)"; Version = "1.0" }
        )
    }
    "LGA1700" = @{
        CpuPattern = "i[3579]-1[234][0-9]{2}"
        Boards = @(
            @{ Manufacturer = "Micro-Star International Co., Ltd."; Product = "PRO Z690-A DDR4 (MS-7D25)";             Version = "1.0" }
            @{ Manufacturer = "ASUSTeK COMPUTER INC.";              Product = "ROG STRIX Z690-A GAMING WIFI D4";       Version = "Rev 1.xx" }
            @{ Manufacturer = "Gigabyte Technology Co., Ltd.";      Product = "Z690 AORUS ELITE AX DDR4";              Version = "x.x" }
            @{ Manufacturer = "ASRock";                              Product = "Z690 Steel Legend";                      Version = "" }
        )
    }
    "AM4" = @{
        CpuPattern = "Ryzen [3579] [0-9]{4}[^0-9]"
        Boards = @(
            @{ Manufacturer = "Micro-Star International Co., Ltd."; Product = "B550 GAMING PLUS (MS-7C56)";  Version = "1.0" }
            @{ Manufacturer = "ASUSTeK COMPUTER INC.";              Product = "ROG STRIX B550-F GAMING";     Version = "Rev 1.xx" }
            @{ Manufacturer = "Gigabyte Technology Co., Ltd.";      Product = "B550 AORUS ELITE V2";         Version = "x.x" }
        )
    }
    "AM5" = @{
        CpuPattern = "Ryzen [579] [789][0-9]{3}"
        Boards = @(
            @{ Manufacturer = "Micro-Star International Co., Ltd."; Product = "MAG B650 TOMAHAWK WIFI (MS-7D75)"; Version = "1.0" }
            @{ Manufacturer = "ASUSTeK COMPUTER INC.";              Product = "ROG STRIX B650E-F GAMING WIFI";    Version = "Rev 1.xx" }
            @{ Manufacturer = "Gigabyte Technology Co., Ltd.";      Product = "B650 AORUS ELITE AX";              Version = "x.x" }
        )
    }
}

# OUIs reais para geração de MACs
$IntelOUIs   = @("3C22FB", "A4BB6D", "48210B", "8C8CAA")
$RealtekOUIs = @("00E04C", "485D36", "2C4D54")

# Padrões de adaptadores de rede para corresponder
$NetworkAdapters = @(
    @{ Match = "Intel.*I219";       OUIPool = $IntelOUIs }
    @{ Match = "Realtek.*2\.5GbE";  OUIPool = $RealtekOUIs }
)

# ============================================================
#  Banco de dados de monitores (EDID)
# ============================================================
# Marca (PNP ID EISA) x modelo pareados. Anti-cheat que hash o EDID
# inteiro flaga combinacoes impossiveis (ex.: DEL com "ROG PG279Q").
# Aqui sorteamos uma marca, depois um modelo pertencente a ela.
# HP monitors reais reportam HWP (nao HPN, que e a subsidiaria Nordic
# usada em perifericos).
$MonitorBrands = @(
    @{ Pnp = "AUS"; Models = @("ROG PG279Q","XG27AQM","VG259QM","TUF VG27AQ","VG278Q") }
    @{ Pnp = "DEL"; Models = @("AW2521HFA","U2723QE","S2721DGF","AW3423DW","U2422H") }
    @{ Pnp = "SAM"; Models = @("S32BG75","G5 LC32G55","G7 LC32G75","M8 S32BM80") }
    @{ Pnp = "GSM"; Models = @("27GN950-B","27GP850-B","32GP850-B","27GN800-B","24GN650-B") }
    @{ Pnp = "MSI"; Models = @("MAG274QRF","MPG321URX","MAG271CR","MAG251RX","G274F") }
    @{ Pnp = "GBT"; Models = @("M27Q","M32Q","M28U","G34WQC","AORUS FI27Q") }
    @{ Pnp = "ACR"; Models = @("XV272U","XB273K","PREDATOR X28","VG272UP","NITRO XV252") }
    @{ Pnp = "HWP"; Models = @("OMEN 27","X27q","X24ih","V27i 4K","Z27k G3") }
    @{ Pnp = "BNQ"; Models = @("EX2710","EX3210U","MOBIUZ EX270","ZOWIE XL2546K","PD2705U") }
    @{ Pnp = "VSC"; Models = @("XG270","ELITE XG270","VX2758-2K","VP2768","XG2431") }
    @{ Pnp = "AOC"; Models = @("Q27G3Z","U28G2XU","AG273QCG","24G2","CQ32G3SU") }
    @{ Pnp = "PXO"; Models = @("PX277 PRIME","PX248","PX277 PRO","PX329","PX259") }
)

# ============================================================
#  Funções auxiliares
# ============================================================

function Show-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║        HWPROFILE  -  Gerador de Perfil HW       ║" -ForegroundColor DarkCyan
    Write-Host "  ║            Perfil centralizado v5               ║" -ForegroundColor DarkCyan
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-Usage {
    Write-Host "  Uso:" -ForegroundColor Yellow
    Write-Host "    .\hwprofile.ps1 -Generate    " -NoNewline -ForegroundColor White
    Write-Host "Gerar novo perfil completo" -ForegroundColor Gray
    Write-Host "    .\hwprofile.ps1 -Show        " -NoNewline -ForegroundColor White
    Write-Host "Exibir perfil atual" -ForegroundColor Gray
    Write-Host "    .\hwprofile.ps1 -Validate    " -NoNewline -ForegroundColor White
    Write-Host "Validar consistência do perfil" -ForegroundColor Gray
    Write-Host "    .\hwprofile.ps1 -WriteDriver " -NoNewline -ForegroundColor White
    Write-Host "Escrever seed do driver no registro" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Localização do perfil: " -NoNewline -ForegroundColor Gray
    Write-Host $ProfilePath -ForegroundColor Cyan
    Write-Host ""
}

function Get-CryptoRandomBytes {
    # Retorna N bytes criptograficamente aleatórios
    param([int]$Count)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] $Count
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return $bytes
}

function Get-CryptoRandomHex {
    # Retorna string hexadecimal aleatória com N caracteres (maiúsculo)
    param([int]$Length)
    $needed = [Math]::Ceiling($Length / 2)
    $bytes = Get-CryptoRandomBytes -Count $needed
    $hex = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""
    return $hex.Substring(0, $Length)
}

function Get-CryptoRandomDigits {
    # Retorna string com N dígitos aleatórios
    param([int]$Count)
    $result = ""
    $bytes = Get-CryptoRandomBytes -Count $Count
    foreach ($b in $bytes) {
        $result += ($b % 10).ToString()
    }
    return $result
}

function Get-CryptoRandomAlnum {
    # Retorna string alfanumérica aleatória (maiúscula) com N caracteres
    param([int]$Count)
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $result = ""
    $bytes = Get-CryptoRandomBytes -Count $Count
    foreach ($b in $bytes) {
        $result += $chars[$b % $chars.Length]
    }
    return $result
}

function Get-CryptoRandomInt {
    # Retorna inteiro aleatorio em [Min, Max] (inclusivo)
    param([int]$Min, [int]$Max)
    if ($Max -lt $Min) { throw "Get-CryptoRandomInt: Max < Min" }
    $range = [uint32]($Max - $Min + 1)
    $bytes = Get-CryptoRandomBytes -Count 4
    $val = [BitConverter]::ToUInt32($bytes, 0)
    return [int]($Min + ($val % $range))
}

function Get-CryptoRandomUInt32 {
    # Retorna uint32 aleatorio (0..0xFFFFFFFF)
    $bytes = Get-CryptoRandomBytes -Count 4
    return [BitConverter]::ToUInt32($bytes, 0)
}

function New-UUIDv4 {
    # Gera UUID v4 válido a partir de bytes criptográficos
    $bytes = Get-CryptoRandomBytes -Count 16

    # Setar versão 4 (bits 4-7 do byte 6)
    $bytes[6] = ($bytes[6] -band 0x0F) -bor 0x40

    # Setar variante RFC 4122 (bits 6-7 do byte 8)
    $bytes[8] = ($bytes[8] -band 0x3F) -bor 0x80

    $hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    $uuid = "{0}-{1}-{2}-{3}-{4}" -f `
        $hex.Substring(0,8),
        $hex.Substring(8,4),
        $hex.Substring(12,4),
        $hex.Substring(16,4),
        $hex.Substring(20,12)

    return $uuid
}

function New-GuidLower {
    # Gera GUID aleatório em minúsculas
    $bytes = Get-CryptoRandomBytes -Count 16
    $bytes[6] = ($bytes[6] -band 0x0F) -bor 0x40
    $bytes[8] = ($bytes[8] -band 0x3F) -bor 0x80
    $hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    return "{0}-{1}-{2}-{3}-{4}" -f `
        $hex.Substring(0,8),
        $hex.Substring(8,4),
        $hex.Substring(12,4),
        $hex.Substring(16,4),
        $hex.Substring(20,12)
}

function New-GuidBracesLower {
    # Gera GUID em minusculas com chaves — formato usado nas chaves MMDevices
    $g = New-GuidLower
    return "{$g}"
}

function New-GuidBracesUpper {
    # Gera GUID em maiúsculas com chaves
    $bytes = Get-CryptoRandomBytes -Count 16
    $bytes[6] = ($bytes[6] -band 0x0F) -bor 0x40
    $bytes[8] = ($bytes[8] -band 0x3F) -bor 0x80
    $hex = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""
    return "{{{0}-{1}-{2}-{3}-{4}}}" -f `
        $hex.Substring(0,8),
        $hex.Substring(8,4),
        $hex.Substring(12,4),
        $hex.Substring(16,4),
        $hex.Substring(20,12)
}

function Get-CryptoRandomItem {
    # Seleciona item aleatório de um array usando RNG criptográfico
    param([array]$Items)
    $bytes = Get-CryptoRandomBytes -Count 4
    $index = [BitConverter]::ToUInt32($bytes, 0) % $Items.Count
    return $Items[$index]
}

function Detect-CPU {
    # Detecta o processador via WMI
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    return $cpu.Name
}

function Match-Socket {
    # Encontra o socket compatível baseado no nome da CPU
    param([string]$CpuName)
    foreach ($socket in $HardwareDB.Keys) {
        $pattern = $HardwareDB[$socket].CpuPattern
        if ($CpuName -match $pattern) {
            return $socket
        }
    }
    return $null
}

function Generate-BoardSerial {
    # Gera serial da placa-mãe baseado no fabricante
    param([string]$Manufacturer)
    switch -Wildcard ($Manufacturer) {
        "Micro-Star*" {
            return "07C" + (Get-CryptoRandomDigits -Count 8)
        }
        "ASUSTeK*" {
            return Get-CryptoRandomHex -Length 12
        }
        "Gigabyte*" {
            return Get-CryptoRandomHex -Length 12
        }
        "ASRock*" {
            return "M80-" + (Get-CryptoRandomDigits -Count 8)
        }
        default {
            return Get-CryptoRandomHex -Length 12
        }
    }
}

function Generate-MAC {
    # Gera endereço MAC com OUI real
    param([string[]]$OUIPool)
    $oui = Get-CryptoRandomItem -Items $OUIPool
    $suffix = Get-CryptoRandomHex -Length 6
    return ($oui + $suffix).ToUpper()
}

function Generate-ProductID {
    # Gera Product ID no formato 00330-80000-XXXXXXX-AAXXX
    $mid = Get-CryptoRandomDigits -Count 7
    $suffix = Get-CryptoRandomDigits -Count 3
    return "00330-80000-$mid-AA$suffix"
}

function Convert-Uint32ToLeHex {
    # Converte uint32 -> 8 hex chars (bytes LE em ordem: b0 b1 b2 b3)
    # Compatibilidade com change-hwid-easy.ps1: aquele script itera bytes 12-15
    # na ordem em que estao no array, entao a string hex deve ser
    # LSB primeiro. Ex: 0x12345678 -> "78563412".
    param([uint32]$Value)
    $b0 = ($Value       ) -band 0xFF
    $b1 = ($Value -shr  8) -band 0xFF
    $b2 = ($Value -shr 16) -band 0xFF
    $b3 = ($Value -shr 24) -band 0xFF
    return ("{0:X2}{1:X2}{2:X2}{3:X2}" -f $b0, $b1, $b2, $b3)
}

function Load-Profile {
    # Carrega perfil do disco
    if (-not (Test-Path $ProfilePath)) {
        Write-Host "  [ERRO] Perfil não encontrado: $ProfilePath" -ForegroundColor Red
        Write-Host "  Execute com -Generate para criar um novo perfil." -ForegroundColor Yellow
        return $null
    }
    try {
        $json = Get-Content -Path $ProfilePath -Raw -Encoding UTF8
        $profile = $json | ConvertFrom-Json
        return $profile
    }
    catch {
        Write-Host "  [ERRO] Falha ao ler perfil: $_" -ForegroundColor Red
        return $null
    }
}

# ============================================================
#  -Generate : Gerar novo perfil
# ============================================================

function Invoke-Generate {
    Write-Host "  [*] Detectando CPU..." -ForegroundColor Cyan
    $cpuName = Detect-CPU
    Write-Host "  [+] CPU detectada: " -NoNewline -ForegroundColor Green
    Write-Host $cpuName -ForegroundColor White

    # Encontrar socket compatível
    $socket = Match-Socket -CpuName $cpuName
    if (-not $socket) {
        Write-Host ""
        Write-Host "  [AVISO] Não foi possível detectar o socket automaticamente." -ForegroundColor Yellow
        Write-Host "  CPU: $cpuName" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Selecione o socket manualmente:" -ForegroundColor Cyan
        $sockets = @($HardwareDB.Keys | Sort-Object)
        for ($i = 0; $i -lt $sockets.Count; $i++) {
            Write-Host "    [$($i+1)] $($sockets[$i])" -ForegroundColor White
        }
        Write-Host ""
        do {
            $choice = Read-Host "  Número do socket"
            $idx = [int]$choice - 1
        } while ($idx -lt 0 -or $idx -ge $sockets.Count)
        $socket = $sockets[$idx]
    }

    Write-Host "  [+] Socket compatível: " -NoNewline -ForegroundColor Green
    Write-Host $socket -ForegroundColor White
    Write-Host ""

    # Listar placas compatíveis para o usuário escolher
    $boards = $HardwareDB[$socket].Boards
    Write-Host "  Placas-mãe compatíveis com $socket`:" -ForegroundColor Cyan
    Write-Host ""
    for ($i = 0; $i -lt $boards.Count; $i++) {
        $b = $boards[$i]
        Write-Host "    [$($i+1)] " -NoNewline -ForegroundColor Yellow
        Write-Host "$($b.Manufacturer) " -NoNewline -ForegroundColor White
        Write-Host "- $($b.Product)" -ForegroundColor Gray
    }
    Write-Host ""

    if ($BoardIndex -gt 0) {
        if ($BoardIndex -gt $boards.Count) {
            Write-Host ("  [ERRO] BoardIndex={0} > numero de placas disponiveis ({1})" -f $BoardIndex, $boards.Count) -ForegroundColor Red
            Write-Host "  [ERRO] Use um indice entre 1 e $($boards.Count), ou omita o parametro para menu interativo." -ForegroundColor Red
            exit 1
        }
        $idx = $BoardIndex - 1
        Write-Host "  [*] BoardIndex=$BoardIndex fornecido - pulando menu" -ForegroundColor DarkGray
    } else {
        do {
            $choice = Read-Host "  Escolha a placa-mãe (número)"
            $idx = [int]$choice - 1
        } while ($idx -lt 0 -or $idx -ge $boards.Count)
    }

    $selectedBoard = $boards[$idx]
    Write-Host ""
    Write-Host "  [+] Placa selecionada: " -NoNewline -ForegroundColor Green
    Write-Host "$($selectedBoard.Product)" -ForegroundColor White
    Write-Host ""

    # ---- Gerar todos os IDs ----
    Write-Host "  [*] Gerando identificadores..." -ForegroundColor Cyan

    # SMBIOS UUID
    $uuid = New-UUIDv4

    # Seriais
    $systemSerial = "K" + (Get-CryptoRandomAlnum -Count 9)
    $boardSerial  = Generate-BoardSerial -Manufacturer $selectedBoard.Manufacturer

    # Chassis version vem da mesma versão da placa
    $chassisVersion = $selectedBoard.Version

    # Windows GUIDs
    $machineGuid = New-GuidLower
    $sqmMachineId = New-GuidBracesUpper
    $productId = Generate-ProductID

    # MACs de rede
    $networkEntries = @()
    foreach ($adapter in $NetworkAdapters) {
        $mac = Generate-MAC -OUIPool $adapter.OUIPool
        $networkEntries += @{
            match = $adapter.Match
            mac   = $mac
        }
    }

    # Storage
    $storageSeedBytes = Get-CryptoRandomBytes -Count 32
    $storageSeedB64   = [Convert]::ToBase64String($storageSeedBytes)

    # ---- Monitor EDID (schema v5, completo) ----
    # Escolhe marca primeiro, depois modelo pertencente a essa marca para
    # que anti-cheat que hash o EDID inteiro nao veja combinacoes impossiveis
    # (ex.: DEL + "ROG PG279Q").
    $selectedBrand = Get-CryptoRandomItem -Items $MonitorBrands
    $mfrPnP        = $selectedBrand.Pnp
    $modelName     = Get-CryptoRandomItem -Items $selectedBrand.Models

    # Product code (uint16 LE, bytes 10-11 do EDID)
    $productCode = Get-CryptoRandomInt -Min 0x1000 -Max 0xFFFF

    # Serial number (uint32 LE, bytes 12-15 do EDID)
    $serialNum = Get-CryptoRandomUInt32
    # Legacy edid_serial: string hex derivada dos 4 bytes LE de serialNum.
    # change-hwid-easy.ps1 le esta string e a aplica em bytes[12..15] na
    # ordem em que aparecem — por isso emitimos LSB primeiro.
    $edidSerialHex = Convert-Uint32ToLeHex -Value $serialNum

    # Semana e ano de fabricacao
    $mfgWeek = Get-CryptoRandomInt -Min 1 -Max 53
    $mfgYear = Get-CryptoRandomInt -Min 2019 -Max 2024

    # Serial ASCII (descriptor block 0xFF), 10..12 chars — cap 12 garante que o
    # descriptor sempre termine com 0x0A + pad 0x20, padrao dos monitores reais.
    $serialAsciiLen = Get-CryptoRandomInt -Min 10 -Max 12
    $serialAscii = Get-CryptoRandomAlnum -Count $serialAsciiLen

    # ---- Audio (schema v5) ----
    # Pool de GUIDs pre-alocados; o rotator consome em ordem para cada
    # endpoint de audio presente na maquina. 12 entradas cobre setups
    # complexos (2 HDMI monitores + USB headset + line-in + Voicemeeter
    # virtual devices tipicamente expoem 6-10 endpoints).
    $audioPool = @()
    for ($i = 0; $i -lt 12; $i++) {
        $audioPool += New-GuidBracesLower
    }

    # ---- EMAC (schema v5) ----
    # UUID persistente falso — substituto para C:\Users\<user>\emac-uuid.
    # Manter constante e proteger com ACL para evitar burst de re-registration.
    $emacUuid = New-UUIDv4

    # Montar o objeto do perfil
    $profile = [ordered]@{
        version        = 5
        generated_utc  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        cpu_detected   = $cpuName
        socket_matched = $socket
        smbios = [ordered]@{
            uuid                 = $uuid
            system_manufacturer  = $selectedBoard.Manufacturer
            system_product       = $selectedBoard.Product
            system_version       = $selectedBoard.Version
            system_serial        = $systemSerial
            system_sku           = "Default string"
            system_family        = "Default string"
            board_manufacturer   = $selectedBoard.Manufacturer
            board_product        = $selectedBoard.Product
            board_version        = $selectedBoard.Version
            board_serial         = $boardSerial
            board_asset_tag      = "Default string"
            chassis_manufacturer = $selectedBoard.Manufacturer
            chassis_type         = 3
            chassis_version      = $chassisVersion
            chassis_serial       = "Default string"
            chassis_asset_tag    = "Default string"
            chassis_sku          = "Default string"

            # -- Type 4 (Processor Information) — apenas string fields.
            # Nao mexer no CPUID/family/model — sao vindos do silicio e
            # criar inconsistencia entre SMBIOS CPU e CPUID e um flag classico.
            processor_serial     = "To Be Filled By O.E.M."
            processor_asset_tag  = "To Be Filled By O.E.M."
            processor_part_num   = "To Be Filled By O.E.M."

            # -- Type 11 (OEM Strings) — vetor de strings arbitrarias.
            # Dell mete service tag aqui, HP mete asset codes, MSI usualmente
            # nao popula. Deixamos duas strings genericas "safe".
            oem_strings          = @("Default string", "Default string")
        }
        windows = [ordered]@{
            machine_guid   = $machineGuid
            sqm_machine_id = $sqmMachineId
            product_id     = $productId
        }
        network = $networkEntries
        storage = [ordered]@{
            seed_b64      = $storageSeedB64
            serial_prefix = "S6BN"
            serial_length = 15
        }
        monitor = [ordered]@{
            mfr_pnp_id   = $mfrPnP
            product_code = $productCode
            serial_num   = $serialNum
            mfg_week     = $mfgWeek
            mfg_year     = $mfgYear
            serial_ascii = $serialAscii
            model_name   = $modelName
            # Legacy field — mantido para compat com change-hwid-easy.ps1.
            # 8 hex chars = 4 bytes LE de serial_num.
            edid_serial  = $edidSerialHex
        }
        audio = [ordered]@{
            # Pool de GUIDs consumido em ordem pelo rotator MMDevices.
            rotation_pool = $audioPool
        }
        emac = [ordered]@{
            # UUID persistente falso — usar em C:\Users\<user>\emac-uuid.
            persistent_uuid = $emacUuid
            # Habilitar ACL lock no arquivo emac-uuid (o applier bloqueia
            # escrita/delete pelo processo do jogo).
            lock_file       = $true
        }
    }

    # Criar diretório se necessário
    if (-not (Test-Path $ProfileDir)) {
        New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
        Write-Host "  [+] Diretório criado: $ProfileDir" -ForegroundColor Green
    }

    # Salvar perfil (atomico: escreve em .tmp, depois Move-Item para evitar
    # race com leitores concorrentes que fariam ConvertFrom-Json em arquivo
    # truncado durante o Set-Content).
    $jsonOut = $profile | ConvertTo-Json -Depth 10
    $tmpPath = "$ProfilePath.tmp"
    Set-Content -Path $tmpPath -Value $jsonOut -Encoding UTF8 -Force
    Move-Item -Path $tmpPath -Destination $ProfilePath -Force
    Write-Host "  [+] Perfil salvo em: $ProfilePath" -ForegroundColor Green
    Write-Host ""

    # Escrever valores do driver no registro
    Write-DriverRegistry -Profile $profile

    # Exibir resumo
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "               RESUMO DO PERFIL GERADO             " -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""
    Show-ProfileData -Profile $profile
}

# ============================================================
#  -WriteDriver : Escrever seed do driver no registro
# ============================================================

function Write-DriverRegistry {
    param($Profile)

    $driverKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters"

    Write-Host "  [*] Escrevendo valores do driver no registro..." -ForegroundColor Cyan

    # Verificar se a chave do serviço existe
    $serviceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt"
    if (-not (Test-Path $serviceKeyPath)) {
        Write-Host "  [AVISO] Chave do serviço RstFlt não encontrada." -ForegroundColor Yellow
        Write-Host "  O driver ainda não foi instalado. Os valores serão escritos," -ForegroundColor Yellow
        Write-Host "  mas o driver precisa ser instalado para funcionar." -ForegroundColor Yellow
        Write-Host ""
    }

    # Criar a chave Parameters se não existir
    if (-not (Test-Path $driverKeyPath)) {
        try {
            New-Item -Path $driverKeyPath -Force | Out-Null
            Write-Host "  [+] Chave de registro criada: $driverKeyPath" -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERRO] Falha ao criar chave de registro: $_" -ForegroundColor Red
            return
        }
    }

    # Obter dados do storage
    $storageData = $null
    if ($Profile -is [PSCustomObject]) {
        $storageData = $Profile.storage
    } else {
        $storageData = $Profile["storage"]
    }

    $seedB64      = if ($storageData -is [PSCustomObject]) { $storageData.seed_b64 }      else { $storageData["seed_b64"] }
    $serialPrefix = if ($storageData -is [PSCustomObject]) { $storageData.serial_prefix } else { $storageData["serial_prefix"] }
    $serialLength = if ($storageData -is [PSCustomObject]) { $storageData.serial_length } else { $storageData["serial_length"] }

    # SerialSeed (REG_BINARY, 32 bytes)
    try {
        $seedBytes = [Convert]::FromBase64String($seedB64)
        Set-ItemProperty -Path $driverKeyPath -Name "SerialSeed" -Value $seedBytes -Type Binary
        Write-Host "  [+] SerialSeed     : " -NoNewline -ForegroundColor Green
        Write-Host "32 bytes (REG_BINARY)" -ForegroundColor White
    }
    catch {
        Write-Host "  [ERRO] Falha ao escrever SerialSeed: $_" -ForegroundColor Red
    }

    # SerialPrefix (REG_SZ)
    try {
        Set-ItemProperty -Path $driverKeyPath -Name "SerialPrefix" -Value $serialPrefix -Type String
        Write-Host "  [+] SerialPrefix   : " -NoNewline -ForegroundColor Green
        Write-Host "$serialPrefix (REG_SZ)" -ForegroundColor White
    }
    catch {
        Write-Host "  [ERRO] Falha ao escrever SerialPrefix: $_" -ForegroundColor Red
    }

    # SerialLength (REG_DWORD)
    try {
        Set-ItemProperty -Path $driverKeyPath -Name "SerialLength" -Value ([int]$serialLength) -Type DWord
        Write-Host "  [+] SerialLength   : " -NoNewline -ForegroundColor Green
        Write-Host "$serialLength (REG_DWORD)" -ForegroundColor White
    }
    catch {
        Write-Host "  [ERRO] Falha ao escrever SerialLength: $_" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  [+] Valores do driver escritos com sucesso." -ForegroundColor Green
}

function Invoke-WriteDriver {
    $profile = Load-Profile
    if (-not $profile) { return }
    Write-DriverRegistry -Profile $profile
}

# ============================================================
#  -Validate : Validar consistência do perfil
# ============================================================

function Invoke-Validate {
    Write-Host "  [*] Validando perfil: $ProfilePath" -ForegroundColor Cyan
    Write-Host ""

    $allPassed = $true
    $checks = 0
    $passed = 0

    # 1. Perfil existe e é analisável
    $checks++
    if (-not (Test-Path $ProfilePath)) {
        Write-Host "  [FALHA] Perfil não encontrado" -ForegroundColor Red
        $allPassed = $false
        return
    }

    try {
        $json = Get-Content -Path $ProfilePath -Raw -Encoding UTF8
        $profile = $json | ConvertFrom-Json
        Write-Host "  [OK]    Perfil existe e é JSON válido" -ForegroundColor Green
        $passed++
    }
    catch {
        Write-Host "  [FALHA] Perfil existe mas JSON inválido: $_" -ForegroundColor Red
        $allPassed = $false
        return
    }

    # 2. Fabricantes system/board/chassis batem
    $checks++
    $sysMfr     = $profile.smbios.system_manufacturer
    $boardMfr   = $profile.smbios.board_manufacturer
    $chassisMfr = $profile.smbios.chassis_manufacturer
    if ($sysMfr -eq $boardMfr -and $boardMfr -eq $chassisMfr) {
        Write-Host "  [OK]    Fabricantes system/board/chassis são iguais: $sysMfr" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "  [FALHA] Fabricantes não coincidem:" -ForegroundColor Red
        Write-Host "          System:  $sysMfr" -ForegroundColor Red
        Write-Host "          Board:   $boardMfr" -ForegroundColor Red
        Write-Host "          Chassis: $chassisMfr" -ForegroundColor Red
        $allPassed = $false
    }

    # 3. Placa é compatível com o socket detectado para a CPU atual
    $checks++
    $cpuName = Detect-CPU
    $currentSocket = Match-Socket -CpuName $cpuName
    $profileSocket = $profile.socket_matched

    if ($currentSocket -and $currentSocket -eq $profileSocket) {
        # Verificar se a placa está no banco de dados do socket
        $boardProduct = $profile.smbios.board_product
        $boardsForSocket = $HardwareDB[$currentSocket].Boards
        $found = $false
        foreach ($b in $boardsForSocket) {
            if ($b.Product -eq $boardProduct) {
                $found = $true
                break
            }
        }
        if ($found) {
            Write-Host "  [OK]    Placa '$boardProduct' é compatível com socket $currentSocket" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "  [FALHA] Placa '$boardProduct' não encontrada no banco de dados para socket $currentSocket" -ForegroundColor Red
            $allPassed = $false
        }
    } elseif (-not $currentSocket) {
        Write-Host "  [AVISO] Não foi possível detectar socket da CPU atual para validação" -ForegroundColor Yellow
        $passed++  # Não falhar por isso
    } else {
        Write-Host "  [FALHA] Socket do perfil ($profileSocket) diferente do detectado ($currentSocket)" -ForegroundColor Red
        $allPassed = $false
    }

    # 4. UUID é v4 válido
    $checks++
    $uuid = $profile.smbios.uuid
    $uuidv4Pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    if ($uuid -match $uuidv4Pattern) {
        Write-Host "  [OK]    UUID é v4 válido: $uuid" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "  [FALHA] UUID não é v4 válido: $uuid" -ForegroundColor Red
        $allPassed = $false
    }

    # 5. MACs não têm bit LA setado (a menos que seja OUI real)
    $checks++
    $macOk = $true
    $allKnownOUIs = $IntelOUIs + $RealtekOUIs
    foreach ($net in $profile.network) {
        $macStr = $net.mac
        if ($macStr.Length -ge 2) {
            $firstByte = [Convert]::ToByte($macStr.Substring(0, 2), 16)
            $laSet = ($firstByte -band 0x02) -ne 0
            $oui = $macStr.Substring(0, 6).ToUpper()
            if ($laSet -and ($allKnownOUIs -notcontains $oui)) {
                Write-Host "  [FALHA] MAC $macStr tem bit LA setado e não é OUI conhecido" -ForegroundColor Red
                $macOk = $false
                $allPassed = $false
            }
        }
    }
    if ($macOk) {
        Write-Host "  [OK]    Endereços MAC válidos (OUIs reais, sem bit LA indevido)" -ForegroundColor Green
        $passed++
    }

    # 6. Product ID no formato esperado
    $checks++
    $pidPattern = "^00330-80000-\d{7}-AA\d{3}$"
    $pid = $profile.windows.product_id
    if ($pid -match $pidPattern) {
        Write-Host "  [OK]    Product ID no formato correto: $pid" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "  [FALHA] Product ID fora do formato esperado: $pid" -ForegroundColor Red
        $allPassed = $false
    }

    # 7. Storage seed tem 32 bytes
    $checks++
    try {
        $seedBytes = [Convert]::FromBase64String($profile.storage.seed_b64)
        if ($seedBytes.Length -eq 32) {
            Write-Host "  [OK]    Storage seed tem 32 bytes" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "  [FALHA] Storage seed tem $($seedBytes.Length) bytes (esperado: 32)" -ForegroundColor Red
            $allPassed = $false
        }
    }
    catch {
        Write-Host "  [FALHA] Storage seed não é base64 válido" -ForegroundColor Red
        $allPassed = $false
    }

    # 8. EDID legacy serial (compat com change-hwid-easy.ps1)
    $checks++
    if ($profile.monitor -and $profile.monitor.edid_serial) {
        $edidHex = $profile.monitor.edid_serial
        if ($edidHex -match "^[0-9A-Fa-f]{8}$") {
            Write-Host "  [OK]    EDID serial (legacy) valido (4 bytes): $edidHex" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "  [FALHA] EDID serial (legacy) formato invalido: $edidHex (esperado: 8 hex chars)" -ForegroundColor Red
            $allPassed = $false
        }
    } else {
        Write-Host "  [AVISO] Secao monitor/edid_serial ausente. Rode -Generate para atualizar." -ForegroundColor Yellow
        $passed++  # Nao falhar para profiles legados
    }

    # 9. Monitor EDID v5 — mfr_pnp_id, product_code, serial_num, week/year
    $checks++
    $monOk = $true
    $mon = $profile.monitor
    if (-not $mon) {
        Write-Host "  [AVISO] Secao monitor ausente" -ForegroundColor Yellow
        $passed++
    } else {
        # mfr_pnp_id: 3 letras maiusculas
        $pnp = $mon.mfr_pnp_id
        if (-not $pnp -or $pnp -notmatch "^[A-Z]{3}$") {
            Write-Host "  [FALHA] monitor.mfr_pnp_id invalido: '$pnp' (esperado: 3 letras uppercase)" -ForegroundColor Red
            $monOk = $false
        }
        # product_code: uint16
        $pc = $mon.product_code
        if ($null -eq $pc -or [int]$pc -lt 0 -or [int]$pc -gt 0xFFFF) {
            Write-Host "  [FALHA] monitor.product_code fora de uint16: $pc" -ForegroundColor Red
            $monOk = $false
        }
        # serial_num: uint32
        $sn = $mon.serial_num
        if ($null -eq $sn) {
            Write-Host "  [FALHA] monitor.serial_num ausente" -ForegroundColor Red
            $monOk = $false
        } else {
            $snStr = "$sn"
            $snBig = [System.Numerics.BigInteger]::Parse($snStr)
            if ($snBig -lt 0 -or $snBig -gt [System.Numerics.BigInteger]::Parse("4294967295")) {
                Write-Host "  [FALHA] monitor.serial_num fora de uint32: $sn" -ForegroundColor Red
                $monOk = $false
            }
        }
        # mfg_week: 1..53
        $wk = [int]$mon.mfg_week
        if ($wk -lt 1 -or $wk -gt 53) {
            Write-Host "  [FALHA] monitor.mfg_week fora de 1..53: $wk" -ForegroundColor Red
            $monOk = $false
        }
        # mfg_year: 2000..2035
        $yr = [int]$mon.mfg_year
        if ($yr -lt 2000 -or $yr -gt 2035) {
            Write-Host "  [FALHA] monitor.mfg_year fora de 2000..2035: $yr" -ForegroundColor Red
            $monOk = $false
        }
        # serial_ascii: <=13 chars ASCII
        $sa = $mon.serial_ascii
        if (-not $sa -or $sa.Length -gt 13 -or $sa -notmatch "^[\x20-\x7E]+$") {
            Write-Host "  [FALHA] monitor.serial_ascii invalido: '$sa' (max 13 chars ASCII)" -ForegroundColor Red
            $monOk = $false
        }
        # model_name: <=13 chars ASCII
        $mn = $mon.model_name
        if (-not $mn -or $mn.Length -gt 13 -or $mn -notmatch "^[\x20-\x7E]+$") {
            Write-Host "  [FALHA] monitor.model_name invalido: '$mn' (max 13 chars ASCII)" -ForegroundColor Red
            $monOk = $false
        }

        if ($monOk) {
            Write-Host "  [OK]    Monitor EDID v5 campos validos (PNP=$pnp, model='$mn', week=$wk, year=$yr)" -ForegroundColor Green
            $passed++
        } else {
            $allPassed = $false
        }
    }

    # 10. Monitor edid_serial (legacy) deriva de serial_num (LE)
    $checks++
    if ($mon -and $null -ne $mon.serial_num -and $mon.edid_serial) {
        try {
            $snU32 = [uint32]([System.Numerics.BigInteger]::Parse("$($mon.serial_num)"))
            $expected = Convert-Uint32ToLeHex -Value $snU32
            if ($mon.edid_serial.ToUpper() -eq $expected.ToUpper()) {
                Write-Host "  [OK]    edid_serial deriva corretamente de serial_num (LE): $expected" -ForegroundColor Green
                $passed++
            } else {
                Write-Host "  [FALHA] edid_serial ($($mon.edid_serial)) != derivacao LE de serial_num ($expected)" -ForegroundColor Red
                $allPassed = $false
            }
        } catch {
            Write-Host "  [FALHA] Erro derivando edid_serial de serial_num: $_" -ForegroundColor Red
            $allPassed = $false
        }
    } else {
        Write-Host "  [AVISO] Nao ha serial_num ou edid_serial para checar derivacao" -ForegroundColor Yellow
        $passed++
    }

    # 11. Audio rotation pool — >=2 GUIDs validos
    $checks++
    $guidBracesPattern = "^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$"
    if ($profile.audio -and $profile.audio.rotation_pool) {
        $pool = @($profile.audio.rotation_pool)
        if ($pool.Count -lt 2) {
            Write-Host "  [FALHA] audio.rotation_pool tem $($pool.Count) entradas (min: 2)" -ForegroundColor Red
            $allPassed = $false
        } else {
            $poolOk = $true
            foreach ($g in $pool) {
                if ($g -notmatch $guidBracesPattern) {
                    Write-Host "  [FALHA] audio.rotation_pool contem GUID invalido: '$g'" -ForegroundColor Red
                    $poolOk = $false
                }
            }
            if ($poolOk) {
                Write-Host "  [OK]    audio.rotation_pool tem $($pool.Count) GUIDs validos" -ForegroundColor Green
                $passed++
            } else {
                $allPassed = $false
            }
        }
    } else {
        Write-Host "  [AVISO] Secao audio ausente. Rode -Generate para atualizar." -ForegroundColor Yellow
        $passed++
    }

    # 12. EMAC persistent_uuid — UUID v4
    $checks++
    if ($profile.emac -and $profile.emac.persistent_uuid) {
        $emacU = $profile.emac.persistent_uuid
        if ($emacU -match $uuidv4Pattern) {
            Write-Host "  [OK]    emac.persistent_uuid e v4 valido: $emacU" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "  [FALHA] emac.persistent_uuid nao e v4 valido: $emacU" -ForegroundColor Red
            $allPassed = $false
        }
    } else {
        Write-Host "  [AVISO] Secao emac ausente. Rode -Generate para atualizar." -ForegroundColor Yellow
        $passed++
    }

    # Resultado final
    Write-Host ""
    Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Resultado: $passed/$checks verificações passaram" -NoNewline
    if ($allPassed) {
        Write-Host " - TUDO OK" -ForegroundColor Green
    } else {
        Write-Host " - FALHAS ENCONTRADAS" -ForegroundColor Red
    }
    Write-Host ""
}

# ============================================================
#  -Show : Exibir perfil atual
# ============================================================

function Show-ProfileData {
    param($Profile)

    $p = $Profile

    # Acessar dados de forma compatível com PSCustomObject e Hashtable
    $smbios  = if ($p -is [PSCustomObject]) { $p.smbios }  else { $p["smbios"] }
    $windows = if ($p -is [PSCustomObject]) { $p.windows } else { $p["windows"] }
    $network = if ($p -is [PSCustomObject]) { $p.network } else { $p["network"] }
    $storage = if ($p -is [PSCustomObject]) { $p.storage } else { $p["storage"] }
    $monitor = if ($p -is [PSCustomObject]) { $p.monitor } else { $p["monitor"] }
    $audio   = if ($p -is [PSCustomObject]) { $p.audio }   else { $p["audio"] }
    $emac    = if ($p -is [PSCustomObject]) { $p.emac }    else { $p["emac"] }

    $version = if ($p -is [PSCustomObject]) { $p.version }       else { $p["version"] }
    $genUtc  = if ($p -is [PSCustomObject]) { $p.generated_utc } else { $p["generated_utc"] }
    $cpuDet  = if ($p -is [PSCustomObject]) { $p.cpu_detected }  else { $p["cpu_detected"] }
    $sockMat = if ($p -is [PSCustomObject]) { $p.socket_matched} else { $p["socket_matched"] }

    # Cabeçalho
    Write-Host "  Versão do perfil : " -NoNewline -ForegroundColor Gray
    Write-Host $version -ForegroundColor White
    Write-Host "  Gerado em (UTC)  : " -NoNewline -ForegroundColor Gray
    Write-Host $genUtc -ForegroundColor White
    Write-Host "  CPU detectada    : " -NoNewline -ForegroundColor Gray
    Write-Host $cpuDet -ForegroundColor White
    Write-Host "  Socket           : " -NoNewline -ForegroundColor Gray
    Write-Host $sockMat -ForegroundColor White
    Write-Host ""

    # SMBIOS
    Write-Host "  --- SMBIOS ---" -ForegroundColor Cyan
    $smbiosFields = @(
        @("UUID",                 "uuid"),
        @("System Manufacturer",  "system_manufacturer"),
        @("System Product",       "system_product"),
        @("System Version",       "system_version"),
        @("System Serial",        "system_serial"),
        @("System SKU",           "system_sku"),
        @("System Family",        "system_family"),
        @("Board Manufacturer",   "board_manufacturer"),
        @("Board Product",        "board_product"),
        @("Board Version",        "board_version"),
        @("Board Serial",         "board_serial"),
        @("Board Asset Tag",      "board_asset_tag"),
        @("Chassis Manufacturer", "chassis_manufacturer"),
        @("Chassis Type",         "chassis_type"),
        @("Chassis Version",      "chassis_version"),
        @("Chassis Serial",       "chassis_serial"),
        @("Chassis Asset Tag",    "chassis_asset_tag"),
        @("Chassis SKU",          "chassis_sku"),
        @("Processor Serial",     "processor_serial"),
        @("Processor Asset Tag",  "processor_asset_tag"),
        @("Processor Part#",      "processor_part_num")
    )

    foreach ($field in $smbiosFields) {
        $label = $field[0].PadRight(22)
        $val   = if ($smbios -is [PSCustomObject]) { $smbios.($field[1]) } else { $smbios[$field[1]] }
        Write-Host "  $label : " -NoNewline -ForegroundColor Gray
        Write-Host $val -ForegroundColor White
    }
    Write-Host ""

    # Windows
    Write-Host "  --- Windows ---" -ForegroundColor Cyan
    $winFields = @(
        @("Machine GUID",   "machine_guid"),
        @("SQM Machine ID", "sqm_machine_id"),
        @("Product ID",     "product_id")
    )
    foreach ($field in $winFields) {
        $label = $field[0].PadRight(22)
        $val   = if ($windows -is [PSCustomObject]) { $windows.($field[1]) } else { $windows[$field[1]] }
        Write-Host "  $label : " -NoNewline -ForegroundColor Gray
        Write-Host $val -ForegroundColor White
    }
    Write-Host ""

    # Rede
    Write-Host "  --- Rede ---" -ForegroundColor Cyan
    foreach ($net in $network) {
        $matchStr = if ($net -is [PSCustomObject]) { $net.match } else { $net["match"] }
        $macStr   = if ($net -is [PSCustomObject]) { $net.mac }   else { $net["mac"] }
        # Formatar MAC com separadores
        $macFormatted = ($macStr -replace '(.{2})', '$1-').TrimEnd('-')
        Write-Host "  $($matchStr.PadRight(22)) : " -NoNewline -ForegroundColor Gray
        Write-Host $macFormatted -ForegroundColor White
    }
    Write-Host ""

    # Storage
    Write-Host "  --- Storage ---" -ForegroundColor Cyan
    $seedB64  = if ($storage -is [PSCustomObject]) { $storage.seed_b64 }      else { $storage["seed_b64"] }
    $prefix   = if ($storage -is [PSCustomObject]) { $storage.serial_prefix } else { $storage["serial_prefix"] }
    $length   = if ($storage -is [PSCustomObject]) { $storage.serial_length } else { $storage["serial_length"] }

    Write-Host "  Serial Prefix        : " -NoNewline -ForegroundColor Gray
    Write-Host $prefix -ForegroundColor White
    Write-Host "  Serial Length        : " -NoNewline -ForegroundColor Gray
    Write-Host $length -ForegroundColor White
    Write-Host "  Seed (base64)        : " -NoNewline -ForegroundColor Gray
    # Mostrar apenas os primeiros 20 chars do seed para legibilidade
    if ($seedB64.Length -gt 24) {
        Write-Host "$($seedB64.Substring(0, 24))..." -ForegroundColor White
    } else {
        Write-Host $seedB64 -ForegroundColor White
    }
    Write-Host ""

    # Monitor / EDID (schema v5, completo)
    if ($monitor) {
        Write-Host "  --- Monitor EDID ---" -ForegroundColor Cyan
        $mfrPnP    = if ($monitor -is [PSCustomObject]) { $monitor.mfr_pnp_id }   else { $monitor["mfr_pnp_id"] }
        $prodCode  = if ($monitor -is [PSCustomObject]) { $monitor.product_code } else { $monitor["product_code"] }
        $snNum     = if ($monitor -is [PSCustomObject]) { $monitor.serial_num }   else { $monitor["serial_num"] }
        $mfgWk     = if ($monitor -is [PSCustomObject]) { $monitor.mfg_week }     else { $monitor["mfg_week"] }
        $mfgYr     = if ($monitor -is [PSCustomObject]) { $monitor.mfg_year }     else { $monitor["mfg_year"] }
        $sAscii    = if ($monitor -is [PSCustomObject]) { $monitor.serial_ascii } else { $monitor["serial_ascii"] }
        $modName   = if ($monitor -is [PSCustomObject]) { $monitor.model_name }   else { $monitor["model_name"] }
        $edidLegacy= if ($monitor -is [PSCustomObject]) { $monitor.edid_serial }  else { $monitor["edid_serial"] }

        if ($mfrPnP) {
            Write-Host "  Fabricante (PNP ID)  : " -NoNewline -ForegroundColor Gray
            Write-Host $mfrPnP -ForegroundColor White
        }
        if ($null -ne $prodCode) {
            $pcHex = "0x{0:X4}" -f [int]$prodCode
            Write-Host "  Product Code (LE)    : " -NoNewline -ForegroundColor Gray
            Write-Host "$prodCode ($pcHex)" -ForegroundColor White
        }
        if ($null -ne $snNum) {
            $snHex = "0x{0:X8}" -f [uint32]([System.Numerics.BigInteger]::Parse("$snNum"))
            Write-Host "  Serial Number (LE)   : " -NoNewline -ForegroundColor Gray
            Write-Host "$snNum ($snHex)" -ForegroundColor White
        }
        if ($null -ne $mfgWk -and $null -ne $mfgYr) {
            Write-Host "  Fabricacao (sem/ano) : " -NoNewline -ForegroundColor Gray
            Write-Host "$mfgWk / $mfgYr" -ForegroundColor White
        }
        if ($modName) {
            Write-Host "  Modelo (bloco 0xFC)  : " -NoNewline -ForegroundColor Gray
            Write-Host $modName -ForegroundColor White
        }
        if ($sAscii) {
            Write-Host "  Serial ASCII (0xFF)  : " -NoNewline -ForegroundColor Gray
            Write-Host $sAscii -ForegroundColor White
        }
        Write-Host "  EDID Serial (legacy) : " -NoNewline -ForegroundColor Gray
        Write-Host $edidLegacy -ForegroundColor White
        Write-Host "  (bytes 12-15 do bloco 0 — LE de serial_num)" -ForegroundColor DarkGray
        Write-Host ""
    }

    # Audio (schema v5)
    if ($audio) {
        Write-Host "  --- Audio (MMDevices) ---" -ForegroundColor Cyan
        $pool = if ($audio -is [PSCustomObject]) { $audio.rotation_pool } else { $audio["rotation_pool"] }
        if ($pool) {
            $pool = @($pool)
            Write-Host "  Rotation pool size   : " -NoNewline -ForegroundColor Gray
            Write-Host "$($pool.Count) GUID(s)" -ForegroundColor White
            for ($i = 0; $i -lt $pool.Count; $i++) {
                $label = ("  [$($i+1)] GUID").PadRight(22)
                Write-Host "$label : " -NoNewline -ForegroundColor Gray
                Write-Host $pool[$i] -ForegroundColor White
            }
        }
        Write-Host ""
    }

    # EMAC (schema v5)
    if ($emac) {
        Write-Host "  --- EMAC (Persistent HWID) ---" -ForegroundColor Cyan
        $pu   = if ($emac -is [PSCustomObject]) { $emac.persistent_uuid } else { $emac["persistent_uuid"] }
        $lock = if ($emac -is [PSCustomObject]) { $emac.lock_file }       else { $emac["lock_file"] }
        Write-Host "  Persistent UUID      : " -NoNewline -ForegroundColor Gray
        Write-Host $pu -ForegroundColor White
        Write-Host "  ACL lock file        : " -NoNewline -ForegroundColor Gray
        Write-Host $lock -ForegroundColor White
        Write-Host "  (substitui C:\Users\<user>\emac-uuid — NAO deletar)" -ForegroundColor DarkGray
        Write-Host ""
    }
}

function Invoke-Show {
    $profile = Load-Profile
    if (-not $profile) { return }

    Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "              PERFIL DE HARDWARE ATUAL              " -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""
    Show-ProfileData -Profile $profile
}

# ============================================================
#  Ponto de entrada principal
# ============================================================

Show-Banner

if ($Generate) {
    Invoke-Generate
}
elseif ($Show) {
    Invoke-Show
}
elseif ($Validate) {
    Invoke-Validate
}
elseif ($WriteDriver) {
    Invoke-WriteDriver
}
else {
    Show-Usage
}
