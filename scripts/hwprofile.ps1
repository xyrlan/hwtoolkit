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
#  Funções auxiliares
# ============================================================

function Show-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║        HWPROFILE  -  Gerador de Perfil HW       ║" -ForegroundColor DarkCyan
    Write-Host "  ║            Perfil centralizado v2               ║" -ForegroundColor DarkCyan
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

    if ($BoardIndex -gt 0 -and $BoardIndex -le $boards.Count) {
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

    # EDID monitor serial (4 bytes aleatórios para substituir bytes 12-15 do bloco EDID 0)
    $edidSerialBytes = Get-CryptoRandomBytes -Count 4
    $edidSerialHex   = ($edidSerialBytes | ForEach-Object { $_.ToString("X2") }) -join ""

    # Montar o objeto do perfil
    $profile = [ordered]@{
        version        = 4
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
            edid_serial = $edidSerialHex
        }
    }

    # Criar diretório se necessário
    if (-not (Test-Path $ProfileDir)) {
        New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
        Write-Host "  [+] Diretório criado: $ProfileDir" -ForegroundColor Green
    }

    # Salvar perfil
    $jsonOut = $profile | ConvertTo-Json -Depth 10
    Set-Content -Path $ProfilePath -Value $jsonOut -Encoding UTF8 -Force
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

    # 8. EDID serial tem 4 bytes (8 hex chars)
    $checks++
    if ($profile.monitor -and $profile.monitor.edid_serial) {
        $edidHex = $profile.monitor.edid_serial
        if ($edidHex -match "^[0-9A-Fa-f]{8}$") {
            Write-Host "  [OK]    EDID serial válido (4 bytes): $edidHex" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "  [FALHA] EDID serial formato inválido: $edidHex (esperado: 8 hex chars)" -ForegroundColor Red
            $allPassed = $false
        }
    } else {
        Write-Host "  [AVISO] Seção monitor/edid_serial ausente (perfil v2?). Rode -Generate para atualizar." -ForegroundColor Yellow
        $passed++  # Não falhar para profiles v2 legados
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

    # Monitor / EDID
    if ($monitor) {
        Write-Host "  --- Monitor EDID ---" -ForegroundColor Cyan
        $edidSerial = if ($monitor -is [PSCustomObject]) { $monitor.edid_serial } else { $monitor["edid_serial"] }
        Write-Host "  EDID Serial (hex)    : " -NoNewline -ForegroundColor Gray
        Write-Host $edidSerial -ForegroundColor White
        Write-Host "  (bytes 12-15 do bloco 0 — serial de fabricacao)" -ForegroundColor DarkGray
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
