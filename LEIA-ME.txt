========================================================
  HW TOOLKIT v4.0 + Fase 2 Track A (CPU registry replay)
  Sistema centralizado de profile + SMBIOS + CPU boot replay
========================================================

OBJETIVO:
  Toolkit completo de spoofing de identificadores de hardware.
  Todos os componentes leem de um profile centralizado para
  garantir consistencia entre si.

RECONHECIMENTO (LEITURA OBRIGATORIA):
  docs/emac-recon-v2.md - findings empiricos corrigidos (procmon
  cross-verified). Supersede o recon v1 (interno, nao versionado)
  que assumia leituras DeviceIoControl / WMI que na realidade nao
  acontecem. Base para decisoes de arquitetura v3.6 (driver
  minimal) e v3.7 (Fase 1.6 registry-only + hotfix MachineGuid).

========================================================
  ESTRUTURA
========================================================

HWToolkit/
  LEIA-ME.txt               <- Este arquivo
  00-gerar-profile.bat      <- Gera profile de hardware (1x)
  01-instalar-ferramentas.bat <- VS Build Tools + WDK (1x)
  02-compilar-driver.bat     <- Compila rstflt.sys (v3.6, SMBIOS replay minimal)
  03-instalar-driver.bat     <- Instala + registra rstflt (SMBIOS boot replay)
  pre-test-checklist.bat     <- Verifier + dump + estado driver (check/arm/disarm)
  04-aplicar-hwid.bat        <- GUIDs, MACs, Product ID, EDID, audio, emac-uuid
  05-aplicar-smbios.bat      <- UUID + strings SMBIOS (Types 1/2/3/4/11)
  06-verificar.bat           <- Verifica tudo
  07-limpar-traces.bat       <- Limpeza de 11 categorias
  08-desinstalar-driver.bat  <- Remove o driver rstflt
  08b-restaurar-smbios.bat   <- Restaura SMBIOS do firmware (limpa spoof)
  09-recuperar-boot.bat      <- Emergencia (WinRE)
  scripts/
    _ui-common.ps1           <- Helpers de output compartilhados (dot-source)
    _smbios-common.ps1       <- Helpers de ACL para mssmbios\Data (dot-source)
    generate-profile.ps1     <- Gerador de profile (v5 schema) [antes: hwprofile.ps1]
    spoof-mac.ps1            <- MAC changer via profile [antes: change-hwid-easy.ps1]
    spoof-smbios.ps1         <- SMBIOS blob modifier (Types 1/2/3/4/11) [antes: spoof-uuid.ps1]
    spoof-audio-guids.ps1    <- Rotate MMDevices audio endpoint GUIDs (GAP #3a)
    spoof-edid-full.ps1      <- Full EDID spoof: PNP ID + product + serial + week/year + descriptor blocks
    manage-emac-uuid.ps1     <- Persist fake emac-uuid file com ACL lock (GAP #6)
    check-consistency.ps1    <- Auditoria read-only: BIOS mirror + cross-check [antes: consistency-check.ps1]
    restore-smbios.ps1       <- Restaura SMBIOS do firmware (limpa spoof) [antes: restore-firmware-smbios.ps1]
  driver/
    rstflt.c                 <- SMBIOS replay v3.6 (minimal - IOCTL removidos)
    rstflt.inf               <- INF do filtro (upper filter de DiskDrive)
    makefile.mak             <- Makefile para rstflt.sys

Profile:
  C:\ProgramData\.hwcfg\profile.json

========================================================
  ORDEM DE EXECUCAO
========================================================

  PRIMEIRA VEZ (setup completo):
    00 -> 01 -> reboot -> 02 -> pre-test-checklist --arm
    -> 03 -> reboot -> 04 -> 05 -> 06 -> 07

  Nota: VolFlt (spoof de VSN via minifilter) foi REMOVIDO em
  v3.5.1. Nao ha 03b. VSN nao esta na cobertura da fingerprint
  do EMAC (ver PROTOCOLO EMAC abaixo).

  Nota (v3.6): Storage IOCTL intercept (disk serial ATA/NVMe)
  tambem foi REMOVIDO do driver. EMAC nao consulta esse vetor
  e os paths tinham historico de BSOD (v3.1-3.4 documentam
  6 correcoes). Driver agora e minimal: apenas SMBIOS replay
  opt-in via EnableSmbiosReplay=1. Ver "MUDANCAS EM v3.6"
  no fim deste arquivo.

  DEPOIS (quando quiser novos IDs):
    00 -> 02 -> 03 -> reboot -> 04 -> 05 -> 06 -> 07

  EMERGENCIA (Windows nao inicia):
    WinRE > Prompt de Comando > 09

========================================================
  O QUE CADA PASSO FAZ
========================================================

  00 - GERAR PROFILE
       Detecta CPU, seleciona board compativel, gera
       todos os IDs de uma vez. Salva em profile.json.
       Roda 1x (ou quando quiser IDs novos).

  01 - INSTALAR FERRAMENTAS
       VS 2022 Build Tools + WDK via winget.
       So precisa rodar 1x. Reboot depois.

  02 - COMPILAR DRIVER
       Compila rstflt.c -> rstflt.sys via nmake.

  03 - INSTALAR DRIVER
       Copia .sys, cria servico system-start, registra
       como upper filter de DiskDrive, escreve SmbiosBlob
       + EnableSmbiosReplay para replay no proximo boot.
       Reboot obrigatorio.

  04 - APLICAR HWID
       Altera Machine GUID, SQM, Product ID, MACs
       (com OUI real), e EDID do monitor (bytes 12-15)
       via spoof-mac.ps1. Alem disso, invoca:
         - spoof-audio-guids.ps1  (rotaciona GUIDs dos endpoints
                                   MMDevices Render/Capture)
         - spoof-edid-full.ps1    (EDID completo: PNP ID, produto,
                                   week/year, serial e descriptor
                                   blocks 0xFC/0xFF)
         - manage-emac-uuid.ps1   (persiste emac-uuid falso com
                                   ACL lock; nao apaga o arquivo)
       Tudo lido do profile.

  05 - APLICAR SMBIOS
       Modifica blob SMBIOS no registro (Types 1/2/3):
       UUID, Manufacturer, Product, Serial, Version.
       Opcao de instalar task agendada para persistir.

  06 - VERIFICAR
       Mostra todos os IDs atuais + roda validacao
       do profile (fabricantes, socket, UUID, MACs).

  07 - LIMPAR TRACES
       11 etapas: processos, arquivos, registro HKCU/HKLM,
       UserAssist ROT13, AppCompat, Jump Lists, Prefetch,
       BAM/SRUM/ShimCache, DNS, GameConfigStore.
       (Event Logs removido em v3.5.1: wevtutil cl gera
       Event 1102 - louder than what it hides.)

  08 - DESINSTALAR DRIVER
       Remove servico, restaura UpperFilters, deleta .sys.

  08b - RESTAURAR SMBIOS DO FIRMWARE
       Limpa o blob SMBIOS spoofado do registro e o cache
       do driver, e desinstala a task agendada de replay.
       Apos reboot, o Windows le SMBIOS direto do firmware
       da placa (valores REAIS). Uso: reverter o spoof
       completo (pos-BSOD, troca de perfil, uninstall limpo).

  09 - RECUPERAR BOOT
       Para WinRE. Carrega registry offline, remove driver
       de ambos ControlSets, restaura UpperFilters.

========================================================
  COBERTURA DE FINGERPRINT
========================================================

  Surface                   Componente               Metodo
  -----------------------   ----------------------   ----------------------
  SMBIOS UUID               spoof-smbios.ps1         Rebuild + cache no driver
  SMBIOS strings            spoof-smbios.ps1         Types 1/2/3 completos + Type 3 SKU
                                                     + Type 4 (proc strings) + Type 11
                                                     (OEM Strings). CPUID nao tocado.
  SMBIOS boot replay        Driver RstFlt            DriverEntry copia blob cacheado
    (v3.6, IOCTL removidos)                          para mssmbios\Data\SMBiosData
                                                     antes de winmgmt/anti-cheat
  CPU registry replay       Driver RstFlt v4.0       Worker system-thread queued em
    (Track A, Fase 2)                                DriverEntry reescreve
                                                     HKLM\HARDWARE\...\CentralProcessor\N\
                                                     {ProcessorNameString, Identifier,
                                                     VendorIdentifier}. Opt-in via
                                                     EnableCpuReplay=1. Backup em
                                                     OrigCpuStrings. Fecha GAP #2.
  Machine GUID              spoof-windows-id.ps1     RESTAURADO em v3.7 (recon v2:
                                                     EMAC LE via RegQueryValueEx
                                                     Buffer Overflow -> Success)
  ComputerName / hostname   spoof-windows-id.ps1     ActiveComputerName + Tcpip Hostname
  SQM Machine ID            (removido em v3.5.1)     EMAC nao le (recon v2 confirmou 0 events)
  Product ID                (removido em v3.5.1)     EMAC nao le (recon v2 confirmou 0 events)
  SCSI Disk model           spoof-disk-registry.ps1  Enum\SCSI\Disk&Ven_*&Prod_* (Fase 1.6)
  PCI HardwareID granular   spoof-pci-hardwareid.ps1 Enum\PCI\...\HardwareID REG_MULTI_SZ
                                                     (SUBSYS+REV+CC) (Fase 1.6)
  Volume GUIDs (Enum)       spoof-volume-guid.ps1    Enum\STORAGE\Volume + MountedDevices
                                                     (Fase 1.6, NUNCA toca volume de boot)
  MAC address               change-hwid              Registry (OUI real)
  EDID monitor serial       spoof-edid-full.ps1      Cobertura completa (ver linhas abaixo)
  Audio endpoint GUIDs      spoof-audio-guids.ps1    HKLM\...\MMDevices\Audio (Render/Capture)
  EDID descriptor blocks    spoof-edid-full.ps1      Blocks type 0xFC (name) + 0xFF (serial ASCII)
  EDID mfr PNP ID           spoof-edid-full.ps1      EDID bytes 8-9 (EISA 3-letter code)
  EDID product/week/year    spoof-edid-full.ps1      EDID bytes 10-11, 16-17
  emac-uuid persistence     manage-emac-uuid.ps1     C:\Users\<user>\emac-uuid + ACL lock
  GameConfigStore           limpar-traces            Registry delete
  Event Logs                (removido em v3.5.1)     wevtutil cl gera Event 1102 - contraproducente
  BAM/DAM                   limpar-traces            Registry values
  SRUM                      limpar-traces            DB delete
  ShimCache                 limpar-traces            Registry delete
  Prefetch                  limpar-traces            File delete
  UserAssist                limpar-traces            ROT13 decode + delete

========================================================
  LIMITACOES CONHECIDAS
========================================================

  - Disk serial (ATA/NVMe) nao spoofado desde v3.6.
    EMAC nao consulta esse vetor no fingerprint atual, e os
    paths de IOCTL intercept do driver (STORAGE_QUERY, SMART
    IDENTIFY, ATA_PASS_THROUGH, ATA_PASS_THROUGH_DIRECT,
    STORAGE_PROTOCOL_COMMAND) tinham historico de BSOD
    (v3.1-3.4 documentam 6 correcoes). Custo > beneficio:
    removido. Se um dia o anti-cheat comecar a consultar
    esse vetor, reintroducao entra em plano.

  - Test signing mode: anti-cheats kernel-level detectam
    a CI policy. Sem DSE bypass, o watermark fica visivel.
    Anti-cheats de nivel EMAC (kernel driver com telemetria
    server-side) pegam o test signing bit. Sem EV cert real
    a ferramenta so passa contra anti-cheats medios.

  - PnPInstanceId dos adapters de rede nao spoofado (GAP #1).
    Anti-cheats que hasheiam esse ID por interface (ex.: EMAC
    coleta os 4 adapters e envia junto do fingerprint) ainda
    identificam a maquina real. Fase 2 (bus filter driver NDIS)
    atende esse caso.

  - ProcessorNameString em HKLM\HARDWARE\DESCRIPTION\System\
    CentralProcessor\0 SPOOFADO em v4.0 (Track A / Fase 2).
    Kernel driver RstFlt agora replays as tres strings
    (ProcessorNameString, Identifier, VendorIdentifier) em
    todos os CentralProcessor\N logicos via CmCallback-free
    approach (ZwSetValueKey em worker thread apos HAL
    popular). Opt-in via EnableCpuReplay=1 (mesma pattern
    do EnableSmbiosReplay). Backup automatico em
    OrigCpuStrings. Fecha GAP #2 completamente.
    NOTA: CPUID (via WMI Win32_Processor.ProcessorId) NAO
    e tocado - vem direto do silicio via cpuid instruction.
    SMBIOS Type 4 tambem nao mexe em bytes 5-15 (CPUID
    dword). Anti-cheat que le HKLM CentralProcessor ve o
    fake; anti-cheat que executa cpuid ve o real. Sao
    dois vetores distintos.

  - GPU Device ID (VEN&DEV) nao esta coberto (filtro PCI
    arriscado, pode causar tela preta com driver NVIDIA).
    Strings da GPU (AdapterString, ChipType) ficam opcionais
    em Fase 2 e exigem teste caso a caso por modelo.

  - Amcache.hve esta locked pelo kernel. Limpar requer
    boot no WinRE.

  - Hostname/ComputerName: coberto em v3.7 via
    spoof-windows-id.ps1 (ActiveComputerName + Tcpip Hostname).
    Renomear via Rename-Computer nao e mais necessario.

  - GAP #5 e GAP #7 (video device GUIDs adicionais e DHCP
    fingerprint em contextos especificos) ficam para Fase 2
    ou aceitos como risco residual dependendo do anti-cheat.

  - Reconhecimento v2 (docs/emac-recon-v2.md) confirmou que
    Fase 1.6 (registry-only) fechou GAPs 7/8/9 (disk model,
    PCI granular HardwareID, Volume GUID). Fase 2 Track A
    fecha GAP #2 (CPU registry mirror). GAP #1 (network
    PnPInstanceId) seria fechavel via CmRegisterCallback
    filtered por PID do RubinOT.exe - considerado pra
    Track B' se procmon pos-v4.0 mostrar necessidade.

========================================================
  PROTOCOLO EMAC / ANTI-CHEATS DE NIVEL AVANCADO
========================================================

  Resumo do reconhecimento feito sobre o protocolo EMAC (anti-cheat
  de kernel com telemetria server-side). Vale para qualquer produto
  similar (BattlEye, EAC, Vanguard usam padroes parecidos).

  - Persistent HWID cache
      Arquivo: C:\Users\<user>\emac-uuid
      Formato: UUID v4 em ASCII (36 bytes, plaintext, sem BOM).
      Escrito na primeira execucao e usado como chave de sessao
      em todos os logins subsequentes.

  - Composicao do fingerprint
      Hash server-side aproximado:
        hash( CPU ProcessorNameString +
              todos os MACs de adapter ativo +
              todos os EDIDs de monitor conectado +
              GUIDs de dispositivo de audio e video )
      Alterar qualquer uma dessas superficies sem alterar as outras
      cria inconsistencia. O toolkit rotaciona todas de uma vez
      via profile centralizado.

  - IMPORTANTE: NAO DELETAR o arquivo emac-uuid
      Deletar o arquivo dispara registration burst pesado do lado
      do cliente (32k+ RegOpenKey observados + POSTs em rajada
      para endpoints Vultr/Cloudflare). Isso e um sinal forte
      para o backend e pode acelerar ban por analise.
      Comportamento correto: usar manage-emac-uuid.ps1 sem -Fresh
      para manter o arquivo persistido, e apenas com -Fresh
      quando toda a rotacao de HW (MAC/EDID/SMBIOS/audio) tambem
      for feita no mesmo ciclo.

  - Screenshot request via WebSocket
      O agente EMAC pode solicitar screenshot on-demand pelo
      canal de telemetria. Desligar overlays antes de logar:
        - Discord overlay
        - MSI Afterburner / RivaTuner
        - Qualquer overlay de cheat / injector
      Overlay visivel na screenshot = ban manual quase certo.

========================================================
  REQUISITOS
========================================================

  - Windows 10/11 x64
  - Conta de administrador
  - Secure Boot DESABILITADO na BIOS
  - ~10 GB livres (para VS Build Tools + WDK)

========================================================
  MUDANCAS EM v4.0.10 (ValidateSmbiosBlob scan window + Build-SmbiosBlob wrapper size)
========================================================

  v4.0.10 - Fix do ValidateSmbiosBlob no driver que rejeitava spuriamente
            TODO blob SMBIOS reconstruido pelo scripts\spoof-smbios.ps1
            em Hyper-V (e provavelmente na maioria dos hosts Windows
            modernos). O breadcrumb LastReplayStatus=0x0300003E que a
            v4.0.9 gerava era esse falso rejeito: o driver rejeitava o
            blob ANTES de sequer tentar escrever no mssmbios\Data.
            Doc principal: docs/postmortem-v4-phase5/incident-v410-smbios-validator-scan-window.md

  Causa (scan window):
    O scan inicial do validador procurava um cabecalho SMBIOS
    (Type 0/1/2/3, Length>=4) nos primeiros 64 bytes do blob,
    comecando em offset 0. Mas os primeiros 8 bytes do blob que
    o driver le do registro sao o wrapper mssmbios documentado:
      [0]  Used21CallingMethod
      [1]  MajVer
      [2]  MinVer
      [3]  DmiRev              (valor 0-3 em Windows moderno)
      [4]  ULONG rawSize LE    (bytes 4..7 = tamanho da tabela)
    O byte 3 (DmiRev) casava com Type 0/1/2/3, e o byte 4 (low
    byte de rawSize DWORD, >=4 pra qualquer tabela nao-vazia)
    casava com o gate Length>=4. A heuristica dava match e
    tableStart colava em 3 em vez de 8. Consequencia: o walker
    das structs rodava tres bytes cedo, nunca alcancava o Type
    127 (End-of-Table), e ValidateSmbiosBlob retornava FALSE.

  Fix:
    - driver/rstflt.c linha 432: loop de scan mudou de
        for (i = 0; ...)
      para
        for (i = 8; ...)
      Ou seja: pula o wrapper mssmbios documentado antes de
      procurar o primeiro header SMBIOS. Impacto zero em blobs
      sem wrapper (nao existe em Windows moderno).
    - driver/rstflt.c linha 442: fallback endurecido de
        tableStart == 0 && Blob[0] > 127
      para
        tableStart == 0
      Bloqueia definitivamente qualquer blob onde o scan nao
      achou header valido, em vez de aceitar por chute.
    - scripts/spoof-smbios.ps1 Build-SmbiosBlob: agora
      recomputa os 4 bytes de raw-size do wrapper (bytes 4..7)
      APOS reemitir as structs Types 1/2/3/4/11. Antes ficava
      stale apontando pro tamanho original do firmware, o que
      podia dessincronizar o wrapper do payload real e trigar
      falhas de walker fora do driver (ex: WMI parsers).
    - scripts/test-smbios-blob.ps1 (novo): porta ValidateSmbiosBlob
      pro PowerShell pra rodar offline. Modos disponiveis:
        -Live       le mssmbios\Data\SMBiosData e valida
        -Cached     le RstFlt\Parameters\SmbiosBlob e valida
        -File <p>   valida arquivo binario em disco
        -Synthetic  gera blob sintetico Hyper-V-like pra
                    validar que o proprio fix da v4.0.10
                    funciona sem instalar driver
    - scripts/spoof-smbios.ps1 Step 10c: agora liga
      Parameters\EnableCpuReplay=1 junto com CpuStrings quando o
      combined arm (sem flags) e usado. Bug historico descoberto na
      verificacao in-VM de v4.0.10: pre-fix, o combined arm cacheava
      CpuStrings mas NUNCA setava EnableCpuReplay=1, entao o
      IsCpuReplayEnabled() do driver retornava FALSE em DriverEntry
      e o worker de CpuReplay nem era enfileirado. Resultado: usuario
      "sente" que armou tudo, mas CPU vazava silenciosamente. Ver
      secao "Second latent bug" no postmortem v4.0.10 para trace
      completo.
    - scripts/spoof-smbios.ps1 -DisableKernelReplay cleanup: agora
      remove tambem EnableCpuReplay junto com CpuStrings. Antes de
      v4.0.10 essa remocao era implicita (a flag nunca era setada,
      entao nao precisava limpar). Agora que Step 10c liga a flag,
      o cleanup precisa remover.
    - Marker RstFltVersion bumpou pra RstFlt-v4.0.10-BUILD-MARKER.

  Como validar apos update:
    .\02-compilar-driver.bat
    .\03-instalar-driver.bat
    # Reiniciar
    .\scripts\spoof-smbios.ps1 -SmbiosOnly
    # Reiniciar
    .\scripts\check-consistency.ps1

    Esperado apos o segundo reboot:
      LastReplayStatus=0x04000000  (tag 0x04 MSSMBIOS-OPEN-FAIL)
    Esse e o steady state documentado em Hyper-V porque o
    mssmbios.sys e SYSTEM_START (Start=1) e sua chave Data
    ainda nao existe quando nosso BOOT_START RstFlt roda.
    Nao e bug: e a evidencia de que passamos da validacao e
    tentamos a escrita no momento certo (so nao encontramos
    o alvo por race natural com o load order).

    NAO deve mais aparecer 0x0300003E. Se ainda aparecer, ver
    docs\postmortem-v4-phase5\incident-v410-smbios-validator-scan-window.md.

  O que este fix NAO resolve:
    WMI-visible spoof em Hyper-V continua ineficaz. O mssmbios
    serve WMI (Win32_ComputerSystemProduct, Win32_BaseBoard,
    Win32_SystemEnclosure, MSSmBios_RawSMBiosTables) DIRETO do
    cache in-kernel populado do firmware no boot, ignorando o
    registro mssmbios\Data completamente. Isso e o Bug 3
    arquitetural confirmado ao vivo na v4.0.9 e permanece
    aberto. Ver docs/roadmap-v41-wmi-intercept.md para o
    proximo passo: IRP_MJ_SYSTEM_CONTROL intercept em
    \Driver\mssmbios ou UMDF WMI provider shadow.

  Descoberta bonus da verificacao in-VM (CpuReplay E WMI-visivel):
    Diferente do Win32_ComputerSystemProduct/BaseBoard/SystemEnclosure
    (Bug 3 arquitetural, servidos do cache in-kernel do mssmbios),
    Win32_Processor.Name le direto do registro
    HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\N\ProcessorNameString,
    exatamente onde nosso driver reescreve. Prova concreta: apos
    ligar EnableCpuReplay=1 manualmente + reboot, check-consistency
    mostrou CPU[0..7] ProcessorNameString todos OK spoofados para
    i5-10600K, E Win32_Processor.Name tambem. Isso significa que
    v4.0.10 nao e so um bug-fix: e uma vitoria real de WMI-spoof
    pra CPU, independente da limitacao arquitetural
    SMBIOS-em-Hyper-V.

  Referencia:
    docs/postmortem-v4-phase5/incident-v410-smbios-validator-scan-window.md

========================================================
  MUDANCAS EM v4.0.9 (Bug 4 fechado + build signing + evidencia ao vivo)
========================================================

  v4.0.9 - Sessao end-to-end de validacao dos 5 bugs do postmortem v4.0.5
           na VM Hyper-V, com todas as provas ao vivo colhidas.
           Doc principal: docs/postmortem-v4-phase5/incident-v407-driver-boot-regression.md

  HOTFIX de assinatura no build (v4.0.7 regression):
    Ao rebuildar v4.0.6 pela primeira vez nesta sessao, a VM entrou em
    loop de Automatic Repair sem bugcheck visivel. Bisecao completa
    (v4.0.7 removeu WriteLastReplayStatus body, v4.0.8 removeu
    RstFltVersion marker+pragma, ate v4.0.4 source PURO do git) todas
    reproduziram identicamente o crash. Root cause identificado
    extraindo o rstflt.sys funcional (21912 bytes, do checkpoint
    pre-v406-test) do guest para o host e comparando: o binario
    funcional tinha um bloco Authenticode PKCS#7 com cert
    "HWToolkit Test Cert 2026" no fim; nossos rebuilds nao tinham.

    Fix: adicionado signtool sign no makefile.mak como ultimo passo
    da regra rstflt.sys. Cert usado: self-signed
    30310EE7644799431FFF099E1194817E813152B9 (HWToolkit Test Cert 2026,
    valido ate 2028-08-30, ja em Cert:\CurrentUser\My do host e
    Cert:\LocalMachine\Root da VM desde v4.0.2 — ver
    incident-v402-signature-plus-filter.md). Timestamped via
    http://timestamp.digicert.com para sobreviver a expiracao do cert.

    NOTA: nunca modifique o makefile.mak sem confirmar que o
    signtool sign step continua depois do link. Sem signature,
    WDAC enforced rejeita BOOT_START driver -> Automatic Repair.

  Bug 4 (crash 52-56s post-arm) - FECHADO como H2 (Hyper-V watchdog):
    Com Pulsacao (Heartbeat) + KVP integration services desabilitados
    NO HOST antes de iniciar a VM, o driver v4.0.9 armado com
    EnableSmbiosReplay=1 booted sem crash algum. Isso confirma por
    eliminacao a hipotese H2: o crash era o host resetando o guest
    via VmHeartbeat watchdog quando o KVP exchange encontrava estado
    inconsistente pos-registry-write. Fix real e do lado guest-agent
    (KVP exchange handling); em bare metal esse mecanismo nao existe
    entao Bug 4 nao se aplica.

    Comando pra reproduzir o fix no host Hyper-V (antes de iniciar a VM):
      Disable-VMIntegrationService -VMName '<nome>' -Name 'Pulsação','Troca do Par Chave-Valor'

    Comando pra reverter (voltar ao behavior brikador):
      Enable-VMIntegrationService  -VMName '<nome>' -Name 'Pulsação','Troca do Par Chave-Valor'

    (Nomes em PT-BR — em EN sao 'Heartbeat' e 'Key-Value Pair Exchange'.)

  Bug 3 (SMBIOS ineficaz) - CONFIRMADO ARQUITETURALMENTE AO VIVO:
    Apos spoof-smbios.ps1 -SmbiosOnly armar EnableSmbiosReplay=1 +
    SmbiosBlob (959 bytes MSI Z490 spoofed) escrito ate no registry
    mssmbios\Data, a query WMI IMEDIATAMENTE depois retornou:
      Win32_ComputerSystemProduct.UUID    = 5B33111A-... (real Hyper-V)
      Win32_ComputerSystem.Manufacturer   = Microsoft Corporation
      Win32_BaseBoard.Manufacturer        = Microsoft Corporation
      Win32_BaseBoard.Product             = Virtual Machine
    Ou seja, WMI SERVIU DO CACHE IN-KERNEL DO MSSMBIOS
    (populado do firmware no boot), IGNORANDO nossa escrita no
    registry. Confirma o Bug 3 arquitetural ao vivo — a estrategia
    inteira de "escrever mssmbios\Data para spoofar WMI" e um
    dead end. Fix real (IRP interception em \Driver\mssmbios ou
    UMDF provider shadow) fica em docs/roadmap-v41-wmi-intercept.md.

  Bug 5 (winmgmt hang) - FECHADO NO RUNTIME:
    spoof-smbios.ps1 completou em <30s (antes travava 60s+). Bug 5
    ficha oficial de fechamento.

  Breadcrumb LastReplayStatus - EVIDENCE-IN-HIVE FUNCIONANDO:
    Primeiro boot com v4.0.9 armado gravou 0x0300003E em
    HKLM\...\RstFlt\Parameters\LastReplayStatus. Decodifica:
      tag=0x03 VALIDATION-FAIL
      NTSTATUS=0x00003E (truncado de STATUS_DATA_ERROR 0xC000003E)
    Ou seja: o ValidateSmbiosBlob() no driver REJEITOU o blob 959-byte
    gerado por spoof-smbios.ps1, antes de tocar mssmbios. Safety net
    do driver funcionando perfeitamente.

    IMPLICACAO: ha um bug latente em spoof-smbios.ps1 Build-SmbiosBlob
    que gera blob que nao passa validacao. Nao critico em Hyper-V
    (Bug 3 arquitetura mata o efeito de qualquer forma), mas
    precisa ser fixado antes de rodar em bare metal onde mssmbios
    pode se comportar diferente. Task de follow-up criada pra v4.1.

  Fix menor:
    scripts/check-consistency.ps1 Read-DriverVersionMarker fazia
    match literal por "RstFlt-v4.0.6-BUILD-MARKER"; agora usa regex
    RstFlt-v(\d+\.\d+\.\d+)-BUILD-MARKER e imprime a versao
    encontrada. Antes reportava falso negativo em v4.0.9+.

  Padronizacao do toolchain (documentado):
    - Visual Studio 2026 Community "VS 18"
      (C:\Program Files\Microsoft Visual Studio\18\Community).
      MSVC 14.51.36231 confirmado bom pra kernel driver builds
      (bisecao provou source-vs-checkpoint byte-equivalente).
    - WDK 10.0.22621
      (C:\Program Files (x86)\Windows Kits\10\...\10.0.22621.0).
      signtool.exe usado em ...\bin\10.0.22621.0\x64.
    - VS 2022 BuildTools se instalado sem workload C++ NAO conta —
      02-compilar-driver.bat prefere VS 18 automaticamente.
    - NAO investigar compiler/linker flag drift como causa de
      boot failures ate ter certeza que signature esta presente
      no rstflt.sys (signtool verify /pa /v).

  Guardrail sugerido pra futuro (opcional em v4.1):
    03-instalar-driver.bat poderia checar signtool verify no .sys
    ANTES de copiar pra System32 — rejeitando com mensagem clara
    se driver nao esta assinado. Isso evita o loop de Automatic
    Repair sem bugcheck que consumiu horas neste ciclo.

  Novo binario:
    driver/rstflt.sys - v4.0.9, 28432 bytes, Authenticode signed,
    SHA256 6E067A2EB1C950A8062D3B79F836FBA92748C68D5FB60E7EF40663AFF134E866
    Compilado com VS 2026 (VS 18) Community + WDK 10.0.22621 + signtool
    (timestamped via digicert.com), /W4 /WX, zero warnings.
    (NOTA: PE tem timestamp embarcado no linker + signature; rebuilds
     do mesmo source geram SHA diferente. Valide via check-consistency.ps1
     -> "[OK] rstflt.sys instalado: v4.0.9" pelo marker embarcado, ou
     signtool verify /pa /v rstflt.sys.)

  Recomendacao para proximo repro na VM (fluxo aprovado):
    Antes:
      Host: Disable-VMIntegrationService -VMName '<nome>' `
            -Name 'Pulsação','Troca do Par Chave-Valor'
    Guest:
      1. 03-instalar-driver.bat  (instala v4.0.9 signed)
      2. scripts\prep-crashdump.ps1  (opcional; so precisa se
         quiser dump em BSOD real futuro. AutoReboot=0 congela em STOP.)
      3. Remove-ItemProperty ...\RstFlt\Parameters
         SmbiosBlob,EnableSmbiosReplay,OrigSmbiosData,CpuStrings,
         EnableCpuReplay,LastReplayStatus -EA SilentlyContinue
      4. scripts\spoof-smbios.ps1 -SmbiosOnly (ou -CpuOnly)
      5. Restart-Computer -Force
      6. Apos boot: scripts\check-consistency.ps1 pra ver
         LastReplayStatus e confirmar estado.

========================================================
  MUDANCAS EM v4.0.6 (Bug 3+5 fechados, Bug 4 evidence)
========================================================

  v4.0.6 - Triage dos 3 bugs abertos no postmortem v4.0.5,
           por workflow multi-agente + investigacao arquitetural.
           Doc principal: docs/postmortem-v4-phase5/incident-v406-bug-triage.md

  Bug 3 (SMBIOS registry replay ineficaz) - ROOT CAUSE ACHADO:
    Dois defeitos empilhados, ambos pela mesma modelo mental errado.

    (a) Arquitetural: mssmbios.sys NAO le HKLM\SYSTEM\...\mssmbios\
        Data\SMBiosData para servir WMI. WMI (Win32_ComputerSystem-
        Product, BaseBoard, SystemEnclosure, MSSmBios_RawSMBiosTables)
        e servida por WmipQueryRawSMBiosTables -> WmipGetRawSMBiosTable-
        Data que le SMBIOS DIRETO do firmware (physical memory scan
        para legacy, ACPI RSMB para UEFI). O registro e cache write-
        back, nao source-of-truth. MSDN diz explicitamente: "consumers
        should continue to use WMI or the GetSystemFirmwareTable() API".
        Ver ReactOS ntoskrnl/wmi/smbios.c.

    (b) Ordem de boot: mssmbios e Start=1 (SYSTEM_START), verificado
        empiricamente 2026-08-30. Nosso RstFlt e Start=0 (BOOT_START).
        RstFlt roda ANTES de mssmbios, entao ZwOpenKey em
        \Registry\Machine\...\mssmbios\Data retorna STATUS_OBJECT_
        NAME_NOT_FOUND — subkey Data e criada pelo proprio mssmbios
        na init dele (provavel REG_OPTION_VOLATILE). Bailamos em
        rstflt.c:490 ANTES do backup path, explicando por que
        Parameters\OrigSmbiosData ficou 0 bytes no postmortem v4.0.5.
        Comentario v4.0 em rstflt.c:1615-1617 afirmava o oposto;
        corrigido.

    Mitigacoes v4.0.6:
    - driver: comentario DriverEntry corrigido para dizer a verdade
      empirica (mssmbios e SYSTEM_START, carrega DEPOIS de nos).
    - driver: novo WriteLastReplayStatus grava breadcrumb REG_DWORD
      em Parameters\LastReplayStatus a cada bail path de
      ApplySmbiosBlobIfCached. Codificacao: (tag<<24)|(NTSTATUS).
      Tags: 0x00 SUCCESS / 0x01 GATE-OFF / 0x02 NO-BLOB /
      0x03 VALIDATION-FAIL / 0x04 MSSMBIOS-OPEN-FAIL /
      0x05 MSSMBIOS-WRITE-FAIL. Em Hyper-V voce vai ver 0x04
      todo boot — isso e o diagnostico esperado, nao um bug.
    - scripts/check-consistency.ps1: nova funcao Read-ReplayStatus
      decodifica e imprime o breadcrumb. Turns evidence-in-hive.
    - scripts/spoof-smbios.ps1: removido gate WMI ($wmiOk) que
      guardava o arming — era placebo (WMI nunca observou nosso
      write). Arming agora e "if $cachedBlob then arm + warn".
    - warning honesta na saida: "em Hyper-V esta cadeia esta
      comprovadamente INEFICAZ contra WMI... bare-metal pode diferir".

    Fix REAL (WMI-visible spoof) pivotado para v4.1 — ver
    docs/roadmap-v41-wmi-intercept.md. Opcoes: (A) UMDF WMI
    provider shadow (baixo risco, testar primeiro), (B) minifilter
    em mssmbios namespace, (C) IRP_MJ_SYSTEM_CONTROL patch via
    PsSetLoadImageNotifyRoutine (alto risco: PatchGuard bugcheck
    0x109). Prototipo bloqueado ate Bug 4 fechar.

  Bug 4 (crash 52-56s post-arm, no bugcheck) - EVIDENCE PIPELINE:
    Nao foi root-caused nesse triage; dump nunca foi capturado.
    Contaminacao de evidencia identificada + corrigida:

    - Grep provou que NENHUM script escreve EnableCpuReplay
      (spoof-smbios so escreve EnableSmbiosReplay). O teste
      "CPU-only" do postmortem v4.0.5 foi armado a mao SEM
      limpar EnableSmbiosReplay=1 do run anterior, entao "CPU-
      only" era na verdade SMBIOS+CPU. Evidencia "mesmo timing
      para dois replays independentes -> causa comum" fica invalida.
    - Hipotese "RstFlt como DiskDrive UpperFilter bloqueia dump
      path" REFUTADA: crash-dump usa stack separada (crashdmp.sys
      + dump_* miniports) que ataca direto no storage port,
      bypassa TODOS os filtros de classe. RstFlt e arquiteturalmente
      invisivel ao KeBugCheck2 dump writer. Removida do postmortem.

    Mitigacoes v4.0.6:
    - NOVO scripts/prep-crashdump.ps1: configura CrashDumpEnabled=1
      (complete), AutoReboot=0, AlwaysKeepMemoryDump=1, IgnorePage-
      fileSize=1, DedicatedDumpFile=C:\rstflt-dump.sys, DumpFile-
      Size=8192 MB. Companion -Restore reverte para default.
      wevtutil sl System /rt:true /ms:262144000 previne rollover
      do System log durante investigacao.
      AVISO: AutoReboot=0 congela na tela STOP; reset manual
      pelo console Hyper-V.
    - scripts/spoof-smbios.ps1: novos switches -SmbiosOnly / -CpuOnly
      mutuamente exclusivos. Cada um LIMPA a chave da outra replay
      antes de armar a propria — garante isolamento REAL entre
      as duas paths. -CpuOnly e early-exit path (nao roda SMBIOS
      nem a query WMI final). Ambos imprimem estado final de
      Parameters antes de sair.

    Fix real espera !analyze -v no proximo repro. Branches esperadas:
    - Se crash desaparece com heartbeat-off no host -> H2 (Hyper-V
      watchdog reset) confirmado, fix e do lado guest-agent, sem
      driver rebuild.
    - Se BSOD congela e dump finaliza -> !analyze -v aponta
      consumer (esperado: sppsvc.exe / Win Activation; ClipSVC;
      CompatTelRunner) -> fix targeted no consumer, nao delay
      cego de 90s no CPU replay (rejeitado como especulativo).
    - Se reset sem dump -> dump-path quebrado, investigacao aparte.

  Bug 5 (Restart-Service winmgmt trava) - FECHADO:
    Cascata SCM de 15+ dependentes bloqueava 60s+. Como Bug 3
    mostrou que a query WMI in-session era placebo (WMI serve
    do cache in-kernel do mssmbios, nao do registry), removi:
      - Restart-Service winmgmt (linha 559)
      - Start-Sleep 2 (linha 560)
      - gate $wmiOk (linhas 606-621)
      - print "Fabricantes CONSISTENTES" (era comparacao inutil)
    Step 12 fica informacional so com -OperationTimeoutSec 5.
    Arming: "if -DisableKernelReplay skip; elseif $cachedBlob
    then Set EnableSmbiosReplay=1 + warn Hyper-V ineffective".
    Safety nets reais nao mudaram: ValidateSmbiosBlob no driver
    rejeita blob malformado; OrigSmbiosData backup preservado.

  Novo binario:
    driver/rstflt.sys - v4.0.6, 20992 bytes,
    SHA256 132CE579A5D56F5F57600CDF0677A49BFD69C82A0E7437871927221EE95F484A
    Compilado com VS 2026 (VS 18) Community + WDK 10.0.22621, /W4 /WX, zero warnings.
    (NOTA: PE tem timestamp embarcado no linker, entao rebuilds do
     mesmo source geram SHA diferente com byte-length identico.
     Valide via check-consistency.ps1 (nova funcao Read-DriverVersionMarker
     imprime "[OK] rstflt.sys instalado: v4.0.6+") ou grep manual pelo marker
     "RstFlt-v4.0.6-BUILD-MARKER" que fica no binario release por
     #pragma comment(linker, "/INCLUDE:RstFltVersion").)

  02-compilar-driver.bat: adicionado suporte para Visual Studio
    18 (2026 Community) alem de VS 2022 — layout mudou de
    "\2022\<edition>\" para "\18\<edition>\".

  Recomendacao para proximo repro na VM:
    1. Reinstalar driver v4.0.6 via 03-instalar-driver.bat.
    2. .\scripts\prep-crashdump.ps1 (uma vez, no guest).
    3. Do host: Disable-VMIntegrationService -VMName <name>
       -Name Heartbeat,'Key-Value Pair Exchange'.
    4. No guest: Remove-ItemProperty ...\RstFlt\Parameters
       SmbiosBlob,EnableSmbiosReplay,OrigSmbiosData,CpuStrings,
       EnableCpuReplay -EA SilentlyContinue (clean slate).
    5. .\scripts\spoof-smbios.ps1 -SmbiosOnly (uma tentativa).
    6. Reboot. Se crash: capturar C:\rstflt-dump.sys, !analyze -v.
    7. Repetir com -CpuOnly para o segundo datum.

========================================================
  MUDANCAS EM v4.0.5 (VM validation session findings)
========================================================

  v4.0.5 - Sessao de validacao end-to-end das Phases 2->6->7->8
           no Hyper-V dev VM (windev2407eval). Achou 5 bugs
           reais antes de tocar no hardware fisico. Detalhe
           completo em docs/postmortem-v4-phase5/
           incident-v405-vm-pipeline-validation.md.

           WINS validados no VM:
             - Phase 8 CPU registry replay: v4.0 crown feature
               provado end-to-end. Todos 8 cores logicos spoofados
               (i7-10700F real -> i5-10600K fake). OrigCpuStrings
               backup preservado. Uninstall path funcional.
             - Phase 6 registry HWIDs: windows-id (MachineGuid,
               ComputerName, TCPIP Hostname), EDID full, EMAC UUID
               todos aplicando corretamente.
             - Phase 2 profile generation + WriteDriver seed OK.

           FIXES aplicados neste commit:

             1) scripts/spoof-smbios.ps1:127 - byte overflow em
                [Math]::Min($len, $Blob.Length - $offset).
                $len e byte (max 255), $Blob.Length-$offset e int
                que passa de 255 em qualquer BIOS moderno (blob
                >= 256 bytes). PS resolvia pro overload Min(byte,
                byte) e falhava o cast. Fix: [int]$len explicit.
                Latente desde spoof-smbios v2 (v3.x); nao pegava
                antes porque Phase 7 nunca completou em campo.

             2) scripts/spoof-mac.ps1 + 04-aplicar-hwid.bat -
                bug do batch abortar apos spoof-mac. spoof-mac
                tinha 3x Read-Host "Pressione Enter para fechar"
                nos exit paths (linhas 27, 48, 120) que travavam
                o batch quando invocado de PS shell parent, com
                cmd.exe emitindo ". was unexpected at this time."
                Fix: adicionado switch -NoPause, todas 3 chamadas
                passam por Wait-Enter que respeita a flag. Batch
                agora invoca com -NoPause. Standalone use (sem
                flag) preserva comportamento pre-v4.0.5.

           BUGS documentados (nao fixados, need WinDbg):

             3) SMBIOS replay ineficaz - driver DriverEntry escreve
                959 bytes fake em HKLM\...\mssmbios\Data mas apos
                reboot o key mostra 1036 bytes originais. mssmbios.sys
                aparentemente sobrepoe nossa write, OU nao lemos/
                escrevemos a key certa. WMI queries continuam
                retornando SMBIOS real Hyper-V. OrigSmbiosData
                (backup) nunca eh escrito. A estrategia "beat
                mssmbios by writing to registry from BOOT_START
                driver" pode precisar rework - talvez como filter
                driver em \\Device\\mssmbios ou como lower filter
                driver do mssmbios.

             4) First-boot-pos-arm crashes ~52-56s em AMBOS os
                replays (SMBIOS e CPU testados isolados). Windows
                registra Event ID 41 (Kernel-Power unexpected
                shutdown) mas nao Event 1001 (BugCheck) e nao
                escreve MEMORY.DMP. Cycle #2 (auto-reboot pos-
                crash) estabiliza; CPU replay applied nesse
                ponto. Padrao identico do timing (~52-56s) sugere
                root cause comum - talvez algum servico ~50s pos-
                boot que le CPU/SMBIOS registry, cracha uma vez
                por inconsistencia, e o SCM marca como "skip this
                boot". UX ruim mas nao data loss. Diagnose via
                WinDbg attach (COM1 pipe ja configurado) +
                !analyze -v.

             5) scripts/spoof-smbios.ps1 trava em Restart-Service
                winmgmt (Step 12, apos armar Parameters). WMI +
                15 dependentes lento pra recuperar; queries pos-
                restart falham com RPC_E_CALL_CANCELED. Ctrl+C
                para o script - Parameters key ja esta armada
                antes desse ponto, entao recuperacao eh trivial:
                pular verificacao WMI, rebootar. Follow-up: rework
                verify+arm pra ser resiliente a WMI travar.

           POSTURA recomendada pro proximo run no hardware fisico:
             GREEN: v4.0.4 correctness, Phase 2, Phase 6 (com MAC
                    real matchando), Phase 8 CPU replay (aceite o
                    crash de cycle #1 unico como quirk conhecido).
             YELLOW: Phase 7 SMBIOS - NAO arme EnableSmbiosReplay
                     ainda ate Bug 3+4 debugados com WinDbg. Deixe
                     SmbiosBlob cachado no Parameters mas skip
                     arm.
             RED:   Phase 6 disk/volume spoofers - risco brick,
                    manual restore point + WinPE stick recomendado.

========================================================
  MUDANCAS EM v4.0.4 (boot correctness patches)
========================================================

  v4.0.4 - Segundo bug de boot: post-boot hang pre-Winlogon.
           Depois do fix v4.0.3 (StartType) eliminar o STOP 0x7B
           primario, o driver carregou mas o guest travou pre-
           Winlogon. Assinatura: uptime crescendo pelo host mas
           HB LostCommunication, CPU 0%, KVP so 7 keys (versus
           21 esperado num boot completo), IP some depois de
           surgir brevemente.

           Root cause: dois defeitos WDM no driver que so
           importam quando o filter roda no boot storage stack
           (o teste VM finalmente exercitou esse path):

             1) DO_POWER_PAGABLE herdado com bitwise OR (linha
                1477 pre-patch): IoCreateDevice defaulta esse
                flag pra 1 (pageable); nossa OR-in nunca CLEAR
                o flag mesmo quando o lower disk.sys FDO tem
                ele zerado pra participar do paging path.
                Filter pageable acima de stack non-pageable
                viola o contrato IRQL de paging IRPs, que
                podem chegar em DISPATCH_LEVEL.

             2) IRP_MN_DEVICE_USAGE_NOTIFICATION nao tratado
                (caia no default pass-through). O kernel manda
                esse IRP quando um device entra/sai do paging
                path (boot volume == paging volume). Sem
                handler proprio, DO_POWER_PAGABLE nunca era
                flippado dinamicamente conforme o disk.sys
                fazia refcount de paging users.

           Fix v4.0.4 em driver/rstflt.c:
             - AddDevice: DO_POWER_PAGABLE agora e assinatura
               EXATA do lower (assign, nao OR). Se lower tem
               cleared, nosso filter tambem tem.
             - DEVICE_EXTENSION ganhou PagingPathCount + FAST_MUTEX
               PagingPathMutex pra serializar as notifications.
             - DispatchPnp trata IRP_MN_DEVICE_USAGE_NOTIFICATION
               explicitamente: forward-and-wait, atualiza
               PagingPathCount sob mutex, flip DO_POWER_PAGABLE
               na transicao 0<->1 (primeiro joiner clear, ultimo
               leaver restore), roll-back se lower retornar erro.
             - Modelado no WDK diskperf sample. Ver
               docs/postmortem-v4-phase5/incident-v404-paging-path.md.

           Combinado com o fix v4.0.3, boot completa clean no
           dev VM (windev2407eval Gen 2 UEFI + storvsc):
             - Uptime cresce monotonico pos-reboot (1 reset)
             - CPU pico 35% (userland real)
             - KVP alcanca 21 keys (full guest agent up)
             - IPv4 restaurada
             - sc query RstFlt: STATE 4 RUNNING, StartType Boot

========================================================
  MUDANCAS EM v4.0.3 (boot correctness patches)
========================================================

  v4.0.3 - STOP 0x7B INACCESSIBLE_BOOT_DEVICE eliminado.

           Historico ate aqui:
             - v4.0 em hardware real: boot freeze silencioso
               (sem BSOD nem dump). Root cause: CPU replay
               worker queued em DriverEntry sem gate check.
             - v4.0.1 hotfix: gate check antes de queue.
               Boot freeze do hardware fixado.
             - v4.0.1 em Hyper-V Gen 2 dev VM: STOP 0x7B em
               todo boot. Bug latente que o freeze de v4.0
               mascarava.
             - v4.0.2 tentou fixar via AlignmentRequirement
               copy no AddDevice (WDM hygiene canonical). Nao
               resolveu o 0x7B (correto mas irrelevante ao
               fluxo defeito).

           Root cause verdadeiro do 0x7B (3-lens adversarial
           research, MSDN "Troubleshooting a Stop 0x7B", WDK
           diskperf INF): servico registrado com StartType=
           SYSTEM_START (1) mas o UpperFilters entry no
           DiskDrive class e walked durante fase BOOT_START.
           PnP tenta instanciar o filter no boot PDO, servico
           nao esta loaded (system-start > boot-start), devnode
           entra em CM_PROB_FAILED_ADD, mount do boot volume
           falha, ntoskrnl bugcheck 0x7B.

           v3.4 tinha explicitamente baixado StartType de boot
           pra system como "safety" contra brick. Foi safety
           incorreta: em vez de proteger, causou o brick assim
           que UpperFilters foi populado. A safety real e
           ErrorControl=Normal (=1): se DriverEntry/AddDevice
           falhar, o kernel loga e continua boot sem carregar
           o driver naquela sessao.

           Fix v4.0.3 em 03-instalar-driver.bat:
             - sc create: start= boot (nao system)
             - Group="PnP Filter" (nao "Filter") - grupo
               canonico de upper filters PnP-enumerated,
               matches WDK diskperf sample INF.
             - error= normal continua (safety contra brick).

           Ver docs/postmortem-v4-phase5/
           incident-v402-signature-plus-filter.md pra research
           completo (3 verifiers adversariais unanimes, 0
           refutados) e incident-v403-startype-boot-order.md
           pra proof de campo do fix.

========================================================
  MUDANCAS EM v4.0
========================================================

  v4.0 - Fase 2 Track A: CPU registry replay via driver.

         Fecha GAP #2 (ProcessorNameString / Identifier /
         VendorIdentifier em HKLM\HARDWARE\DESCRIPTION\
         System\CentralProcessor\N). Anti-cheat que le esses
         valores (recon v2 confirmou EMAC le) agora ve o
         profile em vez do CPUID real.

         Extensao do driver rstflt (v3.6 -> v4.0):
           - Nova funcao ReplayCpuRegistry queued como worker
             system-thread em DriverEntry. Nao bloqueia boot.
           - Opt-in via Parameters\EnableCpuReplay=1 (mesma
             pattern do EnableSmbiosReplay - default 0).
           - Backup automatico em Parameters\OrigCpuStrings
             (REG_MULTI_SZ) na primeira aplicacao.
           - HAL race hardening: aguarda subkey count atingir
             KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)
             antes de enumerar. Pre-check por-valor via
             ZwQueryValueKey garante que so sobrescreve apos
             HAL popular (evita last-writer-wins loss).
           - Blob validation: rejeita DataLength impar,
             enforce caps 128/64/16 wchars por string.
           - Budget total: 10s (100 passes * 100ms). Sem
             impacto em boot time (worker off-thread).

         Profile schema v8 -> v9:
           - Novo bloco 'cpu' com 3 strings deterministicas
             do seed, selecionadas do $CpuPool por socket:
               name_string       (ex.: "Intel(R) Core(TM) ...")
               identifier        (ex.: "Intel64 Family 6 ...")
               vendor_identifier ("GenuineIntel" ou "AuthenticAMD")

         Novo pool em generate-profile.ps1:
           - $CpuPool com 8+ CPUs realistas cobrindo LGA1200,
             LGA1700, AM4, AM5. Selecao filtrada por socket.
           - Parametro -Socket agora funcional (era declarado
             mas nao usado em v3.7).

         Extensoes de spoof-smbios.ps1:
           - Novo Step 10c grava CpuStrings REG_MULTI_SZ em
             Parameters\CpuStrings junto do SmbiosBlob.
           - -Uninstall agora limpa CpuStrings tambem.
           - -Uninstall chama Grant-SmbiosDataWrite ANTES do
             restore (evita silent failure de ACL, v3.7 bug).
           - Type 3 chassis SKU offset corrigido de 0x11 para
             0x15 (pre-existente v3.5 bug: escrevia Height
             byte em vez de SKU string index).

         Extensoes de check-consistency.ps1:
           - Nova secao "CPU registry replay audit" compara
             HKLM CentralProcessor\N com profile.cpu.*.
           - Schema check reconhece v9.
           - Fixed em-dash U+2014 linha 584 (violava contrato
             ASCII-only do arquivo).

         Recovery (09-recuperar-boot.bat):
           - Offline WinRE agora tambem desliga EnableCpuReplay
             + remove CpuStrings. HARDWARE hive e volatil -
             reconstruida com valores reais no proximo boot
             sem intervencao adicional.

         Documentacao Fase 2:
           - docs/fase2-kickoff.md: handoff completo pra
             sessao nova.
           - docs/emac-recon-v2.md: atualizado (GAP #2 fechado).

         Track B (NDIS PnP filter) foi DESCARTADO apos
         analise: EMAC le PnPInstanceId direto do registry
         cache (RegQueryValueEx), nao dispara IRP_MN_QUERY_ID
         em runtime, entao nem LWF nem bus filter cobrem.
         Alternativa Track B' (CmRegisterCallback filtered
         por PID) fica pra pos-v4.0 se procmon mostrar
         necessidade.

         Track C (DSE bypass): decidido aceitar test-signing
         enquanto target for EMAC. Recon v2 nao confirma
         leitura de HKLM\SYSTEM\...\Control\CI\State pelo
         EMAC user-mode.

========================================================
  MUDANCAS EM v3.7
========================================================

  v3.7 - Reconhecimento v2 aplicado. Ver docs/emac-recon-v2.md
         para findings empiricos completos (procmon 7min baseline
         + 18min re-registration burst).

         Correcoes de premissa:
           - MachineGuid E lido pelo EMAC (recon v1 errou).
             Padrao Buffer Overflow -> Success confirma
             RegQueryValueEx em HKLM\SOFTWARE\Microsoft\
             Cryptography\MachineGuid. Hotfix v3.7 restaura
             o campo no profile e cria spoof-windows-id.ps1.
           - EMACDRVGLTB.sys nao coleta HWID. Papel real:
             defesa runtime (ObCallbacks + LoadImage/CreateThread
             notify). 100% da coleta de HWID e user-mode via
             registry.
           - Integrity check do EMAC compara hash de drivers
             bundled (mssmbios.sys, tpm.sys, netbios.sys) vs
             copias em System32\drivers. Impacto para nos:
             NENHUM - so escrevemos no valor de registro
             mssmbios\Data\SMBiosData, nunca no binario .sys.

         Novidades (Fase 1.6, registry-only):
           - spoof-windows-id.ps1: MachineGuid + ComputerName
             + Tcpip\Parameters\Hostname
           - spoof-disk-registry.ps1: reescreve subkeys de
             Enum\SCSI\Disk&Ven_*&Prod_* (modelo/vendor de
             disco falso)
           - spoof-pci-hardwareid.ps1: reescreve HardwareID
             REG_MULTI_SZ em Enum\PCI\VEN_*&DEV_*\{inst}
             (SUBSYS+REV+CC granular)
           - spoof-volume-guid.ps1: reescreve subkeys de
             Enum\STORAGE\Volume\{GUID}#offset + entradas
             correspondentes em MountedDevices. NUNCA toca
             o GUID do volume de boot (C:) - risco de brick.

         Profile schema v7 -> v8:
           - Adicionado windows.machine_guid (restaurado)
           - Adicionado windows.computer_name
           - Adicionado windows.tcpip_hostname (derivado)
           - Adicionado bloco disk_registry (vendor/model
             fakes por instancia SCSI)
           - Adicionado bloco pci_hardwareid (SUBSYS/REV/CC
             fakes por instancia PCI)
           - Adicionado bloco volume_guid (mapa GUID real ->
             GUID fake por volume nao-boot)

         check-consistency.ps1 estendido com novas secoes de
         auditoria (Windows identity, disk registry, PCI HWID,
         volume GUID).

========================================================
  MUDANCAS EM v3.6
========================================================

  v3.6 - Storage IOCTL intercept removido do driver. EMAC
         nao usa esse vetor, e paths tinham historico de
         BSOD (v3.1-3.4 documentam 6 correcoes). Driver
         agora e minimal: apenas SMBIOS boot replay opt-in.
         Profile schema v6 -> v7 (removido bloco storage).

         Impacto pratico:
           - driver/rstflt.c: 1704 -> 778 linhas (metade e
             changelog v1-v3.6 + comentarios de validacao)
           - Registry: SerialSeed/SerialPrefix/SerialLength
             nao sao mais escritos em RstFlt\Parameters
           - profile.json: campo "storage" removido
           - Disk serial ATA/NVMe: valor real e exposto
             (ver LIMITACOES CONHECIDAS)
           - SMBIOS replay: intacto (SmbiosBlob,
             EnableSmbiosReplay, OrigSmbiosData)

========================================================



EXECUTAR SCRIPTS NO POWERSHELL
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
