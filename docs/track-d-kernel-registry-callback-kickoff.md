# Track D - Kernel CmRegisterCallback Registry Filter Kickoff

Data: 2026-09-01
Status: design draft. Nao implementado. Sucede a linha Track A / Track SMBIOS
que ja esta em `rstflt.sys` v4.0.10.

Este documento e handoff self-contained para uma nova sessao Claude Code
com zero contexto anterior executar Track D fim-a-fim - do primeiro
patch em C ate PR mergeado. Idioma-padrao para prosa: portugues-BR
ASCII-only (regra `CLAUDE.md`). Caixas tecnicas em ingles sinalizadas
como `> NOTE:`.

Ordem de leitura antes de propor plano:

1. Este arquivo, fim-a-fim.
2. `CLAUDE.md` - convencoes, VM de teste, cert self-signed, gotchas.
3. `docs/emac-recon-v3.md` - recon EMAC atual, resolucao dos blockers
   T1/T2/T4, matriz de cobertura.
4. `docs/roadmap-v41-wmi-intercept.md` - explicitamente NAO fazer o hook
   naive de `DriverObject->MajorFunction[]` (PatchGuard); Track D usa uma
   rota supportada em vez daquela.
5. `driver/rstflt.c` primeiras 200 linhas + secoes `ReplayCpuRegistry`
   e `ApplySmbiosBlobIfCached` - estrutura existente que Track D estende.
6. `driver/makefile.mak` - assinatura obrigatoria via signtool + cert
   self-signed `HWToolkit Test Cert 2026` thumbprint
   `30310EE7644799431FFF099E1194817E813152B9`.
7. `03-instalar-driver.bat` - fluxo de install (UpperFilters + Parameters).
8. `README.md` secoes "Level A" e "Level C" - framing user-facing;
   Track D vira "Level C+" ou "Track D".

---

## 1. TL;DR

Track D adiciona um registry callback kernel-mode ao `rstflt.sys`
(`CmRegisterCallbackEx`) que intercepta leituras de subkey names sob
`HKLM\SYSTEM\CurrentControlSet\Enum\{SCSI,PCI,USB,HID}` e
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\{Render,
Capture}` feitas por `rubinot_dx.exe`, retornando nomes sinteticos
deterministicos derivados do mesmo seed FNV usado pelos spoofers
userland. Motivacao: tres bans empiricos observados 2026-08-31 a
2026-09-01 confirmam H2 - EMAC le NOMES DE SUBKEY via `RegEnumKeyEx`,
e nosso spoof userland so reescreve VALUES dentro dos subkeys, deixando
o nome-fingerprint intacto. Sucesso: MVP intercepta `Enum\SCSI\Disk`,
passa unit test em VM sem BSOD em soak de 24h, e passa teste bare-metal
com criacao de conta + gameplay RubinOT sem ban.

---

## 2. Background - por que Track D

### 2.1 Tres bans empiricos observados

| # | Data | Configuracao | Duracao ate ban |
|---|------|---------------|------------------|
| 1 | 2026-08-31 | Baseline (host limpo, zero spoof) | ~1min pos-login |
| 2 | 2026-08-31 | Level A userland spoof (`04b-aplicar-hwid-emac.bat`) sem persistencia | ~1min pos-login |
| 3 | 2026-09-01 | Fresh identity: PRs #12/#13/#14/#15 aplicados, PCI + EDID re-armados via persistence task, NLS locale spoofer ativo | ~1min pos-login |

Os tres bans reproduzem o mesmo timing e a mesma linha do log EMAC
(`rubinot_delete_uuid.csv`), sinalizando que o servidor tem um
fingerprint estavel do host que sobreviveu a:

- rotacao de `MachineGuid`, `ComputerName`, `Hostname`;
- reescrita de `HardwareID`/`CompatibleIDs`/`DeviceDesc`/`FriendlyName`
  dentro dos subkeys de `Enum\PCI` e `Enum\USB`;
- CPU strings spoofadas via userland scheduled task (WMI-visible);
- EDID reescrito nos monitores;
- Audio endpoint values regenerados;
- NLS locale + PnP re-arm em persistence task no Winlogon.

### 2.2 H2 confirmado empiricamente

`docs/emac-recon-v3.md` secao 3.1 ranqueia as leituras EMAC por volume:
889 eventos em `Enum\USB\*`, 362 em `Enum\PCI HardwareID`, 54 em
`Enum\HID\*`. O detalhe critico que so foi caracterizado apos ban #3:
EMAC usa `RegOpenKey` + `RegEnumKeyEx` sob o root do branch, coletando
os NOMES DOS SUBKEYS. Exemplos concretos que vazam ainda com Level A
ativo:

- `HKLM\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_KINGSTON&Prod_SA400S3` -
  subkey name expoe vendor + model do SSD. Renomear via reg.exe/reg API
  falha (device ativo, boot-critical).
- `HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_10DE&DEV_2488&SUBSYS_140A7377&REV_A1` -
  o subkey PARENT ja carrega o `SUBSYS`. Spoofer PCI atual reescreve
  o VALUE `HardwareID` dentro do leaf, mas o nome do parent no
  enumerator continua com o SUBSYS real.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_046D&PID_C08B\9A38A63339303338` -
  o leaf subkey name E o serial do dispositivo. Volumes agregados de
  889 leituras / sessao. Cross-check com HID.
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{0.0.0.00000000}.{4d36e972-...}` -
  o proprio subkey name e o GUID do endpoint.

### 2.3 Por que user-mode rename nao funciona em live devices

PR #13 tentou tres approaches user-mode de renomear as subkeys contra
devices SCSI/USB/HID/audio em live host. As tres bateram em open-handle
contention mesmo apos `Disable-PnpDevice` + `Stop-Service` em cascata
(audiodg, AudioEndpointBuilder, AudioSrv). Falhas empiricas concretas
observadas 2026-08-31 e 2026-09-01:

**1. `reg.exe export -> regex replace -> reg.exe import -> reg.exe delete /f`**
   (padrao de `spoof-usb-ids.ps1`, `spoof-hid-ids.ps1`,
   `spoof-audio-guids.ps1`): import cria a subkey fake mas o delete do
   original falha com:

       reg.exe delete HKLM\SYSTEM\CurrentControlSet\Enum\USB\
         VID_0781&PID_5583\4C530001060926101140 /f falhou (1):
         ERRO: Acesso negado.

   E, mesmo com `Disable-PnpDevice` explicito antes:

       reg.exe delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
         MMDevices\Audio\Render\{52b483f2-7ba6-4b95-a8f3-fadfffb84187}
         /f falhou (1): ERRO: Acesso negado.

**2. `Disable-PnpDevice` falha em alguns dispositivos com:**

       Disable-PnpDevice falhou (USB\VID_05E3&PID_0608\5&7ba9868&0&11):
         Sem suporte
       Disable-PnpDevice falhou (USB\VID_0C76&PID_2866&MI_00\
         6&39f38c97&0&0000): Falha generica

**3. `Stop-Service AudioEndpointBuilder -Force` + ownership escalation
   (SID S-1-5-32-544 direto, FullControl com `ContainerInherit`) nao
   liberou os handles nos endpoint subkeys**. mmdevapi/wasapi mantem
   handles residuais alem dos servicos parados.

Diagnostico root cause: PnP manager mantem handles abertos aos device
instance keys durante todo o uptime do device (Enum\\*), e o Windows
Audio Session Manager (WASAPI) mantem handles nos MMDevices endpoint
subkeys mesmo apos servico parado. Kernel object manager nega delete
mesmo para SYSTEM/TrustedInstaller enquanto qualquer handle live existir.
PR #13 fake-rollback preveniu orfaos (import + delete-fail -> rollback do
import), mas o spoof em si nunca ocorreu.

Consequencia empirica: banido em 3 tentativas consecutivas com identidade
progressivamente mais spoofada, deixando gap consistente em disk/audio/USB
subkey names.

### 2.4 Safe Mode nao resolve

Safe Mode reduz o pool de handles ativos (audiodg desativado, servicos
non-essential dormentes), mas:

- HID keyboard/mouse continuam bound ao input stack (senao o usuario nao
  consegue interagir para rodar o toolkit).
- Boot disk permanece boot-critical; `Enum\SCSI\Disk&Ven_*&Prod_*`
  correspondente ao volume system continua com handles do storvsc.
- audiodg cobre so partial da superficie MMDevices; endpoints registrados
  sob HKLM sobrevivem.
- Cada teste custa 2 reboots (para safe + para normal + de volta) contra
  ~1min de gameplay antes do ban - pipeline inviavel.

### 2.5 Por que kernel CmRegisterCallback e a resposta arquitetural

Em vez de tentar mudar o dado subjacente (renomear a subkey), Track D
intercepta o READ. Quando `rubinot_dx.exe` chama `RegEnumKeyEx` sobre
`Enum\SCSI`, nosso callback devolve `KEY_BASIC_INFORMATION` /
`KEY_NODE_INFORMATION` com o NAME reescrito para uma versao sintetica
antes que o kernel devolva o buffer ao caller.

`CmRegisterCallbackEx` e uma extensibility API supportada pela
Microsoft (Windows Vista+), documentada em MSDN como "registry
notification callback routine". Nao e um hook, nao e dispatch swap, nao
e patching de estrutura kernel - por isso NAO trigga PatchGuard, ao
contrario da rota rejeitada em `docs/roadmap-v41-wmi-intercept.md`
Option C (swap de `DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL]`
em mssmbios).

> NOTE: The distinction between CmRegisterCallback (supported) and
> DriverObject major function swap (PatchGuard target) is central to
> Track D's safety. See MSDN "Filtering Registry Calls" and the PG
> warnings in `roadmap-v41-wmi-intercept.md` section "Option C". Do
> NOT confuse them.

---

## 3. Architecture - Track D design

### 3.1 Big picture

Track D e uma extensao IN-PLACE do `rstflt.sys` v4.0.10 existente. Nao
cria driver novo. Mantem:

- BOOT_START, UpperFilter de DiskDrive class (necessario porque rubinot
  pode ser lancado imediatamente pos-Winlogon; callback tem que estar
  armado antes).
- Assinatura via `HWToolkit Test Cert 2026` (mesmo makefile).
- Todas as rotinas Track A (`ReplayCpuRegistry`) e Track SMBIOS
  (`ApplySmbiosBlobIfCached`) existentes - Track D e ORTOGONAL a elas.

Adicoes:

- Chamada `CmRegisterCallbackEx` em `DriverEntry`, apos os passos
  existentes, com Altitude `"321000"` (na faixa de "FSFilter Anti-Virus"
  - **NOTA**: 321000 e altitude nao-registrada test-only. Se Track D
  algum dia sair de dev boxes / bare-metal da propria maquina do
  maintainer, requisitar alocacao via Microsoft. Para uso interno atual
  em VM + host de teste, sem impacto operacional.
  Faixa oficial:
  vira a primeira notificacao antes de qualquer outro filter registry
  eventualmente presente).
- Chamada `CmUnRegisterCallback` em `DriverUnload` (que hoje esta
  desregistrado por design - Track D obriga a re-adicionar, ver risco
  na secao 7).
- Handler unico `RstRegistryCallback` que filtra por PID + path +
  operation type.
- Novos valores em `HKLM\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters`
  (ver 3.3).
- Novo script `scripts/track-d-arm.ps1` para configurar Parameters +
  capturar PID do rubinot.

### 3.2 Read intercepts (detalhado)

| Registry path pattern | O que vaza hoje | O que retornar | Dificuldade |
|-----------------------|------------------|-----------------|-------------|
| `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_*&Prod_*` (subkey name via `RegNtPreEnumerateKey`) | vendor + model do disco real | nome sintetico do profile pool (Kingston / Samsung / WD variants) | LOW - substituicao de string. MVP alvo. |
| `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Enum\PCI\VEN_*&DEV_*&SUBSYS_*&REV_*` (subkey name) | VEN + DEV + SUBSYS + REV reais | preservar VEN+DEV+CC, reescrever SUBSYS+REV usando FNV seed - mesma logica do `spoof-pci-hardwareid.ps1` | LOW - regex-split do nome, splice de campos. |
| `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_*&PID_*\<serial>` (leaf subkey name) | VID + PID + serial real do device | preservar VID+PID do parent, gerar serial sintetico deterministico do FNV(seed, real_serial). EXCLUIR HID class parents (input safety - matches `spoof-usb-ids.ps1` allow-list) | MED - precisa consultar parent path + guard input devices. |
| `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Enum\HID\VID_*&PID_*\<serial>` (subkey name) | HID serial | **(POST-MVP, ver secao 4)** - idem USB, sem excluir keyboard/mouse ATIVOS - Windows re-attach depende do nome real; opcao segura: no-op para HID e absorver o risco de detecao | POST-MVP - fora do escopo v5.0.0 |
| `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\{GUID}` e `\Capture\{GUID}` (subkey name) | GUID de endpoint audio | GUID sintetico deterministico do FNV(seed, real_guid) | LOW. |
| `RegQueryValueEx` sobre values dentro dos paths acima (`HardwareID`, `CompatibleIDs`, `LocationInformation`, `DeviceDesc`, `FriendlyName`) | valor real quando spoofer userland nao rodou; valor spoofado quando rodou | reescrever para valor spoofado (defense-in-depth) mesmo se userland nao aplicou | LOW - so encoding correto do buffer. |

### 3.3 Configuration surface

Novos values em `HKLM\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters`:

| Value | Type | Semantica |
|-------|------|-----------|
| `EnableRegCallback` | `REG_DWORD` | Master on/off. `1` = registrar callback em `DriverEntry`. `0` (default) = no-op, mantem compatibilidade backward com installs Level C v4.0.10. |
| `RubinOtPid` | `REG_DWORD` | PID atual a filtrar. `0` = callback e no-op (pass-through). Setado por `scripts/track-d-arm.ps1` ou por process notification callback (opcao B abaixo). |
| `RegCallbackSeed` | `REG_SZ` | 32-hex FNV-1a seed. Espelho de `profile.pci_hardwareid.randomize_seed`. Mesmo seed = mesma saida sintetica em runs paralelos e em reboots. |
| `RegCallbackPathList` | `REG_MULTI_SZ` | Allow-list de root paths a interceptar. MVP: `[ "Enum\\SCSI" ]`. Expansao incremental: `[ "Enum\\SCSI", "Enum\\USB", "Enum\\HID", "Enum\\PCI", "MMDevices\\Audio\\Render", "MMDevices\\Audio\\Capture" ]`. |
| `LastCallbackStatus` | `REG_DWORD` | Breadcrumb pos-callback. Formato: `(tag << 24) | (NTSTATUS & 0xFFFFFF)`. Tags MVP: `0x00 OK`, `0x01 NO-PID` (RubinOtPid=0), `0x02 PID-STALE` (PID nao existe mais), `0x03 PATH-GET-FAIL` (`CmCallbackGetKeyObjectID` falhou), `0x04 BUFFER-OVERFLOW`, `0x05 ALLOC-FAIL`, `0x06 SEH-FAULT` (excecao capturada em `__try`), `0x07 UNREGISTER-FAIL`. Segue o padrao de `LastReplayStatus` que ja existe. |

Espelha exatamente a shape de config de Track A: opt-in explicito,
breadcrumb estruturado, tags simetricas.

Duas opcoes para popular `RubinOtPid`:

- Opcao A - script userland: `track-d-arm.ps1` lanca `RubinOT.exe`, captura
  PID do `Start-Process -PassThru`, escreve no registry via `Set-ItemProperty`.
  Simples, mas se rubinot reiniciar (crash, close-and-reopen), PID fica stale
  ate proxima corrida do script.
- Opcao B - process notification callback no kernel: registrar
  `PsSetCreateProcessNotifyRoutineEx` no DriverEntry, filtrar por image name
  `rubinot_dx.exe` (compare via `PS_CREATE_NOTIFY_INFO->ImageFileName`), escrever
  PID em variavel global do driver (protegido por spinlock). Robusto contra
  restart. Adiciona ~40 LOC no driver e uma superficie extra de callback.

Recomendacao MVP: opcao A. Opcao B fica em `docs/track-d-followup.md`
se o teste bare-metal expuser flakiness por PID stale.

### 3.4 Determinismo (espelha scripts existentes)

Reuse FNV-1a-64 em kernel (implementacao ~30 LOC de C89, well-tested;
mesmo algoritmo de `scripts/spoof-pci-hardwareid.ps1` e
`scripts/spoof-usb-ids.ps1`). Input:

- `RegCallbackSeed` do Parameters (32-hex = 128 bits de seed).
- Real subkey name capturada via `CmCallbackGetKeyObjectID`.

Saida: nome sintetico deterministico. Dado (seed, real_name), o kernel
sempre devolve o mesmo synthetic - reruns produzem fingerprint identico,
o server EMAC ve o mesmo fingerprint em multiplas conexoes sob o mesmo
profile.

Guarantee critical: o synthetic gerado pelo kernel DEVE bater com o
synthetic que os spoofers userland gerariam para o MESMO real_name.
Caso contrario, um leitor que consulte o VALUE spoofado por userland
(v.g. `Enum\PCI\<realname>\HardwareID`) e o NAME sintetico do parent
via kernel percebe inconsistencia. Solucao: mesmo FNV seed + mesmo
input canonical em ambos os caminhos. Escrever testes de golden vector
compartilhados: um input real produzido em host de dev, aplicar userland
e capturar o output, aplicar kernel-simulator (portar o FNV para PS
harness `test-track-d-fnv.ps1`) e conferir byte-exato.

---

## 4. MVP scope (v5.0.0 alpha)

MVP e propositalmente estreito: apenas `Enum\SCSI\Disk`. Justificativa
empirica:

- WMI diagnostic pos-ban #3 confirmou que Kingston, ADATA, XPG, SanDisk
  aparecem no fingerprint. Enum\SCSI e a gap mais concentrada de
  read-name.
- Uma unica intercept path prova o mecanismo E2E: DriverEntry ->
  `CmRegisterCallbackEx` -> filter -> synthetic name -> caller ve
  synthetic. Se o mecanismo falha, sabemos que o kernel path esta
  quebrado, sem confundir com edge cases de outros tipos.
- Se EMAC aceitar login pos-MVP: pronto. Iterar so se precisar.
- Se EMAC ainda banir apos MVP: expandir incrementalmente na ordem
  `Enum\USB` (2a prioridade por volume - 889 reads/sessao),
  `Enum\PCI`, `MMDevices\Audio\{Render,Capture}`, `Enum\HID`.

Nao-goals MVP:

- HID intercept (input-safety risk; se preciso, ativar em v5.1 apos
  soak test).
- Registry write intercept (Track D e read-side only).
- Registry key create/delete intercept.
- Extensao para outros processos alem de rubinot_dx.exe.

---

## 5. Implementation plan

### 5.1 File-level changes

- `driver/rstflt.c`: adicionar bloco Track D (~400 LOC C89). Estrutura:

  ```
  // Globals (BSS)
  LARGE_INTEGER g_RegCallbackCookie;  // returned by CmRegisterCallbackEx;
                                      // retained for lifetime of the driver;
                                      // passed to CmUnRegisterCallback in
                                      // DisarmRegistryCallback and to
                                      // CmCallbackGetKeyObjectID inside
                                      // RstRegistryCallback. MUST live in
                                      // .data/.bss (never stack-local).
  ULONG         g_RubinOtPid;          // hot path read, cold path write
  KSPIN_LOCK    g_RubinOtPidLock;
  UNICODE_STRING g_RegCallbackPathList[8];  // MVP: 1 entry
  UCHAR         g_RegCallbackSeed[16];      // 128-bit FNV seed
  BOOLEAN       g_RegCallbackEnabled;
  volatile LONG g_LastCallbackStatus;

  // Utility
  static ULONGLONG FnvHash64(PCUCHAR seed, ULONG seedLen, PCWCHAR name, ULONG nameLen);
  static VOID     WriteLastCallbackStatus(ULONG tag, NTSTATUS ntStatus);
  static BOOLEAN  IsInterceptedPid(HANDLE Pid);
  static BOOLEAN  IsInterceptedPath(PCUNICODE_STRING KeyPath);
  static NTSTATUS GenerateSyntheticSubkeyName(PCUNICODE_STRING RealName,
                                              PUNICODE_STRING Synthetic);
  static NTSTATUS PopulateEnumInfo(KEY_INFORMATION_CLASS InfoClass,
                                   PVOID KeyInformation,
                                   ULONG Length,
                                   PULONG ResultLength,
                                   PCUNICODE_STRING Synthetic);
  static NTSTATUS PopulateQueryInfo(KEY_VALUE_INFORMATION_CLASS InfoClass,
                                    PVOID KeyValueInformation,
                                    ULONG Length,
                                    PULONG ResultLength,
                                    PVOID SyntheticValue,
                                    ULONG SyntheticSize,
                                    ULONG ValueType);

  // Main callback
  NTSTATUS RstRegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);

  // Register / unregister
  static NTSTATUS ArmRegistryCallback(PUNICODE_STRING RegistryPath);
  static VOID     DisarmRegistryCallback(VOID);
  ```

- `driver/makefile.mak`: nenhuma mudanca se toda a logica ficar no
  mesmo `rstflt.c`. Se preferir split em `rstflt_regcallback.c`, adicionar
  regra `.obj` correspondente + linkar junto.

- `03-instalar-driver.bat`: idealmente nenhuma mudanca imediata; os
  novos values em Parameters sao criados por `track-d-arm.ps1` post-install.
  **Decisao ratificada**: driver trata `EnableRegCallback` ausente como
  0 (default documentado no C code). `03-instalar-driver.bat` NAO muda.
  Arm exclusivamente via `track-d-arm.ps1 -Enable` pos-install.
  (Alternativa considerada e rejeitada: adicionar `reg add ... EnableRegCallback /d 0` como
  seguranca (garante default off em installs frescos).

- `scripts/track-d-arm.ps1` (novo): configura Parameters + opcionalmente
  lanca RubinOT com captura de PID. Signature:

  ```
  scripts\track-d-arm.ps1 [-Enable] [-Disable] [-Launch] [-Diagnose]
    -Enable   sets EnableRegCallback=1, RegCallbackSeed=<profile.pci.seed>,
              RegCallbackPathList=<MVP list>. Requires reboot to take effect
              only if driver already loaded pre-arm; else takes effect next boot.
    -Disable  sets EnableRegCallback=0. No reboot required if callback already
              armed (Cm callback stays registered but IsInterceptedPid returns FALSE
              -> pass-through).
    -Launch   Start-Process rubinot .exe, capture PID, write RubinOtPid.
    -Diagnose read LastCallbackStatus, decode tag+status, print human summary.
  ```

- `docs/postmortem-v5-track-d/incident-v500-mvp-integration.md`
  (scaffold): registro do primeiro postmortem obrigatorio pelo CLAUDE.md
  style ("Every non-trivial toolkit-behavior discovery gets a new
  incident-v50X-*.md"). Preencher pos-teste bare-metal.

### 5.2 Kernel function signatures (proposta)

```
//
// RstRegistryCallback -- CmRegisterCallbackEx handler
//
// Called by the Configuration Manager for every registered pre/post
// registry operation. Runs at PASSIVE_LEVEL on the caller thread.
// Fast-path exits when the callback is not enabled, when the caller is
// not the RubinOT process, or when the target path is outside the
// allow-list.
//
// Returns:
//   STATUS_SUCCESS           - continue with normal registry operation
//   STATUS_CALLBACK_BYPASS   - we populated the output; kernel skips
//                              the real operation and returns to caller
//   any other error          - propagated to caller; use sparingly
//
NTSTATUS
RstRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,   // REG_NOTIFY_CLASS
    _In_ PVOID Argument2    // per-class info struct
    );

//
// GenerateSyntheticSubkeyName -- deterministic FNV-based rewrite of a
// subkey name. Preserves the well-known field prefixes (e.g. VEN_,
// DEV_, VID_, PID_) and rewrites only the identity-bearing fields
// (SUBSYS, REV, serial-tail) so the resulting name still parses as a
// valid PnP instance ID. Uses g_RegCallbackSeed and the input real
// name as combined FNV input. The output UNICODE_STRING is allocated
// from NonPagedPoolNx; caller is responsible for freeing via
// ExFreePoolWithTag.
//
static
NTSTATUS
GenerateSyntheticSubkeyName(
    _In_  PCUNICODE_STRING RealName,
    _Out_ PUNICODE_STRING  Synthetic
    );

//
// PopulateEnumInfo -- fill a KEY_INFORMATION structure with a
// synthetic subkey name, respecting the caller-provided buffer length.
// Handles KeyBasicInformation and KeyNodeInformation classes (MVP).
// On buffer too small, returns STATUS_BUFFER_OVERFLOW with
// ResultLength set to the required size (mirrors kernel ABI so caller
// retries with a larger buffer).
//
static
NTSTATUS
PopulateEnumInfo(
    _In_  KEY_INFORMATION_CLASS InfoClass,
    _Out_writes_bytes_(Length) PVOID KeyInformation,
    _In_  ULONG                 Length,
    _Out_ PULONG                ResultLength,
    _In_  PCUNICODE_STRING      Synthetic
    );
```

O bloco final de assinaturas fica ~120 LOC de prototypes documentados
apos os headers existentes de v4.0.10. Manter estilo C89, comentarios em
ingles (regra do repo).

### 5.3 Adversarial safety review pre-implementation

Este passo NAO E OPCIONAL. Track D e o primeiro codigo kernel do repo
que roda em callback contexto de caller thread (nao em worker thread do
proprio driver), com acesso a estruturas providas por caller
potentially malicioso.

**PatchGuard:** CmRegisterCallbackEx e API supportada da Microsoft
(WDK header `wdm.h`, documentado desde Vista). Nao e hook nem dispatch
swap. PG NAO flagga. Distinguir explicitamente de:

- `DriverObject->MajorFunction[X] = my_handler;` -> PG FLAGGA (option C
  do `roadmap-v41-wmi-intercept.md`, rejeitado la e aqui).
- `KeSetSystemAffinityThread` + inline patch de ntoskrnl -> PG FLAGGA
  (option D do roadmap, rejeitado).
- `CmRegisterCallbackEx` -> supported API, PG safe.

**BSOD scenarios a mitigar:**

1. Unbounded stack use no callback. Callback roda em thread do caller
   com stack potentially ja consumido. Mitigacao: nenhuma recursao, nenhuma
   alocacao no stack maior que 1 KB. Buffers grandes vao para
   `ExAllocatePoolWithTag(NonPagedPoolNx, ...)`.

2. Reentrancia. Callback roda at PASSIVE_LEVEL sob Cm-internal lock.
   Chamar `Zw*` de dentro do callback pode deadlockar. Regra: ZERO
   registry I/O do proprio driver dentro do handler. Config (Parameters
   values) lida uma vez em DriverEntry / arm/disarm e cacheada em globais.

3. Invalid buffer writes. `KeyInformation` e ponteiro caller que pode
   ser user-mode (em processos user-mode que chamam `NtEnumerateKey`
   diretamente) ou kernel-mode. Envolver todo write em `__try/__except`
   (`ProbeForWrite` primeiro se user-mode). Em `EXCEPTION_EXECUTE_HANDLER`,
   `WriteLastCallbackStatus(0x06, GetExceptionCode())` e retornar
   `STATUS_ACCESS_VIOLATION` sem completar bypass.

4. IRQL invariant. Handler DEVE rodar em PASSIVE_LEVEL. Assert via
   `NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)` no topo do handler
   (`PAGED_CODE()` sozinho so garante `IRQL <= APC_LEVEL` + secao
   pageavel; queremos afirmar `== PASSIVE_LEVEL` que Cm garante por
   contrato). Se assert fail em debug build,
   fallback graceful.

5. Path resolution failure. `CmCallbackGetKeyObjectID` pode retornar
   `STATUS_INVALID_PARAMETER` se o key handle ja foi liberado
   (race benign). Tratar como "nao interceptar" -> pass-through -> tag
   0x03 breadcrumb -> continuar.

6. PID staleness. `IsInterceptedPid` compara `PsGetCurrentProcessId()`
   com `g_RubinOtPid`. Se rubinot morreu e PID foi reciclado para outro
   processo, callback afeta processo errado. Mitigacoes:
   - opcao A (Ps callback): remove risco reciclando g_RubinOtPid on
     PROCESS_EXIT_NOTIFY.
   - opcao B (user-mode): assumir risco baixo (janela de segundos
     entre morte de rubinot e reciclagem do PID).

**Callback context invariants:**

- `PsGetCurrentProcessId()` funciona.
- `CmCallbackGetKeyObjectID(&g_RegCallbackCookie, ObjectContext, &keyId, &keyName)`
  funciona (documentado - retorna UNICODE_STRING do full key path).
- PASSIVE_LEVEL garantido.

**STATUS_CALLBACK_BYPASS semantica:**

- Kernel skip do normal registry operation.
- Somos donos de popular `KeyInformation` + `ResultLength`.
- `RegNtPreEnumerateKey` info em `REG_ENUMERATE_KEY_INFORMATION`
  struct: `{ PVOID Object; ULONG Index; KEY_INFORMATION_CLASS
  KeyInformationClass; PVOID KeyInformation; ULONG Length; PULONG
  ResultLength; }`.
- `RegNtPreQueryValueKey` info em `REG_QUERY_VALUE_KEY_INFORMATION`:
  `{ PVOID Object; PUNICODE_STRING ValueName;
  KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass; PVOID
  KeyValueInformation; ULONG Length; PULONG ResultLength; }`.

---

## 6. Test plan

### 6.1 VM unit tests

Ambiente: Hyper-V VM `Ambiente de desenvolvimento do Windows 10` per
CLAUDE.md. Sequencia:

1. Restaurar checkpoint `clean-no-driver`. Desabilitar heartbeat + KVP
   integration services no host (regra CLAUDE.md).

2. Copiar `driver/rstflt.sys` v5.0.0 assinado para VM via `Copy-VMFile`.
   Copiar `scripts/track-d-arm.ps1`.

3. Rodar `03-instalar-driver.bat` para install base (Track A + SMBIOS
   ainda ativos - Track D e ADD-ON).

4. Rodar `track-d-arm.ps1 -Enable` para setar `EnableRegCallback=1`,
   `RegCallbackSeed=<profile seed>`, `RegCallbackPathList=@("Enum\SCSI")`.

5. Reboot.

6. Pos-reboot: escrever PID de um processo de teste em `RubinOtPid`.
   Test process: PowerShell script que faz
   `Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI` e imprime
   nomes.

7. Verificar:
   - PS test process ve subkey names sinteticas (nao real Kingston/etc).
   - Outro PowerShell (PID diferente) do mesmo `Get-ChildItem` ve nomes
     reais (PID filter funcionando).
   - `LastCallbackStatus` decoded via `track-d-arm.ps1 -Diagnose` mostra
     `0x00 OK` (ou `0x01 NO-PID` para chamadas fora do RubinOtPid).
   - `sc query rstflt` ainda `RUNNING`.
   - **NOTA sobre wmic**: `wmic diskdrive get model` do processo de
     teste devolve o valor **REAL** porque wmic e apenas cliente que
     dispara query em `WmiPrvSE.exe`, e e WmiPrvSE que emite os
     `RegEnumKey` reais - WmiPrvSE.PID != RubinOtPid = filtro nao
     dispara. Isso demonstra a mesma limitacao que se aplicaria a
     RubinOT se RubinOT lesse via WMI (que recon v3 afirma NAO fazer).
     Se ban futuro sugerir EMAC virou WMI-based, exige Track E (UMDF
     provider shadow) separado - fora do escopo Track D.
     Teste correto de filtro:
     mostra divergencia (WMI vai a `Enum\SCSI` via WmiPrvSE que tem PID
     proprio - unit test tem que estabelecer que WmiPrvSE nao esta na
     RubinOtPid, entao ve real; test process ve sintetico se ele mesmo
     faz reg query).

8. Kill test process. Escrever novo PID de outro processo em
   RubinOtPid. Verificar que passthrough dos calls do PID morto se
   torna real (tag 0x02 PID-STALE breadcrumb).

9. `track-d-arm.ps1 -Disable`. Verificar que a partir dai todos os PIDs
   veem real (bypass efetivamente desativado por gate `g_RegCallbackEnabled`).

10. Uninstall via `08-desinstalar-driver.bat`. Reboot. Verificar que
    `Enum\SCSI` volta a real, `sc query rstflt` retorna 1060 (nao existe).

### 6.2 VM soak test (24h)

Restaurar checkpoint `clean-v409-installed`, aplicar patch Track D,
armar EnableRegCallback + RegCallbackPathList completo (`Enum\SCSI +
USB + PCI + HID + MMDevices\Audio\Render + Capture`), deixar VM ligada
24h com script sintetico rodando um loop
`Get-ChildItem` + `Get-ItemProperty` sobre os paths cada segundo.
Metricas de aceitacao:

- Zero BSODs.
- `LastCallbackStatus` estavel em `0x00 OK` (ou `0x01 NO-PID` durante
  reboot windows).
- Sem leak crescente de NonPagedPool (medir com `!poolused` em WinDbg /
  perfmon).
- Sem crescimento visivel de tempo por operacao de registry (nao mais
  que 5x baseline sem callback).

### 6.3 Bare-metal RubinOT test

1. Rollback dos spoofs atuais: `08b-rollback-userland.bat`.
2. Uninstall driver anterior: `08-desinstalar-driver.bat`, reboot.
3. Install v5.0.0: `02-compilar-driver.bat` no host de dev, transferir
   .sys assinado, `03-instalar-driver.bat`, reboot.
4. Regenerar profile fresco: `00-gerar-profile.bat` (seed novo).
5. Level A userland spoofs (defense in depth):
   `04b-aplicar-hwid-emac.bat --skip-disk --skip-volume --skip-usb --skip-hid`.
6. Track D arm: `track-d-arm.ps1 -Enable`.
7. Reboot.
8. Pos-reboot: `track-d-arm.ps1 -Launch` (lanca RubinOT.exe, escreve PID).
9. Criar conta nova no client, tentar login, iniciar gameplay.
10. Metricas:
    - Ban? Se sim, extrair:
      - `%USERPROFILE%\emac-uuid` (novo? mesmo?).
      - `C:\Users\xyrlan\AppData\Local\Temp\rubinot_delete_uuid.csv` se
        gerado.
      - `track-d-arm.ps1 -Diagnose` output.
      - WMI diagnostic (`wmic diskdrive get model,serialnumber /format:list`,
        `Get-PnpDevice | Select FriendlyName, InstanceId`).
    - Se sim: entrar em ciclo de expansao (adicionar `Enum\USB`, refazer).
    - Se nao: MVP shipped. Documentar em incident-v500 como SUCCESS,
      abrir followup para hardening (opcao B do process notification
      callback, cover expand paths que EMAC nao le hoje mas podem passar
      a ler).

### 6.4 Rollback path

Mesma sequencia do rollback atual:

1. `08b-rollback-userland.bat` - reverte spoofers userland.
2. `08-desinstalar-driver.bat --skip-fase16` - remove RstFlt + limpa
   UpperFilters.
3. Reboot.

Track D nao adiciona boot dependencies novas: mantem BOOT_START (mesmo
que hoje - v4.0.10). Se DriverEntry falhar (v.g. `ArmRegistryCallback`
retorna erro), `ErrorControl=Normal` (=1) permite boot continuar sem o
driver. Zero brick-boot risk incremental sobre v4.0.10.

Recovery lifeline: `09-recuperar-boot.bat` continua o fallback fim-de-mundo.

---

## 7. Risks and mitigations

| Risk | Sev | Prob | Mitigation |
|------|-----|------|-----------|
| BSOD em callback kernel (violacao IRQL, dereferencia invalida, race sob Cm lock) | HIGH | LOW | SEH `__try/__except` em toda write de buffer caller; PAGED_CODE assert; zero `Zw*` reentrantes; testes com Driver Verifier armado |
| PatchGuard bugcheck | HIGH | VERY-LOW | Confirmado supported API; distinto de dispatch swap; documentar explicitamente em rstflt.c changelog |
| Path resolution falha silenciosa | MED | MED | Breadcrumb `0x03 PATH-GET-FAIL` + pass-through, nunca BSOD |
| Colisao de nome sintetico (dois discos reais mapeiam para mesmo synthetic) | LOW | VERY-LOW | FNV-64 collision negligivel em espaco de <100 devices por host; adicionar counter no tail se colidir na mesma sessao |
| Windows cache do path (leitor le uma vez, cacha, callback nao dispara em subsequent reads) | LOW | MED | Cm callback dispara em toda invocacao de RegEnumKey/RegQueryValueKey; cache seria acima do kernel; benchmark inicial nos testes VM |
| RubinOT detecta anomalia de timing (callback adiciona latencia perceptivel) | LOW | LOW | Overhead esperado ~microssegundos; hot path e string compare + FNV hash + memcpy; benchmark: ate 5x baseline aceitavel |
| Config mismatch (userland spoof escreve valor X, kernel synthetic devolve valor Y quando queried) | MED | HIGH sem controle, LOW com controle | Mesmo FNV seed em ambos os caminhos; teste golden vector; secao 3.4 tem a garantia formal |
| Cert self-signed expira durante desenvolvimento | MED | LOW | Cert atual valido ate 2028-08-30; se expira, `New-SelfSignedCertificate` + update `SIGN_SHA1` + re-import public cert em `Cert:\LocalMachine\Root` do VM |
| DriverUnload re-registrado permite race sc-stop replace race (motivo de v3.6 ter dropado DriverUnload conforme docs/postmortem-v4-phase5/incident-v402-signature-plus-filter.md - UpperFilters walk aponta pra service marcado pra delete -> STOP 0x7B CM_PROB_FAILED_ADD) | MED | MED | Track D re-adiciona DriverUnload SOMENTE para CmUnRegisterCallback (nao restaura DiskDrive UpperFilter attach detach path). Mitigacao: documentar restricao explicitamente - NAO usar `sc stop rstflt` em live system; usar `08-desinstalar-driver.bat` que faz remove UpperFilter dos backups .hwcfg -> reboot -> sc delete na ordem correta |
| PID stale (rubinot morre, PID reciclado) | MED | LOW | Opcao A default; opcao B (Ps callback) disponivel se necessario |
| RubinOT nao usa `NtEnumerateKey` diretamente e sim `SetupDi*` (leitura via um servico intermediario) | MED | LOW | Recon v3 confirmou reads diretos em rubinot_dx.exe PID; se apos MVP for observado servico intermediario, revisar filter para incluir PIDs alvo alem de rubinot |

---

## 8. File-level deliverables checklist

- [ ] `driver/rstflt.c` bump para v5.0.0 com bloco Track D no changelog
      + implementacao completa (~400 LOC).
- [ ] `scripts/track-d-arm.ps1` novo.
- [ ] `docs/track-d-kernel-registry-callback-kickoff.md` (este doc).
- [ ] `docs/postmortem-v5-track-d/incident-v500-mvp-integration.md`
      scaffold (preencher pos-teste).
- [ ] `README.md` novo secao "Track D" ou "Level C+" - default off,
      opt-in explicito, expor comandos.
- [ ] `CLAUDE.md` "Standard commands" adicionar linha
      `Arm Track D: .\scripts\track-d-arm.ps1 -Enable` e
      `Diagnose Track D: .\scripts\track-d-arm.ps1 -Diagnose`.
- [ ] Optional: `03b-instalar-driver-com-track-d.bat` variante se
      seeding de Parameters ficar complexo (provavelmente nao necessario).
- [ ] Optional: `scripts/test-track-d-fnv.ps1` golden vector harness
      para validar equivalencia kernel<->userland do FNV.
- [ ] Update `driver/makefile.mak` apenas se codigo for split em outro
      `.c` (recomendado: manter em rstflt.c para MVP).

---

## 9. Success criteria

MVP e Done quando:

1. VM unit test passa: processo de teste registrado como RubinOtPid ve
   subkeys sinteticas em `Enum\SCSI`; outros processos veem reais;
   `LastCallbackStatus` reporta `0x00 OK` em >= 100 invocacoes seguidas.
2. VM soak 24h sem BSOD, sem leak visivel de NonPagedPool, sem crescimento
   de latencia >5x baseline.
3. Bare-metal RubinOT test: criacao de conta + login + gameplay session
   sem ban. Este e o gate final; se banir mesmo com MVP, entra o loop de
   expansao secao 4.
4. Rollback via `08-desinstalar-driver.bat` restaura sistema limpo, sem
   residuos de callback (verificar no proximo boot que `sc query rstflt`
   retorna 1060 e nao ha `HKLM\...\Services\RstFlt`).

---

## 10. Time estimate

| Bloco | Estimativa |
|-------|------------|
| C kernel code (bloco Track D no rstflt.c + FNV port) | 2-3 dias |
| Script userland `track-d-arm.ps1` + `test-track-d-fnv.ps1` | 0.5 dia |
| VM testes (unit + soak) | 1-2 dias |
| Bare-metal RubinOT test + iteracao possivel (adicionar USB/PCI se banir) | 0.5-1 dia |
| Docs + PR (README, CLAUDE.md, incident-v500) | 0.5 dia |
| **Total** | **4.5-7 dias** (mid-scope MVP) |

Se expansao for necessaria (todos os 6 paths ativos), somar +2 dias
(cada path novo = ~40 LOC + unit test).

---

## 11. Non-goals (explicito)

- **WMI intercept.** Recon v3 confirma que EMAC NAO usa WMI para HWID
  (WmiPrvSE.exe idle na janela de coleta). Se um dia mudar, abrir Track
  E separado via UMDF WMI provider shadow per
  `docs/roadmap-v41-wmi-intercept.md` Option A. Track D NAO cobre WMI.
- **ETW / network intercept.** Fora de escopo. Se um alvo futuro usar
  ETW providers para HWID, abrir Track separado.
- **SMBIOS blob replay.** Track SMBIOS ja existe em v4.0.10 e permanece
  como esta - ortogonal a Track D.
- **CPUID leaves intercept.** Kernel-mode nao pode fake CPUID contra um
  processo user-mode rodando na mesma CPU sem Hyper-V nested / VMX. Se
  um dia relevante, abrir Track separado (fora de qualquer roadmap
  atual).
- **Registry write intercept.** Track D e read-side only. Writes nao
  precisam ser filtered para atacar o problema empirico.
- **Registry key create/delete intercept.** MVP so intercepta EnumerateKey
  e QueryValueKey. Create/Delete inclusos so em expansao futura se algum
  leitor usar-los para probe (nao observado empiricamente).
- **Substituir Level A userland stack.** Track D e DEFENSE IN DEPTH em
  cima de Level A - nao substitui `04b-aplicar-hwid-emac.bat`. Ambos
  ativos simultaneamente cobrem read-name (kernel) + read-value (userland).

---

## 12. References

- [`CLAUDE.md`](../CLAUDE.md) - convencoes do repo, VM Hyper-V,
  cert self-signed, gotchas.
- [`docs/emac-recon-v3.md`](emac-recon-v3.md) - recon EMAC consolidada,
  ranking de reads por volume, gaps abertos.
- [`docs/roadmap-v41-wmi-intercept.md`](roadmap-v41-wmi-intercept.md) -
  warnings explicitos contra PatchGuard-triggering hooks (Option C /
  Option D). Track D usa a rota supported (CmRegisterCallbackEx) em vez
  daquelas.
- [`docs/fase2-kickoff.md`](fase2-kickoff.md) - Fase 2 kickoff (Track A
  historico); referencia de formato deste doc.
- [`docs/fase2-track-a-windows-test-kickoff.md`](fase2-track-a-windows-test-kickoff.md) -
  Track A test kickoff; referencia de estrutura de test plan.
- [`driver/rstflt.c`](../driver/rstflt.c) - driver existente v4.0.10 a
  estender.
- [`driver/makefile.mak`](../driver/makefile.mak) - build + signtool
  obrigatorio.
- [`03-instalar-driver.bat`](../03-instalar-driver.bat) - install flow
  Level C.
- [`08-desinstalar-driver.bat`](../08-desinstalar-driver.bat) - safe
  uninstall.
- MSDN "Filtering Registry Calls" -
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls
- MSDN `CmRegisterCallbackEx` -
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex
- MSDN `REG_NOTIFY_CLASS` enumeration -
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_reg_notify_class
- MSDN `STATUS_CALLBACK_BYPASS` semantics -
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-status-callback-bypass
- Bans empiricos observados (sessao paralela
  display-affinity-lab / RE): 2026-08-31 baseline ban, 2026-08-31
  Level A ban, 2026-09-01 fresh identity com PR #12/#13/#14/#15 ban.
  CSVs em `C:\Users\xyrlan\AppData\Local\Temp\rubinot_*.csv`.

END OF DOCUMENT.
