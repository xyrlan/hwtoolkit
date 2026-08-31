# EMAC Reconnaissance v3 - consolidacao pos-parallel-session

Data: 2026-08-31
Status: recon v3 - consolida evidencia empirica da sessao paralela de RE
(display-affinity-lab), resolve os blockers T1/T2/T4 que ficaram pendentes
na secao "Fase 2 status" do `emac-recon-v2.md` e reescopa o roadmap de
drivers do hwtoolkit vs EMAC.

Supersede: `docs/emac-recon-v2.md` para todo efeito operacional. v2 fica
como registro historico da transicao "recon v1 assumia X - v2 confirma
nao observado". v3 herda todas as conclusoes de v2 que sobreviveram ao
cross-check e adiciona a camada de evidencia que so a sessao paralela
tinha (18 min de procmon em fluxo re-register, 7 min de baseline, PE
recon do `emac-client64.dll` via kernel RPM proprio, e teste ativo com
driver unsigned carregado).

Idioma: prosa em portugues-BR ASCII-only (sem acentos, sem em-dashes,
sem smart quotes - regra `CLAUDE.md`). Racional tecnico em caixas
inglesas sinalizadas como `> NOTE:`.

---

## TL;DR

- EMAC nao checa `testsigning` nem `CodeIntegrity`/`CI\State` nem
  `WMI\Restrictions` nem `SystemStartOptions` nem `BootDriverFlags` nem
  estado `SecureBoot`. Verificado em quatro fases de captura + teste
  ativo com driver unsigned `affctl.sys` carregado durante sessao de
  jogo. Zero reacao do EMAC.
- Coleta de HWID e `100%` user-mode via `RegQueryValueEx`. Zero
  `DeviceIoControl` (qualquer processo, qualquer IOCTL, janela completa
  de 18 min). Zero WMI (`WmiPrvSE.exe` idle). Zero
  `\Device\PhysicalMemory`. Zero `GetSystemFirmwareTable`. Zero
  `NtQuerySystemInformation(SystemFirmwareTableInformation)`.
- Surfaces de leitura ranqueadas por volume: `Enum\USB\*` 889 eventos,
  `Enum\PCI` HardwareID granular 362 eventos, `Enum\HID\*` 54 eventos,
  `Enum\BTH\*` 12 eventos. `Enum\VMBUS`, `Enum\USBSTOR` e `Enum\ROOT`
  ficaram em zero.
- `Network\{4d36e972-...}\{GUID}\Connection\PnPInstanceId` e leitura via
  cache de registry - nao via `IRP_MN_QUERY_ID`. Confirma o pivo
  Track B -> Track B' registrado em v2 (GAP #1) e valida a decisao de
  matar o driver NDIS LWF de bus filter.
- Level A (userland-only, `04b-aplicar-hwid-emac.bat`) cobre TODA a
  superficie EMAC. Level C (03 + 04 + 05 com rstflt SMBIOS blob) fica
  reservado a anti-cheats futuros que consultem via WMI.
- Over-coverage warning: nove grupos de keys populares em outros
  anti-cheats sao empiricamente NAO lidas pelo EMAC. Spoofa-las =
  desperdicio de esforco e vetor extra de detecao (write anomalies
  sem read match).

---

## 1. Fonte e metodologia

O documento canonico da recon empirica passa a ser
[`display-affinity-lab/docs/emac-hwid-recon.md`](../../display-affinity-lab/docs/emac-hwid-recon.md)
rev.3 (2026-08-29). Ele foi produzido na sessao paralela da
`display-affinity-lab` e reune tres probes independentes:

1. PE recon do `emac-client64.dll` via kernel RPM proprio (`affctl`
   driver + `affapp.exe`) que bypassa `ObRegisterCallbacks` do EMAC.
2. Procmon baseline de 7 min in-game normal + captura estendida de 18
   min forcando fluxo re-register (delete de `%USERPROFILE%\emac-uuid`
   entre captura A e captura B).
3. Cross-check por keys populares de outros anti-cheats (grep dirigido
   por SqmMachineId, ProductId, HardwareConfig, TPM, SecureBoot, ...).

Trecos brutos disponiveis no host de RE:

- `C:\Users\xyrlan\AppData\Local\Temp\rubinot_delete_uuid.csv` e
  `.pml` (captura 18 min, fluxo re-register)
- `C:\Users\xyrlan\AppData\Local\Temp\rubinot_capture.csv` (baseline
  7 min in-game normal)

O `hwtoolkit` importa aqui o resumo dessas capturas e trata o
`display-affinity-lab/docs/emac-hwid-recon.md` como single source of
truth de tudo que se refere a comportamento observado do EMAC. Este
`emac-recon-v3.md` e a projecao operacional dessa recon sobre o
roadmap do hwtoolkit.

> NOTE: The `affctl.sys` RPM driver is developed in a different repo
> (`display-affinity-lab`) and never ships as part of `hwtoolkit`. It is
> mentioned here only to document how the read-side evidence was
> gathered. `hwtoolkit` drivers stay defensive (spoof-only), never
> attach to a target process.

---

## 2. Blockers T1/T2/T4 - resolucao

A tabela "Fase 2 status" de `emac-recon-v2.md` lista tres blockers que
travaram o restante do roadmap por falta de evidencia empirica. A
sessao paralela fechou todos os tres.

| Blocker | Escopo original em v2 | Status em v3 | Evidencia empirica |
|---------|------------------------|--------------|---------------------|
| T1 - `PnPInstanceId` de adapter de rede via NDIS LWF ou bus filter | GAP #1 aberto; Track B (LWF + `IRP_MN_QUERY_ID`) proposto e depois rejeitado por hipotese "EMAC le cache". Ficou pendente confirmar. | VERIFIED. Leitura e `RegQueryValueEx` puro sobre `Control\Network\{4d36e972-...}\{GUID}\Connection\PnPInstanceId` - nao sobe pilha NDIS, nao dispara `IRP_MN_QUERY_ID`. Bus filter e LWF sao ambos overkill. | procmon 18 min: 4 adapters enumerados, 4 leituras do valor cached, zero IRP correspondente. |
| T2 - CPU `ProcessorNameString`/`Identifier`/`VendorIdentifier` via caminho user-mode alternativo | GAP #2 CLOSED em v4.0 por Track A (rstflt BOOT_START reescreve registry mirror). Faltou confirmar se EMAC le mesmo o mirror e nao usa `__cpuid`/`cpuid` inline. | VERIFIED. EMAC le `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\N\ProcessorNameString` via registry, nao emite `cpuid` na `.text` visivel do `emac-client64.dll`, e o Win32_Processor tambem serve dessa mesma key. | procmon: leitura repetida de `ProcessorNameString` por PID rubinot. PE recon: `.text` legivel do modulo nao contem `cpuid` inline pattern (parte pode estar em `.emac` VMProtect - mas se a via user-mode e registry, spoof user-mode do valor la e suficiente para o read visivel). |
| T4 - `testsigning`, `CI\State`, `WMI\Restrictions`, `SystemStartOptions`, `BootDriverFlags`, `SecureBoot` state | Track C proposto como policy decision (EV cert vs BYOVD vs accept-and-document). Assumido que EMAC poderia checar essas keys. | VERIFIED. EMAC nao le NENHUMA delas. Zero eventos em 25 min combinados de captura, cross-check com WmiPrvSE.exe idle, e teste ativo carregando `affctl.sys` unsigned dentro da sessao de jogo (zero reacao). | procmon + grep dirigido; teste ativo com driver unsigned atrelado a testsigning ON no host de RE. |

Consequencia direta: Track C (EV cert vs BYOVD vs accept) pode fechar
com **accept-and-document** - EMAC nao alcanca o watermark de
testsigning e nao consulta as flags de DSE. Isso libera o hwtoolkit
para operar contra EMAC com driver auto-assinado + `bcdedit /set
testsigning on` sem risco de detecao pelo alvo em questao. Para outros
anti-cheats no futuro (EAC / BE / Vanguard) a analise volta a ser
individual.

---

## 3. Superficies de leitura EMAC - expandidas

Contagens absolutas da captura 18 min re-register, cross-verificadas
contra o baseline 7 min. A coluna "Coberto por" indica o
script/driver que ja tramita a superficie ou o novo script Phase 1
proposto quando ha gap.

### 3.1 Enum\* branches (novos)

| Branch | Eventos rubinot_dx.exe | Cobertura | Notas |
|--------|-------------------------|-----------|-------|
| `Enum\USB\*` | 889 | GAP - `spoof-usb-ids.ps1` (novo, Phase 1) | Le `ROOT_HUB30\<inst>`, `USB\VID_*&PID_*`, mais `CompatibleIDs` + `DeviceDesc` + `FriendlyName`. Skip: teclado/mouse ativos (guardas de seguranca) |
| `Enum\HID\*` | 54 | GAP - `spoof-hid-ids.ps1` (novo, Phase 1) | HID enum. Skip: input device primario ativo. |
| `Enum\BTH\*` | 12 | GAP - opcional Phase 1 | Bluetooth stack enum. Volume baixo. |
| `Enum\VMBUS` | 0 | Skip | Confirma que EMAC nao usa VMBUS enum como anti-VM (Hyper-V-visivel). |
| `Enum\USBSTOR` | 0 | Skip | Confirma que storage USB nao adiciona superficie alem de `Enum\SCSI` que ja e coberto. |
| `Enum\PCI\...\HardwareID` | 362 | `spoof-pci-hardwareid.ps1` (existente) | SUBSYS+REV. VEN/DEV nao spoofados por design. |
| `Enum\ROOT` | 0 | Skip | Root devices nao entram no fingerprint. |

### 3.2 Superficies ja conhecidas de v2 - contagens confirmadas

| Vetor | Eventos | Cobertura | Notas |
|-------|---------|-----------|-------|
| `MachineGuid` | 1 (buffer-overflow probe + read) | `spoof-windows-id.ps1` | Single high-signal read. |
| `ComputerName` (ActiveComputerName) | 1 | `spoof-windows-id.ps1` | Confirmado v3. |
| Tcpip `Hostname` | 1 | `spoof-windows-id.ps1` | Usualmente == ComputerName. |
| `Network\{GUID}\Connection\PnPInstanceId` | 4 (uma por adapter) | GAP - `spoof-network-pnpid.ps1` (novo, Phase 1) | Leitura de cache registry, valor stable across reboots. Escrita ok - bus enumeration nao rebuild essa key especifica ao contrario do `Enum\...\<InstanceId>` node. |
| `CentralProcessor\N\ProcessorNameString`/`Identifier`/`VendorIdentifier` | 3 * N cores | Existente driver `rstflt` v4.0 (Level C) + novo `spoof-cpu-userland.ps1` (Level A / Phase 1) | HARDWARE hive e volatile; kernel repopula do CPUID a cada boot. Level A: userland scheduled task no Winlogon. Level C: driver BOOT_START. |
| `Enum\DISPLAY\<PNP>\<INST>\Device Parameters\EDID` | 3 monitores | `spoof-edid-full.ps1` (existente) | 128 bytes cada, blocks 0xFC e 0xFF sao os load-bearing. |
| `Enum\STORAGE\Volume\{GUID}#<hex>` | 3 volumes | `spoof-volume-guid.ps1` (existente) | Boot volume protegido, nunca spoofado. |
| `Enum\SCSI\Disk&Ven_*&Prod_*\<instance>` | 3 drives | `spoof-disk-registry.ps1` (existente) | Ex.: `Kingston_SA400S3`, `IM2P33F3_NVMe_AD`, `XPG_GAMMIX_S70_B`. |
| `MMDevices\Audio\{Render,Capture}\{GUID}` | Enderecos multiplos | `spoof-audio-guids.ps1` (existente) | Per-endpoint fingerprint. |
| `HARDWARE\DEVICEMAP\VIDEO`, `CONTROL\VIDEO\{...}\0000` | Multiplos | `spoof-edid-full.ps1` cobre a via principal | GPU fingerprint - ja atacado via EDID. |

Total de leituras registry de superficie de HWID por fluxo re-register:
`~16.317 RegQueryValue` + `~32.227 RegOpenKey`, dominados por
`Enum\USB` + `Enum\PCI HardwareID`.

---

## 4. O que EMAC NAO le - over-coverage warning

Grep dirigido por key path sobre a captura 18 min mostra zero eventos
para os grupos abaixo. Cada uma foi ativamente consultada pelo processo
de recon (query especifica no CSV, filtrada por `rubinot_dx.exe` e
tambem pelo trace global para descartar coleta cross-processo por
`WmiPrvSE.exe` ou `svchost`).

| Key path (grupo) | Uso tipico em outros anti-cheats | Contagem EMAC |
|------------------|----------------------------------|----------------|
| `HKLM\SOFTWARE\Microsoft\SQMClient\MachineId` | HWID SQM Microsoft | 0 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId` | Install ID (OEM) | 0 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId` | Idem binary | 0 |
| `HKLM\SYSTEM\HardwareConfig\*` | HWID hash oficial do Windows | 0 |
| TPM (`tbs.dll`, `\Device\Tpm`, `Enum\TPM\*`) | Attestation TPM | 0 - `tpm.sys` bundled em `C:\Program Files (x86)\RubinOT 2.0\` e HASH-ONLY integrity check, nao usado runtime |
| SecureBoot state (`Control\SecureBoot\State`) | Boot integrity | 0 |
| `HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\*` | Hardware profile ID (legado XP) | 0 |
| `HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\*` | Root devices | 0 |
| `HKLM\SYSTEM\CurrentControlSet\Control\CI\State` | DSE / test-signing state | 0 |
| `HKLM\SOFTWARE\Microsoft\WBEM\CIMOM\*` (`WMI\Restrictions`) | WMI posture check | 0 (foi listado como leitura em v2 mas revisao rev.3 do doc paralelo removeu - deixado apenas como leitura ocasional de baixo peso) |
| `SystemStartOptions`, `BootDriverFlags` | Boot flags | 0 |

Consequencia operacional: spoofar essas keys tem **impacto zero no
fingerprint EMAC** e ainda pode ser detectado por outro anti-cheat que
consulte-as e observe valor recem-escrito (write anomaly). Ficam
fora do escopo de todos os spoofers do hwtoolkit contra EMAC.

> NOTE: Two caveats. (a) `WMI\Restrictions` was listed as read in
> `emac-recon-v2.md`; rev.3 of the parallel doc downgrades this to
> "occasional low-weight read" - deliberately not spoofed here since
> writing it would produce a suspicious posture without a matching
> read pattern. (b) `SystemSetupInProgress` and `PnpSetupInProgress`
> ARE read (anti-VM heuristic) but they only fingerprint the box as
> "not in OOBE", which is the expected steady state - no spoof needed.

---

## 5. Coverage matrix - hwtoolkit scripts x EMAC surfaces

Estado consolidado, apos parallel-session recon. Colunas indicam se a
superficie e coberta em Level A (userland, sem driver) e/ou Level C
(userland + driver `rstflt` BOOT_START replay).

| Surface | Script/Driver | Level A | Level C |
|---------|---------------|---------|---------|
| `MachineGuid` | `spoof-windows-id.ps1` | Yes | Yes |
| `ComputerName` + Tcpip Hostname | `spoof-windows-id.ps1` | Yes | Yes |
| Network `PnPInstanceId` (4 adapters) | `spoof-network-pnpid.ps1` (novo Phase 1) | Yes | Yes |
| CPU `ProcessorNameString`/`Identifier`/`VendorIdentifier` | `spoof-cpu-userland.ps1` (novo Phase 1) + `rstflt` v4.0 BOOT_START replay | Yes (scheduled task Winlogon) | Yes (BOOT_START driver) |
| `Enum\USB\*` HardwareIDs/CompatibleIDs | `spoof-usb-ids.ps1` (novo Phase 1) | Yes | Yes |
| `Enum\HID\*` HardwareIDs | `spoof-hid-ids.ps1` (novo Phase 1) | Yes | Yes |
| `Enum\PCI HardwareID` (SUBSYS+REV) | `spoof-pci-hardwareid.ps1` | Yes | Yes |
| `Enum\SCSI\Disk&Ven_*&Prod_*` | `spoof-disk-registry.ps1` | Yes | Yes |
| `Enum\STORAGE\Volume\{GUID}` | `spoof-volume-guid.ps1` | Yes | Yes |
| `Enum\DISPLAY\*\EDID` (3 monitores) | `spoof-edid-full.ps1` | Yes | Yes |
| `MMDevices\Audio\{Render,Capture}\{GUID}` | `spoof-audio-guids.ps1` | Yes | Yes |
| MAC per adapter (registry `NetworkAddress`) | `spoof-mac.ps1` | Yes | Yes |
| SMBIOS Types 0/1/2/3/4/11 | `rstflt.sys` BOOT_START blob replay | No (EMAC nao le SMBIOS via WMI) | Yes (relevante contra WMI-reading anti-cheats futuros) |
| `emac-uuid` (`%USERPROFILE%\emac-uuid`) | `manage-emac-uuid.ps1` | Yes | Yes |

Batches novos:

- `04b-aplicar-hwid-emac.bat` - Level A EMAC-only. Roda so os spoofers
  que EMAC efetivamente le. Recomendado como default contra EMAC.
- `08b-rollback-userland.bat` - reverte todos os spoofers userland (le
  os backups `.hwcfg\<name>-backup.json`). Nao mexe em driver.

Batches herdados (mantidos):

- `04-aplicar-hwid.bat` - Level A completo (roda TUDO). Fica reservado
  a testes exploratorios ou a anti-cheats desconhecidos onde ainda nao
  se sabe o escopo de leitura.
- `05-aplicar-smbios.bat` + `03-instalar-driver.bat` - Level C.
  Opt-in explicito por comando.

---

## 6. Driver kernel - re-escopo estrategico

Contra **EMAC especificamente**, `rstflt.sys` (BOOT_START + UpperFilter
de DiskDrive + SMBIOS blob replay + CPU registry replay v4.0) e
**overkill**. Justificativa:

1. EMAC nao le SMBIOS via WMI (`WmiPrvSE.exe` idle). O blob replay do
   `rstflt` alvo `mssmbios\Data\SMBiosData`, cuja chain de leitura passa
   por `Win32_ComputerSystemProduct` / `Win32_BaseBoard` etc via WMI -
   caminho nunca acionado por EMAC.
2. CPU registry replay v4.0 do `rstflt` continua util, mas a mesma
   superficie e cobrivel via userland scheduled task no `Winlogon`
   trigger (o novo `spoof-cpu-userland.ps1`). Vantagem do userland:
   nao exige `testsigning ON`, nao acorda o WDAC de host, nao gera
   watermark, nao arrisca boot loop.
3. UpperFilter de DiskDrive so faz sentido para inline hook de IOCTL
   storage - e EMAC emite zero IOCTLs para storage. Zero valor
   agregado contra o alvo em questao.

Decisao para o proximo release do hwtoolkit:

- **Default recomendado contra EMAC**: Level A via
  `04b-aplicar-hwid-emac.bat`. Sem driver, sem `testsigning`, sem risco
  de boot loop. Reversao trivial via `08b-rollback-userland.bat`.
- **Opt-in Level C**: `03` + `04` + `05` completo. Fica documentado no
  README como via para anti-cheats futuros que consultem SMBIOS via
  WMI (EAC/BE tem essa tendencia). Nao remover o driver do repo - o
  investimento de v3.6 -> v4.0.10 permanece util para pipeline futuro.
- **Roadmap v4.1 WMI intercept** (`docs/roadmap-v41-wmi-intercept.md`)
  continua valido para o mesmo objetivo generalista - so nao e
  necessario contra EMAC.

> NOTE: This is a scope decision, not a code deprecation. `rstflt.sys`
> stays maintained and signed; the change is that `README.md` promotes
> Level A as the default flow against EMAC, and the driver install is
> gated behind an explicit opt-in. No files are removed from the repo
> in this doc; the actual doc-and-batch changes land in the next PR.

---

## 7. Cross-check reproducibility

Comandos para reproduzir as contagens da secao 3 diretamente contra os
CSVs no host de RE (Git Bash disponivel; `wc -l` e `grep` funcionam):

```
# Baseline vs re-register total events por processo:
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | wc -l
grep '"rubinot_dx.exe"' rubinot_capture.csv | wc -l

# USB enum reads:
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep 'Enum\\\\USB' | wc -l

# HID enum reads:
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep 'Enum\\\\HID' | wc -l

# BTH enum reads:
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep 'Enum\\\\BTH' | wc -l

# VMBUS / USBSTOR / ROOT - devem retornar zero:
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep 'Enum\\\\VMBUS' | wc -l
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep 'Enum\\\\USBSTOR' | wc -l
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep 'Enum\\\\ROOT' | wc -l

# PCI HardwareID granular (SUBSYS/REV):
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep 'Enum\\\\PCI' | grep 'HardwareID' | wc -l

# Network PnPInstanceId (per-adapter):
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep 'Connection\\\\PnPInstanceId' | wc -l

# CPU registry mirror:
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep 'CentralProcessor' | wc -l

# Over-coverage check - devem TODAS retornar zero:
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep -i 'SqmMachineId' | wc -l
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep -i 'ProductId' | wc -l
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep -i 'DigitalProductId' | wc -l
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep -i 'HardwareConfig' | wc -l
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep -i 'SecureBoot' | wc -l
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep -i 'IDConfigDB' | wc -l
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep -i 'Enum\\\\ROOT' | wc -l
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep -i 'CI\\\\State' | wc -l

# IOCTL check - deve retornar zero para RubinOT:
grep '"rubinot_dx.exe"' rubinot_delete_uuid.csv | grep -i 'DeviceIoControl' | wc -l

# WMI - WmiPrvSE.exe deve estar idle na janela HWID:
grep '"WmiPrvSE.exe"' rubinot_delete_uuid.csv | wc -l
```

Escapes `\\\\` sao para (a) escape shell, (b) escape regex, (c) escape
para atravessar o CSV que ja escapou os backslashes. Se ajustar o
delimitador do procmon export, reduzir para o par correto.

---

## 8. VM Hyper-V smoke test findings (2026-08-31)

Smoke test of Level A pipeline against a clean Hyper-V dev VM. Purpose: prove
that the userland spoof stack (no kernel driver) touches the surfaces EMAC
reads, and separate real bugs from environment-only limitations.

**Environment:** Hyper-V Gen 2 UEFI Win10 Enterprise VM (windev-image) on
`clean-no-driver` checkpoint. `04b-aplicar-hwid-emac.bat` executed with
`--skip-disk --skip-volume --skip-usb --skip-hid` (subsystems irrelevant or
absent on this VM).

### Validated

- **spoof-cpu-userland (CRITICAL path):** SYSTEM task
  `\HWToolkit\SpoofCPUUserland` registered, fired `AtLogOn` ~15s post-boot,
  `LastTaskResult=0`, log reports "8 cores patched". `Win32_Processor.Name`
  reflects `profile.cpu.name_string` (Intel i5-10600K). Registry
  `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0..7` also patched.
  **Confirms Level A covers CPU via WMI without a kernel driver** - the
  original motivation for spawning v4.1 WMI-intercept work is not blocking
  Level A parity for CPU identity.
- **MachineGuid + ComputerName + Hostname:** applied by `spoof-windows-id`,
  persist across reboot (standard registry writes on writable keys).
- **spoof-network-pnpid safety:** enumerated 14 adapters, all skipped
  correctly (2 VMBUS, 8 SWD, 1 ROOT, 3 with no PnPInstanceId). Safety guards
  from the Bug-2 fix (see `incident-v405-vm-pipeline-validation.md`) hold -
  no brick. No real PCI/USB/BTH adapters exist on the VM to spoof; a
  bare-metal test is required to exercise the write path.

### Limitations (environment, not toolkit bugs)

- **EDID spoof reverts on reboot in Hyper-V.** `spoof-edid-full.ps1` wrote
  manufacturer ID bytes 8-9 = `MSI` (0x36 0x69) during 04b, verified in
  registry immediately after. Post-reboot readback shows bytes 8-9 = `MSH`
  (0x36 0x68) - the original `HyperVMonitor` PnP ID. Root cause hypothesis:
  `HyperVMonitor` is a synthetic device and the VMBus display driver
  regenerates EDID on every boot, overwriting the registry copy. On
  bare-metal with a real monitor (DDC readback cached to registry once at
  install time), this reversion likely does not occur - **needs empirical
  validation on bare-metal before treating as a bug**. Practical workaround
  for VM demos: run 04b immediately before launching RubinOT, no reboot in
  between.
- **spoof-audio-guids:** expected fail on the VM (no audio device passthrough,
  zero endpoints under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices`).
  Not a toolkit bug.
- **spoof-pci-hardwareid:** expected fail on the VM (Hyper-V Gen 2 does not
  expose `HKLM\SYSTEM\CurrentControlSet\Enum\PCI`; every device sits under
  VMBUS). Not a toolkit bug.
- **spoof-mac pattern-match:** the profile's target adapter patterns (Intel
  I219, Realtek 2.5GbE) do not match the Hyper-V synthetic NIC (friendly name
  literally `Ethernet`). Not a bug - `profile.json` would need
  `Microsoft Hyper-V Network Adapter` entries to exercise this path in a VM.
  Expected to pass on bare-metal with real NICs.

### Conclusion

Level A validated for everything the VM environment permits. Bare-metal
validation is still required for USB, HID, PCI, network MAC, and to
disambiguate whether EDID reversion is Hyper-V-specific or a general Windows
DDC-refresh behavior.

---

## 9. Changelog vs v2

| Area | v2 | v3 |
|------|----|----|
| Coleta 100% user-mode via registry | Assumido a partir de duas capturas (7 min + 18 min) | Reconfirmado com 25 min combinados + PE recon + teste ativo com driver unsigned |
| Coverage matrix | GAP #1 (network PnPInstanceId) e GAP #2 (CPU registry) abertos como Fase 2 | GAP #1 CLOSED por spoof userland; GAP #2 CLOSED por Level A userland + Level C driver v4.0 |
| Superficies USB/HID/BTH | Nao caracterizadas | Ranqueadas por volume: 889 / 54 / 12 eventos; USB e HID viram gaps novos, BTH opcional |
| DSE / testsigning / SecureBoot | GAP #3 aberto como policy decision (Track C: EV/BYOVD/accept) | CLOSED como accept-and-document contra EMAC; documentacao unica reservada a futuros anti-cheats |
| Escopo do driver `rstflt` | BOOT_START + SMBIOS + CPU replay como caminho unico | Re-escopado como Level C opt-in contra EMAC; Level A userland vira default |
| Batches | `04-aplicar-hwid.bat` roda tudo | Novo `04b-aplicar-hwid-emac.bat` (Level A EMAC-only) + `08b-rollback-userland.bat`; batches herdados preservados |
| Racional "keys nao lidas" | Confirmed NOT read: 4 grupos | Confirmed NOT read: 11 grupos, com over-coverage warning explicito |
| Fonte canonica | Procmon local mais notas internas v1 | `display-affinity-lab/docs/emac-hwid-recon.md` rev.3 como single source of truth para comportamento observado |

---

## 10. Referencias

- Fonte canonica da recon empirica: `../../display-affinity-lab/docs/emac-hwid-recon.md`
  rev.3 (2026-08-29).
- CSV/PML brutos: `C:\Users\xyrlan\AppData\Local\Temp\rubinot_delete_uuid.csv`,
  `.pml`, `rubinot_capture.csv`.
- Doc superseded: [`docs/emac-recon-v2.md`](emac-recon-v2.md).
- Roadmap adjacente: [`docs/roadmap-v41-wmi-intercept.md`](roadmap-v41-wmi-intercept.md).
- Kickoff Fase 2 original: [`docs/fase2-kickoff.md`](fase2-kickoff.md).
- Postmortem v4 phase 5 (contexto de estabilidade do driver
  contra outros alvos): [`docs/postmortem-v4-phase5/`](postmortem-v4-phase5/).

END OF DOCUMENT.
