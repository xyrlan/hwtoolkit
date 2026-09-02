# Incident v506 Phase 1 - OEM string synthesizer inventory curation

**Status:** Data-complete. Header `driver/trackd_inventory.h` landed, `driver/rstflt.c` include + changelog block landed, build clean `/W4 /WX` + signed. Hot path do driver **byte-identico ao Phase 0** - o `#include` puxa apenas `.rdata` literals que nenhum call site em Phase 1 dereferencia (Phase 2 wira consumers). `rstflt.sys` cresceu 61712 -> 79632 bytes (+17920, matching aggregate footprint dos 78 rows), inert ate Phase 2. **NAO ha VM sanity nem bare-metal test nesta PR** - o driver nao tem superficie de callback nova pra medir.

**Data:** 2026-09-02
**Driver:** `rstflt.sys` v5.0.6 (Phase 1; BUILD-MARKER inalterado `RstFlt-v5.0.6-BUILD-MARKER` - convention: marker so bumpa entre versoes major, nao entre phases de uma mesma versao)
**Escopo:** implementacao da secao 4 (inventarios por classe) + secao 9 checklist Phase 1 rows + secao 10 Q2 do [`../track-d-v506-oem-string-synthesizer-kickoff.md`](../track-d-v506-oem-string-synthesizer-kickoff.md).

---

## 1. TL;DR

Phase 0 (PR #22, 2026-09-02) landou o **scaffolding** (arm flag `EnableValueSynth`, 9 `SynthHit_*` counters declarados, 4 `SynthBail` counters declarados, 3 measure-first counters WIRED, ring 16 -> 128 slots). Phase 2 vai wirar o **dispatch**: extender `TRACKD_VALUE_DESCRIPTOR` com um `Synthesizer` field, adicionar callbacks per-(class, value_name), bumpar os `SynthHit_*` counters no path novo.

Antes desse dispatch fazer sentido, o driver precisa de duas coisas:

1. **Um contrato estavel** (`driver/trackd_inventory.h`) que Phase 2 vai `#include` sem re-tocar em Phase 1.5.
2. **As strings sinteticas em si** - vendor / product literals curados por classe que satisfacam simultaneamente tres restricoes: **enterprise-plausible**, **LATAM-uncommon** (excluir consumer common no playerbase RubinOT brasileiro pra evitar synth==real -> passthrough silencioso), **anti-collision cross-value** (Mfg/DeviceDesc/FriendlyName do mesmo device tem que casar em vendor, ou EMAC pega o gap - o exato mecanismo do ban v5.0.5 Phase 2 "NVIDIA GeForce RTX 3070" + "KINGSTON SA400S37480G" via HardwareID sintetico).

Phase 1 landa **as duas coisas**: header + inventario + contrato de selecao. NAO wira dispatch (Phase 2 fica com essa metade).

**Key design decision (kickoff Q2 resolvida):** PCI sub-classification vai por **Option A - workitem hash-map** (rejeitando Option B que recriaria a vulnerabilidade do v5.0.5 Phase 2, e rejeitando Option C over-engineering pra hot-plug que nao existe em desktop). Header ja reserva `TRACKD_PCI_CLASSHINT` enum publica + `ClassHint` field em cada `TRACKD_PCI_ROW`, pra Phase 2 wirar o workitem body sem quebrar schema. Ver §4.

---

## 2. Files touched

- **`driver/trackd_inventory.h`** (NEW, 832 linhas): contrato de dados + struct typedefs + curated inventory pools per §3. Sem accessor functions - Phase 2 lands consumers.
- **`driver/rstflt.c`** (+108 linhas):
  - Novo bloco changelog `v5.0.6 - Phase 1` acima do bloco Phase 0 (linhas 156-244 antes, agora shifted).
  - `#define TRACKD_INVENTORY_IMPL` + `#include "trackd_inventory.h"` apos o prototype de `PsGetProcessImageFileName` (~linha 1048). Valida sintaxe do header no Phase 1 build (compile-time + link-time); linker inclui .rdata literals no `.sys`, inert ate Phase 2 dereferenciar.
- **`driver/makefile.mak`** (+1 char): dependency line `rstflt.obj: rstflt.c trackd_inventory.h` pra incremental rebuild correctness (single-file rebuild ja aconteceria, mas o explicit dependency documenta intent).
- **`README.md`** (+18 linhas): subblock Phase 1 na secao Track D existente. Descreve inventario + row shape + PCI Q2 resolucao. Sem edit em Standard commands (nenhum novo arm flag).
- **`CLAUDE.md`** (+1 bullet gigante): linha v5.0.6 Phase 1 no Standard commands, acima do bullet Phase 0 existente. Cobre inventario shape + selection formula + PCI Q2 + hot path idem Phase 0.
- **`docs/track-d-v506-oem-string-synthesizer-kickoff.md`** §9 + §10:
  - §9 checklist reestruturado em tres blocos (Phase 0 marcado done, Phase 1 marcado done, Phase 2 pending com sub-tasks).
  - §10 Q2 marcado RESOLVIDA com rationale completa inline.
- **`docs/postmortem-v5-track-d/incident-v506-phase1-implementation.md`** (NEW, este arquivo).

---

## 3. Curation decisions - per pool

Cada pool foi curado cruzando tres axes:
1. **Enterprise-fleet plausibility** - modelos que aparecem em fleet TI corporativa BR/Latam, evita "trigger de ML" via cardinality-per-machine anomalo.
2. **LATAM-uncommon consumer bias** - EXCLUI modelos populares no playerbase RubinOT (RTX 3060/3070/4060 GeForce, Kingston SA400S37/A400, ADATA XPG SU/SX, Realtek 2.5GbE consumer, Nvidia GTX 10xx/16xx/20xx/30xx/40xx consumer, AMD Radeon RX consumer, ASMedia USB bridges) pra evitar synth==real -> passthrough silencioso (kickoff §5.5 anti-pattern).
3. **Anti-collision cross-value** - a estrutura de row-per-device (§4) resolve isso by construction: quando FNV picks row N, DeviceDesc/FriendlyName/Mfg vem TODOS da row N; nao ha como o Mfg dizer "Micron" enquanto o DeviceDesc diz "NVIDIA".

Row shape geral (todos os pools):

```c
typedef struct _TRACKD_<CLASS>_ROW {
    /* per-class classification hint (PCI ClassHint / USB DeviceClass) */
    const WCHAR *VendorPadded_or_VenHex_or_VidHex; /* varies per class */
    const WCHAR *Product_or_DevHex_or_PidHex;
    const WCHAR *Rev;               /* SCSI only */
    const WCHAR *DeviceDesc;
    const WCHAR *FriendlyName;      /* NULL on HID rows (contract: pass through real) */
    const WCHAR *Mfg;
} TRACKD_<CLASS>_ROW;
```

Pool sizes sao **todos primos** (SCSI 19, PCI 13, USB 13, HID 13, BTH 13, STORAGE 7) pra reduzir bias no `FNV1a64 % rowCount` modulo. Combinado com o `>>32` shift antes do modulo (documented no header prologue), a bias residual fica abaixo de measurement noise.

### 3.1 SCSI (19 rows)

`Enum\SCSI\Disk&Ven_*&Prod_*&Rev_*` targets. Vendor field EXATAMENTE 8 chars space-padded (T10 SPC-3 §7.6.4.2). Product <= 16 chars. Rev EXATAMENTE 4 chars.

Composicao: 4 Micron enterprise SSD (5300 MAX / 5400 PRO / 7400 PRO / 9300 MAX), 3 Samsung PM datacenter (MZ7L3960HCJR / MZQL21T9HCJR / MZWLJ3T8HBLS), 2 Intel D-series (SSDSC2KG960G8 SATA / SSDPE2KE016T8 NVMe), 1 Solidigm QLC (SSDPF2KX076T1), 2 Kioxia (KCD6XVUL3T84 NVMe / KPM6VVUG1T60 SAS), 4 nearline HDDs (WDC WUH721818ALE6L4 / SEAGATE ST18000NM000J / TOSHIBA MG09ACA18TE / HGST HUH721010ALE604), 1 TOSHIBA MG10ACA20TE (added for prime count 19), 2 RAID logical volumes (HP LOGICAL VOLUME / DELL PERC H755 Front).

**Windows convention respeitada**: DeviceDesc / FriendlyName para SAS/SATA disks usa `"VENDOR PART SCSI Disk Device"`. NVMe drives usa `"NVMe VENDOR PART"` (SEM `"SCSI Disk Device"` tail), matching stornvme.sys real enumeration behavior no Windows 10/11.

**Mfg plaintext-only** (fix CRITICAL do review pass - ver §5): dropou toda a sintaxe `@rstsyn*.inf,%token%;fallback` do draft inicial. Agora e plain manufacturer strings: `"Micron Technology, Inc."`, `"Samsung Electronics Co., Ltd."`, `"Intel Corporation"`, `"Solidigm"`, `"Kioxia Corporation"`, `"Western Digital Corporation"`, `"Seagate Technology LLC"`, `"Toshiba Corporation"`, `"HGST, a Western Digital Company"`, `"Hewlett Packard Enterprise"`, `"Dell Inc."`.

### 3.2 PCI (13 rows)

`Enum\PCI\VEN_XXXX&DEV_YYYY&SUBSYS_...&REV_...` targets. VenHex sao **REAL PCI-SIG-assigned vendor IDs** enterprise (8086 Intel, 10DE NVIDIA, 1002 AMD, 15B3 Mellanox, 14E4 Broadcom, 1000 LSI/Broadcom SAS, 1B4B Marvell, 10EE Xilinx/RME, 1912 Renesas). DevHex sao **reais matching o SKU** (Policy B unificada apos review - descartou Policy A do draft que misturava real names com invented near-DevHexes).

Composicao por ClassHint:
- **GPU (4)**: NVIDIA RTX A4000 (10DE:24B7), AMD Radeon PRO W6800 (1002:73A3), Intel Data Center GPU Flex 170 (8086:56C0), NVIDIA Tesla T4 (10DE:1EB8).
- **NIC (3)**: Mellanox ConnectX-6 Dx (15B3:101D), Intel X710 SFP+ (8086:1572), Broadcom BCM57504 25GbE (14E4:1751).
- **STORAGE_CTRL (3)**: Broadcom MegaRAID 9560-16i (1000:10E2), Marvell 88SE9230 AHCI (1B4B:9230), Intel VROC/VMD (8086:9A0B).
- **AUDIO (1)**: RME HDSPe AIO Pro (10EE:3FC8) - Xilinx-based FPGA audio interface, enterprise recording studio.
- **USB_CTRL (2)**: Intel xHCI com Microsoft-inbox wrapper (8086:A36D) + Renesas com "(Renesas,1.00,2.03)" wrapper (1912:0014). Kickoff §4.2 pattern: preserva `"(VendorSynth,X.YZ,A.BC)"` tail que o real usbxhci.sys emite. Duas rows com wrapper-styles diferentes cobrem ambos os padroes que aparecem em wild (Microsoft-inbox vs vendor-branded).

Reserved slots pra Phase 1.5 sub-splits (HDA_AUDIO / NVME / RAID_SATA) declarados no enum mas ainda sem rows populadas - vao se Phase 0 measure counters ou Phase 2 bare-metal test mostrarem que sub-classification granular ajuda.

### 3.3 USB (13 rows)

`Enum\USB\VID_XXXX&PID_YYYY` targets. VidHex sao **REAL USB-IF-assigned vendor IDs** (0424 Microchip/SMSC, 0451 Texas Instruments, 8087 Intel Wireless, 04B8 Seiko Epson, 04CA Lite-On, 076B HID Global/OmniKey, 0483 STMicroelectronics, 04F2 Chicony, 06CB Synaptics, 0B95 ASIX Electronics, 1912 Renesas). PidHex escolhidos fora de well-known real ranges pra reduzir colisao com device real do operator.

Composicao por DeviceClass: 1 composite (0424:A012), 1 HID composite (0451:2078), 1 hub (8087:A034), 1 mass storage (0424:B308), 1 print (04B8:D482 - Epson enterprise printer), 1 audio (0424:C401), 1 webcam (04CA:7108 - **generic Microsoft-branded, NOT Chicony** que foi droppada por LATAM-common em consumer laptops brasileiros), 1 smart-card reader (076B:2054 - HID Global OmniKey), 1 keyboard (0483:5710 - STMicro-branded), 1 mouse (04F2:0428), 1 Bluetooth host (8087:0BB0), 1 CDC ether (0B95:178A - **ASIX AX88179A enterprise dock, NOT Realtek** que foi swapped por LATAM-common consumer dongle), 1 fingerprint reader (06CB:00DE - Synaptics WBDI).

**Rows droppadas do draft**:
- USB Root Hub (VID/PID-indexed row nao route pra Enum\USB\ROOT_HUB30 shape que nao tem VID_/PID_ pair).
- Chicony webcam (LATAM-common em Dell G-series / Lenovo Legion / HP Pavilion / Acer Nitro consumer laptops brasileiros).

### 3.4 HID (13 rows)

`Enum\HID\VID_XXXX&PID_YYYY&Col*` targets. **NO VID/PID/vendor info** nas rows - HID DeviceDesc/Mfg values sao by design Windows-generic (input.inf shipped em `%WINDIR%\INF` define esses regardless do device vendor).

Rows sao usage-role descriptions matching input.inf verbatim (space in "touch pad" / "touch screen" e intentional):
`HID-compliant mouse`, `HID-compliant keyboard`, `HID-compliant vendor-defined device`, `HID-compliant touch pad`, `HID-compliant consumer control device`, `HID-compliant system controller`, `HID-compliant game controller`, `HID-compliant device`, `HID-compliant pen`, `HID-compliant digitizer`, `HID-compliant touch screen`, `HID-compliant headset`, `HID-compliant sensor` (13a row added for prime count).

**Mfg uniforme `"(Standard system devices)"`** (parenteses matching input.inf verbatim).

**FriendlyName field == NULL em CADA ROW.** Isso e intencional: input.inf nao seta FriendlyName pra HID collections, e sintetizar um seria por si so um red flag. Phase 2 dispatcher **DEVE** tratar NULL como "pass through the real value untouched" pro `TRACKD_SVN_FRIENDLYNAME` em HID. A coluna existe na struct pra symmetry com os outros 5 row types (uniform per-value dispatch table). Documentado no header row-struct comment + no contract block.

### 3.5 BTH (13 rows)

`Enum\BTH\Dev_*` targets. Todos os values sao Windows-native bth.inf role descriptions - real Enum\BTH\Dev_<hex> child no stock Windows 10/11 surfa com `Mfg="Microsoft"`. Vendor branding pra BT devices vive under `Enum\BTHENUM\{service-guid}\...` ou `Enum\USB` pra BT-USB dongles, NAO em `Enum\BTH\Dev_*`, entao a regra de OEM-brand suppression nao aplica aqui.

Rows: `Bluetooth Device`, `Bluetooth LE Peripheral`, `Bluetooth Low Energy Device`, `Bluetooth Audio Device`, `Bluetooth Handsfree Device`, `Bluetooth Headset`, `Bluetooth Peripheral Device`, `Bluetooth AVRCP Device`, `Bluetooth HID Device`, `Bluetooth Human Interface Device`, `Bluetooth Serial Port`, `Bluetooth PAN Network Adapter`, `Bluetooth GATT Service`. Todos Mfg=`"Microsoft"`.

**Rows droppadas do draft**:
- `Bluetooth Wireless Controller` (namespace errado - radio-side, nao paired-device PDO).
- `Bluetooth Hands-free Audio` (redundant hyphenated variant de "Bluetooth Handsfree Device" canonico).

### 3.6 STORAGE\Volume (7 rows, DEFENSIVE)

`Enum\STORAGE\Volume\{GUID}#offset` targets. **DEFENSIVE pool.** STORAGE\Volume PDOs sao Windows-created objects (volume.inf), nao device-vendor-authored - real-world value space e essencialmente sempre `DeviceDesc="Volume"` / `Mfg="Microsoft"`. Phase 0 measure counter `ValHit_Storage = 0` across 269M callback invocations - EMAC nao le esses value names em telemetry atual.

Pool exists pra Phase 2 flip on synthesis se telemetry futura mostrar hits; cada row preserva o generic `"Volume"` + `"Microsoft"` framing pra ficar indistinguishable de PDOs Windows nao-modificados. FriendlyName varia across Windows-natural role prefixes (Generic / Fixed / Storage / System / Data / Removable) que aparecem organically em real systems.

---

## 4. PCI Q2 resolution

**Escolha: Option A - HASHMAP + WORKITEM** (per-boot enumeration de `Enum\PCI` -> 256-slot FNV1a hash map).

Kickoff §10 Q2 listou tres opcoes:
- **A** hash-map por workitem
- **B** generic pool cross-class
- **C** hot-plug capable dynamic classmap

### 4.1 Rationale

Kickoff §4.2 marca PCI sub-classificacao como "**Phase 1 required**" precisamente porque o ban v5.0.5 Phase 2 foi causado por EMAC pegar **cross-value inconsistencies** (HardwareID vendor sintetico != FriendlyName vendor real). Option B (generic pool cross-class) **recria essa vulnerabilidade exact** - uma Realtek NIC parent (VEN_10EC em HardwareID) recebendo `"NVIDIA GeForce RTX 3070"` de um pool generico e a trivial semantic mismatch que EMAC ja demonstrou catch. Shipar B seria false economy - design known-to-be-banned.

Option C's ~100-LOC premium sobre A resolve hot-plug PCI enumeration, que e essencialmente **non-existent no typical desktop** (target audience). Over-engineering.

Option A satisfaz o §4.2 realism requirement, evita o `Zw*` deadlock hazard by construction (worker runs OUTSIDE o Cm callback lock - mesma contract do `TrackDFlushWorker` v5.0.5 Phase 0), cabe no Phase 2's LOC budget (~150-220 LOC: `IoAllocateWorkItem` + one-shot `ZwEnumerateKey` walk de `\Registry\Machine\SYSTEM\CurrentControlSet\Enum\PCI` + fixed 256-slot FNV1a(VEN|DEV|SUBSYS|REV) hash map + 5-line callback lookup), e deixa Phase 2 consumir `classHint` imediatamente sem Phase 1.5 uplift cycle.

Cold-start window (~few hundred ms entre `DriverEntry` e worker completion) e bounded and safe - callback cai no generic pool + generic DeviceDesc row durante essa janela, matching Option B's steady state, **nao pior**.

### 4.2 Header impact (landed em `driver/trackd_inventory.h`)

O header ja reserva os seguintes hooks pra Phase 2 wirar sem breaking change:

1. **Enum publica `TRACKD_PCI_CLASSHINT`**: valores `UNKNOWN=0, GPU=1, NIC=2, STORAGE_CTRL=3, AUDIO=4, USB_CTRL=5` + reserved `HDA_AUDIO=6, NVME=7, RAID_SATA=8` pra Phase 1.5 sub-splits.
2. **Field `ClassHint`** na primeira posicao de cada `TRACKD_PCI_ROW`, typed as `TRACKD_PCI_CLASSHINT` (era `UCHAR + comment` no draft - typed enum agora catch cross-class typos em MSVC /W4 no row init time).
3. **13 rows PCI ja carregando classHint corretos** - Phase 2 filter da pool por `row.ClassHint == parentClassHint` antes do modulo selection; em subset vazio (novo class-hint que nao tem row curada), fallback pra whole pool.
4. **`EnableValueSynth`-gated PCI classmap build**: workitem vai kickoff de `DriverEntry` via existing `IoAllocateWorkItem` pattern em Phase 2 (**sem novo arm flag** - piggyback no `EnableValueSynth` ja landed em Phase 0).
5. **Comentario `/* reserved - Phase 1.5 */`** nas tres reserved enum slots documenta o extension path pra sub-splits sem confundir Phase 2 maintainer.

### 4.3 Cold-start correctness

O window entre `DriverEntry` return e workitem completion (populando o classmap) e bounded:
- Workitem enqueued em `DriverEntry` via `IoAllocateWorkItem` + `IoQueueWorkItem(DelayedWorkQueue)`.
- Passive-level worker faz `ZwOpenKey` + `ZwEnumerateKey` sync walk de `Enum\PCI` (~30-80 direct children em typical desktop, ~200 instance children total).
- ZwOpenKey + ZwEnumerateKey nao bloqueiam se o hive esta live (steady-state).
- Callback fire ANTES da completion: `TrackDInvGetPciClassHint(parentPath)` retorna `UNKNOWN`, dispatcher cai na generic PCI pool + generic DeviceDesc row. **Comportamento equivale ao Option B durante a janela**, nao regride pra "vazamento OEM real" (o generic pool tem strings sinteticas curadas).

Risks totais Phase 2 vai tratar (nao Phase 1):
1. Cold-start window (§4.3 acima) - mitigado por fallback.
2. FNV1a collision no 256-slot map: linear probing bounded a 16 slots, fall-through pra UNKNOWN.
3. Enum\PCI subkey shape non-conformance: parser tolera missing SUBSYS_/REV_ segments, hash whatever tokens presentes.
4. PCI subkey missing ClassGUID value: map entry armazena UNKNOWN, callback usa generic pool.
5. Early-boot race com SCM: retry-on-fail wrapped em `KeDelayExecutionThread` com 3 attempts, else give up (callback runs com empty map, fallback stays safe).
6. Hot-plug PCI post-boot: acceptable staleness (novo device vira generic row, same as Option B steady state).
7. Memory footprint: ~4 KB nonpaged (256 slots x ~16 bytes) - negligivel.
8. NO PatchGuard trip: pure workitem + `Zw*` pattern ja em uso pra `TrackDFlushWorker` (v5.0.5 Phase 0), zero pattern novo.

---

## 5. Adversarial review pass

Rodei workflow de review com **6 lentes independentes** sobre o header assembled: curation-adversarial, vendor-coherence, INF-collision-anti-detection, contract-fit-phase2, c-syntax-wdk-build, format-plausibility.

**Total: 30 findings** distribuidas:
- **CRITICAL: 2** (ambos APPLIED em cluster unico - ver §5.1).
- **HIGH: 8** (6 APPLIED, 2 DEFERRED pra Phase 2).
- **MEDIUM: 13** (11 APPLIED, 2 DEFERRED).
- **LOW: 13** (6 APPLIED, resto WONT-FIX estilistica).
- **INFO: 5** (5 DEFERRED com rationale).

### 5.1 CRITICAL cluster - synthetic-marker leak via `@rstsyn*.inf` INF-ref syntax

- **Finding 1** (marker-leak): draft inicial das rows SCSI DeviceDesc/Mfg usava sintaxe INF-ref `"@rstsyn.inf,%disk_devdesc%;Disk drive"` (per kickoff §4.1 draft), que serve como fingerprint literal `@rstsyn` - EMAC pode pegar via string match do prefixo.
- **Finding 33** (SCSI Row 9 @rstsyn_v506 divergence): Row 9 Solidigm era outlier com o `_v506` suffix, o resto era plain `@rstsyn`. Trivialmente detectavel via grep + delata a **versao do driver**.

Motivo do bug no draft: eu (workflow curator) segui kickoff §5.5 recommendation de usar `@rstsyn_v506.inf` mas o resolver behavior no `RegQueryValueEx` retorna a **raw string com o prefixo `@rstsyn*`**, nao aplica INF resolution intermediary. Entao o fallback ";..." NAO e o que EMAC ve - EMAC ve o prefix diretamente.

**FIX APPLIED** (cluster fix que resolve ambos): DROPEI toda a sintaxe INF-ref `@rstsyn*.inf` dos SCSI Mfg fields (Rows 0-3 Micron, 9 Solidigm, 10-11 Kioxia, 16 HP, 17 Dell). Agora e **uniform plain plaintext manufacturer strings** (`"Micron Technology, Inc."`, etc). Aplicado mesmo fix nas PCI Mfg pool (§3.2). USB/BTH/STORAGE pools nunca usaram INF-ref syntax (todos usam `"(Standard system devices)"` / `"Microsoft"` que sao real Windows-inbox strings sem `@`).

Verificacao: `grep -c "@rstsyn" driver/trackd_inventory.h` returns `0`. Grep no header confirma zero matches.

Side effect positivo: sem INF resolution intermediary, a string que EMAC ve via `RegQueryValueEx` **e EXACTLY** a mesma que aparece no Device Manager UI + WMI `Description` property, entao operator sanity-check fica robusto sem depender de INF resolver estar working.

### 5.2 HIGH cluster - contract selection formula bug

- **Finding 2** (contract bug, HIGH): draft do contract block sugeriu `subSeed = FNV(g_TrackDBaseSeed, valueName) XOR parentHash`. Isso **quebra determinism cross-value**: se DeviceDesc read pega row 3, FriendlyName read pega row 7, Mfg read pega row 1 - todos com vendor DIFERENTES no mesmo device. **Multi-vendor fake identity per PDO** - estritamente PIOR que o ban v5.0.5 Phase 2 (que pelo menos tinha vendor real coerente entre DeviceDesc/FriendlyName/Mfg).

**FIX APPLIED**: mudei o formula pra `subSeed = FNV1a64(g_TrackDSeed, className)` (**depende so de className**, nao de valueName). E `rowIndex = (ULONG)((FNV1a64(subSeed, parentPathHash) >> 32) % rowCount)`. Isso garante que TODOS os value-name reads no mesmo parent (className, parentPathHash iguais) resolvem pra **mesma row**. DeviceDesc / FriendlyName / Mfg (e HardwareID pro SCSI reconstruction) vem TODOS coerentes.

Worked example do fix documented no header prologue contract block:
```
className     = L"PCI"                  (fixed per callback path)
parentPathHash = <hash of the PCI parent>  (fixed per device)
subSeed       = FNV1a64(g_TrackDSeed, L"PCI")   (fixed per class)
rowIndex      = (ULONG)((FNV1a64(subSeed, parentPathHash) >> 32) % 13)

RegQueryValueEx(L"DeviceDesc")     -> synthRow[rowIndex].DeviceDesc
RegQueryValueEx(L"FriendlyName")   -> synthRow[rowIndex].FriendlyName
RegQueryValueEx(L"Mfg")            -> synthRow[rowIndex].Mfg
```

O `>>32` shift antes do modulo remove FNV1a64 low-bit modulo bias quando rowCount e pequeno (13, 7, 19).

### 5.3 HIGH - PCI Policy A/B mix inconsistency

- **Finding 3** (Policy mix, HIGH): draft misturava rows com **real product name + invented near-DevHex** (ex.: NVIDIA Quadro RTX A4000 com DevHex 24BE - real Ampere GA104 e 24B7) com rows com **invented product + real DevHex**. Inconsistencia detectavel por qualquer PCI-ID DB lookup.

**FIX APPLIED**: unified Policy B (real product name + REAL matching DevHex por SKU) across all 13 PCI rows:
- W6800 73C1 -> 73A3 (real Navi 21 AMD Radeon PRO W6800)
- Flex 170 56E1 -> 56C0 (real Ponte Vecchio-derived Data Center GPU Flex 170)
- Tesla T4 1EE1 -> 1EB8 (real Turing-derived Tesla T4)
- Mellanox CX6 Dx 1051 -> 101D (real ConnectX-6 Dx)
- Intel X710 15F8 -> 1572 (real X710)
- Broadcom BCM57504 1780 -> 1751 (real BCM57504)
- MegaRAID 10F3 -> 10E2 (real MegaRAID SAS 9560)
- Intel VMD 2810 -> 9A0B (real Alder Lake VMD)
- Intel xHCI A9E1 -> A36D (real 400-series xHCI)
- Renesas xHCI 0091 -> 0014 (real uPD720201)

Trade-off aceito: some collision risk com device real que operator pode ter (mitigado pelo LATAM-uncommon workstation bias no product selection).

Rows droppadas por vendor-vs-VID mismatch: **Focusrite RedNet PCIeR** (draft VenHex 1D02 = Tekram, nao Focusrite; keeping row com Xilinx 10EE colidiria com RME's VenHex).

### 5.4 HIGH cluster - HID contract asymmetry

- **Finding 4** (HID FriendlyName, HIGH): draft de HID rows tinha struct com so `(DeviceDesc, Mfg)`. Symmetry-broken com outros 5 row types. Phase 2 dispatcher precisa duplicar HID-specific code path.

**FIX APPLIED**: adicionei `FriendlyName` field a `TRACKD_HID_ROW`, seteado como `NULL` em CADA row (13/13). Phase 2 dispatcher MUST tratar NULL como "pass through the real value untouched" pro `TRACKD_SVN_FRIENDLYNAME` em HID. Documentado no header row-struct comment + contract block. Symmetry preservada + comportamento real ainda preserved (input.inf nao define FriendlyName pra HID, sintetizar seria red flag).

### 5.5 MEDIUM applied (11)

Destaques:
- **Pool sizes bumped to primes**: SCSI 18 -> 19 (added Toshiba MG10), PCI 14 -> 13 (Focusrite drop), USB 15 -> 13 (Root Hub + Chicony drops), HID 12 -> 13 (added sensor), BTH 15 -> 13 (Wireless Controller + Hands-free variant drops), STORAGE 8 -> 7 (Basic Volume drop). Reduce modulo bias.
- **Enum-typed ClassHint / DeviceClass fields**: era `UCHAR` + comment no draft; agora `TRACKD_PCI_CLASSHINT` / `TRACKD_USB_DEVICECLASS`. MSVC /W4 catch cross-class typos no row init.
- **TRACKD_SYNTH_VALUENAME enum added**: Phase 2 resolver o valueName wide-string ONCE at callback front-end; dispatcher vira switch enum-typed em vez de chain de `_wcsicmp`. Prevents silent typo fall-through (o exato leak class que v5.0.6 previne).
- **NVMe token position fixed** em 5 SCSI rows: draft tinha `"MICRON 7400 PRO NVMe SCSI Disk Device"`, real Windows stornvme.sys emite `"NVMe MICRON 7400 PRO"` (NVMe prefix, no SCSI Disk Device tail).
- **USB Mass Storage Mfg fix**: `"Compatible USB storage device"` (singular) -> `"Compatible USB storage devices"` (plural) matching real usbstor.inf `[Manufacturer]` token.
- **Broadcom MegaRAID brand alignment**: FriendlyName `"AVAGO MegaRAID SAS Adapter"` -> `"Broadcom MegaRAID Adapter"` matching DeviceDesc post-Broadcom-acquisition-of-LSI/Avago.

### 5.6 LOW / INFO deferred (7)

- **HID Row 11 headset**: target OS e Win10 recent onde input.inf inclui essa entry; OS-version gating deferido pra Phase 2 se necessario.
- **Struct layout padding reorder** (info): trivial ~200 bytes saved on x64; skip pra Phase 1, revisit em Phase 1.5 quando reserved slots fire.
- **Unreferenced-static-data compile-only touch** (info): MSVC /W4 nao warn C4189 pra file-scope statics; Phase 2 wires consumers so concern evaporates. Sem `#pragma /INCLUDE` marker pra Phase 1.
- **Reserved-identifier `_TRACKD_*` struct/enum tags** (info): matches ntddk.h + rstflt.c convention; MSVC /W4 /WX nao warn.
- **HitRingBuffer alloc-fail asymmetric flush** (from Phase 0 unrelated finding): architectural deferral, unrelated a Phase 1 header contract.

---

## 6. Deferrals

### 6.1 Phase 2 wires (~500-800 LOC C, 3-5 dias inclusive VM sanity + bare-metal test)

- **Callback `Synthesizer` field** em `TRACKD_VALUE_DESCRIPTOR` extension.
- **9 `SynthHit_*` counter increments** no dispatch path (counters ja declarados em Phase 0).
- **4 `SynthBail_*` counter increments** (idem).
- **Per-(class, value-name) synthesizer callbacks**: `TrackDSynthScsiValue`, `TrackDSynthPciValue`, `TrackDSynthUsbValue`, `TrackDSynthHidValue`, `TrackDSynthBthValue`, `TrackDSynthStorageValue`. Cada uma:
  1. Computa `subSeed = FNV1a64(g_TrackDSeed, className)`.
  2. Computa `rowIndex = ((FNV1a64(subSeed, parentPathHash) >> 32) % pool.rowCount)`.
  3. Look-up `pool.rows[rowIndex].<column-by-valueName>`.
  4. Se NULL, pass-through (contract - especifico pra HID FriendlyName).
  5. `RtlStringCbCopyW` no caller's buffer.
- **`TrackDInvGetPciClassHint(parentPath)` body**: 256-slot FNV1a hash map lookup (map populated by workitem).
- **`TrackDInvBuildPciClassmap` workitem body**: `IoAllocateWorkItem` + `ZwOpenKey` + `ZwEnumerateKey` walk de `\Registry\Machine\SYSTEM\CurrentControlSet\Enum\PCI` + populate 256-slot hash map + cleanup on driver unload.
- **USB xHCI format-string substitution**: preserve `"@System32\drivers\usbxhci.sys,#1073807361;%1 USB %2 eXtensible Host Controller - %3 (VendorSynth,X.YZ,A.BC);(VendorSynth,X.YZ,A.BC)"` wrapper per kickoff §4.2 (header ja tem duas rows representing both wire patterns).
- **Phase 2 5-lens adversarial review** + bare-metal test outcome writeup.

### 6.2 Phase 1.5+ potentially

- **Sub-pool populate** pra `HDA_AUDIO / NVME / RAID_SATA` reserved slots (currently empty). Add se Phase 0 measure-first counters ou Phase 2 bare-metal test mostrarem que sub-classification granular ajuda.
- **STORAGE\Volume synthesis wire-on**: pool populated (7 rows) mas `ValHit_Storage=0` em Phase 0 measure - dispatcher skips. Flip on se telemetry futura mostrar hits.
- **Inventory rotation policy** (kickoff §10 Q5): `subSeed` inclui `(currentMonth || year)` hash component. Nao implementado - requer decisao operacional depois de v5.0.6 baseline outcome.
- **HID DeviceDesc/Mfg reads counter**: se EMAC ban post-Phase-2 mostrar novo signal via HID reads, adicionar dedicated `SynthHit_HID_DeviceDesc` / `SynthHit_HID_Mfg` counters (Phase 0 so declarou `SynthHit_HID_FriendlyName`).

---

## 7. Next steps

1. **Commit + PR**: branch `track-d-v506-phase1` -> `main`, squash-merge convention.
2. **NO VM validation nesta PR** - hot path do driver e idem Phase 0, os literals do header sao dead code (`.rdata` inert) ate Phase 2 wirar `TrackDInvSelectRow()`. Testar agora nao mede nada novo. VM sanity vai landar com Phase 2 juntos.
3. **Sanity spot-check post-build local (JA FEITO)**: `signtool verify /pa /v rstflt.sys` PASS, embedded marker `RstFlt-v5.0.6-BUILD-MARKER` intact via `grep -aoE`. `rstflt.sys` grew 61712 -> 79632 bytes (+17920) - expected e documentado no changelog block.
4. **Phase 2**: wirar dispatch. Estimativa revisada per kickoff §6: **5-7 dias** inclusive 5-lens adversarial review + review-fix cycle + VM sanity + bare-metal test. Base checkpoint: `clean-v506-phase0-armed` (Phase 0 armado + boot-validated).

---

## 8. Deliverables desta PR

- `driver/trackd_inventory.h` (NEW, 832 LOC).
- `driver/rstflt.c` (+108 LOC: v5.0.6 Phase 1 changelog block acima do bloco Phase 0 + `#define TRACKD_INVENTORY_IMPL` + `#include "trackd_inventory.h"` apos PsGetProcessImageFileName).
- `driver/makefile.mak` (+trackd_inventory.h dependency).
- `README.md` (+18 LOC subblock Phase 1 no Track D section).
- `CLAUDE.md` (+1 bullet gigante Phase 1 em Standard commands).
- `docs/track-d-v506-oem-string-synthesizer-kickoff.md` §9 (checklist restructured tres blocos) + §10 Q2 (RESOLVIDA rationale inline).
- `docs/postmortem-v5-track-d/incident-v506-phase1-implementation.md` (este arquivo).
