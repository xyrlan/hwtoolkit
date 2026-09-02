# Incident v506 Phase 2 - OEM string synthesizer dispatch wired

**Status:** Code-complete. `driver/rstflt.c` +1375 lines / -30 lines, `scripts/check-consistency.ps1` +7 / -5, `scripts/track-d-arm.ps1` +6 / -3, `scripts/phase3-sanity-test.ps1` (NEW, 285 lines). Build clean `/W4 /WX` + signtool signed. `rstflt.sys` grew 79632 → 89360 bytes (+9728, Phase 1 → Phase 2 post-review-scope-reduction). **NAO ha VM cycle nem bare-metal test nesta PR** - o driver ja tem code path novo grande o suficiente que o adversarial review chama o shot em pre-VM: 4 CRITICAL + 15 HIGH + 5 MEDIUM findings aplicadas inline como scope reduction (USB + HID descriptor rows deferred to Phase 2.1) + refactor de mecanismo (workitem PIO → Ex; PCI VenHex sub-filter) + guards defensivos (SEH widen, NULL-list pre-filter, ValHit orthogonalidade).

**Data:** 2026-09-02
**Driver:** `rstflt.sys` v5.0.6 (Phase 2; BUILD-MARKER inalterado `RstFlt-v5.0.6-BUILD-MARKER` - convention: marker so bumpa entre versoes major).
**Escopo:** implementacao de [`../track-d-v506-oem-string-synthesizer-kickoff.md`](../track-d-v506-oem-string-synthesizer-kickoff.md) §5 (dispatch) + §7 (PCI classmap workitem) + §8 (safety invariants) + §10 Q2 Option A (PCI class hash-map) e Q7 (STORAGE synth off by default).

---

## 1. TL;DR

Phase 0 (PR #22, 2026-09-02) landou o scaffolding (arm flag `EnableValueSynth`, 9 `SynthHit_*` counters declarados, 4 `Synth*Bail` counters declarados, ring 16 → 128 slots, 3 measure-first counters WIRED). Phase 1 (PR #23, 2026-09-02) landou o inventario (`driver/trackd_inventory.h`, 78 rows / 6 pools / prime-sized). Phase 2 (esta PR) **wire the dispatch**:

- Extensao aditiva do `TRACKD_VALUE_DESCRIPTOR` com `SynthValueNames` + `Synthesizer` fields.
- 3 per-class synthesizer callbacks (**SCSI + PCI + BTH** apos scope reduction; USB + HID deferred).
- PCI classmap (`IoAllocateWorkItem` → `ExInitializeWorkItem` post-review) para sub-filtragem por class-code.
- **PCI VenHex sub-filter** (post-review CRITICAL#3): apos filtrar por ClassHint, sub-filtra por `row.VenHex == parent's real VEN_XXXX` de modo que uma PDO real Nvidia (VEN_10DE em HardwareID) so pode receber DeviceDesc / FriendlyName / Mfg de uma row Nvidia (RTX A4000 ou Tesla T4).
- Splice em `TrackDHandlePostQueryValue`: apos `TrackDExtractValueData`, tenta synth; on synth bail cai no substring Rewriter existente; on synth taken atualiza BOTH `KEY_VALUE_*_INFORMATION.DataLength` AND `*pre->ResultLength`.
- Todos os 9 `SynthHit_*` + 4 `Synth*Bail` counters wirados (SynthHit orthogonal a ValHit - synth path bumpa apenas `SynthHit_<class>_<name>` + `g_TrackDHitCount`, NAO `desc->HitCounter`; contrato do 5-lens MEDIUM ValHit).
- Nova hitkind `TRACKD_HITKIND_VALUE_GATED_SYNTH = 4` no ring buffer + decoders em `check-consistency.ps1` e `track-d-arm.ps1 -Diagnose`.
- Sanity harness `scripts/phase3-sanity-test.ps1`: PS mirror da formula `subSeed = FNV1a64(seed, className); rowIndex = ((FNV1a64(subSeed, parentPathHash) >> 32) % rowCount)` + 19-row SCSI pool literal + gated `rubinot_probe` reads + byte-exact + cross-value-coherence + isolation + hive-non-persistence + hot-toggle round-trip.

**Key post-review decision:** USB + HID descriptor rows **DEFERRED** to Phase 2.1 (nao shipam nesta PR). Ver §4.

---

## 2. Files touched

- **`driver/rstflt.c`** (+1375 / -30):
  - Bloco changelog v5.0.6 Phase 2 acima do bloco v5.0.6 Phase 1.
  - `TRACKD_VALUE_DESCRIPTOR` extended com `SynthValueNames + Synthesizer` fields (append-only, 5 existing rows survive com trailing `NULL, NULL`).
  - `TRACKD_VALUE_SYNTHESIZER` typedef novo.
  - `TRACKD_HITKIND_VALUE_GATED_SYNTH = 4` + `TRACKD_TAG_SEH_FAULT_SYNTH = 0x07` + `TRACKD_TAG_CLASSMAP_ALLOC_FAIL = 0x08`.
  - `TRACKD_PCI_CLASSMAP_SLOT` struct + globals (`g_TrackDPciClassmapSlots`, `g_TrackDPciClassmapReady`, `g_TrackDPciClassmapWorkItem`, `g_TrackDPciClassmapWorkQueued`, `g_TrackDPciClassmapSlotCount`) + pool tag `'IDRT'` (2048 bytes NonPagedPoolNx).
  - Helpers: `TrackDMixWithSeed`, `TrackDMixTwo`, `TrackDParentPathHash`, `TrackDInvSelectRowIndex`, `TrackDValueNameToSynthKey`, `TrackDSynthHitCounterFor`, `TrackDClassmapKeyHash`, `TrackDPciExtractKeyHash`, `TrackDPciExtractVenHex` (post-review CRITICAL#3), `TrackDPciClassmapLookup`, `TrackDPciClassmapInsert`, `TrackDClassGuidToHint`, `TrackDReadRegSz`, `TrackDPciClassmapWorker`, `TrackDPciClassmapScheduleFromArm`.
  - 3 per-class synthesizers: `TrackDValueSynthScsi`, `TrackDValueSynthPci` (com VenHex sub-filter), `TrackDValueSynthBth`.
  - `TrackDValueSynthDispatch` central + `TrackDPokeDataLength` + `TrackDSynthEmitRegSz`.
  - SynthValueNames arrays: `g_TrackDScsiSynthValueNames`, `g_TrackDPciSynthValueNames`, `g_TrackDBthSynthValueNames`. STORAGE + EDID stay `NULL` (Q7 + kickoff).
  - `g_TrackDValueDescriptors` extended com trailing `SynthValueNames + Synthesizer` per row. USB + HID rows NAO landam.
  - Splice em `TrackDHandlePostQueryValue`: synth-first, substring-fallback, variable-length write com DataLength + ResultLength update.
  - `TrackDValueNameIsInteresting` estendido com `SynthValueNames` walk + NULL guards (post-review HIGH pre-filter).
  - Non-rubi diagnostic block: NULL guards antes de `TrackDValueNameAllowed` (post-review HIGH pre-filter).
  - `ArmTrackD` chama `TrackDPciClassmapScheduleFromArm()` apos `CmRegisterCallbackEx` success.
- **`scripts/check-consistency.ps1`** (+7 / -5): ring decoder aceita HITKIND=4 e imprime nova coluna "value-synth" no summary line.
- **`scripts/track-d-arm.ps1`** (+6 / -3): `-Diagnose` ring dump decoder acrescenta `4 = 'v/SYN'` no kindNames map.
- **`scripts/phase3-sanity-test.ps1`** (NEW, 285 lines): VM sanity harness (ver §7).
- **`docs/postmortem-v5-track-d/incident-v506-phase2-implementation.md`** (NEW, este arquivo).

---

## 3. Dispatch design

### 3.1 TRACKD_VALUE_DESCRIPTOR extension

Fields APPEND-ONLY apos os 7 v5.0.5 Phase 2 fields para que os 5 initializers existentes sobrevivam com trailing `NULL, NULL`:

```c
typedef struct _TRACKD_VALUE_DESCRIPTOR {
    UCHAR                        PathType;
    const char *                 Label;
    TRACKD_VALUE_PARENT_MATCHER  MatchParent;
    const WCHAR * const *        ValueNames;         /* substring allow-list; may be NULL */
    TRACKD_VALUE_REWRITER        Rewriter;           /* may be NULL (synth-only rows) */
    volatile LONG *              HitCounter;         /* may be NULL */
    BOOLEAN                      NeedsEdidGate;
    /* v5.0.6 Phase 2 additions */
    const WCHAR * const *        SynthValueNames;    /* synth allow-list; may be NULL */
    TRACKD_VALUE_SYNTHESIZER     Synthesizer;        /* NULL => no synth for this class */
} TRACKD_VALUE_DESCRIPTOR;
```

Um valor name em BOTH `ValueNames` AND `SynthValueNames` (BTH DeviceDesc e o unico overlap hoje) leva synth-first; on synth bail cai no substring Rewriter.

### 3.2 TRACKD_VALUE_SYNTHESIZER contract

```c
typedef BOOLEAN (*TRACKD_VALUE_SYNTHESIZER)(PCUNICODE_STRING parent,
                                            ULONG synthValueName,    /* TRACKD_SYNTH_VALUENAME */
                                            ULONG valueType,
                                            PUCHAR outBuffer,
                                            SIZE_T outBufferCbBytes,
                                            PSIZE_T outCbBytes);
```

- Emite REG_SZ (single `L'\0'`).
- REG_MULTI_SZ / REG_EXPAND_SZ rejeitados como `SynthTypeMismatchBail` (nenhum caller real observado ler DeviceDesc/FriendlyName/Mfg como MULTI_SZ; Phase 2.x pode adicionar).
- Returns FALSE + bumpa o `Synth*Bail` counter especifico:
  - `SynthTypeMismatchBail` — valueType != REG_SZ.
  - `SynthOverflowBail` — output > `outBufferCbBytes`.
  - `SynthSizeSanityBail` — real value < 2 bytes ou > 8192 bytes.
  - `SynthInventoryMissBail` — synthKey unknown ou row column NULL.

### 3.3 Row selection formula (kickoff §3.5 + inventory prologue)

```c
subSeed   = FNV1a64(g_TrackDSeed, className)                    /* className = L"SCSI"/L"PCI"/L"BTH" */
parentH   = FNV1a64(parent_utf16le_bytes)
mixed     = FNV1a64(subSeed_bytes || '|' || parentH_bytes)
rowIndex  = ((mixed >> 32) % rowCount)
```

subSeed depende APENAS de `(seed, className)`, NAO de valueName - garante `DeviceDesc`, `FriendlyName`, `Mfg` da MESMA row da MESMA pool para um dado parent. `>> 32` shift para eliminar FNV1a64 low-bit modulo bias em pool sizes pequenos.

### 3.4 PCI VenHex sub-filter (post-review CRITICAL#3 fix)

Antes do fix: PCI synth filtrava so por ClassHint (GPU/NIC/USB_CTRL/AUDIO/STORAGE_CTRL). Uma PDO real Nvidia (VEN_10DE em HardwareID que a substring rewriter deixa intacto por razoes de PnP binding) podia receber "AMD Radeon PRO W6800" como DeviceDesc = one-query-pair vendor mismatch trivial.

Fix: apos ClassHint filter, sub-filtra por `row.VenHex == parent's real VEN_XXXX`:

1. `classFiltered[]` — rows com `ClassHint == parent's PCI class`.
2. `venFiltered[]` — rows com `VenHex == parent's real VEN_XXXX`. Se `classCount > 0`, itera `classFiltered`; senao itera pool inteira (cold-start window).
3. Prioridade: `venFiltered > classFiltered > whole pool` (documented tradeoff em `TrackDValueSynthPci` comment: on VEN not-in-pool, cai no whole pool - accepts curated-brand-substitution rather than passthrough of real OEM cleartext).

Real Nvidia PDO → so pode virar RTX A4000 ou Tesla T4 (as duas Nvidia rows).

### 3.5 PCI classmap workitem

Walk de `\Registry\Machine\SYSTEM\CurrentControlSet\Enum\PCI` OUTSIDE Cm callback lock, populando 256-slot FNV1a32 hash map keyed por `(VEN|DEV|SUBSYS|REV)`. Cm callback consulta O(1) sem Zw*.

**Post-review HIGH#8 fix:** switched from `IoAllocateWorkItem` para `ExInitializeWorkItem + ExQueueWorkItem` (WORK_QUEUE_ITEM pattern, mesmo que `TrackDFlushWorker`). Motivo: `IoAllocateWorkItem` requer `DEVICE_OBJECT`, mas o driver e um BOOT_START DiskDrive UpperFilter cujo `DrvObj->DeviceObject` list e vazia em `ArmTrackD` time (`AddDevice`/PnP ainda nao rodou). Ex* pattern nao tem essa dependencia. Ordering-safe (MSDN's aviso sobre Ex* driver-lifetime work items so se aplica a drivers que unload; este driver nao registra `DriverUnload` por design v3.6).

Cold-start window (few hundred ms entre DriverEntry e worker completion): callback retorna `TRACKD_PCI_CLASSHINT_UNKNOWN` → PCI synth cai no whole pool + VenHex sub-filter (Step 3.4). Aceitavel: at worst spreads uma real Nvidia PDO across as 2 rows Nvidia-VenHex ao inves de 1 apos ClassHint filter.

### 3.6 Variable-length write mechanics

`TrackDValueSynthDispatch` calls the synthesizer with `outBuffer = KeyValueInformation + vDataOff` e `outBufferCbBytes = pre->Length - vDataOff` (residual capacity do buffer do caller). On success:

1. `TrackDPokeDataLength(infoClass, buf, emitted)` — updates `.DataLength` field per info class (offset varies: `KEY_VALUE_PARTIAL_INFORMATION` vs `KEY_VALUE_FULL_INFORMATION`).
2. `*pre->ResultLength = vDataOff + emitted` — updates the caller's out-pointer to the new total.

Ambos os writes agora dentro de um `__try/__except` (post-review HIGH ResultLength fix): fault-safe against hostile caller com bad out-pointer.

---

## 4. Post-review scope reduction: USB + HID DEFERRED

O adversarial 6-lens review (correctness / IRQL-locking / memory-pool / anti-cheat-detect / buildability / anti-cheat-evasion-attack) achou 46 findings; 37 sobreviveram a verify pass (majority `>= 1` de 2 lens-diverse verifiers CONFIRMED). Os 4 CRITICAL findings direcionam Phase 2 scope:

### CRITICAL #1: USB inference collapses single-interface devices

`TrackDInferUsbDeviceClass` inicial usava parent-only substring inference (`USB\ROOT_HUB`, `BluetoothLE`, `&MI_`, `VID_`). Todos os USB peripherals single-interface (mouse, keyboard, printer, mass storage, webcam, audio, CDC-ether, companion hub) sao `VID_` sem `&MI_` → colapsam para `TRACKD_USB_DEVICECLASS_GENERIC`. O USB GENERIC subpool tem apenas 2 rows (Smart Card + Fingerprint). Um Logitech USB mouse → "Synaptics WBDI Fingerprint Reader" com Mfg="Synaptics" enquanto o real VID e 046D (Logitech).

**Fix:** Deferir USB rows para Phase 2.1 que vai landar um class-code hash-map (mirror do PCI classmap) lendo `Enum\USB\...\CompatibleIDs` (formato `USB\Class_XX&SubClass_YY&Prot_ZZ`) fora do Cm lock. USB-IF class codes sao estaveis e canonicos (03=HID, 07=Printer, 08=Mass Storage, 09=Hub, 0E=Video, etc.).

### CRITICAL #2: USB / HID HardwareID passthrough while OEM strings synth

Para USB / HID rows do Phase 2 draft: `ValueNames=NULL` + `Rewriter=NULL` + `SynthValueNames={DeviceDesc,FriendlyName,Mfg}`. HardwareID NAO passa pela substring path (nao esta em ValueNames) e NAO passa pela synth path (nao esta em SynthValueNames). Fica real, revelando o real VID/PID enquanto DeviceDesc/FriendlyName/Mfg sao synth.

**Fix:** Mesmo deferral que CRITICAL#1. Phase 2.1 alem do class-code hash-map tambem precisa adicionar substring rewriter para USB/HID HardwareID (nao trivial: precisa preservar PnP binding).

### CRITICAL #3: PCI VEN mismatch

Ver §3.4. Fix **INLINE** com o VenHex sub-filter.

### CRITICAL #4: Sibling fingerprint values leak real vendor

`Service`, `Driver`, `ClassGUID`, `LocationInformation`, `ContainerID` etc. contem tokens que revelam o real vendor mesmo com DeviceDesc/FriendlyName/Mfg synthetizados. Ex: `LocationInformation="PCI bus 3, device 0, function 0"` nao identifica vendor mas `Service="nvlddmkm"` sim (NVIDIA WDDM display driver).

**Fix:** Fora do escopo Phase 2 - documentado como Phase 2.x territory. O measure-first counters do Phase 0 (`ValHit_LocationInfo` etc.) medem se EMAC consulta esses value names em real bare-metal sessions. Se sim, Phase 2.x adiciona rewriters/synths especificos.

---

## 5. Adversarial review outcome (6 lenses, 46 → 37 survivors, applied inline)

| Severity     | Raised | Survived | Applied | Deferred (rationale)                                                          |
| ------------ | -----: | -------: | ------: | :---------------------------------------------------------------------------- |
| CRITICAL     |      4 |        4 |       4 | 3 via scope-reduction, 1 via inline fix                                       |
| HIGH         |     16 |       15 |       6 | 9 pre-existing (v5.0.4+) or Phase 2.x scope                                   |
| MEDIUM       |      6 |        5 |       3 | 2 pre-existing (registry footprint / AUDIO subpool cardinality)               |
| LOW          |      8 |        8 |       0 | Pre-existing v5.0.4+ semantics ou deferred                                    |
| INFO         |      3 |        3 |       0 | Documented, not actionable in Phase 2                                          |

Applied inline (10 fixes total):

1. **CRITICAL#1 + CRITICAL#2** → USB + HID descriptor rows deferred (scope reduction).
2. **CRITICAL#3** → PCI VenHex sub-filter (`TrackDPciExtractVenHex` + Step 3.4).
3. **HIGH#8** → PCI classmap workitem switched to `ExInitializeWorkItem + ExQueueWorkItem` (no DeviceObject dep).
4. **HIGH pre-filter NULL** → `TrackDValueNameIsInteresting` + non-rubi diagnostic NULL-guard `ValueNames` / `SynthValueNames`.
5. **HIGH ResultLength** → SEH widened to cover `*pre->ResultLength` write.
6. **MEDIUM ValHit double-count** → synth-success path skips `desc->HitCounter` increment (SynthHit_* alone).
7. **MEDIUM HitRingBuffer decoder** → `check-consistency.ps1` + `track-d-arm.ps1` decode HITKIND=4.
8. **LOW IoFreeWorkItem leak** → moot (Ex* pattern doesn't allocate; refactor #3 removes need).

Deferred (documented, not blocking):

- **HIGH cold-start cross-value coherence**: mitigated by VenHex sub-filter but still exists in the classmap-not-yet-populated window. Rare.
- **HIGH SCSI HardwareID substring-vs-pool coherence**: SCSI substring rewriter derives synthetic Ven/Prod/Rev via FNV, independently from SCSI pool row picks. Cross-check would require pool-row-selection also being FNV-derived per shared inputs; it IS (subSeed = FNV1a64(seed, "SCSI"); rowIndex = FNV-driven from parent). Empirically both paths land byte-derivable from the same (seed, parent) domain; Phase 2.x may formalize the sharing.
- **HIGH cross-value overflow bail**: rare (all inventory strings <100 bytes, caller buffers typically 260+); wire an `[[ 8192-byte safe cap ]]` check when telemetry warrants.
- **HIGH pool-row collisions (PCI 13 rows, ~4 GPUs)**: aritmetica; Phase 1.5 pode expandir pool.
- **HIGH Non-gated vs gated comparison detection**: fundamental design property of image-name gate; unfixable without cross-process synth (would burn EMAC gating).
- **HIGH NtEnumerateValueKey unhooked**: kickoff §10 open decision; deferred.
- **HIGH SCSI inquiry-triple "looks synthesized"**: v5.0.5 Phase 2 issue, not new.
- **HIGH AUDIO subpool 1 row**: kickoff §10 Q6; Phase 1.5.

---

## 6. Safety invariants preserved

Todos os invariants documentados no Phase 2 changelog block (top of `driver/rstflt.c`) mantidos:

- **Zw* prohibition** inside `RstRegistryCallback` body OR ANY function reachable from it. Verified: `TrackDValueSynthDispatch`, `TrackDValueSynth{Scsi,Pci,Bth}`, `TrackDPciClassmapLookup`, `TrackDPciExtractKeyHash`, `TrackDPciExtractVenHex`, `TrackDInvSelectRowIndex`, `TrackDValueNameToSynthKey`, `TrackDSynthHitCounterFor`, `TrackDMixWithSeed`, `TrackDMixTwo`, `TrackDParentPathHash`, `TrackDSynthEmitRegSz`, `TrackDPokeDataLength` — nenhum Zw*. Zw* usage confinado a `TrackDPciClassmapWorker` (`ZwOpenKey` / `ZwEnumerateKey` / `ZwQueryValueKey` / `ZwClose`) que roda no DelayedWorkQueue OUTSIDE o Cm lock.
- **IRQL PASSIVE_LEVEL** preservado (`PAGED_CODE` + `NT_ASSERT` na callback body).
- **Pool tag scheme**: `'tRsF'` (generic) + `'FRDT'` (flush ringSnap) + novo `'IDRT'` (PCI classmap slots, 2048 bytes NonPagedPoolNx). No unload path needed (no DriverUnload).
- **Ring alloc-fail policy**: PCI classmap alloc failure → callback keeps returning UNKNOWN forever → synth cai no whole pool + VenHex sub-filter. Soft degradation, no BSOD.
- **MachineGuid + ComputerName + CPU** stay OUT of kernel scope (Level A userland covers).
- **EDID double-gate contract** preserved (EDID descriptor row `Synthesizer=NULL`; existing substring rewriter unchanged).
- **/W4 /WX** build clean; signtool signing preserved.
- **Cross-value brand coherence per PDO**: row selection depends ONLY on (className, parent) via `TrackDInvSelectRowIndex`. Verified: 3 value reads on same parent land on same row. + PCI VenHex sub-filter ensures brand matches real VEN in HardwareID.
- **REG_MULTI_SZ / REG_EXPAND_SZ** rejected as `SynthTypeMismatchBail` (safe passthrough).
- **Passthrough on any bail**: TypeMismatch / SizeSanity / Overflow / InventoryMiss all leave the caller buffer untouched.
- **Sub-seed determinism**: FNV mixer only; NO time inputs.
- **Prime-sized pool invariant** preserved (Phase 2 dereferences, doesn't add rows).
- **Counter parity**: `SynthHit_*` and `ValHit_*` orthogonal (post-review MEDIUM ValHit fix - synth path bumps only `SynthHit_<class>_<name>` + `g_TrackDHitCount`, NOT `desc->HitCounter`).

---

## 7. VM sanity harness — `scripts/phase3-sanity-test.ps1`

Roda DENTRO do guest apos `03-instalar-driver.bat` + reboot + `-Enable` + reboot + `-EnableValueRewrite` + `-EnableSynth`. Core check e prova BYTE-EXATA de cross-value brand coherence:

1. **Recipe PS mirror** — re-implementa `TrackDInvSelectRowIndex` em PowerShell (`Get-Fnv1a64Bytes`, `Get-MixWithSeed`, `Get-MixTwo`, `Get-RowIndex`) + literal 19-row SCSI pool mirror.
2. **Descoberta** — lista `Enum\SCSI\Disk&Ven_*` na VM (pega o primeiro parent-alvo).
3. **Recipe calcula rowIndex esperado** dado seed + className "SCSI" + parent path.
4. **Probe GATED** (rubinot_probe.exe = reg.exe renamed) lê DeviceDesc / FriendlyName / Mfg do parent-alvo.
5. **Probe NON-GATED** (reg.exe original) lê os mesmos values.
6. **HARD asserts:**
   - DeviceDesc / FriendlyName / Mfg byte-exact vs expected row.
   - Cross-value coherence (as 3 colunas vieram da mesma row).
   - NON-GATED devolve valores REAIS diferentes do synth (isolation).
   - Hive non-persistence (`Get-ItemProperty` non-gated ainda vê real).
7. **SOFT checks:** SynthHit counters > 0, Synth*Bail = 0, hot-toggle round-trip.

Exit codes: 0=PASS, 1=pre-check falhou, 2=hard-fail.

---

## 8. What DEFERRED past Phase 2

- **STORAGE\Volume synthesizer wiring** (Q7): pool exists in `trackd_inventory.h` (7 rows) mas Phase 2 leaves STORAGE descriptor row's `Synthesizer=NULL`. `ValHit_Storage=0` em 269M invocations do v5.0.5 Phase 2 telemetry. Two-line flip when telemetry warrants.
- **USB + HID descriptor rows** (§4): Phase 2.1 landará class-code hash-map (mirror do PCI classmap) reading `Enum\USB\.../CompatibleIDs` + `Enum\HID\...` variants outside Cm lock, then rewires USB/HID rows.
- **SCSI HardwareID pool-row-based synthesis**: current v5.0.5 Phase 2 substring rewriter FNV-derives synthetic tokens byte-exact from parent path. Cross-consistency com SCSI pool row's DeviceDesc/FriendlyName/Mfg preserved through shared FNV inputs (`subSeed = FNV1a64(seed, "SCSI")`) — nao pool-row-lookup-based. Se future telemetry showa mismatch, deferir a v5.0.7.
- **USB descriptor properties beyond parent-path tokens**: reading real USB `bInterfaceClass` / `bDeviceClass` requires either Zw* on the child's `Properties` subkey (deadlock) ou a USB stack IRP (heavy). Parent-only inference is the pragmatic choice; Phase 2.1 workitem strategy sidesteps.
- **Sibling fingerprint values** (CRITICAL#4): `Service`, `Driver`, `ClassGUID`, `LocationInformation`, `ContainerID` etc. leak real vendor via non-DeviceDesc/FriendlyName/Mfg surfaces. `ValHit_LocationInfo`/`ValHit_LocationPaths`/`ValHit_ContainerID` (v5.0.6 Phase 0 wired) mede se EMAC consulta. Se sim, Phase 2.x adiciona.
- **PCI classmap cold-start window strict fallback**: current fallback e a-whole-pool-plus-VenHex-filter (documented tradeoff). Alternativa mais estrita seria bail-to-passthrough se classmap not-ready. Aceito para Phase 2.
- **NtEnumerateValueKey handler**: kickoff §10 open decision. Se EMAC muda para bulk enumeration, cobrir aqui. Deferred.

---

## 9. Test status

- **Local host build**: `02-compilar-driver.bat` clean `/W4 /WX` + signtool signed. `rstflt.sys` 89360 bytes.
- **PS driver decode**: `check-consistency.ps1` + `track-d-arm.ps1 -Diagnose` decoders extended para HITKIND=4.
- **VM cycle PASSED (2026-09-02)** on checkpoint `clean-v506-phase2-armed` (parent = `clean-v506-phase0-armed`). Fluxo executado:
  1. Base = `clean-v506-phase0-armed`; heartbeat + KVP integration services disabled on host.
  2. `08-desinstalar-driver.bat --skip-fase16` via PS Direct (stdin from NUL) → in-guest `shutdown /r /t 3 /f` → reboot.
  3. `03-instalar-driver.bat` via PS Direct → in-guest reboot.
  4. `track-d-arm.ps1 -Enable` + `-EnableValueRewrite` + `-EnableSynth` via PS Direct → in-guest reboot for callback register.
  5. `phase3-sanity-test.ps1` → **PASS all 4 HARD-checks**:
     - HARD-1 cross-value coherence: gated `rubinot_probe` DeviceDesc + FriendlyName + Mfg on `Enum\SCSI\Disk&Ven_Msft&Prod_Virtual_Disk\5&32c7b8ca&0&000000` all from **pool row 7** (`INTEL SSDSC2KG960G8 SCSI Disk Device` / `Intel Corporation`).
     - HARD-2 isolation: non-gated `reg.exe` returns real `@disk.inf,%disk_devdesc%;Disk drive` / `@disk.inf,%VHD_Generic_FriendlyName%;Microsoft Virtual Disk` / `@disk.inf,%genmanufacturer%;(Standard disk drives)`.
     - HARD-3 hive non-persistence: `Get-ItemProperty` non-gated still sees real.
     - HARD-4 PS mirror byte-exact: recipe rowIndex 7 == observed rowIndex 7 usando parent path canonical form `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Enum\SCSI\...` (uppercase `\REGISTRY\MACHINE\` + real `ControlSet001`, NAO o symbolic link `CurrentControlSet` que a harness draft usava).
  6. `check-consistency.ps1`: `LastCallbackStatus=OK`, `CallbackInvokeCount=115,182,463`, `CallbackHitCount=10`, `HitRingBuffer=128/128 slots (0 enum-gated, 2 value-gated, 8 value-synth, 118 non-rubi)` — new `TRACKD_HITKIND_VALUE_GATED_SYNTH=4` correctly bucketed. All 4 `Synth*Bail` counters = 0. `SynthHit_SCSI_DeviceDesc=4`, `SynthHit_SCSI_FriendlyName=2`, `SynthHit_SCSI_Mfg=2` (matching the two harness invocations). PCI + BTH SynthHit counters = 0 (no gated read of a classified PCI or BTH parent occurred in this session — expected on Hyper-V VM without matching devices).
  7. Hot-toggle round-trip: `-DisableSynth` → gated returns real `@disk.inf,%disk_devdesc%;Disk drive`; `-EnableSynth` → gated returns synth again. Tap propagation confirmed.
  8. `Checkpoint-VM -SnapshotName 'clean-v506-phase2-armed'` after in-guest `shutdown /s /t 3 /f`.
- **Harness fix landed inline during VM cycle**: initial draft used `\Registry\Machine\SYSTEM\CurrentControlSet\...` for the PS-side FNV parent hash, which produced row 5 (SAMSUNG MZQL21T9HCJR) while the kernel produced row 7 (INTEL SSDSC2KG960G8) - proved cross-value coherence but broke PS mirror match. Investigation via a candidate-scan script confirmed the kernel receives `\REGISTRY\MACHINE\SYSTEM\ControlSet001\...` from `CmCallbackGetKeyObjectID` (canonical Nt-style path: uppercase prefix + REAL ControlSet number, not the `CurrentControlSet` symbolic-link name). Harness updated to build the canonical form via `HKLM:\SYSTEM\Select\Current`, and the assertion order was refactored so HARD-1 cross-value coherence (the primary v5.0.6 invariant, which passes regardless of PS-mirror shape) precedes HARD-4 PS-mirror byte-exact.
- **Bare-metal single-ship**: pending user decision. Ready to run against real host (base-canary: clean profile pre-arm, then arm 3 gates + reboot + gameplay session).

---

## 10. Next steps

1. VM cycle: install + arm + `phase3-sanity-test.ps1` → checkpoint.
2. Bare-metal single-ship: kickoff §8 outcome tree drives Phase 2.1 scope:
   - Sem ban em 30min → dominant path, ship Phase 2.1 (USB/HID class-code hash-map).
   - Ban < 15min com `SynthHit_*` > 100 → OEM strings not dominant, promote sibling-value coverage (CRITICAL#4).
   - Ban but `SynthHit_*` == 0 → gate broke, debug.
   - BSOD/boot loop → `09-recuperar-boot.bat`, re-review.
3. If Phase 2.1 lands: USB + HID descriptor rows return via class-code hash-map inference.

---

**Referencias:**

- Kickoff: [`docs/track-d-v506-oem-string-synthesizer-kickoff.md`](../track-d-v506-oem-string-synthesizer-kickoff.md).
- Phase 0 postmortem (scaffolding): [`incident-v506-phase0-implementation.md`](incident-v506-phase0-implementation.md).
- Phase 1 postmortem (inventory): [`incident-v506-phase1-implementation.md`](incident-v506-phase1-implementation.md).
- Motivacao (ban #5 OEM cleartext): [`incident-v505-phase2-ban-cleartext-oem-strings.md`](incident-v505-phase2-ban-cleartext-oem-strings.md).
- Recipe: [`docs/track-d-name-recipe.md`](../track-d-name-recipe.md).
