# Track D v5.0.5 - Value-read handler + instrumentation preflight - Kickoff

Status: **DRAFT / READY FOR IMPLEMENTATION**
Data: 2026-09-01
Driver origem: rstflt.sys v5.0.4 (validado VM + bare-metal armed, ban #4 documentado em [`postmortem-v5-track-d/incident-v505-post-ban-triage.md`](postmortem-v5-track-d/incident-v505-post-ban-triage.md))
Objetivo: fechar o gap value-read (RegQueryValueEx `100%` da coleta EMAC per recon-v3:32) + resolver a inconsistencia name-vs-value que v5.0.4 esta ativamente criando + adicionar instrumentacao suficiente para diagnosticar a proxima falha sem outra sessao RubinOT.

---

## 1. Motivacao (compressed)

Ver [`postmortem-v5-track-d/incident-v505-post-ban-triage.md`](postmortem-v5-track-d/incident-v505-post-ban-triage.md) para triage completo. Seis pontos empiricos (Q2/Q3/Q4 CSVs procmon incorporados) que este kickoff atende:

1. **v5.0.4 handles ZERO value-read notify classes** ([`driver/rstflt.c:2916-2925`](../driver/rstflt.c)); ~16,317 RegQueryValue events per re-register burst passam intactos (recon-v3 §3.2).
2. **v5.0.4 cria inconsistencia name-vs-value** ativa: parent name synth `Disk&Ven_F583&Prod_2FB5A67112E6`, mas RegQueryValueEx("HardwareID") na mesma subkey retorna real `Kingston SA400S37240G`. Stronger ban tell que fingerprint raw.
3. **HitCount global = 2 em 15min** ([`driver/rstflt.c:2828`](../driver/rstflt.c)) explicado empiricamente: EMAC usa `RegOpenKey(exact-name obtido via SetupDi/CM_*) + RegQueryValueEx(HardwareID)`, NAO `RegEnumKeyEx`. Nosso `RegNtPostEnumerateKey` handler nao dispara para esse padrao. Gate `_strnicmp("rubinot", 7)` esta 100% funcional para os 2 processos alvo (`rubinot_dx.exe` + `RubinOT.exe` - ambos matcham case-insensitive + delimiter guard). Postmortem §3.1.
4. **PCI/USB/HID/MMDev ja shipped em v5.0.4**; net-new name-side e apenas BTH + STORAGE\Volume.
5. **WMI out-of-process empiricamente cold para EMAC** - Q4 confirmou WmiPrvSE = 0 events em 2 CSVs procmon distintos. Cross-process HW enum via svchost tambem descartado (baseline PnP housekeeping only). UMDF WMI provider fica em v5.1+ backlog.
6. **Dual-flow HW enum** - `rubinot_dx.exe` (game client, loada emac-client64.dll) + `RubinOT.exe` (launcher Tauri, HW enum via Rust backend proprio, NAO usa emac-client64.dll). Ambos matcham gate. Phase 2 value handler naturalmente cobre os DOIS porque filtra por image name, nao por qual DLL originou a chamada.

---

## 2. Escopo v5.0.5

### 2.1 IN

- **Phase 0**: instrumentacao per-path + ring buffer + non-`rubinot*` parent-match counter
- **Phase 1**: BTH + STORAGE\Volume enum-name rewriters + descriptor-table refactor
- **Phase 2**: `RegNtPostQueryValueKey` + `RegNtPostGetValueKey` handler, table-driven, cobrindo ~14 value patterns

### 2.2 OUT

- WMI provider shadow (v5.1+ backlog em [`roadmap-v41-wmi-intercept.md`](roadmap-v41-wmi-intercept.md))
- HARDWARE\DEVICEMAP\VIDEO intercept (v5.0.6+ gated behind separate Parameters value, so se Phase 2 EDID nao flippar o ban)
- cpuid inline / GetSystemFirmwareTable / IOCTL SMBIOS (empiricamente cold; estruturalmente exige hypervisor)
- IRP mssmbios hook (roadmap-v41 Path B, PatchGuard-adjacent, cold para EMAC)

### 2.3 Non-goals explicitos

- NAO ampliar o image-name gate. Q2 confirmou que o gate atual ja cobre AMBOS os processos alvo (rubinot_dx.exe + RubinOT.exe). Trocar por speculacao e piorar risk sem ganho.
- NAO refatorar Track D para hot-reconfig runtime (Parameters values ficam boot-time salvo `EnableRegCallback` que ja tem tap).
- NAO adicionar `RegNtPreQueryValueKey` (nem `RegNtPreGetValueKey`) - so o Post variant. Motivos em §5.1.

---

## 3. Phase 0 - Instrumentation preflight

**Custo: ~0.5 dia, ~60 LOC C + ~30 LOC PowerShell**
**Rationale pos-Q2/Q4**: NAO e para diagnosticar "gate deaf" (ja sabemos que gate ok). E para (a) validar Phase 2 handler dispara pros processos certos, (b) contar quantos value reads por path type em sessao real (metrica de sucesso do Phase 2), (c) post-mortem fine-grained se Phase 2 nao flippa ban outcome (i.e. escalar para EDID persistence probe / DEVICEMAP\VIDEO / cpuid ceiling).

### 3.1 Per-path-type counters

Substituir `g_TrackDHitCount` unico por 8 `volatile LONG`:

```c
static volatile LONG g_TrackDHitCount_SCSI     = 0;
static volatile LONG g_TrackDHitCount_PCI      = 0;
static volatile LONG g_TrackDHitCount_USB      = 0;
static volatile LONG g_TrackDHitCount_HID      = 0;
static volatile LONG g_TrackDHitCount_AudioR   = 0;
static volatile LONG g_TrackDHitCount_AudioC   = 0;
static volatile LONG g_TrackDHitCount_BTH      = 0;  /* Phase 1 lands this */
static volatile LONG g_TrackDHitCount_Storage  = 0;  /* Phase 1 lands this */
```

Incremento por path type dentro da switch em [`driver/rstflt.c:2783-2816`](../driver/rstflt.c), APOS `childOk == TRUE` e antes do writeback. Manter `g_TrackDHitCount` global como soma (backward-compat com check-consistency.ps1).

### 3.2 Non-`rubinot*` parent-match counter

Novo `volatile LONG g_TrackDNonRubiParentMatchCount` incrementado quando: parent path classifica em qualquer path type (TRACKD_PATH_NONE != classification) AND image name nao passa o `_strnicmp("rubinot", 7)`. Esta e a evidencia decisiva de "quem enumera nossos targets".

### 3.3 Ring buffer de last-16 hits

```c
typedef struct _TRACKD_HIT_RECORD {
    LARGE_INTEGER   Timestamp;      /* KeQuerySystemTime */
    CHAR            ImageName[16];  /* ANSI, trailing NUL */
    UCHAR           PathType;       /* TRACKD_PATH_TYPE enum */
    UCHAR           WasGated;       /* 1 = rewrite landed, 0 = miss */
    USHORT          ParentPathHash; /* FNV16 de parent, so pra grep */
    WCHAR           ChildName[32];  /* first 31 wchars + NUL */
} TRACKD_HIT_RECORD;

static TRACKD_HIT_RECORD g_TrackDRingBuffer[16];
static volatile LONG     g_TrackDRingIndex = 0;
```

Write via `InterlockedIncrement` no index + modulo mask, sem lock. Loss racy = aceitavel para diagnostic.

### 3.4 Persistencia + exposicao

Estender `TrackDFlushWorker` ([`driver/rstflt.c:2930+`](../driver/rstflt.c)) para gravar todos os 8 per-path counters + `NonRubiParentMatchCount` como REG_DWORD, e o ring buffer como REG_BINARY (concat de 16 * sizeof(TRACKD_HIT_RECORD)).

Update `check-consistency.ps1` + `track-d-arm.ps1 -Diagnose` para decodificar o REG_BINARY e imprimir tabela: `Timestamp | Image | PathType | Gated | ChildName`.

### 3.5 Pre-validation (Phase 0 solo)

- Rebuild + install em `clean-no-driver` checkpoint.
- `Copy-Item C:\Windows\System32\reg.exe .\rubinot_probe.exe; Copy-Item ... .\launcher_probe.exe; Copy-Item ... .\wmiprvse_probe.exe` (3 nomes distintos).
- Query cada um contra `HKLM\SYSTEM\CurrentControlSet\Enum\SCSI` e `Enum\PCI`.
- Verificar: `HitCount_SCSI` e `HitCount_PCI` incrementam para `rubinot_probe.exe`; `NonRubiParentMatchCount` incrementa para os outros dois; ring buffer captura todos os 3 image names.

**Zero RubinOT session necessario para Phase 0 solo validation.**

---

## 4. Phase 1 - BTH + STORAGE\Volume + descriptor-table refactor

**Custo: ~2-3 dias, ~150-220 LOC C**

### 4.1 Descriptor-table refactor (pre-requisito para Phase 2)

Converter `TrackDClassifyParent` ([`driver/rstflt.c:2385-2397`](../driver/rstflt.c)) de if/else chain para tabela:

```c
typedef BOOLEAN (*TRACKD_PARENT_MATCHER)(PCUNICODE_STRING parent);
typedef BOOLEAN (*TRACKD_CHILD_GATE)(PCUNICODE_STRING child, ULONG realWchars);
typedef VOID    (*TRACKD_NAME_SYNTH)(const WCHAR *realName, ULONG realWchars, WCHAR *outName);
typedef NTSTATUS (*TRACKD_VALUE_REWRITER)(PCUNICODE_STRING valueName,
                                          PVOID information, ULONG informationClass,
                                          ULONG *resultLength);

typedef struct _TRACKD_PATH_DESCRIPTOR {
    UCHAR                   PathType;         /* TRACKD_PATH_TYPE enum */
    const char *            Label;            /* "SCSI", "PCI", etc - for ring buffer */
    TRACKD_PARENT_MATCHER   MatchParent;
    TRACKD_CHILD_GATE       ChildGate;        /* name-side */
    TRACKD_NAME_SYNTH       SynthName;        /* name-side */
    /* value-side (Phase 2 uses these; NULL in Phase 1) */
    const TRACKD_VALUE_ROW *ValueRows;
    ULONG                   ValueRowCount;
    volatile LONG *         HitCounter;       /* per-type from Phase 0 */
} TRACKD_PATH_DESCRIPTOR;

static const TRACKD_PATH_DESCRIPTOR g_TrackDDescriptors[] = {
    { TRACKD_PATH_SCSI,    "SCSI",    TrackDMatchScsiSuffix,   TrackDGateDiskVenPrefix, TrackDBuildSyntheticName,      NULL, 0, &g_TrackDHitCount_SCSI },
    { TRACKD_PATH_PCI,     "PCI",     TrackDMatchPciSuffix,    TrackDGateVenPrefix,     TrackDBuildSyntheticPciName,   NULL, 0, &g_TrackDHitCount_PCI },
    { TRACKD_PATH_USB,     "USB",     TrackDMatchUsbParent,    TrackDGateAny,           TrackDBuildSyntheticUsbHidInstance, NULL, 0, &g_TrackDHitCount_USB },
    /* ... HID, AudioR, AudioC, BTH, Storage */
};

static UCHAR TrackDClassifyParent(PCUNICODE_STRING parent, const TRACKD_PATH_DESCRIPTOR **outDesc) {
    for (ULONG i = 0; i < ARRAYSIZE(g_TrackDDescriptors); ++i) {
        if (g_TrackDDescriptors[i].MatchParent(parent)) {
            *outDesc = &g_TrackDDescriptors[i];
            return g_TrackDDescriptors[i].PathType;
        }
    }
    *outDesc = NULL;
    return TRACKD_PATH_NONE;
}
```

`TrackDHandlePostEnumerate` vira single loop: match parent -> pega descriptor -> se ChildGate() OK, chama SynthName(), writeback, `InterlockedIncrement(*desc->HitCounter)`. Reduz da switch atual a ~30 LOC.

### 4.2 BTH pattern

- Parent suffix: `\Enum\BTH` case-insensitive.
- Child names formato `Dev_XXXXXXXXXXXX` (12 hex = 6-byte MAC). Custom child gate: `TrackDStartsWithI("Dev_", child)` + validate 12 hex chars.
- Synth: preservar `Dev_` prefix (4 wchars) + gerar 12 hex via FNV(seed + realTokenBytes, "BTH_DEV|"). Same-wchar-count.
- **Safety**: nao interferir com o BT stack em bindings ativos - gate ja restringe a rewrites so quando image name gated (currently `rubinot*`, ampliado em Phase 2 se Phase 0 evidencia mandar).

### 4.3 STORAGE\Volume pattern

- Parent suffix: `\Enum\STORAGE\Volume` case-insensitive.
- Child names formato `{GUID}#offset` (38 wchars GUID + `#` + N digitos). Custom child gate: GUID shape check (mesma logica de `TrackDBuildSyntheticAudioGuid`) + `#` presente.
- Synth: rewrite so a parte GUID via FNV(seed + realGUIDbytes, "STORAGE_VOL|"), preservar `#offset` byte-exato.
- **Safety-critical**: se offset for zero (boot volume), NAO rewrite. Boot volume GUID e load-bearing para `\SystemRoot` resolution. Check: `#0` ou `#0x0` sufixo -> bail return STATUS_SUCCESS unmodified. Gate adicional em cima do image-name gate.

### 4.4 Pre-validation (Phase 1 solo)

- Rebuild + reload em `clean-v504-armed-track-d-tested` checkpoint.
- `rubinot_probe.exe query HKLM\SYSTEM\CurrentControlSet\Enum\BTH` - verificar HitCount_BTH incrementa, subkey names synth.
- `rubinot_probe.exe query HKLM\SYSTEM\CurrentControlSet\Enum\STORAGE\Volume` - HitCount_Storage incrementa, non-boot volume GUIDs synth, boot volume GUID **inalterado**.
- Regression: SCSI/PCI/USB/HID/Audio probes continuam funcionando (per-path counters mostram delta > 0 em cada).

Zero RubinOT session.

---

## 5. Phase 2 - Value-read handler (P0, dominante)

**Custo: ~5-7 dias, ~500-700 LOC C**

### 5.1 Notify classes

Adicionar ao switch top-level em [`driver/rstflt.c:2916-2925`](../driver/rstflt.c):

```c
case RegNtPostQueryValueKey:
    status = TrackDHandlePostQueryValue((PREG_POST_OPERATION_INFORMATION)Argument2);
    break;
case RegNtPostGetValueKey:
    status = TrackDHandlePostGetValue((PREG_POST_OPERATION_INFORMATION)Argument2);
    break;
```

**Post-only design.** Motivos: (a) buffer ja populado pelo kernel, so precisamos rewrite in-place; (b) evita a arquitetura Pre + CallContext + Post que triplica surface de buffer-arithmetic bugs; (c) IRQL PASSIVE_LEVEL identico ao PostEnumerateKey ja handled.

### 5.2 Descriptor rows

Estender cada `TRACKD_PATH_DESCRIPTOR` com um array de:

```c
typedef struct _TRACKD_VALUE_ROW {
    const WCHAR *   ValueName;         /* L"HardwareID", L"EDID", etc */
    UCHAR           ExpectedType;      /* REG_SZ, REG_MULTI_SZ, REG_BINARY */
    ULONG           FixedLength;       /* 0 = variable; 128 for EDID; etc */
    TRACKD_VALUE_REWRITER Rewriter;
} TRACKD_VALUE_ROW;
```

Rows por parent (~14 no total):

| Parent | Value | Type | Rewriter |
|---|---|---|---|
| `\SOFTWARE\Microsoft\Cryptography` | `MachineGuid` | REG_SZ | GUID synth (FNV seed + "MACHGUID\|") |
| `\Control\ComputerName\ActiveComputerName` | `ComputerName` | REG_SZ | 15-char alphanum |
| `\Services\Tcpip\Parameters` | `Hostname` | REG_SZ | mirror ComputerName |
| `\Enum\SCSI\*\*` | `HardwareID` | REG_MULTI_SZ | preserve MULTI_SZ shape, rewrite Ven/Prod token positions |
| `\Enum\SCSI\*\*` | `CompatibleIDs, DeviceDesc, FriendlyName` | REG_SZ/MULTI_SZ | same |
| `\Enum\PCI\*\*` | `HardwareID` | REG_MULTI_SZ | preserve VEN/DEV, rewrite SUBSYS/REV positions (mirrors name rewrite) |
| `\Enum\USB\*\*` | `HardwareID, CompatibleIDs, DeviceDesc, FriendlyName` | REG_SZ/MULTI_SZ | preserve VID/PID, rewrite serial |
| `\Enum\HID\*\*` | same 4 | REG_SZ/MULTI_SZ | same |
| `\Enum\BTH\*\*` | `HardwareID, DeviceDesc` | REG_SZ/MULTI_SZ | rewrite MAC-shape tokens |
| `\Enum\DISPLAY\*\*\Device Parameters` | `EDID` | REG_BINARY (128) | rewrite descriptor 0xFC (name) + 0xFF (serial), recompute byte 127 checksum |
| `\Control\Network\{4d36e972-...}\{GUID}\Connection` | `PnPInstanceId` | REG_SZ | FNV synth |
| `\HARDWARE\DESCRIPTION\System\CentralProcessor\N` | `ProcessorNameString, Identifier, VendorIdentifier` | REG_SZ | mirror Level A userland spoof |
| `\Enum\STORAGE\Volume\*` | `HardwareID` (etc) | REG_MULTI_SZ | rewrite GUID token |
| `\MMDevices\Audio\{Render,Capture}\{GUID}\Properties` | per-endpoint values | REG_BINARY/REG_SZ | endpoint metadata synth |

### 5.3 Safety contracts (BSOD-critical)

- **NO Zw* inside callback**. Rewriters sao pure string/binary math + FNV. Buffer manipulation so via `RtlCopyMemory` em memoria ja allocada pelo kernel.
- **KEY_VALUE_INFORMATION_CLASS awareness**. Handle: `KeyValueBasicInformation`, `KeyValuePartialInformation`, `KeyValueFullInformation`. Cada um tem offset diferente para o data buffer. Se o class nao esta em nossa allow-list (raro), bail unmodified.
- **REG_MULTI_SZ double-null preservation**. Rewrite token-in-place - qualquer mudanca de tamanho requer STATUS_BUFFER_OVERFLOW handling (nao implementar em v5.0.5; se new value nao fit, bail unmodified). O double-null terminator no fim NUNCA pode ser sobrescrito.
- **EDID checksum**. Byte 127 = -(sum of bytes 0-126) mod 256. Apos rewrite de descriptor 0xFC/0xFF, recompute e escrever. Graphics driver rejeita EDID com checksum invalido e pode triggar mode reset.
- **Same-length rewrites only**. Se new token > old token, truncate + bail unmodified. Nao complicar com resize em v5.0.5.
- **Image-name gate obrigatorio antes de qualquer rewrite**. Same gate que PostEnumerateKey. Se Phase 0 evidenciar necessidade de allow-list, tratar em kickoff v5.0.6 - **NAO** ampliar gate em Phase 2 sem evidencia.
- **Pre-Winlogon boot safety**. `EnableValueReadRewrite` deve default OFF em boot. Ligar so via track-d-arm.ps1 apos Windows subir. Bug nesse handler durante LSA/Winlogon boot path = brick.

### 5.4 Pre-validation (Phase 2 solo)

- Unit tests (userland harness que simula KEY_VALUE_INFORMATION_CLASS buffers): REG_MULTI_SZ fuzz (empty, single-null, double-null, huge), EDID 20+ real blocks com checksum verification.
- Reboot em `clean-v504-armed-track-d-tested` com `EnableValueReadRewrite=0` primeiro - verificar zero regression boot path.
- Arm `EnableValueReadRewrite=1`, probe MachineGuid via `rubinot_probe.exe query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid` - synthetic. Non-`rubinot*` probe do mesmo path - real.
- Probe cada uma das ~14 rows via gated processo. Ring buffer confirma path type + gate = TRUE.

Zero RubinOT session ate integracao completa.

---

## 6. Test plan integrado

### 6.1 VM cycle (por commit)

1. `.\02-compilar-driver.bat` (build + sign)
2. `Copy-VMFile` para checkpoint `clean-v504-armed-track-d-tested`
3. Guest: uninstall v5.0.4 -> install v5.0.5 -> `Restart-Computer -Force`
4. Guest: `.\scripts\track-d-arm.ps1 -Enable` + `Restart-Computer -Force`
5. Guest: `.\scripts\rubinot-probe.ps1` (todos os 3 image names, todas as N target parents)
6. Guest: `.\scripts\track-d-arm.ps1 -Diagnose` -> validate per-path counters + ring buffer

Sem BSOD. Sem non-rubinot process match count runaway. Todos os per-path counters > 0.

### 6.2 Bare-metal armed (single ship)

Somente apos VM cycle passar clean:

1. Rollback userland: `.\08b-rollback-userland.bat` (limpa Level A state)
2. Uninstall v5.0.4 driver: `.\08-desinstalar-driver.bat --skip-fase16`, reboot
3. Regenerate profile: `.\00-gerar-profile.bat`
4. Aplicar Level A: `.\04b-aplicar-hwid-emac.bat --skip-hid` (manter HID skip por input-safety)
5. Install v5.0.5: `.\03-instalar-driver.bat`, reboot
6. Arm: `.\scripts\track-d-arm.ps1 -Enable` + `EnableValueReadRewrite=1`, reboot
7. Validate: `.\scripts\check-consistency.ps1` + `-Diagnose`
8. **Fresh procmon capture** (7-10min, filter `Process Name contains rubinot OR wmiprvse OR svchost`) - **antes** de logar em RubinOT. Confirma current-build behavior + gera baseline para diff pos-sessao.
9. RubinOT session ate ~15min pos-login OU ate ban.

### 6.3 Post-session diagnostic

Ver ring buffer + per-path counters. Cross-check com procmon capture.

**Outcome tree**:

- **Ban NAO fired em 15min + all per-path counters > 0 + non-rubinot count baixo** -> v5.0.5 flippou o ban outcome. Ship. Update memory + README.
- **Ban fired + all per-path counters > 0 (gate ok) + value handler engaged for HardwareID/EDID/etc** -> value-side coverage nao foi suficiente. Escalar para Phase 4 (DEVICEMAP\VIDEO) + verify EDID persistence + reopen cpuid unfalsifiability probe.
- **Ban fired + per-path counters ainda baixo (~2-100) + NonRubiParentMatchCount ALTO** -> gate confirmed deaf. Kickoff v5.0.6 = gate broadening (allow-list ou remove image gate para read paths, rely on child-shape validation).
- **BSOD** -> revert v5.0.5 install, restore backups, root-cause em postmortem v5.0.6 antes de qualquer ship.

---

## 7. Deliverables

- [ ] [`driver/rstflt.c`](../driver/rstflt.c) v5.0.5 changelog block topo
- [ ] Phase 0 + 1 + 2 code
- [ ] Update `check-consistency.ps1` + `track-d-arm.ps1` para decodificar novos counters + ring buffer
- [ ] Update `README.md` (secao Track D): novos Parameters values (`EnableValueReadRewrite`), novos diagnostic outputs
- [ ] Postmortem `incident-v505-implementation.md` apos VM test passar
- [ ] Bare-metal test writeup em `incident-v505-baremetal-test.md`
- [ ] Update `CLAUDE.md` "Standard commands" com novo arm flag
- [ ] New checkpoint `clean-v505-armed` apos VM validation

---

## 8. Open questions - status

Todas as 4 questions do postmortem originalmente listadas estao agora resolvidas (Q1/Q2/Q4) ou reduzidas a teste executavel local (Q3):

1. **Q1 (HitCount scope)**: RESOLVIDO via grep - global, [`driver/rstflt.c:2828`](../driver/rstflt.c).
2. **Q2 (nome real do processo)**: RESOLVIDO via 2 CSVs procmon - `rubinot_dx.exe` (game) + `RubinOT.exe` (launcher Tauri), ambos matcham gate.
3. **Q3 (EDID persistence bare-metal)**: PREDIZIDO teoricamente + teste discriminativo local (nao-destructive, ~5 min):
   ```powershell
   $edid1 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY\MHH2708\*\Device Parameters' -Name EDID -EA 0).EDID
   # hot-plug HDMI cable OU sleep+wake do monitor
   $edid2 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY\MHH2708\*\Device Parameters' -Name EDID -EA 0).EDID
   if ($edid1 -eq $edid2) { 'REGISTRY DURAVEL' } else { 'PNP RE-ESCREVEU - kernel intercept obrigatorio' }
   ```
   Ambos outcomes convergem em "Phase 2 EDID value handler e a defesa correta". Executar antes de escrever Phase 2 EDID rewriter para calibrar se o rewriter e defense-in-depth (registry duravel) ou load-bearing (PnP re-escreve).
4. **Q4 (cross-process WMI/proxy)**: RESOLVIDO via CSVs - WmiPrvSE = 0, svchost baseline PnP only.
5. **Q4-adjacent (in-process wbemprox status)**: Recon zera IOCTL para \Device\WMIDataDevice e mssmbios, o que e inconsistente com wbemprox in-proc fazendo queries reais. Verificacao definitiva: ETW WMI-Activity trace durante rubinot_dx.exe lifecycle:
   ```powershell
   logman start WmiCheck -p Microsoft-Windows-WMI-Activity -o wmi.etl -ets
   # <15min RubinOT session>
   logman stop WmiCheck -ets
   ```
   Zero events -> Phase 3 formalmente closed. Events -> elevate Phase 3 para v5.0.6 backlog.

---

## 9. Referencias

- [`postmortem-v5-track-d/incident-v505-post-ban-triage.md`](postmortem-v5-track-d/incident-v505-post-ban-triage.md) - triage empirico completo
- [`emac-recon-v3.md`](emac-recon-v3.md) §3.2 - read counts + zero-WMI evidence
- [`track-d-kernel-registry-callback-kickoff.md`](track-d-kernel-registry-callback-kickoff.md) §3.2 row 6 - RegNtPreQueryValueKey handler prometido em MVP scope, jamais landeu
- [`postmortem-v5-track-d/incident-v504-pid-matching-simplification.md`](postmortem-v5-track-d/incident-v504-pid-matching-simplification.md) §8 - P0.2 flagado desde o audit v5.0.4
- [`roadmap-v41-wmi-intercept.md`](roadmap-v41-wmi-intercept.md) - onde WMI shadow fica ate v5.1+ target diferente aparecer
