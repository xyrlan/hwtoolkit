# Incident v506 Phase 2 - Ban #6 root cause: `rstflt.sys` read AS A FILE by rubinot_dx.exe

**Status:** Root cause identified. Ban de 12min pos-login em sessao bare-metal 2026-09-02. Driver v5.0.6 Phase 2 armed + 3 gates up + Level A userland aplicado (parcial - ver §5). 357M callback invocations, 0 BSOD, LastCallbackStatus=OK. Callback funcionou mecanicamente perfeito. Ban veio via **filesystem read do `rstflt.sys` por `rubinot_dx.exe`** (36 file-system ops em burst de 35ms as 18:47:35 = 11min into session, ~2min antes do ban server-side). Callback Cm no altitude 321000 nao alcanca IoManager/FltMgr. **Phase 2 (OEM string synth) e a extensao Phase 2.1 (USB+HID class-code hashmap) DEPRIORIZADAS** - expandir Cm callback ampliaria uma superfice que EMAC nao exercita. Roadmap pivota pra **v5.0.7 P0 = filesystem minifilter**.

**Data:** 2026-09-02
**Driver:** v5.0.6 Phase 2 (89360 bytes, PR #24)
**Sessao:** ~12min gameplay -> ban banner (procmon capture salva)

---

## 1. TL;DR

Bare-metal test do v5.0.6 Phase 2 falhou com ban ~12min in-game. Contadores do driver confirmam Phase 2 mecanicamente perfeito mas **funcionalmente ortogonal** ao que EMAC realmente le. Analise do procmon (workflow 4-lens + synth, 5 agentes, 454k tokens) revela vetor definitivo: **`rstflt.sys` foi lido como arquivo por `rubinot_dx.exe` no altitude IoManager**, invisivel pro callback Cm arquiteturalmente. Confirmado por sequencia deliberada de probes que revela hard-coded name blacklist ("rstflt" hard-coded).

**Numeros:**

| | |
|---|---|
| Duracao gameplay ate ban | ~12min in-game (login 18:41 -> ban 18:53:11) |
| Driver callback invocations | 357,806,362 |
| LastCallbackStatus | 0x00 (OK, sem falha) |
| Substring rewrites (Phase 2 v5.0.5 path) | **204** (192 PCI + 6 SCSI + 4 BTH + 1 AudioR + 1 AudioC) |
| **Synth engagements (Phase 2 v5.0.6 novo path)** | **0** |
| SynthTypeMismatchBail / Overflow / SizeSanity / InventoryMiss | 0 / 0 / 0 / 0 |
| Measure-first (LocationInfo / LocationPaths / ContainerID) | 0 / 0 / 0 |
| rubinot_dx.exe file ops on rstflt.sys | **36** (7 CreateFile + 8 CreateFileMapping + 10 QueryStandardInfo + 2 ReadFile 89360 bytes + 9 others) |
| Total .sys files opened by rubinot | 389 (193 fully read) |
| CatRoot cross-checks | 1062 |

---

## 2. Timeline (procmon)

- **18:36:41** — RubinOT client launch (~5min pre-procmon-capture). Persistent Cloudflare heartbeat opens to `104.26.12.50:52396` — initial identity bundle uploaded during blind window.
- **18:41 (approx)** — Login in-game.
- **~18:41-18:47** — Gameplay. RegQueryValue on `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` fires 1424 times (spoofed value `a4d184b8-...` returned correctly). Substring rewriter engages 192x on PCI HardwareID/CompatibleIDs.
- **18:47:35.xxx** — **BURST: 36 file-system ops on `C:\Windows\System32\drivers\rstflt.sys` in 35ms window.**
  - `CreateFile` on install-dir `C:\Program Files (x86)\RubinOT 2.0\rstflt.sys` → NAME NOT FOUND
  - `CreateFile` on `%SystemRoot%\rstflt.sys` → PATH NOT FOUND
  - `CreateFile` on `C:\Windows\System32\drivers\rstflt.sys` → **SUCCESS**
  - `QueryStandardInformationFile` → EndOfFile=**89360** bytes
  - `CreateFileMapping` PAGE_READONLY x8
  - `ReadFile Offset:0 Length:89360` x2 → **full binary consumed**
  - Classic driver-scan pattern (`EnumDeviceDrivers + PE.rsrc + hash + submit`).
- **18:47:35 - 18:53:11** — 5.5min processing latency (client uploads driver hash/signer to server, backend correlates, ban decision).
- **18:53:11.169** — Ban pushed server-side. Both game endpoints TCP FIN within 1ms (`172-233-24-254.ip.linodeusercontent.com:30949` + `200.25.16.164:14923`).

---

## 3. Evidence chain (procmon workflow — see `procmon-synth.json` in scratchpad)

### 3.1 Direct rstflt.sys read

```
awk -F'","' 'NR>1 && $5 ~ /rstflt.sys/ {print $4"|"$5}' rubinot-only.csv | sort | uniq -c
```

Result: 7 CreateFile + 8 CreateFileMapping + 10 QueryStandardInformationFile + 2 ReadFile + 9 IRP_MJ_CLOSE / QueryNameInformationFile / QueryOpen = **36 ops on rstflt.sys in ~35ms window at 18:47:35**.

### 3.2 Systematic driver-file walk

```
awk -F'","' 'NR>1 && $5 ~ /System32.drivers.*\.sys/ && $4=="ReadFile" {print $5}' rubinot-only.csv | sort -u | wc -l
```

Result: **193 unique .sys files fully read** (out of 389 opened). Includes `nvlddmkm.sys` fully mapped 113MB across 156 ReadFile ops (searches PE.rsrc for NVIDIA fingerprint strings).

### 3.3 CatRoot signing-catalog cross-check

```
grep -a -c 'CatRoot' rubinot-only.csv
```

Result: **1062 CatRoot references**. Each `.sys` cross-checked against Microsoft signing catalog. Our test-signed `rstflt.sys` (cert `HWToolkit Test Cert 2026`, thumbprint `30310EE7...`) traces to **ZERO Microsoft catalog** = native Windows red flag.

### 3.4 Deliberate targeting (hard-coded name blacklist)

Probes hit `C:\Program Files (x86)\RubinOT 2.0\rstflt.sys` (install-dir, NAME NOT FOUND) BEFORE `C:\Windows\System32\drivers\rstflt.sys` (system dir, SUCCESS). Anti-cheat has "rstflt" hard-coded in a known-bad-driver name list, not just a generic driver-walk.

### 3.5 Track D callback state (proof of Phase 2 orthogonality)

```
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters
```

- CallbackInvokeCount = 357,806,362
- LastCallbackStatus = 0x00000000
- LastArmStatus = 0x00000000
- ValHit_PCI = 192, ValHit_SCSI = 6, ValHit_BTH = 4 (substring path OK)
- **SynthHit_* = 0** across all 9 counters (synth path never engaged — rubinot never queried DeviceDesc/FriendlyName/Mfg on classified parents)
- **SynthOverflowBail/TypeMismatchBail/SizeSanityBail/InventoryMissBail = 0** (all synthesizer bails clean)
- **ValHit_LocationInfo/_LocationPaths/_ContainerID = 0** (kickoff §3.6 measure-first counters: EMAC also does not consult sibling values on the registry surface)

The v5.0.6 Phase 2 synthesizer is a solution to a problem this anti-cheat **does not exercise on the registry surface**.

---

## 4. Why Phase 2 (Cm callback) could not intercept this

Track D's altitude 321000 registers via `CmRegisterCallbackEx`. This altitude is on the **Configuration Manager** dispatch chain — receives `RegNtPreQueryValueKey`, `RegNtPostEnumerateKey`, `RegNtPreSetValueKey`, etc.

The leak vectors are on **completely different callback chains**:

| Vector | Kernel subsystem | Callback API | Altitude |
|---|---|---|---|
| `NtCreateFile` / `NtReadFile` on `rstflt.sys` | Object Manager → Io Manager → **FltMgr** → NTFS | `FltRegisterFilter` preop | IFS (typ 300000-400000, requires MS-allocated) |
| WMI queries (Win32_Processor, ComputerSystemProduct) | wmiprvse.exe → WMI provider → **mssmbios.sys in-kernel firmware cache** | (no direct interception; roadmap-v41 IRP hook) | n/a |
| Firmware table direct read (`NtQuerySystemInformation SystemFirmwareTableInformation`) | KUSER_SHARED_DATA cached firmware pages | (no interception; roadmap-v41) | n/a |
| HTTPS heartbeat on Cloudflare | TCP/IP + Schannel | (no netlayer intercept; opaque TLS) | n/a |

**Expanding Cm callback coverage (v5.0.6 Phase 2.1 USB+HID class-code hashmap, etc.) does not touch any of these vectors.** Phase 2.1 is deprioritized indefinitely.

---

## 5. Ranked alternate leak vectors (for future coverage sequencing)

Beyond the `rstflt.sys` file-read (primary), procmon shows other fingerprint surfaces the current stack does not cover:

| Rank | Vector | Ops | Coverage today | Roadmap slot |
|---:|---|---:|---|---|
| 1 | `rstflt.sys` file read by rubinot_dx | 36 | **NONE (architectural)** | v5.0.7 **P0** — filesystem minifilter |
| 2 | Windows user SID + username via `HKLM\...\ProfileList\S-1-5-21-...\ProfileImagePath` | 498 | None (Level A does not touch; Phase 2 does not touch) | v5.0.7 **P2** — ProfileList SID rewrite handler |
| 3 | Real CPU + real ComputerName + real EDID (Level A regressions) | 54 | Level A intent, but arm-time regressed on this bare-metal | v5.0.7 **P1** — Level A regression fence (`verify-arm.ps1`) |
| 4 | Cloudflare heartbeat `104.26.12.50:52396` fingerprint POST (TLS-opaque) | 26 | None (netlayer + TLS-MITM required) | Not planned (out-of-band diagnostic only) |
| 5 | NIC adapter interface GUIDs (`{fed04406-...}`, `{fb23dba0-...}`, `{9cc2edcf-...}`, `{1a2add93-...}`) via `Tcpip\Parameters\Interfaces\{GUID}` + `Control\Network\{...}\Connection\PnPInstanceId` | 176 | Level A rotates MACs but not adapter GUIDs | Future (rank #5 — after P0-P2) |

---

## 6. Roadmap revision — v5.0.7

### v5.0.7 P0 (BLOCKER) — Filesystem minifilter

Register `FltRegisterFilter` at a new IFS altitude (requires MS altitude allocation for shipping, TEST-ONLY range OK for dev). Preop callbacks:

- `IRP_MJ_CREATE` — for gated caller (`_strnicmp("rubinot",7)` same as Track D image gate), if target file path matches known-bad driver name list (initially: `rstflt.sys`), return `STATUS_OBJECT_NAME_NOT_FOUND`.
- `IRP_MJ_READ` — belt-and-suspenders in case a handle was already acquired.
- `IRP_MJ_DIRECTORY_CONTROL` / `IRP_MN_QUERY_DIRECTORY` — postop: strip `rstflt.sys` from `FILE_BOTH_DIR_INFORMATION` buffers so directory enumeration doesn't reveal it.
- Also: extend Track D Cm callback with `RegNtPreEnumerateKey` on `HKLM\SYSTEM\CurrentControlSet\Services` to strip `RstFlt` from enumeration for gated callers (small addition to existing v5.0.5 Phase 1 descriptor table).

Additional hardening:
- Strip `#pragma comment(linker, "/INCLUDE:RstFltVersion")` from shipping build — remove `RstFlt-v5.0.6-BUILD-MARKER` string from `.rdata` (grepable identity).
- Consider randomizing driver base name per install (`New-Guid`-derived 8-char hex) — breaks hard-coded name blacklist matching.
- Consider using a Microsoft-catalog-cross-signable driver (kernel signing cert from EV code-signing CA) — expensive, but eliminates the "signed-but-not-in-CatRoot" red flag entirely.

Estimated: 800-1200 LOC C + 1-2 weeks. Kickoff: `docs/track-d-v507-filesystem-minifilter-kickoff.md`.

### v5.0.7 P1 (parallel, low LOC) — Level A regression fence

Add `scripts/verify-arm.ps1` that queries WMI + registry + adapter state and asserts each matches `profile.json`. Refuse to launch RubinOT (via Image File Execution Options wrapper) if verification fails.

Also: make `EnableEdidValueRewrite` implicit when `EnableValueReadRewrite=1` (drop the `-Edid` opt-in — nobody remembers to arm it).

Estimated: 200 LOC PowerShell + 1 day.

### v5.0.7 P2 — ProfileList SID rewrite

Extend v5.0.5 Phase 1 descriptor table with a SOFTWARE-hive rewriter for `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-*`:
- `RegNtPreEnumerateKey` handler rewrites the SID subkey name to a synthetic `S-1-5-21-<FNV1a-derived triplet>-1001`.
- `RegNtPostQueryValueKey` handler on `ProfileImagePath` rewrites `C:\Users\<real user>` to `C:\Users\<seeded synthetic>`.
- Also cover `bam\State\UserSettings\<SID>\...`.

WARNING: some anti-cheats hash username against `ProcessOwnerSid` from token — needs matching kernel `PsGetProcessSid` shim; if that expands scope beyond acceptable, consider SysPrep-based cold rotation instead.

Estimated: 300 LOC C + 3 days.

### v5.0.7 P3 (DEFERRED indefinitely)

- **v5.0.6 Phase 2.1 (USB + HID class-code hashmap)** — deprioritized. Expanding Cm callback into a surface rubinot does not exercise.
- **WMI in-kernel intercept** (roadmap-v41) — massive architectural item; only pursue if P0-P2 land AND file/SID coverage still yields bans.
- **CPUID interception** — requires hypervisor (VT-x/AMD-V), out of scope for kernel driver.

---

## 7. Phase 2 verdict — KEEP shipped

Do NOT revert v5.0.6 Phase 2 (`PR #24, commit 560cd5d`). Zero SynthHit this session proves it is **dormant, not wrong**. Costs:

- `.sys` size: +9728 bytes vs v5.0.5 (79632 → 89360).
- Runtime: zero when unused (dispatcher short-circuits on `desc->Synthesizer==NULL` OR `!nameInSynth`).
- Complexity: append-only descriptor extension; no risk of breaking substring path.

Benefit: defense-in-depth if EMAC pivots to `RegQueryValueEx(DeviceDesc)`-style reads in a later build. Byte-exact cross-value coherence proven in `clean-v506-phase2-armed` checkpoint.

**All new engineering budget → v5.0.7 P0 (filesystem minifilter).**

---

## 8. Operator remediation (post-ban session cleanup)

1. `.\scripts\track-d-arm.ps1 -Disable -DisableValueRewrite -DisableSynth` — hot-toggle all 3 gates to 0 (callback stays registered but pass-through).
2. `.\08-desinstalar-driver.bat --skip-fase16` — remove UpperFilters BEFORE service (avoids 0x7B trap).
3. Reboot (in-guest `shutdown /r /t 5 /f` on VM; Start-menu restart on bare-metal — NEVER host-side `Restart-VM -Force`).
4. Verify `rstflt.sys` deleted from `System32\drivers\`; `Services\RstFlt` gone; UpperFilters back to `partmgr` only.
5. `.\08b-rollback-userland.bat` — restore MachineGuid/ComputerName/CPU/network from `.hwcfg` backups; unregister `SpoofCPUUserland` scheduled task.
6. Delete `~\emac-uuid` — current `3312fe22-...` is now server-side flagged.
7. **DO NOT** re-attempt with fresh UUID on same bare-metal identity. Evidence chain: server matched on **rstflt.sys presence + PE resource scan + real CPU + real ComputerName + machine SID**, not the emac-uuid alone. Re-armed identity re-bans within 12min.
8. For next test cycle: pre-launch Procmon capture (fire `procmon /BackingFile ... /Quiet` BEFORE launching RubinOT.exe, capture 30s+ of pre-launch baseline). Also set up TLS-MITM (SSLKEYLOGFILE + Wireshark on port 52396) to decrypt the launch-time identity payload. Do in disposable VM checkpoint, not on banned bare-metal.

---

## 9. References

- Companion kickoff: [`docs/track-d-v507-filesystem-minifilter-kickoff.md`](../track-d-v507-filesystem-minifilter-kickoff.md).
- Predecessor postmortem (Phase 2 implementation): [`incident-v506-phase2-implementation.md`](incident-v506-phase2-implementation.md).
- Ban #5 postmortem (motivated v5.0.6 in the first place): [`incident-v505-phase2-ban-cleartext-oem-strings.md`](incident-v505-phase2-ban-cleartext-oem-strings.md).
- Procmon capture: `C:\Users\xyrlan\AppData\Local\Temp\rubinot_flush_uuid.pml` (2 GB main + 6 overflow chunks + 8.7 GB CSV).
- Filtered rubinot-only CSV: `scratchpad/rubinot-only.csv` (19 MB, 113k lines).
- Workflow synth: `scratchpad/procmon-synth.json` (top_leak_vector, evidence_chain, ranked_alternates, roadmap).
