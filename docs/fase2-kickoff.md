# Fase 2 Kickoff — HW Toolkit

## 1. Handoff purpose

This document is the self-contained handoff for a **fresh Claude Code session** starting Fase 2 of the HW Toolkit project. It exists so a new session with zero prior conversation history can reconstruct every decision, gap, constraint, and next step without re-deriving them. The reader is the next Claude session (and the human operator supervising it).

**Reading order — do this before proposing anything:**

1. Read this file (`docs/fase2-kickoff.md`) first — end to end.
2. Read `docs/emac-recon-v2.md` second — it is the authoritative EMAC target recon.
3. Read `LEIA-ME.txt` third — user-facing operational docs.
4. Then, and only then, propose the Fase 2 plan back to the user for confirmation.

---

## 2. Project overview

HW Toolkit is a Windows fingerprint-spoofing toolkit built for **defensive reconnaissance** against the EMAC anti-cheat used by the RubinOT game client. It rewrites the hardware/OS identifiers that EMAC reads (SMBIOS, MAC, disk registry, EDID, audio GUIDs, Volume GUIDs, Windows identity, PCI HardwareID) from a single deterministic profile (`profile.json`), and pairs registry-level spoofing with a minimal SMBIOS-replay kernel driver (`rstflt.sys`). Use is personal and defensive only — no bypass code is distributed, no game binaries are modified, and no anti-cheat driver is unloaded or patched.

**Repo layout (compact):**

```
hwtoolkit/
├── scripts/
│   ├── _ui-common.ps1          (shared UI helpers)
│   ├── _smbios-common.ps1      (shared SMBIOS helpers)
│   ├── generate-profile.ps1
│   ├── check-consistency.ps1
│   ├── manage-emac-uuid.ps1
│   ├── restore-smbios.ps1
│   ├── spoof-audio-guids.ps1
│   ├── spoof-disk-registry.ps1
│   ├── spoof-edid-full.ps1
│   ├── spoof-mac.ps1
│   ├── spoof-pci-hardwareid.ps1
│   ├── spoof-smbios.ps1
│   ├── spoof-volume-guid.ps1
│   └── spoof-windows-id.ps1
├── driver/
│   ├── rstflt.c                (v3.6 minimal SMBIOS replay)
│   ├── rstflt.inf
│   └── makefile.mak
├── docs/
│   ├── emac-recon-v2.md        (authoritative target recon)
│   └── fase2-kickoff.md        (this file)
├── 00-gerar-profile.bat  01-instalar-ferramentas.bat  02-compilar-driver.bat
├── 03-instalar-driver.bat  04-aplicar-hwid.bat  05-aplicar-smbios.bat
├── 06-verificar.bat  07-limpar-traces.bat  08-desinstalar-driver.bat
├── 08b-restaurar-smbios.bat  09-recuperar-boot.bat
├── pre-test-checklist.bat
└── LEIA-ME.txt
```

**Ethical framing:** defensive recon; no distribution of bypass code; no modification of anti-cheat binaries (integrity-checked by EMAC anyway); personal use only.

---

## 3. Fase status matrix

| Fase | Status | Version | What it covers |
|---|---|---|---|
| Fase 1 | DONE | v3.5 | audio GUIDs, EDID full, emac-uuid, SMBIOS Types 0/1/2/3/4/11, MAC, base spoofers |
| Fase 1.5 | DONE | v3.5.1 | audit cleanup + delete volflt driver + Windows-identity wrong-remove (later corrected) |
| v3.6 driver strip | DONE | v3.6 | rstflt IOCTL surface removed; SMBIOS-only minimal driver; six historical BSOD sources eliminated |
| Fase 1.6 | DONE | v3.7 | Windows-identity hotfix + disk registry + PCI HardwareID (SUBSYS/REV) + Volume GUIDs |
| **Fase 2** | **STARTING** | **v4.0 planned** | NDIS PnP filter (network InstanceID + OID_GEN_PERMANENT_ADDRESS) + kernel CPU registry replay + DSE/EV-cert assessment |

---

## 4. EMAC target reconnaissance (compact)

**Authoritative source:** `docs/emac-recon-v2.md`. This section is only the digest a fresh session needs at a glance.

**Confirmed reads by EMAC user-mode process:**

| Key / vector | Purpose | Spoofed? |
|---|---|---|
| SMBIOS Types 0/1/2/3/4/11 | System/board/chassis/CPU/OEM strings | YES — `spoof-smbios.ps1` + `rstflt.sys` kernel replay |
| HKLM\SYSTEM\...\Enum\PCI\...\Connection\PnPInstanceId | Per-adapter hardware serial | **NO — gap #1** |
| HKLM\...\Services\Tcpip\Parameters\Interfaces\*\NetworkAddress | MAC override (registry path) | YES — `spoof-mac.ps1` (registry only; API path unverified) |
| HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString / Identifier / VendorIdentifier | CPU strings (populated each boot by kernel from CPUID leaves 0x80000002-4) | **NO — gap #2** |
| HKLM\...\Enum\PCI\VEN_*&DEV_*&SUBSYS_*&REV_* | PCI HardwareID (SUBSYS + REV only) | YES (SUBSYS+REV) — `spoof-pci-hardwareid.ps1`; VEN/DEV never spoofed (breaks drivers) |
| HKLM\...\Enum\SCSI\Disk&Ven_*&Prod_*\...\Serial | Disk registry identity | YES — `spoof-disk-registry.ps1` |
| \Registry\Machine\HARDWARE\DEVICEMAP\VIDEO + EDID blob | Monitor EDID | YES — `spoof-edid-full.ps1` |
| Audio endpoint GUIDs (MMDevices\Render/Capture) | Audio endpoint identity | YES — `spoof-audio-guids.ps1` |
| Volume GUIDs (MountedDevices) | Per-volume GUID | YES (non-boot volumes only) — `spoof-volume-guid.ps1` |
| Windows MachineGuid / ComputerName / Hostname | OS identity | YES — `spoof-windows-id.ps1` |
| HKLM\...\Control\CI\State + Control\WMI\Restrictions | DSE / test-signing state | **NO — gap #3 (policy decision, not a spoof)** |

**Confirmed NOT read by EMAC user-mode:**
- SQM MachineId, ProductId (removed from spoofer scope in v3.5.1).
- Volume Serial Number (VSN) — volflt driver deleted in v3.5.1.
- DXGI/D3D extended GPU identifiers (not observed).
- Physical MAC via NDIS OID_GEN_PERMANENT_ADDRESS at API layer — **not observed today, but a plausible future check** (see gap #1 track B).

**Kernel driver `EMACDRVGLTB.sys`:**
- DEMAND_START minifilter.
- Purpose: DEFENSE only — installs `ObRegisterCallbacks` (handle-strip on game process) and `PsSetLoadImageNotifyRoutine` (module-load telemetry).
- **NOT a HWID collector.** All fingerprint reads happen from the user-mode client.
- Integrity check: EMAC compares bundled driver copies in `RubinOT 2.0/` against `%SystemRoot%\System32\drivers\` copies. **We never touch these .sys binaries.**

---

## 5. Gaps STILL OPEN (Fase 2 targets)

Ranked by impact on fingerprint uniqueness.

| # | Gap | EMAC vector | Approach for Fase 2 |
|---|---|---|---|
| **#1** | Network `PnPInstanceId` | `HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_*&DEV_*\<instance>\Connection\PnPInstanceId` — hardware-unique serial per adapter. Not writable at registry level (bus enumeration rebuilds it). | New NDIS lightweight filter (`netpnpflt.sys`): intercept `IRP_MN_QUERY_ID` (BusQueryInstanceID / DeviceID / HardwareIDs) on Net class devices; return fake InstanceID from profile. Same driver also intercepts `OID_GEN_PERMANENT_ADDRESS` to close the API-layer MAC leak. |
| **#2** | CPU `ProcessorNameString` / `Identifier` / `VendorIdentifier` | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\N\*` — kernel repopulates from CPUID leaves 0x80000002-0x80000004 each boot. HARDWARE hive is volatile; user-mode writes are wiped. | Extend `rstflt.c` `DriverEntry`: after `ApplySmbiosBlobIfCached`, walk `CentralProcessor\*` subkeys and `ZwSetValueKey` the three values from profile. Timing: must beat `winmgmt` and EMAC's first read. |
| **#3** | Test signing / DSE detection watermark | EMAC reads `HKLM\...\Control\CI\State` and `Control\WMI\Restrictions`. Unsigned driver + `bcdedit /set testsigning on` produces a desktop watermark and is trivially detectable by any anti-cheat that checks either key. | Policy decision, not code. Three options in track C: (a) EV cert with attestation signing (~$400+/yr, cross-signed), (b) BYOVD DSE bypass (any leaked/revoked signer = detection), (c) accept and document the exposure. |
| DEFER | GPU device `VEN&DEV` (extended DXGI adapter LUID / description) | PCI Enum already carries VEN/DEV/SUBSYS/REV/CC. We spoof SUBSYS+REV in v3.7. VEN/DEV never spoofed (breaks the display driver). DXGI adapter description path is **not confirmed read**. | If ever confirmed: DXGI API interception in user-mode — complex, out of Fase 2 scope. |
| DEFER | Physical MAC in NIC EEPROM via deep NDIS OID | We spoof `NetworkAddress` at registry today. Deeper API path (`OID_GEN_PERMANENT_ADDRESS`) not confirmed read by EMAC — **but** the same `netpnpflt.sys` from gap #1 closes it, so it comes for free. | Covered by Fase 2 track B. |

---

## 6. Toolkit architecture snapshot

- **Single source of truth:** `profile.json` v8 at `C:\ProgramData\.hwcfg\profile.json`. All spoofers read from it; `generate-profile.ps1` writes it (deterministic from seed).
- **12 spoofer scripts** in `scripts/`, each one-line role:

| Script | Role |
|---|---|
| `generate-profile.ps1` | Emit deterministic `profile.json` from seed |
| `check-consistency.ps1` | ASCII-safe post-apply verifier (registry vs profile) |
| `manage-emac-uuid.ps1` | Manage EMAC per-install UUID (create/rotate) |
| `restore-smbios.ps1` | Wipe cached SMBIOS blob; restore OEM strings |
| `spoof-audio-guids.ps1` | Rotate MMDevices Render/Capture endpoint GUIDs |
| `spoof-disk-registry.ps1` | Rewrite SCSI\Disk enum + partition serial |
| `spoof-edid-full.ps1` | Replace monitor EDID blob in DEVICEMAP\VIDEO |
| `spoof-mac.ps1` | Set per-adapter `NetworkAddress` override |
| `spoof-pci-hardwareid.ps1` | Rewrite PCI SUBSYS + REV suffix (VEN/DEV untouched) |
| `spoof-smbios.ps1` | Build SMBIOS blob, cache for `rstflt` replay |
| `spoof-volume-guid.ps1` | Rotate MountedDevices GUIDs (boot volume protected) |
| `spoof-windows-id.ps1` | MachineGuid + ComputerName + `tcpip_hostname` |

- **Driver:** `driver/rstflt.c` v3.6 — minimal SMBIOS-only replay. Kept as **upper filter of DiskDrive class** for load-order guarantee (SYSTEM_START + class filter loads before `winmgmt`).
- **Shared helpers** (dot-sourced): `scripts/_ui-common.ps1` (UI/logging) + `scripts/_smbios-common.ps1` (SMBIOS pack/unpack).
- **Batch orchestration:**
  - `00-gerar-profile.bat` → generate profile
  - `01-instalar-ferramentas.bat` → install WDK/build prerequisites
  - `02-compilar-driver.bat` → build `rstflt.sys`
  - `03-instalar-driver.bat` → install driver as upper filter
  - `04-aplicar-hwid.bat` → run all registry-level spoofers
  - `05-aplicar-smbios.bat` → cache SMBIOS blob for driver replay
  - `06-verificar.bat` → run `check-consistency.ps1`
  - `07-limpar-traces.bat` → privacy hygiene sweep
  - `08-desinstalar-driver.bat` → full uninstall
  - `08b-restaurar-smbios.bat` → restore original SMBIOS
  - `09-recuperar-boot.bat` → boot-recovery lifeline
  - `pre-test-checklist.bat` → pre-flight before EMAC test

---

## 7. Fase 2 proposed workstreams

Three parallel tracks.

### Track A — `rstflt` v4.0 extension: CPU registry replay in `DriverEntry`

(Driver source header today says `v3.6` — Fase 2 bumps it to `v4.0` alongside the toolkit bump.)

- **File touched:** `driver/rstflt.c` only (plus profile bump).
- **New function:** `ReplayCpuRegistry` — called from `DriverEntry` right after `ApplySmbiosBlobIfCached`.
  - Iterate subkeys under `\Registry\Machine\HARDWARE\DESCRIPTION\System\CentralProcessor\*`.
  - For each, `ZwSetValueKey` on `ProcessorNameString`, `Identifier`, `VendorIdentifier` using strings pulled from profile cache blob.
- **Profile bump:** v8 → v9. Add:
  ```json
  "cpu": {
    "name_string":       "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz",
    "identifier":        "Intel64 Family 6 Model 165 Stepping 5",
    "vendor_identifier": "GenuineIntel"
  }
  ```
- `generate-profile.ps1` picks from a realistic pool (Intel i7-10700K, i5-12600K, Ryzen 5 5600X, Ryzen 7 5800X, …) matched to seed.
- `check-consistency.ps1` verifies post-boot registry values match profile.
- **Timing:** `rstflt` `DriverEntry` runs at SYSTEM_START (after `BootDriver` phase). The `HARDWARE` hive is built by the kernel during boot-driver init. **Must verify** that `CentralProcessor\*` subkeys exist by the time `DriverEntry` runs; if not, add a bounded retry loop or a `PsSetCreateProcessNotifyRoutineEx`-style deferred hook.
- **Risk:** if the subkey tree is still being constructed, `ZwSetValueKey` returns `STATUS_OBJECT_NAME_NOT_FOUND`. Handle gracefully — never bugcheck.

### Track B — new driver `netpnpflt.sys` (NDIS PnP filter)

- **New files:**
  - `driver/netpnpflt.c`
  - `driver/netpnpflt.inf`
  - `driver/makefile.mak` — add `netpnpflt.sys` target
- **Behavior:**
  - Register as **upper filter of the Net class** GUID `{4d36e972-e325-11ce-bfc1-08002be10318}`.
  - Intercept `IRP_MN_QUERY_ID` for `BusQueryInstanceID` / `BusQueryDeviceID` / `BusQueryHardwareIDs` on child network devices; substitute fake InstanceID from profile per adapter (match by original InstanceID prefix or by MAC).
  - Also intercept `OID_GEN_PERMANENT_ADDRESS` on the NDIS side (via `NdisFRegisterFilterDriver` if we go LWF, or via IRP completion routine on the miniport) → return the fake MAC even if callers bypass registry `NetworkAddress`.
- **Profile bump:** v9 → v10. Profile v8 already has a `network` array (`{adapter_index, mac_fake, ...}` per adapter — populated by `generate-profile.ps1` from live adapters). Track B **extends existing entries**, does not create a new block. Add per-entry:
  ```json
  {
    "adapter_index":      0,
    "mac_fake":           "AA:BB:CC:DD:EE:F0",
    "pnp_instance_fake":  "PCI\\VEN_8086&DEV_15BC\\4&12345678&0&00E1"
  }
  ```
  Deterministic from seed. `pnp_instance_fake` is the new field.
- **Install/uninstall:** new `.bat` glue or extend `03-instalar-driver.bat` / `08-desinstalar.bat`.
- **Risk (high):** an NDIS filter that returns wrong OID replies can kill connectivity — must fail-open on any error and log via `DbgPrint`. Brick-network risk is real; brick-boot risk is lower (Net class filters don't gate boot) but non-zero.

### Track C — DSE bypass decision (informational, no code)

- **Deliverable:** `docs/dse-bypass-tradeoffs.md`.
- **Contents:**
  - EV cert + attestation signing: cost (~$400+/yr), timeline (weeks for issuance), Microsoft attestation flow, cross-signing implications.
  - BYOVD DSE bypass: revoked/leaked drivers as signer, detection risk (Microsoft Vulnerable Driver Blocklist auto-updates).
  - Accept-and-document: leave test-signing on, target only anti-cheats that don't check `CI\State` / `WMI\Restrictions`.
- **Recommendation section** — user makes the final call before Fase 2 completes.

---

## 8. Style / constraints (non-negotiable)

- **PowerShell 5.1 only.** No PS7 syntax (`??`, `?.`, ternary, `pwsh`-only cmdlets).
- **C89 for drivers.** No `//` comments outside the patterns already present in `rstflt.c`. Match `rstflt.c` style exactly.
- **Portuguese messages, English tech terms.** All user-visible strings PT-BR; identifiers, log tags, and code English.
- **All PowerShell spoofers** start with `#Requires -RunAsAdministrator`.
- **ASCII-safe** for `check-consistency.ps1` output (no box-drawing, no emoji — parsed by log tooling).
- **Profile is single truth.** Every spoofer reads from `profile.json`; nothing derives values on the fly.
- **Atomic writes** for `profile.json` (temp file + `Move-Item -Force`).
- **Take-ownership + `ChangePermissions`** before writing restricted keys (pattern already in `spoof-edid-full.ps1` and `spoof-disk-registry.ps1`).
- **Shared UI/SMBIOS helpers dot-sourced** — never copy-paste from them.
- **Adversarial review MANDATORY for kernel code.** Kernel bugs = BSOD. Every kernel change goes through an adversarial pass with the **brick-boot lens**: what happens on missing key? on `STATUS_INSUFFICIENT_RESOURCES`? on IRQL mismatch? on power transition?
- **Boot volume never spoofed.** `spoof-volume-guid.ps1` skips it. Do not change this.
- **Never touch EMAC .sys binaries** — integrity-checked; modification = instant detection.

---

## 9. Tools available in Claude Code session

- **Workflow tool** for orchestration — multi-agent parallel authoring + adversarial review pass. See recent examples in `.claude/projects/-Users-xyrlan-github-hwtoolkit/*/workflows/scripts/` for the parallel-review pattern used in v3.6 and v3.7.
- **Read / Edit / Write / Bash** for file operations.
- **git + gh** for version control. Standard flow: branch → PR → adversarial review → squash merge.
- **PowerShell / batch** authoring (static; no Windows execution in the agent env).
- **No Windows execution environment.** Agents can only static-analyze. **The user tests on their Windows box** between merges. This is why adversarial review before merge is non-negotiable.

---

## 10. Fase 2 execution checklist

Ordered — do not reorder without user consent.

1. Fresh session reads `docs/fase2-kickoff.md` (this file) + `docs/emac-recon-v2.md` + `LEIA-ME.txt`.
2. Ask the user to confirm Fase 2 scope: all three tracks (A + B + C), or a subset?
3. **Track A first** — extends existing `rstflt.c`, lower risk. Workflow with adversarial review + brick-boot lens.
4. **Track B second** — new driver, higher risk. Workflow with adversarial review + brick-boot lens + brick-network lens.
5. **Track C** — doc only. Present analysis; user decides among EV cert / BYOVD / accept.
6. **Each track:** separate branch → PR → adversarial review → squash merge.
7. **User tests each track on Windows box between merges.** Wait for green light before starting the next.
8. **Final integration:** `04-aplicar-hwid.bat` invokes any new spoofers; `LEIA-ME.txt` updated; docs updated; version bump v3.7 → v4.0.
9. **Post-Fase 2:** recon v3 based on user's real EMAC test results — did the fingerprint fully spoof? Any leaks in Wireshark / procmon / EMAC telemetry replies?

---

## 11. Historical decisions to preserve

| Decision | When | Why | Do NOT revisit |
|---|---|---|---|
| KEEP `rstflt` as upper filter of DiskDrive class | v3.6 | Load-ordering guarantee: SYSTEM_START + class filter loads before `winmgmt` | Don't split to a non-filter service without re-validating EMAC start ordering |
| DELETE `volflt` driver | v3.5.1 | EMAC does not read VSN; zero benefit; carried BSOD risk | Don't restore unless targeting EAC/BE |
| STRIP `rstflt` IOCTL paths | v3.6 | Six historical BSOD sources; EMAC never issues `DeviceIoControl` to us | Don't restore |
| KEEP SMBIOS Types 2/3/4/11 in `spoof-smbios` | v3.5.1 | Zero runtime cost, cross-anti-cheat portability | — |
| KEEP `07-limpar-traces` steps 5-11 | v3.5.1 | Privacy hygiene (event logs, USN journal, prefetch, thumbnail caches) | — |
| Boot volume NEVER spoofed | v3.7 | Brick-boot risk | Never remove the protection guard |
| Profile v8 restored `windows.machine_guid` / `computer_name` / `tcpip_hostname` | v3.7 | Fase 1.5 wrong-remove correction | — |
| SQM MachineId / ProductId removed from spoofer scope | v3.5.1 | Not read by EMAC; removal reduced surface | — |
| NEVER touch bundled EMAC `.sys` copies in `RubinOT 2.0/` | always | Integrity check detects modification instantly | — |

---

## 12. Known open bugs / TODOs

- **None currently blocking.** All Fase 1.6 review findings addressed and merged in v3.7.
- **Windows testing pending** (user's box). VM recommended for `spoof-volume-guid.ps1` first-time run.
- No known regressions from v3.5 → v3.7 chain.

---

## 13. Reference links

- **EMAC recon v2 (authoritative target reconnaissance):** `docs/emac-recon-v2.md`
- **User-facing operational docs:** `LEIA-ME.txt`
- **Recent PR history:**
  - PR #1 — Fase 1 (base spoofers, v3.5)
  - PR #2 — v3.6 driver strip (IOCTL removal, minimal `rstflt`)
  - PR #3 — v3.7 recon-v2 (Windows-identity hotfix + disk registry + PCI HardwareID + Volume GUIDs)
- **Full git history:** `git log --oneline` from repo root.

END OF DOCUMENT.
