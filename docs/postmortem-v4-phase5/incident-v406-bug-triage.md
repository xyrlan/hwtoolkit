# INCIDENT — v4.0.6 bug triage: closing Bugs 3+5, arming evidence collection for Bug 4

**Date:** 2026-08-31
**Trigger:** three open bugs from `incident-v405-vm-pipeline-validation.md` blocking the next VM re-test cycle.
**Method:** multi-agent workflow triage (7 agents: 3 investigators, 3 adversarial verifiers, 1 synthesizer) plus manual anchor-research against MSDN + ReactOS `ntoskrnl/wmi/smbios.c`.
**Outcome:** two bugs closed, one converted from "mystery" to "evidence-collectable in one boot".

## Wins

### Bug 3 — SMBIOS registry replay is architecturally ineffective (two defects stacked)

**Root cause A (architectural).** `mssmbios.sys` does NOT serve WMI queries from the registry mirror at `HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data\SMBiosData`. That mirror is a write-back cache **produced** by mssmbios for external tooling and the crash-dump path — never **consumed** by WMI queries against `Win32_ComputerSystemProduct`, `Win32_BaseBoard`, `Win32_SystemEnclosure`, `MSSmBios_RawSMBiosTables`.

Where WMI actually reads: `WmipQueryRawSMBiosTables` → `WmipGetRawSMBiosTableData` walks the firmware SMBIOS entry-point directly (legacy F-segment scan starting at physical `0xF0000` for pre-UEFI, or ACPI `RSMB` for UEFI), maps the referenced physical table, parses it, and returns the buffer via `IRP_MJ_SYSTEM_CONTROL` to the WMI infrastructure. The registry is not on this path. Verified by reading `reactos/ntoskrnl/wmi/smbios.c` (ReactOS mirrors Windows WMI behavior) and MSDN's note on the mssmbios driver: *"the driver stores this information in the registry... consumers should continue to use WMI or the GetSystemFirmwareTable() API to retrieve SMBIOS data"* — explicitly telling readers the registry is not the source of truth.

**Root cause B (boot ordering, discovered during v4.0.6 triage).** The v4.0 rationale comment in `driver/rstflt.c:1615-1617` said "mssmbios itself has already booted at BOOT_START before us". This was **factually wrong**. Verified empirically on Windows 10 Pro dev host 2026-08-30:

```powershell
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\mssmbios |
    Select Start, Type, Group
# Start:1 (SYSTEM_START), Type:1 (Kernel driver), Group:<empty>
```

vs. our driver installed at `Start=0` (BOOT_START, per `03-instalar-driver.bat:141`). RstFlt runs **before** mssmbios, so `ZwOpenKey` on `\Registry\Machine\SYSTEM\CurrentControlSet\Services\mssmbios\Data` returns `STATUS_OBJECT_NAME_NOT_FOUND` at DriverEntry — the `Data` subkey is created by mssmbios's own init pass (likely `REG_OPTION_VOLATILE`, matching the observed "recreated every boot" behavior). We bail at `rstflt.c:490` before reaching the backup-write step, which is why `Parameters\OrigSmbiosData` stayed 0 bytes in v4.0.5's postmortem.

Two defects stack. Even if the boot-ordering bug were fixed, WMI would still return firmware values from mssmbios's in-kernel cache. The whole registry-write strategy is unrecoverable at the architecture level.

**v4.0.6 fixes:**

1. `driver/rstflt.c:1606-1620` (comment) — rewritten to state the empirical truth: mssmbios is SYSTEM_START, loads after us, `ZwOpenKey` typically fails, WMI reads from firmware in-kernel cache anyway, real fix is IRP interception in v4.1.
2. `driver/rstflt.c` new helper `WriteLastReplayStatus` — writes `Parameters\LastReplayStatus` `REG_DWORD` at every bail path in `ApplySmbiosBlobIfCached`. Encoding: `(tag << 24) | (NTSTATUS & 0x00FFFFFF)`. Tags: `0x00 SUCCESS`, `0x01 GATE-OFF`, `0x02 NO-BLOB`, `0x03 VALIDATION-FAIL`, `0x04 MSSMBIOS-OPEN-FAIL`, `0x05 MSSMBIOS-WRITE-FAIL`. On stock Windows expect tag=`0x04` every boot.
3. `scripts/check-consistency.ps1` — new `Read-ReplayStatus` function decodes the breadcrumb and prints it at the top of the audit. Turns previously-invisible bail state into a one-line print for the operator on the next boot after arming.
4. `scripts/spoof-smbios.ps1` — the "verify via WMI in-session" gate that guarded arming `EnableSmbiosReplay=1` was a placebo (WMI never observed our writes; the gate always passed). Removed; arming is now unconditional on `$cachedBlob=true`. The `ValidateSmbiosBlob()` in the driver + `OrigSmbiosData` backup are the actual safety nets, and both remain.
5. Honesty warning added to spoof-smbios output: "NOTA v4.0.6: em Hyper-V esta cadeia esta comprovadamente INEFICAZ contra WMI Win32_ComputerSystemProduct/BaseBoard/etc — mssmbios serve do cache in-kernel populado do firmware, nao do registro. Bare-metal pode ter comportamento diferente."
6. `docs/roadmap-v41-wmi-intercept.md` — captures the empirical `mssmbios Start=1` finding, the correct `PsSetLoadImageNotifyRoutine` hook point, the UMDF WMI provider alternative to test first, and the explicit PatchGuard warning against naive `DriverObject->MajorFunction[]` patching.

### Bug 5 — `spoof-smbios.ps1` hangs on `Restart-Service winmgmt`

**Root cause.** Restart-Service under `-Force` on a service with 15+ dependents (Winrm, ProfSvc, Themes, wuauserv, wscsvc, Schedule, iphlpapi, ...) invokes SCM's cascade Stop/Start cycle. Wall time is 60s+ typical, minutes worst case. When Restart-Service finally returns, the following six sequential `Get-CimInstance` calls at lines 568-573 open fresh RPC channels while winmgmt's provider host is still initializing, and get cancelled with `RPC_E_CALL_CANCELED (0x80010002)`.

**Compounding.** Per Bug 3, the entire "restart WMI then re-query" flow could never have observed the modified `mssmbios\Data` bytes in-session because WMI serves from a different source (in-kernel firmware cache). The gate at lines 605-621 was a placebo — the WMI query always returned non-empty firmware strings, so `$wmiOk` always evaluated to true and arming happened regardless.

**v4.0.6 fixes:**

1. `scripts/spoof-smbios.ps1:555-561` — DELETED `Restart-Service winmgmt -Force -ErrorAction SilentlyContinue` and its `Start-Sleep -Seconds 2`. Replaced with a comment referencing Bug 3+5 postmortem.
2. `scripts/spoof-smbios.ps1:562-594` — Step 12 verify block reduced to informational Get-CimInstance calls wrapped with `-OperationTimeoutSec 5 -ErrorAction SilentlyContinue`. Removed the `Fabricantes CONSISTENTES` consistency print. Added a `Write-Warn` clarifying that current-session WMI does NOT validate the spoof (it reads the in-kernel firmware cache) — validation happens at the next boot inside the driver.
3. `scripts/spoof-smbios.ps1:605-621` — DELETED the `$wmiOk` gate. Arming is now `if ($DisableKernelReplay) { skip } elseif ($cachedBlob) { arm + warn }`.
4. `scripts/spoof-smbios.ps1:470-479` — Step 10b header comment updated to reflect that WMI verification is no longer part of arming; validation is now driver-side (ValidateSmbiosBlob + OrigSmbiosData backup).

**Verification.** PowerShell parser succeeds on the modified script (`[System.Management.Automation.Language.Parser]::ParseFile`), smoke tests confirm `-SmbiosOnly -CpuOnly` mutual exclusion enforced, `-DisableKernelReplay` path preserved.

## Bug 4 — evidence collection armed, real fix deferred

Bug 4 could not be root-caused in this triage; the crash-dump pipeline had never captured a `MEMORY.DMP` for it. The triage produced two changes that enable evidence collection on the next repro:

### Repro contamination corrected

Grep-verified that no PowerShell/batch in `scripts/**` or the root batch files writes `EnableCpuReplay`. The v4.0.5 "CPU-only" repro was necessarily armed by the manual `Set-ItemProperty` mentioned in `docs/fase2-track-a-windows-test-kickoff.md:210`. That manual step did not clear `EnableSmbiosReplay=1` from the prior arming run, so "CPU-only" was actually SMBIOS+CPU. The observed "same 52-56s timing for two independent replays → shared fault site" inference is broken.

**v4.0.6 fix:** `scripts/spoof-smbios.ps1` gained mutually-exclusive `-SmbiosOnly` and `-CpuOnly` param switches:
- `-SmbiosOnly`: `Remove-ItemProperty` on `CpuStrings` + `EnableCpuReplay` before starting; skips Step 10c (CpuStrings cache).
- `-CpuOnly`: `Remove-ItemProperty` on `SmbiosBlob` + `EnableSmbiosReplay` + `OrigSmbiosData`; skips all SMBIOS work (Steps 4-10b); sets `CpuStrings` + `EnableCpuReplay=1` and exits with a final Parameters state print.

Default codepath (no switch) is unchanged — existing callers see identical behavior.

### Dump collection primed

`scripts/prep-crashdump.ps1` (NEW) applies the CrashControl configuration needed to actually capture a kernel dump on the next Bug 4 repro:

- `CrashDumpEnabled=1` (complete memory dump, not the default automatic mini-dump)
- `AutoReboot=0` (BSOD freezes on the STOP screen; requires manual reset via Hyper-V console — big warning banner printed)
- `AlwaysKeepMemoryDump=1`
- `IgnorePagefileSize=1`
- `DedicatedDumpFile=C:\rstflt-dump.sys`, `DumpFileSize=8192` (bypasses the pagefile-size failure common on small guest VMs)
- `wevtutil sl System /rt:true /ms:262144000` prevents System event log rollover during investigation

Companion `-Restore` flag reverts everything to Windows defaults after the investigation.

### Refuted hypothesis removed from Bug 4 write-up

An earlier speculative "RstFlt-as-DiskDrive-UpperFilter blocks the dump path" hypothesis was refuted by the triage: Windows crash dumps use a separate stack (`crashdmp.sys` + `dump_*` miniports bound directly to the storage port) that bypasses **all** class-level filters, both upper and lower. RstFlt as a DiskDrive class filter is architecturally invisible to `KeBugCheck2`'s dump writer, so it cannot block the dump path. The Bug 4 section of `incident-v405-vm-pipeline-validation.md` was rewritten to remove that hypothesis and document the true-independent repro protocol + heartbeat-off falsifier.

### Expected next-repro branches

Assuming next VM run applies the Track A + evidence changes and runs:

- **Branch A** — clean boot, no crash, no reset: H2 (host-side Hyper-V watchdog reset via VmHeartbeat integration service) is confirmed. Next work is on the KVP/heartbeat guest-agent path, **not** a driver rebuild.
- **Branch B** — STOP screen (BSOD) freezes at ~52-56s: dump finalizes to `C:\rstflt-dump.sys`. Manually reset via Hyper-V console. Recover boot per `09-recuperar-boot.bat`. Copy `C:\rstflt-dump.sys` off-guest. Run `!analyze -v` in WinDbg. Expected suspects (in priority order): `sppsvc.exe` (Software Protection Platform / Windows Activation — documented reader of `Win32_ComputerSystemProduct` + `Win32_Processor`), `ClipSVC` (Client License Service), `CompatTelRunner.exe`.
- **Branch C** — reset still fires at 52-56s with no STOP screen and no dump: H2 falsified AND dump-path itself is broken. Verify `Get-ItemProperty ...\Control\CrashControl` values landed correctly; if they did, this is a genuinely novel failure mode (possibly bare triple-fault or SLAT violation) warranting a Hyper-V synth-debugger session.

## Rejected during triage

Two candidate fixes were explicitly rejected — recording them here so they do not re-surface in future incidents:

- **"Delay CPU replay 90s"** driver change. Rationale rests on H3 (a Windows service reads CPU registry during first ~90s and faults on modified state) but is proposed **before** any evidence has actually identified the consumer or confirmed the timing. Applying it now can (a) mask the real bug by moving the crash window into cycle #2/#3, (b) create a new race between the delayed worker and any first-boot service that legitimately reads CPU registry within its expected 90s window, or (c) touch the KTIMER/KDPC/work-item chain in a driver with a documented history of subtle boot-time regressions (v4.0 → v4.0.1 hotfix). Revisit only after WinDbg + dump identify the actual consumer.
- **Naive `DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL]` swap** on `\Driver\mssmbios` as the initial v4.1 SMBIOS-intercept approach. Modifying a foreign DriverObject's dispatch table is a documented PatchGuard target on Windows 10 20H1+; typically bugchecks `0x109 CRITICAL_STRUCTURE_CORRUPTION` within 30-120s on any system with signature-enforced kernel integrity. The user's target has WDAC enforced (mode 2) and testsigning ON — PG is still armed absent explicit disable, so the naive swap would brick the box. Preferred lower-risk alternative (documented in `docs/roadmap-v41-wmi-intercept.md`): UMDF WMI provider or higher-precedence WMI class provider registration at user mode; test that first before considering any kernel dispatch patching.

## Files touched this commit

- `driver/rstflt.c` — v4.0.6 changelog block; corrected DriverEntry comment (mssmbios is SYSTEM_START, not BOOT_START); new `WriteLastReplayStatus` helper + call sites at every bail path in `ApplySmbiosBlobIfCached`.
- `02-compilar-driver.bat` — added support for Visual Studio 18 (2026 Community Edition, `\Microsoft Visual Studio\18\Community\`) alongside VS 2022. Version banner bumped to v4.0.6.
- `scripts/spoof-smbios.ps1` — new `-SmbiosOnly` / `-CpuOnly` param switches with mutual-exclusion check; -CpuOnly is a full early-return path (clean SMBIOS state, cache CpuStrings, arm EnableCpuReplay=1, print state, exit); -SmbiosOnly clears CpuStrings/EnableCpuReplay upfront and skips Step 10c; Step 11 (Restart-Service) deleted; Step 12 informational-only with -OperationTimeoutSec 5; Step 12b `$wmiOk` gate deleted; honesty warning about Hyper-V ineffectiveness.
- `scripts/check-consistency.ps1` — new `Read-ReplayStatus` function called at script start, decoding driver v4.0.6+ `LastReplayStatus` breadcrumb.
- `scripts/prep-crashdump.ps1` — NEW file. Sets CrashControl for complete dump + AutoReboot=0 + DedicatedDumpFile. Companion `-Restore` mode.
- `docs/postmortem-v4-phase5/incident-v405-vm-pipeline-validation.md` — v4.0.6 status header at top; Bug 4 section prefixed with the true-independent repro protocol + heartbeat-off falsifier + refuted-hypothesis note (original write-up preserved below for continuity).
- `docs/roadmap-v41-wmi-intercept.md` — NEW file. v4.1 SMBIOS interception plan: empirical mssmbios Start=1 verification, correct hook points, PatchGuard concerns, UMDF WMI provider as lower-risk alternative to test first, accepted Hyper-V limitation (VMBus/KVP cross-reference channels).
- `README.md` — new `MUDANCAS EM v4.0.6` section.

## New driver artifact

- `driver/rstflt.sys` — v4.0.6, 20992 bytes, SHA256 `132CE579A5D56F5F57600CDF0677A49BFD69C82A0E7437871927221EE95F484A` (build 2026-08-31 00:37 UTC-3).
- Built under Visual Studio 2026 (VS 18) Community + WDK 10.0.22621 with `/W4 /WX /kernel`, zero warnings.
- **NOTE:** the PE `IMAGE_FILE_HEADER.TimeDateStamp` is stamped by `link.exe` at build time, so a rebuild from identical source produces a different SHA256 even byte-length-identical. To validate that a driver came from v4.0.6 source, either:
  - Run `scripts/check-consistency.ps1` — its new `Read-DriverVersionMarker` decodes the marker embedded in the installed driver at `C:\Windows\System32\drivers\rstflt.sys` and prints `[OK] rstflt.sys instalado: v4.0.6+` when the marker is present.
  - Or manually: search the binary for the ASCII string `RstFlt-v4.0.6-BUILD-MARKER` — kept in the binary by `#pragma comment(linker, "/INCLUDE:RstFltVersion")` regardless of `DBG` (unlike the `DbgPrint` banner which is stripped in release).

## Recommended posture for next VM re-test

**Green (script/doc changes only, no driver install needed to gain benefit):**
- `spoof-smbios.ps1` no longer hangs on winmgmt restart.
- `-SmbiosOnly` / `-CpuOnly` give true isolation between the two replay paths.
- `prep-crashdump.ps1` primes the guest for real dump capture on the next crash.

**Yellow (requires driver reinstall for the breadcrumb to help you):**
- Reinstall the new `driver/rstflt.sys` (v4.0.6) via `03-instalar-driver.bat`. On the next boot after arming (SMBIOS or CPU), `check-consistency.ps1` will decode `Parameters\LastReplayStatus` and tell you exactly where `ApplySmbiosBlobIfCached` bailed. On Hyper-V expect tag `0x04 MSSMBIOS-OPEN-FAIL` every boot — that is the confirmed diagnosis, not a bug.

**Red (do NOT run until Bug 4 evidence lands):**
- SMBIOS `EnableSmbiosReplay=1` arming remains inert on Hyper-V (confirmed by Bug 3), but the exit path is now safe (driver bails cleanly). Test on physical hardware only after v4.0.6 is validated on VM without regressions.
- `05-aplicar-smbios.bat` option 2 (`-InstallTask`) — still installs the scheduled-task fallback that would keep triggering the same crash pattern on every boot per v4.0.5's Bug 4. Wait for Bug 4 evidence before using.

## References

- Prior postmortems in this series:
  - `incident-v4-phase5-boot-freeze.md`
  - `incident-v401-inaccessible-boot-device.md`
  - `incident-v402-signature-plus-filter.md`
  - `incident-v403-startype-boot-order.md`
  - `incident-v404-paging-path.md`
  - `incident-v405-vm-pipeline-validation.md`
- ReactOS `ntoskrnl/wmi/smbios.c` — reference implementation showing WMI reads firmware directly, not the registry mirror.
- MSDN "Microsoft System Management BIOS Driver (mssmbios)": *"consumers should continue to use WMI or the GetSystemFirmwareTable() API to retrieve SMBIOS data"* — confirms the registry is not the source of truth.
- MSDN "Writing a crash dump miniport driver" — confirms crash-dump path uses `dump_*`-prefixed miniports bypassing class filters.
- Companion: `docs/roadmap-v41-wmi-intercept.md`.
