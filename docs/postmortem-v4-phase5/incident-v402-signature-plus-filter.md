# INCIDENT — v4.0.2 signature workaround + full 3-lens analysis + persistent 0x7B

**Date:** 2026-08-30 (continuation of prior v4.0.1 incident, same day)
**Session type:** Windows test session on Hyper-V (physical host = i7-10700F Win10)
**Test VM:** "Ambiente de desenvolvimento do Windows 10" (windev2407eval, Win10 Enterprise, Gen 2 UEFI, storvsc synthetic SCSI, 8 vCPU, 4 GB RAM, SecureBoot Off, HVCI Off, testsigning On)
**Repo state:** main at `ee02f88` (v4.0.1) with local patch to `driver/rstflt.c:1481` adding `AlignmentRequirement` copy (staged, uncommitted)
**Driver built:** signed with self-signed test cert `CN=HWToolkit Test Cert 2026`, thumbprint `30310EE7644799431FFF099E1194817E813152B9`, SHA256 `4C2555F8A44118E92DC725250E6853ABCD44F697E4FA81424AADA9C911B471AA` (unsigned equivalent: `D3132BF3EA0F95A112D5C6063F1A09EB1F1C3206993E8B77858E724617AC9D24`)

## TL;DR

- v4.0.1 hotfix's `IsCpuReplayEnabled` gate WORKED on the physical hardware freeze path.
- On the VM, we then hit STOP 0x7B INACCESSIBLE_BOOT_DEVICE.
- 3-lens adversarial workflow (WDM sample diff / IRP flow / attach invariants) found 21 defects, converged on `AlignmentRequirement` missing copy as most likely root cause.
- Applied that fix (rstflt.c:1481, one-line change + comment) → still 0x7B.
- Confirmed WDAC enforcement on the dev VM was rejecting the unsigned driver with error 577 (ERROR_INVALID_IMAGE_HASH).
- Created self-signed test cert, signed the driver, installed cert into VM's `Cert:\LocalMachine\Root` (TrustedPublisher install got Access Denied but Root chain alone is enough for kernel signature check).
- Confirmed signature valid: `Get-AuthenticodeSignature` returns `Status: Valid`.
- Loaded the SIGNED driver at DEMAND-start post-boot via `sc.exe start rstflt` → **RUNNING**, no crash. DriverEntry executes clean, dispatch registered, no attached devices (no UpperFilter entry).
- Reconfigured service to SYSTEM_START + injected `RstFlt` into DiskDrive class `UpperFilters` + rebooted.
- **Still STOP 0x7B INACCESSIBLE_BOOT_DEVICE** — same as before.

**Conclusion:** signature was ONE necessary condition (unsigned driver never loaded, so prior "BSODs" may have been PnP-side effects of failed load). But even a properly signed, properly loadable driver with all our current fixes STILL crashes boot when placed in the DiskDrive class UpperFilters at SYSTEM_START. Something about the way this driver participates as a boot-storage-stack UpperFilter is fundamentally wrong for Gen 2 UEFI + storvsc, and the fix is deeper than any single AddDevice / dispatch tweak we have tried so far.

Session paused for deeper research (internet + Microsoft docs + WDK samples with a kernel debugger) in a fresh session.

## Timeline of hypotheses and their disposition

| # | Hypothesis | Evidence for | Result |
|---|---|---|---|
| 1 | v4.0.1 hotfix (`IsCpuReplayEnabled` early gate) fixes the boot freeze | Applied by dev session in PR #6; DriverEntry now returns cleanly with gate = 0 | Confirmed — DriverEntry itself is fine at boot on VM (later demand-start load also clean) |
| 2 | `AlignmentRequirement` missing copy in AddDevice (workflow synthesis pick) | 3-lens workflow attach-invariants finding, matched timing signature (0x7B at first storage I/O post-loader) | REJECTED — applied the one-line fix, still 0x7B |
| 3 | DiskDrive class UpperFilter role itself is the culprit (workflow's finding #2 escalation) | Load-order-only justification; SYSTEM_START loads before winmgmt regardless of filter status | INCONCLUSIVE — I removed only the UpperFilters injection (kept SYSTEM_START + service registration), user's vmconnect couldn't reconnect. I reverted based on "can't reconnect" but that MAY have been just vmconnect latency, not a BSOD. Never definitively established. |
| 4 | `start=system` boot-timing specific (not the code itself) | Registered service as `start= demand` (no auto-load at boot) → boot clean | Confirmed — service registration alone doesn't break boot. Boot broken only when driver actually loads at SYSTEM_START phase. |
| 5 | Unsigned driver rejected by WDAC | `sc.exe start rstflt` returned error 577 `ERROR_INVALID_IMAGE_HASH`. `Get-AuthenticodeSignature` returned `NotSigned`. `Get-CimInstance Win32_DeviceGuard` showed `CodeIntegrityPolicyEnforcementStatus=2 (Enforced)` and multiple active `.cip` policy files in `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\` | Confirmed — signed the driver, ran it demand-start post-boot, RUNNING. |
| 6 | Signed + demand-start-only WORKS, so SYSTEM_START + UpperFilters combo is what breaks | Demand-start post-boot = RUNNING; SYSTEM_START + UpperFilters = 0x7B every time | Confirmed — this is the persistent failure mode, and our current v4.0.2 fixes are not enough to make the SYSTEM_START + UpperFilters + boot combo work on Gen 2 UEFI + storvsc |

## Verified facts (do NOT re-derive)

1. **Driver base compile is clean** — MSVC 14.51 + WDK/SDK 10.0.22621, `/W4 /WX`, no warning suppression. The `CL=/wd4018` workaround was needed only under 14.44 with the pre-v4.0.1 code; v4.0.1 (main) already casts FIELD_OFFSET to (ULONG).
2. **Local VS BuildTools install (17.x) is broken** — VC/Auxiliary/Build/ is missing vcvars64.bat despite MSVC 14.44 being present. Workaround: use VS 18 Community Preview install found at `C:\Program Files\Microsoft Visual Studio\18\Community\` (has MSVC 14.51 + working vcvars). Documented in scratchpad but not in repo. Would be nice to have both install paths in `02-compilar-driver.bat` for future sessions.
3. **Test cert exists on host** — thumbprint `30310EE7644799431FFF099E1194817E813152B9`, exported to `<scratchpad>/hwtoolkit-testcert.cer`. Cert stays in host's `Cert:\CurrentUser\My` store after this session; can be re-used or recreated as needed. Timestamped signatures survive cert expiry.
4. **VM has WDAC enforced with multiple active .cip policies** — kernel-mode CI enforcement = mode 2 (Enforced). Signed driver with cert-in-Root loads OK; unsigned drivers are rejected with error 577.
5. **VM snapshot `pre-hwtoolkit-test-20260830-0905` is intact and reliable for revert** — used at least 4 times this session, always returned to pristine pre-first-boot state.
6. **`vmicguestinterface` service inside VM defaults to Manual startup on this dev VM image** — must be started manually (`Start-Service vmicguestinterface`) after every snapshot revert before `Copy-VMFile` from host works. `Set-Service ... -StartupType Automatic` inside VM is lost on snapshot revert (snapshot was taken before we changed it).
7. **Copy-VMFile from host** works once guest service is running. Cert install: `Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root` succeeds under elevated PS; TrustedPublisher store returns Access Denied (probably WDAC-blocked write). Root install alone is sufficient for kernel signature verification.
8. **VMConnect reconnect after guest reboot is laggy** — a "can't reconnect" state that lasts 30-60s can be just vmconnect UX latency, NOT a BSOD. Do not revert VM based on reconnect issue alone; check `Get-VM` state + heartbeat + IP first.

## Open questions for next session's research

1. **What EXACTLY does Windows 10 Gen 2 UEFI boot with storvsc do when it enumerates a DiskDrive class UpperFilter that adds a WDM filter DO above disk.sys's FDO on the boot PDO?** Timing, IRP sequence, what invariants must hold in our filter for the mount-boot-volume path to succeed. This driver's dispatch code looks canonically correct (forward-and-wait for START/REMOVE, pass-through for everything, remove-lock for I/O safety) but SOMETHING at the boot stage rejects it. Need actual kernel-debugger session to see the exact IRP flow.

2. **Is DiskDrive class the right class for a "load early to run DriverEntry before winmgmt" architecture?** The v3.6 docs explicitly say the class UpperFilter role is a load-ordering trick. Are there alternative mechanisms that provide the same early-load guarantee without inserting into the boot storage stack?
   - Bus-level filter (SCSI adapter class, storvsc class) — would still be storage-adjacent, similar risk
   - Non-filter SYSTEM_START service with LoadOrderGroup = "PNP Filter" or "Base" — the workflow's finding #2 proposed this; my incomplete test (removed UpperFilters only, kept SYSTEM_START on the service key) either didn't reproduce boot failure or I reverted too early on a vmconnect latency false alarm — needs a proper re-test
   - Boot-execute program (BootExecute registry) — user-mode, but runs very early
   - Session-manager KnownDlls or similar hook — different mechanism

3. **How does Windows 10 Enterprise dev VM's WDAC policy specifically evaluate self-signed drivers?** Our test cert install in Root was enough for `sc start` demand-load. But maybe the policy has boot-time-only rules that reject our cert during PnP filter enumeration. Would need `wdac-policy-tool` or Get-CIPolicy dump.

4. **What tool chains have others successfully used to develop / test WDM upper filters for the DiskDrive class on Hyper-V Gen 2 VMs?** Any WinDbg session captures / MSDN samples specifically for this boot-stack scenario. The classic WDK "toaster/filter" and "toastMon" samples are for made-up hardware and don't touch boot storage.

5. **Should the driver switch to KMDF (Kernel-Mode Driver Framework)?** WDM filter driver correctness is notoriously error-prone; KMDF handles pass-through, PnP, power, and remove-lock semantics automatically. This is 20+ hours of dev work to migrate but eliminates the whole class of subtle bugs. Worth considering for v5.0.

## Data available for next session

**In the repo (main branch as of `ee02f88` + this session's local `driver/rstflt.c` edit and postmortem docs to commit):**
- `docs/postmortem-v4-phase5/incident-v4-phase5-boot-freeze.md` — original v4.0 freeze on physical hardware
- `docs/postmortem-v4-phase5/incident-v401-inaccessible-boot-device.md` — first v4.0.1 VM 0x7B
- `docs/postmortem-v4-phase5/compile-bug-C4018-report.md` — resolved in v4.0.1
- `docs/postmortem-v4-phase5/utf8-bom-fix-report.md` — resolved in v4.0.1
- `docs/postmortem-v4-phase5/user-winre-recovery-log.txt` — evidence of WinRE recovery script failure
- `docs/postmortem-v4-phase5/incident-v402-signature-plus-filter.md` — THIS DOCUMENT

**In host's scratchpad (not committed):**
- `hwtoolkit-testcert.cer` — public cert for VM cert-store install
- `hwtoolkit-v402.zip` — repo snapshot for VM push
- `compile-driver-vs18.bat` — build wrapper using VS 18 Community
- Various compile-*.out logs

**In host's local repo tree (uncommitted diff):**
- `driver/rstflt.c` — one-line fix at line 1481 adding `flt->AlignmentRequirement = dx->LowerDevice->AlignmentRequirement;` plus 14 lines of comment explaining the fix. Not the operational fix for the 0x7B (proven this session), but is genuine WDM hygiene per the workflow analysis. Suggest committing separately from the postmortem docs so it stays isolated if the eventual fix ends up needing to remove the class filter role entirely.

**On the VM (state preserved by snapshot revert):**
- Snapshot `pre-hwtoolkit-test-20260830-0905` = pre-first-boot state, guest tools not yet enabled inside VM, no rstflt artifacts. Reliable revert target.

## Recommended next-session posture

1. Open new session with fresh context (this session's turn tokens will be freed).
2. Read this doc first, plus the two prior postmortems, plus fase2-track-a-windows-test-kickoff.md.
3. Do NOT re-run the failed hypothesis tests (waste of time and BSOD-revert cycles). The verified-facts list above is the ground truth.
4. Priorities in order:
   a. Get a kernel debugger attached to the VM (host WinDbg → VM COM/named pipe / net debug) so the next 0x7B has actual `!analyze -v` data.
   b. Research WDM upper filter of DiskDrive class boot-stack correctness patterns beyond what the 3-lens workflow found. Focus on Gen 2 UEFI + storvsc specifics.
   c. Consider dropping the class filter role entirely (workflow finding #2) — retest properly this time with explicit boot success verification (not just "vmconnect reconnected").
   d. Consider KMDF port for v5.0.
5. All work stays in a hotfix branch off `main`. Do NOT force-push over the postmortem-v4-phase5 branch that carries the docs and the AlignmentRequirement patch.

## What this session succeeded at

- Diagnosed the C4018 compile error and worked around it (dev session then fixed in v4.0.1).
- Diagnosed the UTF-8 BOM issue and worked around it (dev session then fixed in v4.0.1).
- Confirmed v4.0.1's `IsCpuReplayEnabled` gate correctness (DriverEntry runs clean).
- Discovered the recovery script (`09-recuperar-boot.bat`) is unusable in WinRE (no PowerShell there) — dev session fixed in v4.0.1.
- Diagnosed WDAC-enforced signature rejection with concrete error 577 evidence.
- Established a signed-driver workflow (test cert + Root store) that lets the driver load post-boot on this VM.
- Established that the driver's SYSTEM_START + DiskDrive UpperFilter combination is what breaks boot on Gen 2 UEFI + storvsc, INDEPENDENT of any single WDM code defect we have addressed. This narrows the search space dramatically for the next session.

## What this session did NOT achieve

- Did not get the driver to boot cleanly at SYSTEM_START + UpperFilters on this VM.
- Did not confirm or refute the workflow's alternative fix (drop class-filter role entirely) because the one test attempt of that path was aborted based on a probably-false BSOD signal (VMConnect latency mistaken for boot failure).
- Did not run the actual EMAC test in Phase 6-12. Zero data on whether v4.0's spoof coverage is complete against EMAC.
- Did not deploy anything to physical hardware since the v4.0 initial freeze; hardware boot is stable but nothing v4.0.x has been verified there.
