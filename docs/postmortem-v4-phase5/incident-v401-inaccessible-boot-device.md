# INCIDENT — v4.0.1 Phase 5 VM test → INACCESSIBLE_BOOT_DEVICE

**Date:** 2026-08-30
**Session:** Windows test kickoff (post-v4.0.1 hotfix retest in Hyper-V)
**Repo commit tested:** `ee02f88` (v4.0.1 hotfix)
**Driver built:** `rstflt.sys` 19968 bytes, SHA256 `2875e4d4282cd3dcd7bb7a87949631adc18edc70233c701303ef1847539f9d9b`
**Compiled with:** MSVC 14.51.36256 (VS 18 Community preview toolset, since VS 17 BuildTools install was broken locally), WDK/SDK 10.0.22621, `/W4 /WX` clean, no warning suppression
**Test host:** Hyper-V Gen 2 UEFI VM "Ambiente de desenvolvimento do Windows 10" (MS Win10 Enterprise dev VM, `windev2407eval`)
  - Generation 2 (UEFI firmware)
  - Secure Boot: Off
  - HVCI: Off
  - testsigning: Yes (already enabled in the image)
  - 8 vCPUs, 2 GB RAM
  - SCSI virtual disk via storvsc (Hyper-V synthetic controller)
  - Base checkpoint `pre-hwtoolkit-test-20260830-0905` for instant revert

## Summary

v4.0.1's `IsCpuReplayEnabled` gate fix successfully prevented the boot-loader hang that killed
the physical hardware test. Driver installed cleanly (service registered SYSTEM_START, UpperFilters
prepended `RstFlt, partmgr`, hash-verified `.sys` in `System32\drivers`, `EnableSmbiosReplay=0`,
`EnableCpuReplay` unset — everything as expected). Reboot triggered a clean Windows loader stage.

But at the point Windows tried to mount the boot volume, the system bugchecked with
**STOP 0x7B INACCESSIBLE_BOOT_DEVICE** and displayed the standard Windows sad-face BSOD ("Your device
ran into a problem and needs to restart"). QR code sighted, no MEMORY.DMP written on the reverted
snapshot (rollback happens before the crash-dump path finishes).

Snapshot `pre-hwtoolkit-test-20260830-0905` restored instantly. VM stable, reverted state OK.

## Diagnostic

0x7B = the OS could not access the device from which it boots. The storage stack failed after
kernel init but before session manager start. On a boot with `RstFlt` prepended to the DiskDrive
class UpperFilters and every replay gate off, the ONLY thing the driver still does at boot time
is the filter attach + IRP dispatch. That is where the bug is.

Very likely causes (in order of probability given the STOP code):

1. **Incomplete IRP MajorFunction table** — the driver only sets pass-through routines for
   IRP_MJ_DEVICE_CONTROL / IRP_MJ_CREATE / IRP_MJ_CLOSE (or a similar minimal subset). Boot-critical
   IRPs (IRP_MJ_PNP, IRP_MJ_POWER, IRP_MJ_SCSI, IRP_MJ_READ, IRP_MJ_WRITE) fall through to the
   default handler which completes them with STATUS_INVALID_DEVICE_REQUEST or similar. Lower drivers
   in the stack never see these IRPs and the device fails to enumerate/read.

2. **AddDevice implementation broken** — either not calling `IoAttachDeviceToDeviceStack` at all,
   or attaching to the wrong device, or not chaining PDO relationships correctly. Result: kernel
   sees the filter DO but the underlying disk PDO does not receive IRPs.

3. **PnP handling wrong** — filter drivers must forward IRP_MJ_PNP requests (especially
   IRP_MN_START_DEVICE, IRP_MN_REMOVE_DEVICE, IRP_MN_QUERY_DEVICE_RELATIONS) to the next
   device. Missing forwarding will fail device init.

4. **Boot-critical flag missing** — since RstFlt is a boot device stack filter (UpperFilter of
   DiskDrive with SYSTEM_START), the driver may need SERVICE_BOOT_START-adjacent handling. But
   SYSTEM_START on the class UpperFilter usually works. Less likely than 1-3.

**Host escaped this bug because** it froze earlier in the CPU replay worker path (per v4.0.1
commit note). Now that path is gated, the boot progresses far enough to trip the filter
pass-through issue that was always latent.

## Reproduction

Trivial and 100% reproducible in the VM. Steps:

1. Ensure `pre-hwtoolkit-test-20260830-0905` snapshot exists on
   "Ambiente de desenvolvimento do Windows 10" VM.
2. Start VM. Log in as `windev2407eval\user`.
3. Copy toolkit + built rstflt.sys 19968-byte v4.0.1 into VM's `C:\hwtoolkit`.
4. Run `.\03-instalar-driver.bat` inside VM. Confirm service registered, gates off,
   UpperFilters shows `RstFlt, partmgr`.
5. `Restart-Computer -Force`.
6. VM bugchecks with STOP 0x7B INACCESSIBLE_BOOT_DEVICE (visible in vmconnect within ~30s
   of reboot).
7. From host: `Restore-VMSnapshot -VMName "Ambiente de desenvolvimento do Windows 10"
   -Name "pre-hwtoolkit-test-20260830-0905" -Confirm:$false` to reset.

Cycle time host → BSOD → revert → back to clean state: under 60 seconds. **This is the
fast iteration loop the driver desperately needs.** Dev session should use this VM for every
subsequent hotfix cycle.

## Recommendation for dev session

1. **Audit `driver/rstflt.c` for full IRP MajorFunction coverage.** Every IRP major function
   that a boot-critical DiskDrive class filter can receive needs a pass-through. Reference:
   https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/writing-dispatch-routines
   and the sample filter drivers in the WDK samples (`filter/`, `simrep/`, `usbsamp/`).

2. **Audit `AddDevice`** — confirm `IoCreateDevice` + `IoAttachDeviceToDeviceStack` +
   proper DEVICE_OBJECT flags (`DO_POWER_PAGABLE`, `DO_BUFFERED_IO`/`DO_DIRECT_IO` matching
   the lower device).

3. **Add pass-through PnP** — implement `RstFltDispatchPnP` that completes
   IRP_MN_REMOVE_DEVICE locally (unregister + detach + delete) but forwards all other minor
   codes to the next device.

4. **Consider using KMDF instead of WDM** if the current implementation is WDM. KMDF handles
   the boilerplate filter mechanics (attach, detach, PnP forwarding, power) automatically and
   is much less error-prone for filter drivers. This would be a bigger change but eliminates
   the whole class of bug.

5. **Test in the VM first for every hotfix.** The physical-hardware freeze from v4.0 was
   opaque (no dump, no STOP code). The VM STOP 0x7B is easy to diagnose. Use the VM as the
   primary iteration surface until the driver is boot-stable, then re-verify on hardware.

6. **Add adversarial review lens: `boot-critical filter driver correctness`** — the existing
   review lenses (brick-boot, brick-network) didn't catch this. A dedicated pass focused on
   "does this driver correctly implement pass-through for every IRP the storage stack can
   send during boot?" would.

## Contrast with v4.0 physical hardware freeze

| Aspect | v4.0 physical | v4.0.1 VM |
|---|---|---|
| Symptom | Silent boot freeze at BIOS/loader stage | Windows loader → 0x7B → BSOD screen |
| STOP code visible | No | Yes: INACCESSIBLE_BOOT_DEVICE (0x7B) |
| MEMORY.DMP | No (system hung before dump path) | Not persisted (revert happens quickly) |
| Kernel-Power event 41 | No | (would appear if reboot loop tolerated) |
| Root cause | CPU replay worker queued at boot, race with system init | Filter driver's IRP pass-through broken |
| Fixed by | v4.0.1 `IsCpuReplayEnabled` gate before ExQueueWorkItem | STILL OPEN — needs another hotfix |
| Recovery cost | ~30 min manual WinRE + reg cleanup | Snapshot revert, ~10 seconds |

v4.0.1 was a real fix for the v4.0 bug. But it uncovered a pre-existing latent bug that the
earlier freeze was masking. This is normal for kernel-mode iterative debugging — each fix
peels a layer, exposing the next.

## What is safe in v4.0.1

The `IsCpuReplayEnabled` implementation appears clean. Once the filter pass-through is fixed,
we expect the CPU replay code (already merged in v4.0, unchanged in v4.0.1) to work as
designed since its DriverEntry hook is behind the fixed gate.

The BOM adds, C4018 casts, and cmd-only recovery script are all orthogonal to this bug and
remain correct.

## State post-incident

- **Physical host:** clean, boot-stable, no residual driver. `git pull` complete
  (main = `ee02f88`). VS 17 BuildTools broken locally (VC dir missing vcvars) — worked around
  with VS 18 Community for compile. Non-blocking for dev session.
- **VM:** reverted to `pre-hwtoolkit-test-20260830-0905` (state as of 2026-08-30 09:05,
  pre-first-boot with guest tools enabled but no driver artifacts). Fully clean.
- **Repo working tree on host:** clean (was clean before pull, still clean).
- **Baseline captures + profile v9:** intact at `C:\baseline-v4\` and
  `C:\ProgramData\.hwcfg\profile.json` (host). Reusable for next test cycle.
