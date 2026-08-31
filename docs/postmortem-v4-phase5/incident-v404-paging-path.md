# INCIDENT — v4.0.4 fix: DO_POWER_PAGABLE + DEVICE_USAGE_NOTIFICATION handler closes the secondary post-boot hang

**Date:** 2026-08-30 (final closure of the Phase 5 boot-freeze investigation)
**Session type:** Windows test session on Hyper-V, continuation of v4.0.3 test cycle
**Test VM:** windev2407eval (Win10 Enterprise dev), Gen 2 UEFI, storvsc synthetic SCSI, 8 vCPU, 4 GB RAM, SecureBoot Off, HVCI Off, testsigning On, WDAC enforced
**Repo state:** branch `postmortem/v402-signature-plus-filter` at `c8d97ec` + local driver v4.0.4 patch (uncommitted at time of test)
**Driver tested:** freshly built v4.0.4 signed .sys, 21912 bytes, SHA256 `FD274AF97556EAE6DB53835A253DBE1BEAA75D87014D0AF28A9E06E301FFF0B0`, signed with test cert `30310EE7…`

## TL;DR

The v4.0.3 fix (StartType=BOOT_START + Group="PnP Filter" + ErrorControl=Normal — see `incident-v403-startype-boot-order.md`) eliminated the STOP 0x7B primary bug. The very first successful post-fix reboot then exposed a **secondary bug**: the driver loaded cleanly at BOOT_START, no bugcheck, but the guest hung mid-boot before Winlogon completed.

Objective signals of the hang from the host side (Hyper-V does not see a bugcheck since the guest did not auto-reboot):
- Guest Uptime kept growing (Hyper-V counts wall-clock from Running state)
- Heartbeat degraded from `OkApplicationsUnknown` to `LostCommunication`
- CPU stayed at 0% (kernel idle, no userland work)
- KVP guest agent published only 7 keys (early publisher only; a healthy boot reaches 21+ once the full KVP service starts)
- IP briefly appeared post-reboot then disappeared

The research workflow's Rank #3 hypothesis predicted this exact failure mode:

> "**DO_POWER_PAGABLE mismatch:** filter DO advertises DO_POWER_PAGABLE (IoCreateDevice default, then OR-in kept it) while the boot storvsc/disk stack under it has DO_POWER_PAGABLE cleared for the paging path. The power/PnP subsystem sees the pageable filter above a non-pageable boot stack and rejects the stack for boot volume mount." … "Contributor once the filter actually attaches. Not the first-cold-boot cause when the filter never attached at all."

The prediction was exactly right: once v4.0.3 let the filter attach, this dormant defect fired.

## Root cause (two related WDM defects)

Both defects live in the driver code and only matter when the filter participates in the boot storage stack. Prior versions escaped them because either (a) they crashed earlier (v3.x freeze paths) or (b) the class-registry UpperFilters entry was not populated (older test configs).

**Defect 1 — bitwise-OR propagation of `DO_POWER_PAGABLE` in AddDevice (line 1477 pre-patch):**

```c
flt->Flags |= dx->LowerDevice->Flags &
              (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
```

`IoCreateDevice` defaults `DO_POWER_PAGABLE=1` on the freshly created filter DO. Using `|=` to propagate from the lower device only ever **sets** the flag — it never **clears** it. On the boot volume, the lower `disk.sys` FDO has `DO_POWER_PAGABLE` cleared to participate in the paging path. Our filter, sitting above, keeps `DO_POWER_PAGABLE=1`. A pageable filter above a non-pageable stack violates the paging IRP IRQL contract: paging IRPs can arrive at DISPATCH_LEVEL, and if a paging code path touches pageable code, a page fault at DISPATCH_LEVEL is fatal (bugcheck 0xA IRQL_NOT_LESS_OR_EQUAL) or hangs the paging code path.

**Defect 2 — no handler for `IRP_MN_DEVICE_USAGE_NOTIFICATION`:**

The kernel sends `IRP_MN_DEVICE_USAGE_NOTIFICATION` when a device joins or leaves the paging (or hibernation, or crash-dump) I/O path. On the boot volume — which is also the paging volume — this fires during early boot. A well-behaved filter above the paging device must:

1. On the first paging joiner (`InPath=TRUE`, refcount 0 → 1), **clear** `DO_POWER_PAGABLE` on its DO **before** forwarding, so the flag is correct by the time lower drivers see the notification.
2. Track the paging refcount under a serializer (FAST_MUTEX in the canonical shape).
3. On the last paging leaver (refcount 1 → 0), **restore** `DO_POWER_PAGABLE` so power management returns to normal.

Our pre-v4.0.4 driver had this IRP fall into the default `IoSkip + IoCallDriver` branch — no refcount, no flag flip. Even if defect 1 were fixed alone (assign instead of OR), defect 2 would still bite whenever the boot volume was dynamically added to the paging path after AddDevice completed.

## The fix (v4.0.4)

### Change 1 — DEVICE_EXTENSION (rstflt.c ~206)

Added `PagingPathCount` (LONG) and `PagingPathMutex` (FAST_MUTEX) to per-device state.

### Change 2 — AddDevice (rstflt.c ~1477)

Split the OR-in into two:
- `DO_BUFFERED_IO | DO_DIRECT_IO` still propagated with `|=` (OR-in is correct there).
- `DO_POWER_PAGABLE` explicitly assigned: **exactly** what lower has.

Also initializes the FAST_MUTEX before clearing `DO_DEVICE_INITIALIZING` (once cleared, IRPs may arrive).

### Change 3 — DispatchPnp (rstflt.c ~1358)

Added a dedicated `IRP_MN_DEVICE_USAGE_NOTIFICATION` case, modeled on the diskperf WDK sample:

- Acquire PagingPathMutex.
- If joining and refcount==0: clear `DO_POWER_PAGABLE` on our DO, remember we did so.
- Release mutex.
- Forward-and-wait to the lower stack (KEVENT + PnpStartCompletion which returns `STATUS_MORE_PROCESSING_REQUIRED`).
- Re-acquire mutex.
- On success: increment or decrement `PagingPathCount`; if refcount returns to 0, restore `DO_POWER_PAGABLE`.
- On lower-driver failure: if we cleared the flag on the way in, restore it (roll back).
- Release mutex, complete IRP, release remove lock.

### Change 4 — DriverEntry DbgPrint

Version tag bumped to `v4.0.4, SMBIOS + gated CPU replay + paging-path handler`.

## Field validation

Same test cycle as v4.0.3 (see `incident-v403-startype-boot-order.md`) but with the freshly rebuilt v4.0.4 signed .sys pushed to the VM before the install. Install script (`install-v403-test.ps1`) is version-agnostic — it applies the StartType/Group/ErrorControl fix and injects UpperFilters regardless of driver version.

Host-side poll output (5-minute budget, 10-second interval):

```
BASELINE t=21:29:16 Uptime=357s HB=OkApplicationsUnknown IP=172.26.99.15 KVP=21 CPU=6%
t=21:29:27  Uptime=  368s  HB=OkApplicationsUnknown  CPU=  1%  KVP= 7  IP=            (guest starting shutdown)
t=21:29:37  Uptime=   10s  HB=OkApplicationsUnknown  CPU= 35%  KVP=21  IP=172.26.99.15   [UPTIME RESET #1]
t=21:29:47  Uptime=   20s  HB=OkApplicationsUnknown  CPU=  7%  KVP=21  IP=172.26.99.15
t=21:29:58  Uptime=   31s  HB=OkApplicationsUnknown  CPU=  0%  KVP=21  IP=172.26.99.15
...
t=21:30:59  Uptime=   93s  HB=OkApplicationsUnknown  CPU=  0%  KVP=21  IP=172.26.99.15

*** BOOT SUCCESS ***
    Uptime past 90s : 93 s
    Reboots seen    : 1 (want 1)          <- no auto-reboot loop
    Peak CPU%       : 35 (userland real)
    Peak KVP        : 21 (full service, vs 7 during v4.0.3 hang)
    IPv4 post-boot  : True
```

Guest-side confirmation:

```
sc query RstFlt          STATE : 4 RUNNING
Get-Service RstFlt       Status: Running, StartType: Boot
```

Contrast with the v4.0.3-only test that hung (same install config, only difference is the v4.0.2 vs v4.0.4 driver binary):

| Signal              | v4.0.3 (v4.0.2 driver, hung)      | v4.0.4 (fixed)                     |
|---------------------|-----------------------------------|------------------------------------|
| Uptime past reboot  | grew (host clock, kernel idle)    | grew with real work                |
| Heartbeat trend     | Ok → LostCommunication            | Ok stable                          |
| Peak CPU%           | 0                                 | 35                                 |
| KVP keys published  | 7 (early publisher only)          | 21 (full KVP service alive)        |
| IPv4 post-reboot    | briefly then gone                 | restored, stayed                   |
| sc query RstFlt     | (guest unreachable to check)      | STATE:4 RUNNING                    |

## Why KMDF port was ruled out

The research also asked whether porting from WDM to KMDF (Kernel Mode Driver Framework) would eliminate this whole class of bugs. Verdict from that agent:

> "Not worth it for v5.0. KMDF/WDF does not eliminate the 0x7B risk — it re-shapes it and introduces a second failure mode: Wdf01000.sys's own boot ordering. Two documented cases (Microsoft's own Hyper-V IC storage driver with Group=Base instead of WdfLoadGroup, and OSR NTDEV thread 55650 'Help with KMDF Disk Filter Driver - BSOD after install') produce the exact same STOP 0x7B this driver already hits. No Microsoft-blessed KMDF sample exists for a DiskDrive class UpperFilter on the boot volume. The 40-100h migration cost buys us framework-managed DO_* flag copies, StackSize/AlignmentRequirement inheritance and DO_DEVICE_INITIALIZING clear — but our WDM code already gets those right; it does NOT buy us correct StartType/LoadOrderGroup, which was the actual bug per the ranked hypotheses. WDF also changes power IRP semantics (framework consumes and re-emits rather than raw pass-through) and forces re-designing every PnP minor we currently forward transparently. Recommendation: keep WDM."

## Remaining follow-ups

- **Physical hardware validation:** v4.0.4 is proven on Hyper-V Gen 2 UEFI + storvsc. Physical hardware (LGA1200 + real AHCI) may exercise different paging path timing. Re-run `pre-test-checklist` + Phase 5–12 on the user's real box before shipping to any anti-cheat.
- **v4.0.5 nice-to-haves (not blocking):** consider setting `PNP_DEVICE_NOT_DISABLEABLE` on `IRP_MN_QUERY_PNP_DEVICE_STATE` for boot devices (defense against a user accidentally disabling the boot disk in Device Manager); consider moving `ApplySmbiosBlobIfCached` out of DriverEntry into `IoRegisterBootDriverReinitialization` for cleanliness (currently at SYSTEM_START… now BOOT_START, hive I/O in DriverEntry stops being cheap).
- **Wider test matrix:** the v4.0.3+v4.0.4 fix has been proven on ONE VM configuration. Confidence would grow with tests on: physical hardware, a Gen 1 BIOS VM (different boot device stack), a VM with hibernation enabled (exercises DEVICE_USAGE_NOTIFICATION for hibernation on top of paging), and a VM with a crash dump file on a separate volume (dump path is also a `DeviceUsageType`).

## References

- WDK sample `diskperf` (canonical DiskDrive UpperFilter with proper `IRP_MN_DEVICE_USAGE_NOTIFICATION` handler): microsoft/Windows-driver-samples storage/class/diskperf
- MSDN "Propagating the DO_BUFFERED_IO and DO_DIRECT_IO Flags": https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/propagating-the-do-buffered-io-and-do-direct-io-flags
- MSDN "Handling IRP_MN_DEVICE_USAGE_NOTIFICATION": https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/handling-an-irp-mn-device-usage-notification-request-in-a-filter-driver
- MSDN "Initializing a Device Object": https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/initializing-a-device-object
- Companion doc: `incident-v403-startype-boot-order.md` for the StartType fix that made this defect surface.
