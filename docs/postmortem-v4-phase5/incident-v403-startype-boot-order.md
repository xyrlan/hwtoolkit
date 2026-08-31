# INCIDENT — v4.0.3 fix: StartType/Group/ErrorControl closes the primary STOP 0x7B

**Date:** 2026-08-30 (continuation of v4.0.2 signature+filter session, same day)
**Session type:** Windows test session on Hyper-V + research phase in fresh session
**Test VM:** windev2407eval (Win10 Enterprise dev), Gen 2 UEFI, storvsc synthetic SCSI, 8 vCPU, 4 GB RAM, SecureBoot Off, HVCI Off, testsigning On, WDAC enforced (mode 2)
**Repo state:** branch `postmortem/v402-signature-plus-filter` at `c8d97ec` (v4.0.2 docs + AlignmentRequirement patch)
**Driver tested:** v4.0.2 signed .sys (same 27408-byte binary from prior session, cert `30310EE7…`, sig valid in VM's Root store)

## TL;DR

- 3-lens adversarial research workflow (9 agents, unanimous vote from 3 skeptics, 0 refuted) identified the primary bug: **service `StartType=SYSTEM_START (1)` conflicts with the DiskDrive class UpperFilters entry, which PnP walks during `BOOT_START` phase**.
- When PnP tries to attach the filter to the boot disk PDO under storvsc/disk.sys (BOOT_START loading), our service is not yet loaded (SYSTEM_START comes later), so the walk fails with `CM_PROB_FAILED_ADD` / `CM_PROB_DRIVER_FAILED_LOAD` on the boot devnode, boot volume mount fails, `ntoskrnl` bugchecks `STOP 0x7B INACCESSIBLE_BOOT_DEVICE`.
- Canonical reference: WDK `diskperf` INF ships `StartType=0` (BOOT_START) + `LoadOrderGroup="PnP Filter"` + `ErrorControl=Normal`. Our INF/install script (from v3.4 through v4.0.2) shipped `SYSTEM_START` + `Group="Filter"`.
- Microsoft's own "Troubleshooting a Stop 0x7B" documents this exact failure mode: an UpperFilters entry whose service is not loadable at boot ⇒ 0x7B.
- **Fix (no driver rebuild):** change `sc create` in `03-instalar-driver.bat` to `start= boot`, and set `Group="PnP Filter"`. `ErrorControl=Normal` was already correct.
- Proof of field validity: applied the change to the running v4.0.2 signed driver via runtime service config; reboot; **no more 0x7B, no auto-reboot loop** (Uptime monotonically grew past 90s, only 1 uptime reset from the deliberate `shutdown /r`).

## Why v3.4 shipped the wrong StartType

Comment in the old `03-instalar-driver.bat` explained the v3.3→v3.4 downgrade:

> "v3.4: baixado de boot para system. Se DriverEntry/AddDevice quebrar, o Windows ainda sobe (o driver simplesmente nao carrega nesta sessao) em vez de brickar o boot como aconteceu em v3.3."

The intent was correct (protect the user from a bricked boot on a broken driver) but the mechanism was wrong. What actually protects boot from a broken driver is **`ErrorControl=Normal` (=1)**: kernel logs the AddDevice/DriverEntry failure and continues booting without loading the driver that session.

`StartType=SYSTEM_START` on a DiskDrive class UpperFilter does not protect boot; it **guarantees** boot failure the moment the UpperFilters entry is populated, because the boot storage stack is enumerated in the BOOT_START phase before SYSTEM_START services load.

v3.4 escaped this bug because field tests through v3.6 exercised the driver without hitting the specific combination of "signed SYSTEM_START service + populated UpperFilters entry + boot storage stack enumeration under a synthetic HBA." The Hyper-V Gen 2 dev VM finally exercised it in v4.0.

## Timeline of hypotheses (this session)

| # | Hypothesis | Source | Result |
|---|---|---|---|
| 1 | v4.0.1 gate check fixes freeze | Prior session PR #6 | Confirmed clean |
| 2 | AlignmentRequirement missing copy | Prior session workflow | REJECTED — one-line fix did not resolve 0x7B on VM |
| 3 | Signature was necessary | Prior session | Confirmed necessary but not sufficient |
| 4 | **StartType=SYSTEM_START + UpperFilters entry incompatibility** | This session's 3-lens workflow | **CONFIRMED — fix eliminates 0x7B** |

## Verify votes (all 3 skeptics unanimous, 0 refuted)

- **sample-diff lens** (looks for a canonical counter-example that boots with SYSTEM_START): "no counter-example exists in the shipped OS or WDK; every DiskDrive UpperFilter that must observe the boot PDO (crashdmp, dumpfve, iaStorAfsService, historical Intel Rapid Storage filter) ships StartType=0."
- **irp-flow lens** (walks the boot IRP sequence): "before IRP_MN_START_DEVICE is delivered, PnP walks the DiskDrive class UpperFilters REG_MULTI_SZ and calls IopLoadDriver for each entry — RstFlt has StartType=1, its image is not resident and \\SystemRoot is not yet mounted, so IopLoadDriver fails and the boot devnode is marked CM_PROB_FAILED_ADD."
- **boot-timing lens** (reconciles demand-start-works vs SYSTEM_START-0x7Bs asymmetry): "at demand-start the boot disk stack is already built and PnP does not rebuild it, so the missing filter simply never attaches and never crashes; the boot disk devnode never enters the failing UpperFilters-load path."

## Fix applied

**`03-instalar-driver.bat`** (this repo, this commit):

```diff
-echo [*] Criando servico RstFlt (system start)...
-sc create RstFlt type= kernel start= system error= normal binPath= "%SystemRoot%\System32\drivers\rstflt.sys" DisplayName= "Intel(R) RST Storage Filter"
+echo [*] Criando servico RstFlt (boot start, PnP Filter group)...
+sc create RstFlt type= kernel start= boot   error= normal binPath= "%SystemRoot%\System32\drivers\rstflt.sys" DisplayName= "Intel(R) RST Storage Filter"

-reg add "HKLM\SYSTEM\CurrentControlSet\Services\RstFlt" /v Group /t REG_SZ /d "Filter"     /f >nul
+reg add "HKLM\SYSTEM\CurrentControlSet\Services\RstFlt" /v Group /t REG_SZ /d "PnP Filter" /f >nul
```

Comments in the script were also rewritten to reflect the new understanding.

## Field validation (VM)

Test cycle 1 with only this StartType change applied to the v4.0.2 signed driver:

- Install completes clean (`sc qc RstFlt` shows START_TYPE=0 BOOT_START, LOAD_ORDER_GROUP=PnP Filter, ERROR_CONTROL=1 NORMAL, UpperFilters=RstFlt,partmgr).
- Guest reboots with `shutdown /r /t 0`.
- Host-side poll: exactly **one** uptime reset (the deliberate shutdown), then monotonic growth. **No auto-reboot loop.**
- **0x7B eliminated.**

## What the v4.0.3-only test also revealed

Same test cycle exposed a **secondary bug**: the driver loaded (no 0x7B), but the guest hung post-driver-load pre-Winlogon-complete. Objective host-side signals:
- Uptime kept growing (Hyper-V wall clock from Running state — not a hang signal on its own)
- Heartbeat degraded from `OkApplicationsUnknown` to `LostCommunication`
- CPU stayed at 0% (no userland work)
- KVP guest agent published only 7 keys (early publisher only; healthy boot reaches 21+)
- IP address disappeared after briefly appearing

This is documented as a separate incident in `incident-v404-paging-path.md`, and the second fix (v4.0.4) is the driver code change (DO_POWER_PAGABLE + IRP_MN_DEVICE_USAGE_NOTIFICATION handler) that resolves the hang.

## References

- MSDN "Troubleshooting a Stop 0x7B in Windows": https://techcommunity.microsoft.com/blog/askperf/troubleshooting-a-stop-0x7b-in-windows/375185
- MSDN "Bug Check 0x7B — INACCESSIBLE_BOOT_DEVICE": https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x7b--inaccessible-boot-device
- MSDN "Specifying Driver Load Order": https://learn.microsoft.com/en-us/windows-hardware/drivers/install/specifying-driver-load-order
- WDK sample `diskperf` INF (canonical DiskDrive UpperFilter shape): microsoft/Windows-driver-samples storage/class/diskperf
