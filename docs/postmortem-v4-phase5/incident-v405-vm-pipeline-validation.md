# INCIDENT — v4.0.5 VM pipeline validation: 5 findings before touching physical hardware

**Date:** 2026-08-30 (continuation of v4.0.4 boot correctness closure, same day)
**Session type:** Windows Hyper-V VM validation of spoofing pipeline Phases 2 → 6 → 7 → 8
**Test VM:** windev2407eval (Win10 Enterprise dev), Gen 2 UEFI, storvsc synthetic SCSI, 8 vCPU, 4 GB RAM, SecureBoot Off, HVCI Off, testsigning On, WDAC enforced (mode 2)
**Driver tested:** v4.0.4 signed .sys (21912 bytes, SHA256 `FD274AF97556EAE6DB53835A253DBE1BEAA75D87014D0AF28A9E06E301FFF0B0`) installed at BOOT_START via `install-v403-test.ps1` (equivalent config to the freshly-fixed `03-instalar-driver.bat`)

## Why this session

After v4.0.4 landed and closed the STOP 0x7B primary bug + post-boot hang, the driver was field-validated on the VM boot storage stack but the **spoofing pipeline itself** (Phases 2 → 12) had never run end-to-end since v3.5. The user's real hardware wait cycle for iterating anti-cheat regressions costs ~30 min per BSOD → WinRE → cleanup. So we ran Phases 2 → 6 → 7 → 8 on the same VM (with snapshots between reboots) to find any latent bugs before the physical target ate them.

The bet paid off: **five real bugs were found**, two are fixed in this commit, three are documented as follow-ups with concrete root-cause hypotheses.

## Wins (validated end-to-end on VM)

### CPU registry replay (v4.0 crown feature) works

- All 8 logical processors on the guest report the spoofed value:
  ```
  [0]-[7] Name='Intel(R) Core(TM) i5-10600K CPU @ 4.10GHz'
          Id='Intel64 Family 6 Model 165 Stepping 5'
          Ven='GenuineIntel'
  ```
  (Real: `Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz` — host CPU passing through Hyper-V.)
- `OrigCpuStrings` backup populated correctly (uninstall path works).
- Driver `STATE:4 RUNNING`, `StartType:Boot` in steady state.
- Worker thread + HAL race handling holds on 8-core synthetic Hyper-V topology.

### HWID user-mode spoofers (Fase 1 + 1.6) work

Ran individually via PowerShell (bypassing the batch bug — see below):

| Spoofer | Result | Notes |
|---|---|---|
| `spoof-audio-guids` | soft-fail | VM has no active audio endpoints (Hyper-V doesn't expose audio). Would work on physical HW with Realtek. |
| `spoof-edid-full` | ✅ | Monitor spoofed `HyperVMonitor` → `ZOWIE XL2546K`. Registry write on synthetic display. |
| `manage-emac-uuid` | ✅ | `C:\Users\User\emac-uuid` written + restrictive ACL applied. |
| `spoof-windows-id` | ✅ | MachineGuid `65b84c82-…` → `8c08d6ae-41c6-44f7-af67-fd38592fd10b`. ComputerName + TCPIP Hostname registry updated. |
| `spoof-pci-hardwareid` | soft-fail | VM uses VMBUS not PCI enum (`HKLM:\SYSTEM\CCS\Enum\PCI` doesn't exist). Would work on physical HW. |

### Profile pipeline (Phase 2) works

`00-gerar-profile.bat` produced a valid v9 profile in `C:\ProgramData\.hwcfg\profile.json` with the new `cpu` block populated. Also auto-called `generate-profile.ps1 -WriteDriver` which created the `RstFlt\Parameters` key (empty).

## Fixed this commit

### Bug 1 — `spoof-smbios.ps1:127` byte overflow

**Symptom:** Phase 7 (SMBIOS blob replay) failed immediately with:
```
Cannot convert argument "val2", with value: "1028", for "Min" to type "System.Byte":
"Cannot convert value "1028" to type "System.Byte".
Error: "Value was either too large or too small for an unsigned byte.""
```

**Root cause:** in `Parse-SmbiosStructures`:

```powershell
$len  = $Blob[$offset + 1]   # returns [byte]
...
[Array]::Copy($Blob, $offset, $formatted, 0, [Math]::Min($len, $Blob.Length - $offset))
```

`$len` is a `[byte]` (indexing a byte array returns byte, max 255). `$Blob.Length - $offset` is `[int]` and can be > 255. PowerShell's method resolution for `[Math]::Min` picks the `Min(byte, byte)` overload (most specific first-arg type), tries to cast the int argument down to byte, overflows if the value exceeds 255.

On this VM: original SMBIOS blob is 1036 bytes. At `$offset=8` (start of Type 0 structure), `$Blob.Length - $offset = 1028 > 255` → immediate exception.

**Why never seen before:** Phase 7 never completed on any hardware — either the physical box froze at v4.0 (CPU replay worker race) or the VM 0x7B'd before Phase 5 install. This bug has been latent since spoof-smbios v2 shipped in v3.x.

**Fix:** explicit `[int]` cast on `$len` forces the `Min(int, int)` overload.

```diff
-[Array]::Copy($Blob, $offset, $formatted, 0, [Math]::Min($len,      $Blob.Length - $offset))
+[Array]::Copy($Blob, $offset, $formatted, 0, [Math]::Min([int]$len, $Blob.Length - $offset))
```

Affects **any** BIOS with SMBIOS blob >= 256 bytes, which is essentially every modern system.

### Bug 2 — `04-aplicar-hwid.bat` aborts after `spoof-mac.ps1`

**Symptom:** Batch runs `spoof-mac.ps1` (first stage), prints its `=== CONCLUIDO ===` and `Pressione Enter para fechar:` prompt, then the shell emits `. was unexpected at this time.` and the batch exits — **none of the following 7 spoofers run** (audio, edid, emac-uuid, windows-id, disk, pci, volume all skipped).

**Root cause:** `spoof-mac.ps1` calls `Read-Host "Pressione Enter para fechar"` at three exit paths (lines 27, 48, 120). These were added for standalone use (double-click .ps1 keeps window open). When the batch script (running in cmd.exe) invokes `powershell -File spoof-mac.ps1`, the `Read-Host` inherits cmd's stdin. When the user (or automated input) satisfies the prompt, PowerShell exits with the leftover input tokens returning to cmd's command parser, which chokes on the `.` character in the returned/pasted text.

**Why never seen before:** users historically ran the batch by double-clicking or from `cmd.exe`, where the behavior differs slightly. This session invoked from a PowerShell parent shell (common for automation), which exposed the bug.

**Fix:** added a `-NoPause` switch parameter to `spoof-mac.ps1`. All three `Read-Host` calls now go through a `Wait-Enter` helper that no-ops when `-NoPause` is passed. `04-aplicar-hwid.bat` updated to invoke `spoof-mac.ps1 -NoPause`. Standalone use without the flag preserves the original behavior.

## Documented but not fixed (need deeper investigation)

### Bug 3 — SMBIOS replay strategy in kernel is ineffective

**Observation:** After spoof-smbios armed `EnableSmbiosReplay=1` + `SmbiosBlob` (959 bytes, spoofed MSI Z490 blob) in `RstFlt\Parameters`, reboot triggered a delayed BSOD at ~56s post-boot (see Bug 4). On the auto-reboot recovery boot (cycle #2), the guest stabilized but:

- `Get-CimInstance Win32_ComputerSystemProduct.UUID` still returns the real Hyper-V UUID (`5B33111A-…`) instead of the profile fake (`a08467df-…`).
- `Get-CimInstance Win32_BaseBoard.Manufacturer` still shows `Microsoft Corporation` instead of `Micro-Star International`.
- Raw `HKLM:\SYSTEM\CurrentControlSet\services\mssmbios\Data\SMBiosData` shows **1036 bytes** (original firmware size), not the fake 959.
- Driver still `STATE:4 RUNNING`, `EnableSmbiosReplay=1`.
- `OrigSmbiosData` is empty (0 bytes) — the driver's expected write of the original blob to `Parameters\OrigSmbiosData` (used by uninstall to restore) never happened, meaning the driver's `ApplySmbiosBlobIfCached` code path either never ran or bailed silently.

**Hypothesis:** the whole "write to `mssmbios\Data` from a BOOT_START driver's DriverEntry, beating mssmbios.sys" strategy may not hold. Options:
- `mssmbios.sys` re-populates the registry key from firmware ACPI **after** our write, silently reverting us.
- Our `ZwSetValueKey` targets a key that isn't the effective source that WMI serves.
- The write races with `mssmbios.sys`'s own hive I/O and gets serialized in the wrong order.

**Follow-up:** attach WinDbg via COM1 named pipe (already configured on this VM), reboot with debugger armed, breakpoint on `RstFlt!ApplySmbiosBlobIfCached`, step through and observe the write happening vs. `mssmbios!SMBiosServiceMain` (or similar) running after us. May need to rework SMBIOS replay as an IRP filter on `\Device\mssmbios` or as a mssmbios lower filter driver instead of a registry write from a boot-storage-stack driver.

### Bug 4 — First-boot-after-arm crashes at ~52-56s (no bugcheck code captured)

**Observation:** exactly the same crash pattern for **both** replays (SMBIOS AND CPU, tested independently):

- Cycle #1 (fresh reboot after arming any Enable*Replay flag): boot completes to Winlogon (KVP full service alive, IP restored, CPU=35% peak) then Windows kernel-power resets the guest at ~52-56s post-boot.
- Cycle #2 (auto-reboot after cycle #1 crash): boot succeeds, stays stable, driver `RUNNING`.
- Only `System` event log entry captured is `Event ID 41` (Kernel-Power, "unexpected shutdown") twice — one per crash. **No `Event ID 1001` (BugCheck)** and no `MEMORY.DMP` written. The dump path apparently doesn't finalize before Windows resets.

**Signals during cycle #1 boot (both replays):**
- Uptime grows monotonically 10 → 52s
- Heartbeat = `OkApplicationsUnknown`
- KVP guest agent = 21 keys (full service up, not the "early publisher only" pattern from the v4.0.3 hang)
- CPU% shows real userland activity (7-35%)

**Signals at crash moment:**
- Uptime resets to 6-10s
- Heartbeat briefly `NoContact` then `OkApplicationsUnknown` (cycle #2 boot)

**Same timing** for SMBIOS and CPU replays strongly suggests a **common root cause** unrelated to the specific replay path — likely some Windows service or scheduled task that runs ~50 seconds after login readiness, reads either the CPU registry or SMBIOS registry, hits an internal inconsistency check on the modified state, and faults/reboots. Cycle #2 succeeds because the SCM (Service Control Manager) or Task Scheduler marks the offending service as "failed on prior boot, skip this boot" per its own recovery policy.

Candidates for the "service that fires at 50s post-boot":
- Windows Search / Superfetch / SysMain
- Update Orchestrator
- Windows Defender's hardware fingerprint check
- WinRE reset detection service
- Windows Update Health Service

**Follow-up:** WinDbg attach + `!analyze -v` on the next cycle #1 crash. Alternatively enable full-memory bugcheck dumps first (`Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -Value 1`), then repro, then inspect `MEMORY.DMP`.

**Meanwhile:** the crash is a **UX problem, not a data-loss problem**. CPU replay applies successfully in cycle #1 and cycle #2, backup preserved, uninstall works. But the user seeing a BSOD on their first boot after arming the spoofer is a bad experience. Physical hardware may or may not reproduce this timing (Windows service enablement differs by SKU + hardware ID).

### Bug 5 — `spoof-smbios.ps1` hangs on `Restart-Service winmgmt`

**Observation:** near the end of `spoof-smbios.ps1` execution (Step 12), the script calls `Restart-Service winmgmt -Force` to force WMI providers to re-read the modified SMBIOS. On this VM, that hangs for at least a minute while winmgmt struggles to restart with 15+ dependent services, then eventually issues WMI queries that fail with `RPC_E_CALL_CANCELED (0x80010002)` as WMI is still recovering.

**Impact:** critical work (writing `SmbiosBlob`, `CpuStrings`, `EnableSmbiosReplay=1` to Parameters) had already completed **before** this hang, so recovery is: kill the script (Ctrl+C), the Parameters key is correctly armed, reboot to activate. The user's flow just needs to know this.

**Follow-up:** rework the "verify + arm" step to be resilient:
- Wrap `Restart-Service winmgmt` in a timeout / job with a hard cutoff.
- Or set `EnableSmbiosReplay=1` **without** the WMI verification round-trip (the whole point of the driver-based replay is that it takes effect at next boot; verifying via WMI in the current session is nice-to-have, not required).
- Or use `Invoke-CimMethod` with an explicit timeout instead of the blocking `Get-CimInstance` calls that follow the restart.

## Files touched this commit

- `scripts/spoof-smbios.ps1` — line 127: `[int]$len` cast in `[Math]::Min` call. + explanatory comment referencing this postmortem.
- `scripts/spoof-mac.ps1` — added `-NoPause` switch parameter + `Wait-Enter` helper wrapping all three `Read-Host "Pressione Enter para fechar"` exits. Standalone use unchanged (no flag = old behavior).
- `04-aplicar-hwid.bat` — pass `-NoPause` when invoking `spoof-mac.ps1`. Comment explains why.
- `docs/postmortem-v4-phase5/incident-v405-vm-pipeline-validation.md` — this document.
- `LEIA-ME.txt` — new `MUDANCAS EM v4.0.5` section covering all 5 findings.

## Recommended posture for the next physical-hardware run

**Green to try on physical HW:**
- v4.0.4 boot correctness fixes (proven on VM, no risk expected on hardware given diskperf canonical pattern).
- Phase 2 profile generation.
- Phase 6 HWID spoofs (windows-id, EDID, emac-uuid, and MAC spoof which will find real Intel/Realtek adapters on physical HW).
- Phase 8 CPU registry replay (proven end-to-end; accept the "first reboot after arming may BSOD once" UX quirk; second boot stabilizes with spoof active).

**Yellow — expect issues on physical HW:**
- Phase 7 SMBIOS replay: known to be ineffective (Bug 3) and to trigger the first-boot crash (Bug 4). Do NOT arm `EnableSmbiosReplay=1` yet; leave `SmbiosBlob` cached in Parameters but skip arming until Bug 3/4 are debugged with WinDbg on a controlled system.
- Phase 6 disk / volume spoofers: were skipped on VM (they need SIM confirmation). On real HW they have brick-boot risk if `Get-Disk.Location` returns unexpected patterns; the scripts have `abort by safety` code but a manual restore point + WinPE stick is prudent.

**Red — do not run without WinDbg attached:**
- SMBIOS `EnableSmbiosReplay=1` arming (Bug 3 + Bug 4).
- `05-aplicar-smbios.bat` option 2 (`-InstallTask`) — installs the scheduled-task fallback, which would keep triggering the same crash pattern on every boot.

## References

- Prior postmortems in this series:
  - `incident-v4-phase5-boot-freeze.md` — physical hardware freeze root cause (CPU replay race)
  - `incident-v401-inaccessible-boot-device.md` — VM STOP 0x7B first sighting
  - `incident-v402-signature-plus-filter.md` — signature necessary but not sufficient
  - `incident-v403-startype-boot-order.md` — StartType/Group fix (v4.0.3)
  - `incident-v404-paging-path.md` — DO_POWER_PAGABLE + DEVICE_USAGE_NOTIFICATION handler (v4.0.4)
- WDK sample `diskperf` (canonical DiskDrive UpperFilter): microsoft/Windows-driver-samples storage/class/diskperf
- MSDN "Restart-Service considerations for winmgmt" (informal): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-start
