# INCIDENT — v4.0 Phase 5 driver install → boot freeze

**Date:** 2026-08-30
**Session:** Windows test kickoff (fase2-track-a-windows-test-kickoff)
**Repo commit tested:** `2301248` (top of main, kickoff docs + b53d149 v4.0)
**Test host:** i7-10700F, LGA1200, MSI real board, Win10 19045, Secure Boot OFF, testsigning ON, HVCI OFF, 32 GB RAM
**Verifier:** /standard armed on rstflt.sys, flags 0x001209bb (Pool special + IRQL + Deadlock + DDI compat + Extended)

## Summary

Driver `rstflt.sys v4.0` compiled cleanly (with `CL=/wd4018` workaround, see separate report) at 12800 bytes.
Install (Phase 5, `03-instalar-driver.bat`) completed successfully — service registered SYSTEM_START, UpperFilters
injected as `RstFlt, partmgr`, `.sys` copied to System32\drivers, hash match verified, Parameters chave criada
with `EnableSmbiosReplay=0` and `EnableCpuReplay` unset (both opt-in gates OFF).

On first reboot after install, **Windows boot froze** at the Windows loader stage (before login).
User did hard-power-off 3× — but Windows never bugchecked cleanly. No new MEMORY.DMP or minidump was written
(latest existing dumps are from 27/08, days before this incident). No BugCheck event 1001 recorded either.

Startup Repair auto-triggered on the third failed boot and ran successfully — implying the loader was reaching
Windows kernel init but hanging BEFORE the crash-dump path could persist a dump. Verifier was armed on rstflt.sys
and would have caught pool/IRQL/deadlock violations, but produced no persisted evidence.

Because gates were both OFF, both replay code paths should have early-returned. So the freeze must originate in:
- `DriverEntry` prologue (before gate check), OR
- `AddDevice` / filter attach path on the DiskDrive class, OR
- interaction between rstflt.sys and Verifier at load time

## Recovery attempt

`09-recuperar-boot.bat` FAILED to run correctly under WinRE. The script uses inline
`powershell -ExecutionPolicy Bypass -Command …` to load registry hives, delete services, and restore
UpperFilters, but WinRE's base image does not carry `powershell.exe` on PATH. The batch's early section
also uses `if exist "C:\Windows\System32\config\SYSTEM"` to detect the Windows drive — under WinRE the
Windows install is often mounted on D:/E:/F:, not C:, so drive detection can fail even before reaching
the PowerShell block.

User was forced to clean state manually from the WinRE cmd shell using only `reg`, `del`, `dir`, and
`diskpart` — no PowerShell available. Manual cleanup that user performed:

1. Located Windows drive via `diskpart list volume`.
2. Deleted `<drv>\Windows\System32\drivers\rstflt.sys` via `del /f`.
3. Loaded SYSTEM hive via `reg load HKLM\OFFSYS <drv>\Windows\System32\config\SYSTEM`.
4. Deleted `HKLM\OFFSYS\ControlSetXXX\Services\RstFlt` via `reg delete`.
5. Restored `HKLM\OFFSYS\ControlSetXXX\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}\UpperFilters`
   to `partmgr` (baseline).
6. `reg unload HKLM\OFFSYS`.
7. Rebooted normally.

Post-cleanup state verified stable — 4h38m uptime, service gone, UpperFilters back to `partmgr`,
CrashDumpEnabled=7 preserved (AutoReboot flipped back to 1 by Startup Repair, AlwaysKeepMemoryDump cleared,
Verifier fully disarmed).

## Two bugs found

### Bug 1 — rstflt.sys v4.0 crashes at load even with all gates OFF

**Severity:** critical (blocks any test of v4.0 on hardware)

Symptoms:
- Boot freeze at Windows loader stage (post-boot-manager, pre-login).
- No MEMORY.DMP written despite CrashDumpEnabled=7 + AlwaysKeepMemoryDump=1 armed.
- No BugCheck event 1001 in system event log.
- Startup Repair auto-triggered after 3 hard resets.
- Boot recovers cleanly once rstflt is removed.

Reproducibility: 100% — driver was compiled cleanly, installed correctly, gates verified OFF,
reboot froze. This is not a race or timing issue — it happens every time.

Investigation lanes (recommend for dev session):
- **Filter attach path:** `AddDevice`/`IRP_MN_ADD_DEVICE` for the DiskDrive class. Even a NOP filter
  must correctly attach and pass through. Any pool/IRQL bug here fires immediately at first boot.
- **DriverEntry prologue:** anything before the gate check that touches the registry, allocates pool,
  or interacts with `IoRegisterDeviceInterface`.
- **Worker thread queuing:** if the CPU replay worker is queued in DriverEntry regardless of the gate
  (only the WORKER checks the gate, not the queue call), a bug in the worker init could fire even
  when the worker itself early-returns.
- **Verifier interaction:** flag 0x02 (Force IRQL check) is aggressive; any DriverEntry code path
  that briefly runs at wrong IRQL will fault.

Data collection for next attempt:
- Boot in Safe Mode first, verify driver either loads clean or Safe Mode skips it.
- If crash reproduces, `!analyze -v` on any dump would clarify.
- Consider a debug build with `DBG=1` + serial kernel debugger (WinDbg over network) attached to
  catch the crash before Windows resets.
- Try attaching to a different class (or as demand-start service with no filter attach) to isolate
  whether the filter registration is the killer.

### Bug 2 — 09-recuperar-boot.bat is not WinRE-compatible

**Severity:** critical (recovery lifeline non-functional when actually needed)

Symptoms:
- Script runs to completion (intro banner printed) but the recovery body silently no-ops.
- WinRE base image does not carry `powershell.exe` — the inline `powershell -Command …` call
  fails without visible error because the batch does not check `%ERRORLEVEL%` after it.
- Windows drive detection tries C: through F: only. Under WinRE the mount letters can be different
  (X: for WinPE ram disk, W:/D:/E: for Windows depending on hardware).

Recommended fixes for dev session:
- **Do not depend on WinRE having PowerShell.** Rewrite the recovery logic using only cmd built-ins
  and `reg`/`del`/`copy`/`if exist`. All the current PowerShell operations (`reg load`, iterate
  ControlSet001+002, delete keys, restore UpperFilters, restore SMBiosData, remove CpuStrings)
  can be done with `reg load` + `reg delete` + `reg add /f`. It is verbose but reliable.
- Alternative: attempt to locate `%WINDRV%\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  explicitly (that exists on the mounted Windows even if WinRE PATH does not have it) and use it
  with full path.
- Extend Windows drive detection to enumerate all mounted volumes via `for /F` over `mountvol`
  or `wmic logicaldisk` — the C-F hardcoded range is a footgun.
- Add explicit `%ERRORLEVEL%` checks after every powershell call and echo status. Currently the
  batch prints its intro then goes silent because the powershell body dies without visible signal.
- Add a smoke test that dry-runs the recovery script under WinRE (WinPE) before committing.

## State the toolkit is in now (post-cleanup)

- Repo working tree: 9 modified `scripts/*.ps1` (UTF-8 BOM added by earlier Windows test workaround),
  4 untracked scratch files (`RAM+1GB`, `qc`, `query`, `recobery-log.txt` — safe to delete).
- Driver artifacts: `driver/rstflt.sys` still present locally (12800 bytes, compiled with /wd4018),
  `driver/rstflt.obj` present.
- `C:\Windows\System32\drivers\rstflt.sys` — DELETED.
- Service `RstFlt` — DELETED from HKLM\SYSTEM\CurrentControlSet\Services.
- `HKLM\SOFTWARE\HWToolkit\OrigUpperFilters` — DELETED (backup gone, but current UpperFilters is
  already the baseline `partmgr` so recovery is not needed).
- Boot config: AutoReboot=1 (default), CrashDumpEnabled=7 (kept), AlwaysKeepMemoryDump blank
  (default), Overwrite=1, Verifier disarmed.
- Testsigning ON, SecureBoot OFF, HVCI OFF — all preserved.
- Baseline captures in `C:\baseline-v4\` intact.
- Profile v9 in `C:\ProgramData\.hwcfg\profile.json` intact.

## Recommendation

**Do NOT re-attempt Phase 5+ on this hardware without a dev-session fix.** The current v4.0 driver
will freeze the boot again with the same profile.

Next actions on the dev-session side:
1. Open branch off `main`.
2. Investigate bug 1 (driver base crash). Consider a Hyper-V or VMware VM smoke test before
   returning to physical hardware — safer iteration loop.
3. Fix bug 2 (recovery script cmd-only rewrite).
4. Fix the C4018 signed/unsigned mismatch on `rstflt.c:483` reported earlier
   (`compile-bug-C4018-report.md`) — remove the need for the CL=/wd4018 workaround.
5. Fix the UTF-8 BOM omissions in scripts/ reported earlier (`utf8-bom-fix-report.md`).
6. Land those fixes, then user pulls locally, then re-run this test kickoff from Phase 1.

Until then, this Windows box is CLEAN and SAFE. No residual driver, no residual gates, boot stable.
