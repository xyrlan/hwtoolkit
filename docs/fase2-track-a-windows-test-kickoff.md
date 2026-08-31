# Fase 2 Track A — Windows Test Kickoff

## Purpose

Self-contained handoff for a **new Claude Code session running on the user's Windows box** to execute the v4.0 kernel-level test flow. This session is DIFFERENT from the macOS design/review sessions — it runs on the actual hardware where the driver will be tested, so it has real Windows execution capability (PowerShell, sc, reg, procmon, WinRE recovery) instead of static analysis only.

**Reading order — do this before any command:**

1. Read this file (`docs/fase2-track-a-windows-test-kickoff.md`) — end to end.
2. Read `docs/fase2-kickoff.md` — Fase 2 overall context.
3. Read `docs/emac-recon-v2.md` — EMAC target recon.
4. Read `README.md` sections "MUDANCAS EM v4.0" and "COBERTURA DE FINGERPRINT".
5. Then confirm to the user which phase to start.

---

## Session identity

- **Host:** user's Windows 10/11 x64 desktop (hardware real, NOT VM).
- **Repo path:** `C:\hwtoolkit` (or wherever the user cloned).
- **User privileges:** Admin (PowerShell/cmd running elevated).
- **Prerequisites already validated by user:**
  - Secure Boot disabled in BIOS.
  - `bcdedit /enum | findstr /i testsigning` → `Yes`.
  - Fresh install (no prior v3.5-v3.7 install carrying stale state).
- **Lifeline:** the same NTFS partition holding `C:\hwtoolkit\09-recuperar-boot.bat`. If Windows won't boot, WinRE mounts this partition and executes the recovery. (No dedicated USB stick redundancy — user accepted this trade-off.)

---

## Current toolkit state (as of merge b53d149)

- Version: **v4.0** (Track A merged into main).
- Profile schema: **v9** (includes new `cpu` block).
- Driver: **rstflt.sys v4.0** (1484 lines) — adds `ReplayCpuRegistry` worker-thread + `EnableCpuReplay` opt-in + `OrigCpuStrings` backup + HAL race handling.
- All 21 adversarial review findings resolved. Post-verify N1 fix applied.

---

## Test flow — 12 phases

Order is FIXED. Do NOT skip. Every phase has a checkpoint — pause and confirm with the user before advancing.

### Phase 0 — Pre-flight (verify, don't assume)

```powershell
# Confirm all prerequisites the user claimed
bcdedit /enum | findstr /i testsigning        # expect: Yes
Confirm-SecureBootUEFI                          # expect: False
[System.Environment]::OSVersion.Version         # expect: 10.x
whoami /priv | findstr SeLoadDriverPrivilege    # expect: Enabled
```

If ANY fails: stop, tell user what's off, wait for fix.

Capture baseline hardware state for post-test comparison:

```powershell
mkdir C:\baseline-v4 -Force
Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" |
    Select ProcessorNameString, Identifier, VendorIdentifier |
    Out-File C:\baseline-v4\cpu-real.txt
(Get-CimInstance Win32_ComputerSystemProduct).UUID | Out-File C:\baseline-v4\smbios-uuid-real.txt
(Get-CimInstance Win32_BaseBoard).SerialNumber    | Out-File C:\baseline-v4\board-serial-real.txt
Get-NetAdapter | Select Name, MacAddress          | Out-File C:\baseline-v4\mac-real.txt
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" |
    Select MachineGuid | Out-File C:\baseline-v4\machineguid-real.txt
```

### Phase 1 — Repo + build tools

```powershell
cd C:\hwtoolkit
git log --oneline -3   # confirm b53d149 or newer
findstr /C:"v4.0" driver\rstflt.c | Select-Object -First 3
```

If VS Build Tools + WDK missing:
```powershell
.\01-instalar-ferramentas.bat
```
Reboot after this if it prompts.

Verify presence:
```powershell
where nmake
where sc
dir "$env:ProgramFiles(x86)\Windows Kits\10\Include" | Select-Object -First 3
```

### Phase 2 — Generate profile v9

```powershell
.\00-gerar-profile.bat
```

Interactive:
- Detects CPU.
- Prompts for board choice (menu).

Verify:
```powershell
$prof = Get-Content C:\ProgramData\.hwcfg\profile.json -Raw | ConvertFrom-Json
$prof.version        # MUST be 9
$prof.cpu            # MUST show name_string, identifier, vendor_identifier
```

If `version -ne 9`: stop. Repo is stale — user needs `git pull`.

### Phase 3 — Compile driver

```powershell
.\02-compilar-driver.bat
dir driver\rstflt.sys                          # must exist, ~30-60 KB
```

If build fails: capture last 30 lines of output, report to user, DO NOT proceed.

### Phase 4 — Pre-test arm

```powershell
.\pre-test-checklist.bat --arm
```

This arms Driver Verifier at a mild level to catch pool corruption / IRQL issues fast.

### Phase 5 — Install driver (HIGH RISK — first potential BSOD)

**CHECKPOINT BEFORE:** confirm user wants to proceed. Confirm lifeline recovery script is readable from cmd offline:
```powershell
Get-ChildItem C:\hwtoolkit\09-recuperar-boot.bat  # must exist
```

Read that script and confirm the user understands the recovery path (2 minutes):
- Boot loops → hard-power-off 3× → WinRE auto-triggers.
- Advanced Options → Command Prompt.
- Navigate to `C:\hwtoolkit\09-recuperar-boot.bat` (letter may shift to D:/E: under WinRE — check with `dir X:\hwtoolkit`).
- Run it. Reboot.

Now install:
```powershell
.\03-instalar-driver.bat
```

Reboot when prompted. WAIT for the user to report back after reboot.

**CHECKPOINT AFTER REBOOT:**
```powershell
sc query rstflt          # expect: STATE : 4  RUNNING
```

If NOT RUNNING or the machine BSOD'd:
- Ask user for STOP code (0xC5 / 0x50 / 0x7B / 0xE6 / 0xC2 are historical suspects).
- Tell them to run 09-recuperar-boot.bat via WinRE.
- Do NOT proceed with next phase. Diagnose.

If RUNNING: check DbgView output (user opens DebugView.exe as admin, `Capture → Capture Kernel` checked, filter `[RstFlt]`) for:
```
[RstFlt] DriverEntry OK (v4.0, SMBIOS + CPU replay)
```

**PAUSE and confirm with user before Phase 6.** Driver is loaded but NO spoofing active yet — all opt-in gates are OFF.

### Phase 6 — Registry-only HWID spoof (low risk)

```powershell
.\04-aplicar-hwid.bat
```

Runs all the safe registry-level spoofers: MAC, EDID, audio, disk, PCI, volume, windows-id, emac-uuid. No kernel involvement here beyond writing values that a running system tolerates.

Verify quickly:
```powershell
Get-NetAdapter | Select Name, MacAddress   # should show fake MACs from profile
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid  # should match $prof.windows.machine_guid
```

### Phase 7 — SMBIOS blob replay (medium risk)

```powershell
.\05-aplicar-smbios.bat
```

Watch for these OKs in the output:
- `[OK] SmbiosData atualizado!`
- `[OK] Blob cacheado (X bytes) — opt-in ainda OFF`
- `[OK] CpuStrings gravado no cache do driver (3 valores)`  ← v4.0 NEW
- `[OK] Replay em kernel ARMADO (EnableSmbiosReplay=1)`

**CpuStrings is written but `EnableCpuReplay` stays 0** at this point. That's intentional — we validate SMBIOS replay first, THEN turn on CPU replay in a separate reboot.

**Reboot.** Wait.

**CHECKPOINT AFTER REBOOT:**
```powershell
(Get-CimInstance Win32_ComputerSystemProduct).UUID     # expect: profile fake, not real
(Get-CimInstance Win32_BaseBoard).Manufacturer          # expect: profile fake
(Get-CimInstance Win32_BaseBoard).Product               # expect: profile fake
$prof = Get-Content C:\ProgramData\.hwcfg\profile.json -Raw | ConvertFrom-Json
$prof.smbios.uuid                                       # must equal Win32_ComputerSystemProduct.UUID
```

If SMBIOS values still real: SmbiosBlob replay failed. Check DbgView for `[RstFlt] SMBIOS replay:` messages. Diagnose.

If SMBIOS fake but CPU still real (expected): normal. Proceed to Phase 8.

### Phase 8 — Enable CPU replay (v4.0 crown feature — HIGH RISK)

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters" `
    -Name "EnableCpuReplay" -Value 1 -Type DWord

Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters" |
    Select EnableSmbiosReplay, EnableCpuReplay, CpuStrings
```

Both DWORDs = 1. CpuStrings shows 3 wide strings.

**Reboot.** This is the moment worker-thread + HAL race handling faces reality.

**CHECKPOINT AFTER REBOOT:**
```powershell
# Registry values on core 0
Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" |
    Select ProcessorNameString, Identifier, VendorIdentifier

# Compare to profile
$prof = Get-Content C:\ProgramData\.hwcfg\profile.json -Raw | ConvertFrom-Json
$prof.cpu

# All cores must be spoofed (worker enumerates all)
Get-ChildItem "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor" | ForEach-Object {
    $val = (Get-ItemProperty $_.PSPath).ProcessorNameString
    "{0} : {1}" -f $_.PSChildName, $val
}

# Backup created?
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters" |
    Select OrigCpuStrings

# WMI (goes through registry, so must show fake too)
wmic cpu get Name
```

Expected:
- Registry values = profile fake.
- All cores show fake (not just core 0).
- `OrigCpuStrings` populated (backup written).
- `wmic cpu get Name` = fake.

DbgView (look for these):
```
[RstFlt] CPU replay: EnableCpuReplay=1, proceeding
[RstFlt] CPU replay: expected N logical processors
[RstFlt] CPU replay: SubKeys count reached expected after pass K
[RstFlt] CPU replay: wrote 3 values to CentralProcessor\N (N=0..N-1)
[RstFlt] CPU replay: backed up X bytes to OrigCpuStrings
```

If registry values STILL real after reboot:
- Check DbgView for `[RstFlt] CPU replay:` messages.
- Common failure: `EnableCpuReplay` DWORD wasn't set (typo in path).
- Verify with `Get-ItemProperty ...Parameters | Select EnableCpuReplay` again.

If BSOD on this reboot: STOP code, WinRE, `09-recuperar-boot.bat` (removes the opt-in and clears CpuStrings — HARDWARE hive is volatile, next boot the kernel rebuilds it from real CPUID).

### Phase 9 — Full audit

```powershell
.\06-verificar.bat
```

Runs `check-consistency.ps1`. Expected: all sections green, especially the new "CPU registry replay audit". Capture full output for the user log.

### Phase 10 — Baseline procmon capture (do BEFORE running RubinOT)

The user should already have baseline captures from a real EMAC session (see `docs/emac-recon-v2.md` — 7min + 18min PMLs). If not, capture one now:

Download Procmon (Sysinternals). Run as admin.
1. `Filter → Include → Process Name is RubinOT.exe` (or the actual EMAC binary name).
2. Start capture.
3. User plays RubinOT for 5 minutes (light login + normal in-game activity).
4. Stop, `File → Save → All events → Native format (PML) → postv4-first-session.PML`.

### Phase 11 — Verify EMAC reads

Open the PML in Procmon.

Key filters to run:
```
Path contains CentralProcessor
Operation is RegQueryValue
```
Every hit's `Details → Data` column must show the FAKE CPU string, not the real one.

```
Path contains \Cryptography\MachineGuid
```
Data = profile machine_guid.

```
Path contains \MMDevices\Audio
```
Data = profile audio GUIDs.

```
Path contains \Connection\PnPInstanceId
```
Data = **real** (GAP #1 still open, expected — Track B' deferred).

```
Path contains \Enum\SCSI\Disk
```
Data = profile disk vendor+product.

Report a summary of hits per category to the user.

### Phase 12 — Report + decision

Consolidate findings for the user:

- **v4.0 verdict**: PASS / FAIL / PARTIAL (list which categories bad).
- **GAP #1 (PnPInstanceId) status**: was it read by EMAC? Frequency? If never observed in the capture, deprioritize Track B'. If read hundreds of times per session, prioritize.
- **BSOD count**: should be 0.
- **DbgView anomalies**: any unexpected `[RstFlt]` errors.
- **Next step recommendation** to user.

If the user wants to send you the PML for offline analysis: they upload to WeTransfer / Drive, share link. Do NOT commit PML files to the repo (may contain private paths).

---

## Recovery playbook (if any BSOD)

1. Hard-power-off 3× to trigger WinRE.
2. Advanced Options → Command Prompt.
3. Find Windows drive letter (usually D: or E: under WinRE):
   ```
   diskpart
   list volume
   exit
   ```
   Look for the volume with the Windows install (label "Windows" or NTFS bootable ~100GB+).
4. Confirm:
   ```
   dir X:\hwtoolkit\09-recuperar-boot.bat
   ```
5. Execute:
   ```
   X:
   cd \hwtoolkit
   09-recuperar-boot.bat
   ```
6. Wait for `PRONTO! Reinicie o PC normalmente.` line.
7. Reboot.

The script removes:
- RstFlt service entirely.
- `RstFlt` from `UpperFilters` of DiskDrive class.
- `SMBiosData` restored from `Parameters\OrigSmbiosData` backup.
- `EnableCpuReplay` and `CpuStrings` from Parameters (v4.0).
- `rstflt.sys` file from `System32\drivers\`.

After successful recovery, ask user for the STOP code from the BSOD screen (if they captured it) so we can diagnose which code path faulted.

---

## Style rules (this session)

- Portuguese messages, English identifiers (matches project convention).
- **Never** run any 04-08 batch without confirming user is ready — kernel changes only after explicit "go".
- **Always** pause after a reboot for the user to report back before the next command.
- **Never** modify `driver/*` or `scripts/*` from this session — this is TEST session, not development. Bugs found → report to user, they open a fix branch in the macOS dev session.
- **Read-only** posture toward the codebase except for temp captures and logs that go to `C:\baseline-v4\` or scratchpad.

---

## Anti-goals

- Do NOT try to run WSL or bash-only tooling. This is native Windows.
- Do NOT touch EMAC / RubinOT binaries in `C:\Program Files (x86)\RubinOT 2.0\` — hash-integrity-checked by EMAC.
- Do NOT delete the user's `C:\Users\<user>\emac-uuid` file — deletion triggers heavy re-registration burst, itself a ban signal.
- Do NOT enable disk-serial spoofing (removed in v3.6 — historical BSOD source).
- Do NOT modify Secure Boot / test-signing state — user's responsibility.

---

## Report back template for the macOS dev session

If test finds a v4.0 bug and needs a fix, user pastes this to the macOS dev session:

```
### Track A test result — v4.0

Phase reached: <number>
Verdict: FAIL / PARTIAL / PASS
Details:
  - Phase 5 driver install: OK / BSOD (STOP <code>)
  - Phase 7 SMBIOS reboot:  values fake? Y/N
  - Phase 8 CPU replay:     all cores fake? Y/N
  - `06-verificar.bat`:     <paste key section>
  - DbgView [RstFlt]:       <paste any error/warn>
  - EMAC PML link (if any): <WeTransfer / Drive URL>
```

---

END OF DOCUMENT.
