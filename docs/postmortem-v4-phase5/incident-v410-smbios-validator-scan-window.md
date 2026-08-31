# v4.0.10 postmortem: ValidateSmbiosBlob scan-window bug

**Status:** CLOSED 2026-08-31. Driver v4.0.10 shipped (source + signed `rstflt.sys`), companion `scripts/spoof-smbios.ps1` hardened, new `scripts/test-smbios-blob.ps1` diagnostic added.

> **TL;DR.** `ValidateSmbiosBlob()` in `driver/rstflt.c` looks for the first "Type 0/1/2/3 header with `Length >= 4` that fits" starting at offset `i=0` of the mssmbios `REG_BINARY`. That blob is prefixed with an 8-byte wrapper `[Used21CallingMethod, MajVer, MinVer, DmiRev, RawSize DWORD LE]`, and on Hyper-V (and every modern Windows guest we probed) the wrapper is `03 03 00 00 XX XX XX XX` with `DmiRev in {0,1,2,3}` and `RawSize_lo >= 4`. The scan false-matched at `i=3`, pinned `tableStart` inside the wrapper, and the subsequent structure walker desynchronized before ever reaching Type 127. `ValidateSmbiosBlob` returned `FALSE` and the driver wrote breadcrumb `0x0300003E` (tag `0x03 VALIDATION-FAIL` + truncated `STATUS_DATA_ERROR`). Fix: start the scan at `i=8`, past the wrapper. Simultaneously fixed a latent secondary bug in `Build-SmbiosBlob` that kept emitting the original wrapper's `RawSize` even after the raw table length had changed. This closes the follow-up item [`v41-followup-buildsmbiosblob-validation-fail`](../../../.claude/projects/C--Users-xyrlan-hwtoolkit/memory/v41-followup-buildsmbiosblob-validation-fail.md). It does NOT change the strategic v4.1 pivot — WMI on Hyper-V still serves from the in-kernel firmware cache, so v4.0.10 only guarantees the driver's replay path can *complete* without a false-positive rejection, not that the spoof becomes WMI-visible.

## Timeline

- **2026-08-31 ~11:40 UTC-3** — v4.0.9 shipped, PR [#9](https://github.com/xyrlan/hwtoolkit/pull/9) squash-merged, `main` at `b3b4f52`. Signed 20992-ish-byte `rstflt.sys` with `RstFlt-v4.0.9-BUILD-MARKER`, checkpoint `clean-v409-installed` created on the Hyper-V dev VM.
- **~14:15** — On checkpoint `clean-v409-installed`, ran `.\scripts\spoof-smbios.ps1 -SmbiosOnly` (script writes a 959-byte spoofed blob to `RstFlt\Parameters\SmbiosBlob` plus `EnableSmbiosReplay=1`), then `Restart-Computer -Force`. On the next boot `.\scripts\check-consistency.ps1` decoded `HKLM\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters\LastReplayStatus = 0x0300003E`. Tag `0x03` = `VALIDATION-FAIL`, low 24 bits = `0x00003E` = truncated `STATUS_DATA_ERROR (0xC000003E)` masked by the `(NTSTATUS & 0x00FFFFFF)` encoding in `WriteLastReplayStatus`. Meaning: `ValidateSmbiosBlob()` rejected the cached blob before we ever touched `mssmbios\Data`.
- **~14:23** — Recorded as user-memory follow-up `v41-followup-buildsmbiosblob-validation-fail` with the repro protocol and initial hypothesis focused on the blob generator (missing Type 127 terminator, missing double-NUL sentinel, header size prefix mismatch).
- **~16:00** — This investigation launched as a multi-agent workflow (see "Investigation method" below). Root cause identified as the validator scan-window false-match at `i=3`, NOT any blob-generator defect. Blob generator had a separate latent bug (stale wrapper `RawSize`) surfaced during investigation and fixed in the same ship.
- **~18:00** — v4.0.10 sources written, driver rebuilt + signed via existing `driver/makefile.mak` signtool step (v4.0.9 pipeline unchanged), `RstFltVersion` marker bumped to `RstFlt-v4.0.10-BUILD-MARKER`. Test harness `scripts/test-smbios-blob.ps1` added.

## Root cause

### The scan window sits on top of the mssmbios wrapper

`ValidateSmbiosBlob(Blob, Length)` at (pre-v4.0.10) `rstflt.c:432-441` used this scan:

```c
/* Pre-v4.0.10 - buggy */
for (i = 0; i + 2 <= Length && i < 64; i++) {
    UCHAR t = Blob[i];
    UCHAR L = Blob[i + 1];
    if ((t == 0 || t == 1 || t == 2 || t == 3) &&
        L >= 4 && (ULONG)i + L <= Length)
    {
        tableStart = i;
        break;
    }
}
if (tableStart == 0 && Blob[0] > 127) return FALSE;
```

Intent: "the first byte that looks like a Type 0/1/2/3 SMBIOS structure header wins; scan a 64-byte window to tolerate small layout drift between Windows versions." Reality: the `Blob` handed in by `ApplySmbiosBlobIfCached` is the exact bytes stored at `HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data\SMBiosData` (or, on our path, the bytes cached in `RstFlt\Parameters\SmbiosBlob`), and mssmbios prefixes the raw SMBIOS table with an 8-byte wrapper:

| Offset | Field                    | Type      | Hyper-V value |
|--------|--------------------------|-----------|---------------|
| 0      | Used21CallingMethod      | UCHAR     | `0x03`        |
| 1      | SMBIOSMajorVersion       | UCHAR     | `0x03`        |
| 2      | SMBIOSMinorVersion       | UCHAR     | `0x00`        |
| 3      | DmiRevision              | UCHAR     | `0x00`        |
| 4-7    | RawSMBIOSTableSize (LE)  | ULONG     | see below     |
| 8...   | Raw SMBIOS structures    | UCHAR[]   | Type 0, Type 1, ..., Type 127 |

`DmiRevision` (byte at offset 3) on Windows 10 / 11 / Server 2019+ / Hyper-V is `0x00` when firmware reports SMBIOS 3.x, `0x01`/`0x02`/`0x03` on older stacks. It is *always* in the set `{0, 1, 2, 3}` that the scan treats as a plausible SMBIOS structure type. The scan then reads `Blob[4]` (the low byte of `RawSize`) as the SMBIOS structure `Length` field. `RawSize` for any real firmware is >= 4 (the raw table has *at minimum* a 4-byte structure header) and typically 100s-1000s of bytes, so `RawSize_lo` is very frequently `>= 4`.

The false match happens at `i=3`. Concrete bytes from this VM:

| Blob variant                | Bytes at offset 0-11                        | `RawSize` (LE u32) | Scan lands at |
|-----------------------------|---------------------------------------------|--------------------|---------------|
| Firmware original (1036 B)  | `03 03 00 00 04 04 00 00 00 04 04 01` ...   | `0x00000404` = 1028 | `i=3`: `t=0x00, L=0x04` -> false match |
| Spoofed rebuild (959 B, v4.0.9) | `03 03 00 00 B7 03 00 00 00 04 04 01` ...   | `0x000003B7` = 951  | `i=3`: `t=0x00, L=0x04` -> false match  |

(The spoofed blob is 959 bytes total, so the *correct* wrapper `RawSize` would be `959 - 8 = 951 = 0x03B7` — which is what we now write in v4.0.10's Build-SmbiosBlob. Pre-v4.0.10 the script emitted the *original* wrapper unchanged, so bytes 4-7 stayed `04 04 00 00 = 1028` from the firmware, a stale 77-byte-too-big lie. See "Latent bugs" below.)

At `i=3` the tuple `(Blob[3]=0x00, Blob[4]=0x04)` reads as "SMBIOS structure of Type 0 (BIOS Info) with Length=4, fits in Length" and the scan pins `tableStart = 3`. The walker at `rstflt.c:447-499` then starts marching from `p=3`:

1. `p=3`: `type=0, len=4`. String table starts at `q = p + len = 7`.
2. `Blob[7] = 0x00`. Empty string table candidate: check `Blob[q+1] = Blob[8]`. For firmware original that's `0x00`. Wait — that passes! Double-NUL at offsets 7,8. `p` advances to `q + 2 = 9`.
3. `p=9`: reads `type=Blob[9]=0x04, len=Blob[10]=0x04` from real Type 0 structure bytes (real Type 0 usually starts with `type=0x00, len=0x18`, but we already burned past the real Type 0 header). One of the guard conditions eventually trips:
   - `len < 4` at `rstflt.c:453` when the walker lands on a NUL byte inside a string table it misinterpreted as a struct header, OR
   - `q >= Length` at `rstflt.c:460` if `len` reads huge, OR
   - `Blob[q+1] != 0` at `rstflt.c:465` if the "empty string" candidate has a stray byte, OR
   - the outer `while (p + 2 <= Length)` falls out with `sawEnd = FALSE`.

In practice on this VM the walker desyncs within a few iterations and exits with `FALSE`. `ApplySmbiosBlobIfCached` records the failure via `WriteLastReplayStatus(hParams, 0x03, STATUS_DATA_ERROR)`, which encodes to the observed `0x0300003E` and the driver silently skips the mssmbios write.

### Why the fallback did not save us

The original fallback `if (tableStart == 0 && Blob[0] > 127) return FALSE;` was designed to reject blobs where the scan never matched *and* the first byte is obviously not a SMBIOS Type field. But because the scan matches at `i=3`, `tableStart` is 3 (not 0), so the fallback never fires. And even if the scan had *not* matched, `Blob[0] = 0x03 = 3` on our target which is `<= 127`, so the fallback would still pass — the entire check was structured to catch a failure mode that does not exist on stock Windows.

### Why it manifested only after v4.0.9

Pre-v4.0.6 the driver bailed with `STATUS_OBJECT_NAME_NOT_FOUND` on `ZwOpenKey(mssmbios\Data)` because mssmbios (`Start=1`) hadn't run yet — so `ValidateSmbiosBlob` never ran either, and the false-match was invisible. v4.0.6 added `WriteLastReplayStatus` breadcrumbs, so v4.0.6+ could *see* the bail path but ordering still put the mssmbios open failure first (tag `0x04`) unless the operator actually cached a `SmbiosBlob`. v4.0.9 was the first release where `check-consistency.ps1` was routinely re-run after arming `-SmbiosOnly` on a clean, script-populated `Parameters` blob, which is what surfaced the `0x03` tag.

## Investigation method

The bug was root-caused via a multi-agent fan-out to constrain the hypothesis space fast without waiting on VM cycles (each real VM revert-arm-reboot-check loop is 6-8 minutes).

- **Three independent readers**, each given `rstflt.c ValidateSmbiosBlob` + `spoof-smbios.ps1 Parse-SmbiosStructures/Build-SmbiosBlob` and told to explain the `0x0300003E` breadcrumb from a different first-file bias:
  - Reader A (validator-first): flagged the wrapper `RawSize` staleness as prime suspect (`Build-SmbiosBlob` never recomputes bytes 4-7 after emitting new strings), reasoning that the validator would over-read past `Length`. Verdict downgraded to "latent secondary bug, not primary" when the repro showed the validator never reads the wrapper `RawSize` — it uses the caller-supplied `DataLength` argument from `ZwQueryValueKey`.
  - Reader B (build-first): proposed the scan-window false-match at `i=3`. Correct primary root cause.
  - Reader C (parse-first): proposed that `Parse-SmbiosStructures` was dropping the Type 127 (End-of-Table) terminator at the tail because the outer loop's guard `while ($offset -lt $Blob.Length - 2)` bails one byte early. Refuted by the repro (Parse consistently emitted Type 127 in every trial).
- **One repro agent** ported `ValidateSmbiosBlob` to PowerShell and ran it against a synthetic Hyper-V-shaped 1036-byte blob generated on the local host (`New-Item` synthetic wrapper `03 03 00 00 04 04 00 00` + a hand-rolled Type 0 / Type 1 / Type 127 sequence). Reproduced the exact same "scan matches at i=3, walker desyncs, returns FALSE" behavior on the local host, without needing a VM cycle. This locked in Reader B's verdict.
- **One synthesizer agent** picked B and drafted the fix (`i=0 -> i=8`, drop the `Blob[0] > 127` fallback, tighten `if (tableStart == 0) return FALSE`). Also flagged Reader A's finding as worth fixing in the same ship.
- **Two adversarial refuters**, each shown the proposed fix and told to break it:
  - Refuter 1 (`CONFIRMED` verdict): could not construct a wrapper shape where `i=8` misses a real Type 0/1/2/3 header. Windows has shipped the same 8-byte wrapper since Vista.
  - Refuter 2 (`PARTIAL` verdict): agreed the fix closes the observed bug class. Noted the theoretical possibility of a future Windows revision reshaping the wrapper to non-8 bytes, in which case `i=8` would be wrong in the opposite direction (skip the real header). Deemed acceptable — flagged as a comment in the source and captured in the "Latent bugs" section below.

Hypothesis reconciliation:

| Hypothesis                                                    | Reader | Post-repro status                                         |
|---------------------------------------------------------------|--------|-----------------------------------------------------------|
| A. `Build-SmbiosBlob` emits stale wrapper `RawSize`           | A      | Real bug but not the cause of `0x03`. Fixed anyway.       |
| B. Validator scan false-matches at `i=3` inside wrapper       | B      | **Confirmed primary root cause.** Repro reproduced offline. |
| C. `Parse-SmbiosStructures` drops Type 127 at tail            | C      | Refuted. Parse emitted Type 127 in every trial.           |

## Fix

### `driver/rstflt.c` — validator scan window and fallback

```c
/* v4.0.10: scan now STARTS at i=8, not i=0. The mssmbios REG_BINARY
   layout begins with an 8-byte wrapper
       [Used21CallingMethod, MajVer, MinVer, DmiRev, RawSize DWORD LE]
   whose byte values collide with the "plausible Type 0/1/2/3 header"
   heuristic. See docs/postmortem-v4-phase5/
   incident-v410-smbios-validator-scan-window.md. */
-for (i = 0; i + 2 <= Length && i < 64; i++) {
+for (i = 8; i + 2 <= Length && i < 64; i++) {
     UCHAR t = Blob[i];
     UCHAR L = Blob[i + 1];
     ...
 }
-if (tableStart == 0 && Blob[0] > 127) return FALSE;
+/* v4.0.10: with i starting at 8, tableStart==0 uniquely means the
+   scan window [8,63] never matched any plausible SMBIOS struct header
+   - genuinely malformed input, reject. The pre-v4.0.10 Blob[0]>127
+   side condition was permissive fallback for weird pre-wrapper layouts
+   and is nonsensical now that tableStart is never 0 on accept. */
+if (tableStart == 0) return FALSE;
```

Everything past the scan (the `while (p + 2 <= Length)` structure walker at what was `rstflt.c:447-499`) is unchanged. That code was already correct — it just never got aligned input.

### `scripts/spoof-smbios.ps1` — Build-SmbiosBlob wrapper `RawSize` recompute

Reader A's finding: `Build-SmbiosBlob` copies the `$Header` bytes verbatim as the first 8 bytes of the output, but if `$Structures` were re-emitted with new strings of different total length, bytes 4-7 (`RawSize`) still describe the *original* firmware's raw table size, not the newly-built one. Not the cause of the `0x03` breadcrumb (validator uses `DataLength` from `ZwQueryValueKey`, not the wrapper field) — but mssmbios itself may read the wrapper `RawSize` when serving downstream consumers, and letting it stay stale is a latent over-read / under-read bug. Fix inside `Build-SmbiosBlob`:

```powershell
# Assume wrapper of 8 bytes (Used21CallingMethod, Major, Minor, DmiRev,
# RawSize DWORD LE). If $Header.Length != 8 skip this fix (unknown layout).
if ($Header.Length -eq 8 -and $result.Count -ge 8) {
    $rawLen = $result.Count - 8
    $result[4] = [byte]($rawLen -band 0xFF)
    $result[5] = [byte](($rawLen -shr 8)  -band 0xFF)
    $result[6] = [byte](($rawLen -shr 16) -band 0xFF)
    $result[7] = [byte](($rawLen -shr 24) -band 0xFF)
}
```

Gated on `Header.Length -eq 8` because a future mssmbios layout with a different wrapper size would render blind overwrites at offsets 4-7 wrong; better to skip and let the unknown-layout blob flow through unchanged.

### `scripts/test-smbios-blob.ps1` — new offline validator

New standalone diagnostic that ports `ValidateSmbiosBlob` to PowerShell (byte-for-byte semantics of the driver's walker) so an operator can validate a blob without a VM cycle. Modes:

- `Live`   — read `HKLM:\SYSTEM\CurrentControlSet\Services\mssmbios\Data\SMBiosData` from the current host and validate.
- `Cached` — read `HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters\SmbiosBlob` and validate what the arming script wrote.
- `File`   — validate a blob dumped to disk (arbitrary path).
- `Synthetic` — build a known-good blob in-memory and validate (regression harness).

Prints `tableStart` and the exact walker step where a failing blob desyncs, so the next time a `0x03` breadcrumb fires we can identify the offset without cracking WinDbg.

### Version marker

- `RstFltVersion` bumped: `RstFlt-v4.0.9-BUILD-MARKER` -> `RstFlt-v4.0.10-BUILD-MARKER`. `#pragma comment(linker, "/INCLUDE:RstFltVersion")` still forces the string into the binary. `check-consistency.ps1 Read-DriverVersionMarker` regex updated to match `v4.0.10`.
- File header changelog block appended in `driver/rstflt.c` for `v4.0.10 - ValidateSmbiosBlob scan-window fix`.

## What did NOT need to change

- The structure walker past the scan window (former `rstflt.c:447-499`, now shifted a few lines by the comment additions). Semantically correct; only received desynced input in pre-v4.0.10.
- `Parse-SmbiosStructures` round-trip with `Build-SmbiosBlob`. Reader C's parse-drops-Type-127 hypothesis was refuted by the repro.
- The v4.0.9 signing pipeline (`driver/makefile.mak` signtool step). Unchanged. The v4.0.7-v4.0.9 boot regression (see `incident-v407-driver-boot-regression.md`) is closed and does not overlap this bug.
- `03-instalar-driver.bat`. Same UpperFilters + Parameters flow.
- `ApplySmbiosBlobIfCached` and every other consumer of the validator. Same call sites, same breadcrumb tags.

## Verification protocol

The end-to-end verification requires a VM revert on the Hyper-V dev VM. Not run at ship time (multi-agent workflow closed on the local-host synthetic repro), but the protocol below is the canonical way to confirm on real Windows:

1. Host, elevated PowerShell:
   ```powershell
   Disable-VMIntegrationService -VMName 'Ambiente de desenvolvimento do Windows 10' `
       -Name 'Pulsação','Troca do Par Chave-Valor'
   Restore-VMCheckpoint -VMName 'Ambiente de desenvolvimento do Windows 10' `
       -Name clean-v409-installed -Confirm:$false
   Disable-VMIntegrationService -VMName 'Ambiente de desenvolvimento do Windows 10' `
       -Name 'Pulsação','Troca do Par Chave-Valor'    # again post-restore
   Start-VM 'Ambiente de desenvolvimento do Windows 10'
   ```
2. In-guest, elevated PowerShell: reinstall the v4.0.10 driver over the top of v4.0.9 (SCM will replace `C:\Windows\System32\drivers\rstflt.sys` and re-arm the UpperFilters entry idempotently):
   ```powershell
   .\03-instalar-driver.bat
   ```
   Reboot.
3. Clear stale breadcrumb + arm:
   ```powershell
   Remove-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters `
       -Name SmbiosBlob,EnableSmbiosReplay,OrigSmbiosData,CpuStrings,EnableCpuReplay,LastReplayStatus `
       -EA SilentlyContinue
   .\scripts\spoof-smbios.ps1 -SmbiosOnly
   Restart-Computer -Force
   ```
4. After boot:
   ```powershell
   .\scripts\check-consistency.ps1
   ```

**Expected `LastReplayStatus` after v4.0.10:** `0x04000000` — tag `0x04 MSSMBIOS-OPEN-FAIL`, low bits `0x000000`. This is the documented Hyper-V steady state per the v4.0.6 changelog and CLAUDE.md Gotchas: mssmbios is `Start=1` (SYSTEM_START) and its `Data` subkey does not exist yet at BOOT_START when `ApplySmbiosBlobIfCached` runs. The validator now *passes*, so execution proceeds past the pre-check to the `ZwOpenKey(mssmbios\Data)` call, which fails with `STATUS_OBJECT_NAME_NOT_FOUND` — precisely the expected outcome on this VM. **NOT `0x03000...`**. If we still see tag `0x03`, revisit — the local-host synthetic repro strongly suggests this cannot happen on any Hyper-V or physical Windows we would target, but the empirical verification on the VM is the final word.

Real WMI-visible spoof continues to require the v4.1 IRP interception; a `0x04` breadcrumb is not "spoof succeeded", it is "the driver's replay path is now unblocked from its false-positive rejection and instead hits the *architectural* limitation documented since v4.0.6."

## Latent bugs surfaced (documented, not blocking v4.0.10)

- **Reader A — stale wrapper `RawSize` in `Build-SmbiosBlob`.** Fixed in this ship (see above).
- **Reader C — `Parse-SmbiosStructures` outer-loop guard `while ($offset -lt $Blob.Length - 2)`.** Refuted for the observed input (Type 127 was consistently appended). The condition still terminates one byte early relative to what it looks like it means (`-2` should probably be `-1` to allow reading a final 2-byte header where `Blob[$offset+1]` is at the last valid index). On the shapes we care about (mssmbios blobs of 1036-ish bytes with the End-of-Table struct well before the end), this is invisible. Left as-is for now; add a fix only if a corpus test surfaces a real blob it drops.
- **`Set-StructureString` silent no-op when `Formatted[X] = 0`.** Some SMBIOS structures encode a "no string" sentinel by placing `0x00` in the string-index byte (e.g. `Formatted[7]=0` for Type 1 Manufacturer). `Set-StructureString` currently early-returns on `$StringIndex -le 0`, so if the profile asks us to spoof a field whose original struct has no string slot allocated, that spoof is silently dropped. Functional, not structural — the blob still validates. Would need `Set-StructureString` to (a) refuse to spoof structures with `Formatted[X]=0`, or (b) allocate a new string slot and rewrite the `Formatted[X]` byte. Deferred.
- **Refuter 2 — hypothetical future Windows wrapper reshape.** `i=8` in the validator assumes an 8-byte wrapper. If a future Windows revision extends it to 12 or 16 bytes, `i=8` would land inside the still-wrapper region and re-hit a variant of the same false-match. Not fixed defensively (defensive fix would be to parse the wrapper's own version fields and derive the offset, which introduces its own drift risk); recorded as a source comment in `ValidateSmbiosBlob`.

## Second latent bug: combined arm never lit EnableCpuReplay

**Discovered:** 2026-08-31, in-VM verification of v4.0.10 combined arm (`.\scripts\spoof-smbios.ps1` with no flags).

**Symptom:** After combined arm + reboot on the Hyper-V VM with v4.0.10 installed, `check-consistency.ps1` still reported `[GAP] CPU[N] ProcessorNameString vazamento` on all 8 logical processors — the driver's CPU replay path had not fired even though the CPU strings were correctly cached in `RstFlt\Parameters\CpuStrings`. `LastReplayStatus = 0x04000034` confirmed the SMBIOS gate passed (validator fix works), so this was CPU-specific and unrelated to the primary scan-window bug fixed above.

**Registry state after combined arm + reboot (evidence):**

| Value                | State                                                                        |
|----------------------|------------------------------------------------------------------------------|
| `EnableSmbiosReplay` | `1` (armed)                                                                  |
| `SmbiosBlob`         | 959 bytes (cached)                                                           |
| `LastReplayStatus`   | `0x04000034` (SMBIOS gate `MSSMBIOS-OPEN-FAIL`, expected on Hyper-V)         |
| `EnableCpuReplay`    | **(absent)** — flag never set                                                |
| `CpuStrings`         | 3 strings, correct values (`i5-10600K`, `Family 6 Model 165 Stepping 5`, `GenuineIntel`) |
| `OrigCpuStrings`     | (absent) — never populated because `CpuReplay` never ran                     |

**Root cause:** `scripts/spoof-smbios.ps1` Step 10c (lines ~625-651 pre-v4.0.10) cached `CpuStrings` into `RstFlt\Parameters` but never wrote `EnableCpuReplay=1`. The driver's `IsCpuReplayEnabled()` in `DriverEntry` therefore returned FALSE, skipping the entire CPU replay allocation + queue path. Only the `-CpuOnly` early-exit block (lines ~165-168) explicitly set the flag; combined mode (`spoof-smbios.ps1` with no flags) silently omitted it. This has been broken since the `-SmbiosOnly` / `-CpuOnly` switches were introduced in v4.0.6 (Bug 4 in [`incident-v405-vm-pipeline-validation.md`](incident-v405-vm-pipeline-validation.md)), whose postmortem itself flagged "nenhum script nunca escreveu EnableCpuReplay — operador ligava a mao SEM limpar EnableSmbiosReplay=1 do run anterior" — the fix was to add split-mode switches, but the combined mode's CPU arming was never plumbed.

**Why it wasn't caught earlier:** every CPU-replay validation in the v4.0.5 postmortem was done via `-CpuOnly` (which does set the flag) or by the operator manually setting `EnableCpuReplay=1`. Nobody ran the combined mode end-to-end against `check-consistency.ps1` on a boot cycle. Combined mode looked fine on inspection (`CpuStrings` cached, blob cached, `EnableSmbiosReplay=1`) and the missing DWORD went unnoticed until a v4.0.10 verification pass explicitly re-audited the two enable flags side-by-side.

**Verification of the driver's CpuReplay path with v4.0.10 (pre-fix):** the operator manually set `EnableCpuReplay=1` on top of the already-cached `CpuStrings` (from the previous combined arm), rebooted, and re-ran `check-consistency.ps1`. Result: all 8 `CPU[N]` entries reported OK for `ProcessorNameString`, and `Win32_Processor.Name` also reflected the spoof — proving the driver's `CpuReplay` path is intact under v4.0.10 and reaches WMI via the `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\N` registry keys (which, unlike mssmbios's in-kernel cache, do serve WMI).

**Fix:** in `scripts/spoof-smbios.ps1` Step 10c, immediately after `Set-ItemProperty ... "CpuStrings"`, add:

```powershell
Set-ItemProperty -Path $driverParams -Name "EnableCpuReplay" -Value 1 -Type DWord
```

The `-DisableKernelReplay` cleanup block was also updated to remove `EnableCpuReplay` alongside `CpuStrings` (previously an implicit no-op because the flag was never set — now required for symmetric cleanup). Both changes mirror the pattern already used by the `-CpuOnly` early-exit block. No driver changes needed.

**Architectural asymmetry surfaced — CPU replay path IS WMI-visible on Hyper-V.** This test surfaced a distinction that matters for the v4.1 planning. `Win32_ComputerSystemProduct` / `Win32_BaseBoard` / `Win32_SystemEnclosure` serve from mssmbios's in-kernel firmware cache (Bug 3 in [`incident-v406-bug-triage.md`](incident-v406-bug-triage.md)), so SMBIOS spoof via `mssmbios\Data` write is not WMI-visible on this VM. **But `Win32_Processor` reads directly from `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\N` registry keys, which is exactly what the driver's CPU replay path rewrites** — so CPU spoof IS WMI-visible even on Hyper-V. This is a genuine v4.0.10 win independent of the strategic v4.1 pivot. To be captured in [`docs/roadmap-v41-wmi-intercept.md`](../roadmap-v41-wmi-intercept.md) as "CPU replay path is already WMI-visible; v4.1 focus is exclusively on SMBIOS via `IRP_MJ_SYSTEM_CONTROL` intercept or UMDF WMI provider shadow." Per CLAUDE.md's Gotchas, the mssmbios in-kernel cache constraint remains — this discovery narrows, but does not lift, the v4.1 scope.

## Why WMI-visible SMBIOS spoof is STILL unfixed even with v4.0.10

v4.0.10 removes a false-positive rejection in the driver's *replay path*. It does not change the architectural fact — established in [`incident-v406-bug-triage.md`](incident-v406-bug-triage.md) Bug 3 — that WMI does not read from the registry mirror `mssmbios\Data\SMBiosData`. `WmipQueryRawSMBiosTables` in `Wmiperf.sys` reads the firmware SMBIOS entry-point directly (via the ACPI `RSMB` table on UEFI systems, F-segment scan on legacy), mapping the referenced physical pages through mssmbios's in-kernel cache. Registry writes into the mirror do not participate in that read path. See `docs/roadmap-v41-wmi-intercept.md` and CLAUDE.md's Gotchas section for the strategic conclusion:

- v4.1 path A — kernel `IRP_MJ_SYSTEM_CONTROL` intercept on `\Driver\mssmbios`. Rejected as the initial approach because naive `DriverObject->MajorFunction[]` patching is a PatchGuard target on Windows 10 20H1+ (WDAC mode 2 + testsigning ON leaves PG armed absent explicit disable).
- v4.1 path B — UMDF WMI provider shadow (higher-precedence class provider registered at user mode that intercepts `Win32_ComputerSystemProduct`, `Win32_BaseBoard`, `Win32_SystemEnclosure`, `MSSmBios_RawSMBiosTables`). To test first per the v4.0.6 triage decision.
- v4.1 path C — accept the Hyper-V ineffectiveness and validate the whole chain on physical hardware where mssmbios's own on-firmware read path can be probed for consumer sensitivity to the registry mirror (still uncertain; needs bare-metal test).

v4.0.10 is a *precondition* for any of A/B/C — before we can test whether an alternative WMI path even matters, we need to know the driver's own writes are not being silently blocked by a validator false-positive.

## References

- Follow-up item this incident closes: [`v41-followup-buildsmbiosblob-validation-fail`](../../../.claude/projects/C--Users-xyrlan-hwtoolkit/memory/v41-followup-buildsmbiosblob-validation-fail.md).
- Prior incidents in this series (context, in order):
  - [`incident-v405-vm-pipeline-validation.md`](incident-v405-vm-pipeline-validation.md) — original discovery of the SMBIOS-replay ineffectiveness class of bugs.
  - [`incident-v406-bug-triage.md`](incident-v406-bug-triage.md) — architectural root-cause A (WMI reads firmware cache, not registry) and root-cause B (mssmbios is `Start=1` so we bail on `ZwOpenKey`); introduced `WriteLastReplayStatus` breadcrumb and encoding that made this bug visible.
  - [`incident-v407-driver-boot-regression.md`](incident-v407-driver-boot-regression.md) — signing pipeline restoration; produced the v4.0.9 signed binary and the `clean-v409-installed` checkpoint that this investigation ran against.
- v4.1 pivot doc: [`docs/roadmap-v41-wmi-intercept.md`](../roadmap-v41-wmi-intercept.md) — why v4.0.10 alone does not make the spoof WMI-visible.
- CLAUDE.md Gotchas: entry on `mssmbios.sys` being `Start=1` and the `0x04 MSSMBIOS-OPEN-FAIL` tag being expected steady state on this Hyper-V VM.
