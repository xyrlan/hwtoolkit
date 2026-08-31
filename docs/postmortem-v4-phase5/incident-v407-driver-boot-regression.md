# INCIDENT — v4.0.7-v4.0.9 boot regression: 3 hours of bisection tracked down to one missing signtool line

**Date:** 2026-08-31
**Trigger:** Reinstalling driver `v4.0.6` (built from the same source tree that shipped in commit 3e6ed67) on the Hyper-V dev VM triggered Windows Automatic Repair loop, no visible bugcheck, no MEMORY.DMP. Same VM had happily booted the previous `v4.0.4` binary from a checkpoint many times.
**Method:** Reverted v4.0.6 source additions one at a time (v4.0.7 → v4.0.8), then rebuilt pure v4.0.4 from git. All variants failed identically. That ruled out source-code changes as the cause and pointed at the build environment. Extracted the working v4.0.4 binary out of the VM (`Copy-VMFile` guest→host is not supported; base64-into-chat was the fallback) and inspected it — it had an Authenticode signature block using the self-signed `HWToolkit Test Cert 2026` from `v4.0.2`. Our rebuilds had no signature. Added `signtool` to the makefile linking rule and rebuilt — boot passed on the first try.
**Root cause:** `driver/makefile.mak` never called `signtool` after `link.exe`, so every rebuild produced an unsigned `rstflt.sys`. Under WDAC enforced mode 2 on this VM, an unsigned BOOT_START driver is rejected by `winload.exe` during the UpperFilters walk on the DiskDrive class, `CM_PROB_FAILED_ADD` fires, the storage stack cannot come up, and after three failed boot attempts Windows drops into WinRE Automatic Repair — with no bugcheck screen because the kernel never finished loading.

## Timeline

- **2026-08-30 ~19:24 UTC-3** (v4.0.2 session) — self-signed `HWToolkit Test Cert 2026` created, thumbprint `30310EE7644799431FFF099E1194817E813152B9`, exported to `hwtoolkit-testcert.cer`, installed into VM's `Cert:\LocalMachine\Root`. Driver signed manually with `signtool.exe sign /sha1 …`. Documented in [`incident-v402-signature-plus-filter.md`](incident-v402-signature-plus-filter.md).
- **2026-08-30 ~23:33** — commit `3e6ed67` (v4.0.5 postmortem) references `SHA256 FD274AF97556EAE6DB53835A253DBE1BEAA75D87014D0AF28A9E06E301FFF0B0` as the signed `rstflt.sys` in test. That binary is what ends up in the checkpoint `pre-v406-test`.
- **2026-08-31 ~00:37** — v4.0.6 built from modified source (added `WriteLastReplayStatus` breadcrumb, `RstFltVersion` marker + `#pragma comment(linker, "/INCLUDE:")`, corrected DriverEntry comment about mssmbios boot ordering). **No signing step invoked.** SHA `132CE579A5D56F5F57600CDF0677A49BFD69C82A0E7437871927221EE95F484A`.
- **~08:00-11:00** — installed into VM, Automatic Repair loop. Bisected:
  - v4.0.7 — neutered `WriteLastReplayStatus` body to `UNREFERENCED_PARAMETER` no-op. Still fails.
  - v4.0.8 — additionally removed `RstFltVersion` const + `#pragma /INCLUDE`. Still fails.
  - **v4.0.4 pure source from git** (`git show HEAD:driver/rstflt.c`) rebuilt with current toolchain. **Still fails.**
- **~10:20** — extracted signed 21912-byte v4.0.4 binary from checkpoint via user copy → base64-into-chat. Base64 revealed `MIIFdAIBATEP...CN=HWToolkit Test Cert 2026` tail — an Authenticode PKCS#7 signature block. Rebuilds had **no** such block.
- **~10:45** — added `signtool sign` step to `driver/makefile.mak` after the `link.exe` rule. Rebuilt v4.0.4 pure source **with** signing. Deployed. **Booted cleanly on first try.**
- **~11:05** — restored the full v4.0.6 source (breadcrumb + marker + WriteLastReplayStatus body active) as **v4.0.9**, rebuilt with signing, deployed. **Boots cleanly.** Confirms every v4.0.6 source change was innocent; the sole regression was the missing signtool step.

## Why the source-side bisection kept "looking right"

The v4.0.6-triage workflow (see [`incident-v406-bug-triage.md`](incident-v406-bug-triage.md)) ran three parallel investigations and picked H2 (`WriteLastReplayStatus` `ZwSetValueKey` at BOOT_START) as the most likely culprit with `high` confidence, entirely on plausibility grounds — it was the "only new runtime code path executed on this VM's empirical gate=0 path." That framing was internally sound but rested on an unstated assumption: **that the toolchain output was itself unchanged**. It was not — the binary went from signed (21912 bytes with PKCS#7 tail) to unsigned (20480 bytes, no tail). The adversarial verifier explicitly flagged this as a hazard in its notes:

> Recommended: run the H2 fix first (as it stands), and if it does not boot, DO NOT jump to H1 — instead verify the v4.0.7 rstflt.sys actually replaced the one on disk (compare SHA vs C:\\Windows\\System32\\drivers\\rstflt.sys after install), then rebuild from a fully clean tree.

The verifier caught the "artifact regression, not source regression" possibility one step too late — after H2 fix. The correct guardrail (which we now add) is to **check whether the binary is signed** as part of "diagnose why v4.0.4 rebuild does not boot but the checkpoint binary does". A one-line `signtool verify /pa /v rstflt.sys` at that step would have shown "no signature found" and short-circuited the entire bisection.

## v4.0.9 fixes

### `driver/makefile.mak` — added signing step

```make
# --- Signtool (v4.0.9+ requirement) ---
SIGNTOOL     = C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe
SIGN_SHA1    = 30310EE7644799431FFF099E1194817E813152B9
SIGN_STORE   = MY
TSA_URL      = http://timestamp.digicert.com

rstflt.sys: rstflt.obj
	$(LINK) $(LFLAGS_COMMON) $(RSTFLT_LIBS) rstflt.obj /OUT:rstflt.sys
	@echo [*] Signing rstflt.sys with test cert $(SIGN_SHA1)
	"$(SIGNTOOL)" sign /fd SHA256 /s $(SIGN_STORE) /sha1 $(SIGN_SHA1) /tr $(TSA_URL) /td SHA256 rstflt.sys
```

Prerequisites (host machine):
1. Self-signed `HWToolkit Test Cert 2026` present in `Cert:\CurrentUser\My` (thumbprint `30310EE7644799431FFF099E1194817E813152B9`). Recreate via `New-SelfSignedCertificate -Subject "CN=HWToolkit Test Cert 2026" -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -KeyUsage DigitalSignature -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)` if expired or missing (thumbprint will differ — update `SIGN_SHA1` in makefile.mak).
2. WDK 10.0.22621 installed (for `signtool.exe`). Fallback to `10.0.26100` if the 22621 SDK is removed — just update `SIGNTOOL` path.
3. Internet access to `http://timestamp.digicert.com` for RFC-3161 timestamping. If offline, drop `/tr … /td SHA256` from the signtool line — signature still validates until cert expiry.

Prerequisites (target VM, one-time):
1. Public cert (`hwtoolkit-testcert.cer`) installed into `Cert:\LocalMachine\Root` on the guest. `Import-Certificate -FilePath hwtoolkit-testcert.cer -CertStoreLocation Cert:\LocalMachine\Root` under elevated PowerShell.
2. Testsigning ON (`bcdedit /set testsigning on`; `03-instalar-driver.bat` already handles this).
3. HVCI OFF (checked by `03-instalar-driver.bat` early).

### `driver/rstflt.c` — restored v4.0.6 additions (marker + breadcrumb)

- `RstFltVersion` const + `#pragma comment(linker, "/INCLUDE:RstFltVersion")` restored. Value bumped to `RstFlt-v4.0.9-BUILD-MARKER`.
- `WriteLastReplayStatus` body restored to active `ZwSetValueKey` write. All 10 call sites in `ApplySmbiosBlobIfCached` remain from v4.0.6.
- DriverEntry banner updated (v4.0.6 → v4.0.9, DBG-only string, stripped in release).
- Corrected DriverEntry comment about mssmbios boot ordering (v4.0.6 change) preserved.

### VS 2026 (VS 18 Community) standardization

Documented explicitly: the toolchain that produces the working driver **is** VS 18 (VS 2026 Community, MSVC 14.51.36231) + WDK 10.0.22621. The full v4.0.7/v4.0.8 bisection through v4.0.4-pure-source proved the source is byte-equivalent between "sessão anterior" and "sessão atual". Do NOT investigate compiler/linker flag drift as a cause of boot failures unless the signature has been verified present first.

## Recommended posture

- **Every `nmake`-generated `rstflt.sys` is now signed.** No manual signtool step needed by users.
- **`03-instalar-driver.bat` needs no change** — WDAC accepts the signed driver, boot-time load passes.
- **When cert expires** (currently 2028-08-30): regenerate via New-SelfSignedCertificate, export public cert, re-import into every target VM's `Root` store, update `SIGN_SHA1` in makefile.mak. Existing timestamped signatures on already-built binaries survive cert expiry — the cert timestamp validates against the DigiCert TSA response, not against current cert validity.
- **Guardrail against future recurrence:** if `signtool verify /pa /v rstflt.sys` on host says `no signature`, do not deploy. Should probably be added to `03-instalar-driver.bat` as an early sanity check (rejects unsigned .sys with a clear error before touching System32).

## Files touched this commit

- `driver/rstflt.c` — bumped v4.0.6 changelog entry to v4.0.9, restored WriteLastReplayStatus active body + RstFltVersion marker after their (rejected) v4.0.7/8 removal-bisection attempts.
- `driver/makefile.mak` — added SIGNTOOL/SIGN_SHA1/SIGN_STORE/TSA_URL vars + `signtool sign` step to rstflt.sys build rule.
- `docs/postmortem-v4-phase5/incident-v407-driver-boot-regression.md` — this file.
- `README.md` — new MUDANCAS EM v4.0.9 section.

## References

- [`incident-v402-signature-plus-filter.md`](incident-v402-signature-plus-filter.md) — original session that created the test cert.
- [`incident-v406-bug-triage.md`](incident-v406-bug-triage.md) — the v4.0.6 shipping context (Bug 3+5 closed, Bug 4 dump collection primed).
