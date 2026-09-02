# CLAUDE.md — hwtoolkit project notes

Windows hardware-fingerprint spoofing toolkit: BOOT_START kernel filter driver (`driver/rstflt.c`, DiskDrive class UpperFilter) + PowerShell user-mode spoofers (`scripts/`) + sequential `NN-*.bat` pipeline in the repo root. Targets: Fase 5 anti-cheat detection surfaces (WMI, SMBIOS, CPU registry, MAC, EDID, disk serial, Windows machine identity). Primary threat model docs: `docs/emac-recon-v2.md`, `docs/fase2-kickoff.md`.

**As of Phase 1 (2026-08-31), Level A (EMAC-only userland spoof, no kernel driver) is the recommended default against EMAC-tier anti-cheats (RubinOT) per `docs/emac-recon-v3.md`.** Level C driver install (`03-instalar-driver.bat` + kernel replay) remains opt-in for future stronger anti-cheats that inspect SMBIOS/CPUID beyond what EMAC surfaces today.

**As of Track D (2026-09-01, driver v5.0.0), an ADD-ON to Level C exists: `CmRegisterCallbackEx`-based kernel rewrite of `Enum\SCSI\Disk&Ven_*` subkey names, targeting the three consecutive RubinOT/EMAC bans (baseline / Level A / fresh identity + PRs #12/#13/#14/#15) that confirmed H2 - EMAC reads NAMES via `RegEnumKeyEx`, not just values.** Opt-in via `.\scripts\track-d-arm.ps1 -Enable` after `03-instalar-driver.bat`. Design + safety contract: [`docs/track-d-kernel-registry-callback-kickoff.md`](docs/track-d-kernel-registry-callback-kickoff.md) + v5.0.0 changelog block at top of `driver/rstflt.c`.

**Language conventions in-repo**: user-facing prose in `README.md`, `.bat`, script output, and PowerShell comments is Portuguese-BR. Driver code comments, postmortems, and technical rationale in English. Commit messages in English. Keep this split when adding content.

## Toolchain — DO NOT deviate

- Compiler: **Visual Studio 2026 Community "VS 18"** (`C:\Program Files\Microsoft Visual Studio\18\Community`), MSVC 14.51+. VS 2022 BuildTools alone works if the C++ workload is installed; without it, `02-compilar-driver.bat` falls through to VS 18.
- WDK: 10.0.22621 at `C:\Program Files (x86)\Windows Kits\10\...\10.0.22621.0`. `signtool.exe` from the same SDK bin.
- Build: `.\02-compilar-driver.bat` from the repo root; wraps `nmake /f driver\makefile.mak`.
- **Signing is mandatory** — `makefile.mak` calls `signtool sign` after `link.exe` using self-signed cert `HWToolkit Test Cert 2026` (thumbprint `30310EE7644799431FFF099E1194817E813152B9`, valid until 2028-08-30, in host's `Cert:\CurrentUser\My`). If you remove or break the signing step, WDAC-enforced Win10 rejects the BOOT_START load and drops the box into an Automatic Repair loop with no bugcheck screen — see [`docs/postmortem-v4-phase5/incident-v407-driver-boot-regression.md`](docs/postmortem-v4-phase5/incident-v407-driver-boot-regression.md). If the cert expires, regenerate via `New-SelfSignedCertificate` and update `SIGN_SHA1` in `makefile.mak` and re-import public cert into target VM's `Cert:\LocalMachine\Root`.

## Standard commands

- Generate profile: `.\00-gerar-profile.bat` (writes `C:\ProgramData\.hwcfg\profile.json` v9+).
- Build driver: `.\02-compilar-driver.bat` (produces signed `driver\rstflt.sys`).
- Install driver: `.\03-instalar-driver.bat` (checks HVCI + testsigning, then `sc create` + UpperFilters + Parameters key). Requires reboot to activate.
- Arm SMBIOS-only replay: `.\scripts\spoof-smbios.ps1 -SmbiosOnly` — clears CPU state first.
- Arm CPU-only replay: `.\scripts\spoof-smbios.ps1 -CpuOnly` — clears SMBIOS state, sets `EnableCpuReplay=1`.
- Prep for BSOD dump collection: `.\scripts\prep-crashdump.ps1` (sets `AutoReboot=0` + `DedicatedDumpFile=C:\rstflt-dump.sys`); `-Restore` to revert.
- Audit consistency post-boot: `.\scripts\check-consistency.ps1` — decodes driver's `LastReplayStatus` breadcrumb, verifies driver version marker, cross-checks WMI/registry/SMBIOS/CPU/network.
- Uninstall: `.\08-desinstalar-driver.bat --skip-fase16` — always the safe way to remove the driver (restores UpperFilters from backup key). Requires reboot to fully release.
- Aplicar Level A (EMAC-only, sem driver kernel): `.\04b-aplicar-hwid-emac.bat --skip-disk --skip-volume --skip-usb --skip-hid` - modo recomendado default contra EMAC-tier (RubinOT). Ver docs/emac-recon-v3.md.
- Rollback Level A userland: `.\08b-rollback-userland.bat` - reverte MachineGuid/ComputerName/etc dos backups .hwcfg + unregistra HWToolkit\SpoofCPUUserland task. Nao toca driver.
- Arm Track D (v5.0.0+, Cm registry callback kernel): `.\scripts\track-d-arm.ps1 -Enable` — grava `EnableRegCallback=1` + `RegCallbackSeed` em `Services\RstFlt\Parameters`. Precisa driver ja instalado. Reboot para o callback armar. Desde v5.0.4: gate por image name inline (`PsGetProcessImageFileName + _strnicmp "rubinot"`) — sem PID plumbing, sem `-SetPid`, sem `RubinOtPid`. Para probar em VM: spawnar qualquer processo com nome comecando `rubinot*` (`Copy-Item reg.exe rubinot_probe.exe; .\rubinot_probe.exe query ...`).
- Diagnose Track D: `.\scripts\track-d-arm.ps1 -Diagnose` — decode `LastCallbackStatus` (tag/status) + `CallbackHitCount`. Também disponível via `.\scripts\check-consistency.ps1` (agora inclui bloco Track D).
- **v5.0.5 Phase 1 (2026-09-01)**: descriptor-table refactor + BTH (`Enum\BTH\Dev_*`) + STORAGE\Volume (`Enum\STORAGE\Volume\{GUID}#offset`, boot-volume offset-zero protegido) enum-name rewriters. `CallbackHit_BTH`/`CallbackHit_Storage` passam de reservados a WIRED. Sem novo arm flag (o gate/seed são os mesmos; `EnableValueReadRewrite` é Phase 2). VM sanity harness: [`scripts/phase1-sanity-test.ps1`](scripts/phase1-sanity-test.ps1) — inspeciona os filhos reais de BTH/STORAGE\Volume na VM vs o gate do driver (valida a premissa de shape) + SCSI regression check. Spec: [`docs/track-d-v505-value-handler-kickoff.md`](docs/track-d-v505-value-handler-kickoff.md) §4.
- Disable Track D (sem uninstall driver): `.\scripts\track-d-arm.ps1 -Disable` — grava `EnableRegCallback=0`. Efeito imediato (hot path pass-through), callback continua registrado no kernel.
- Boot recovery from WinRE: `.\09-recuperar-boot.bat` (offline registry surgery to remove `RstFlt` from UpperFilters and delete the service).

**Do NOT invoke** `sc stop RstFlt ; sc delete RstFlt ; Restart-Computer -Force` in one shot without first removing `RstFlt` from `HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-...}\UpperFilters` — this reproduces the STOP 0x7B failure mode documented in [`incident-v402-signature-plus-filter.md`](docs/postmortem-v4-phase5/incident-v402-signature-plus-filter.md) (UpperFilters walk points at deleted service → `CM_PROB_FAILED_ADD` → 0x7B). `08-desinstalar-driver.bat` does the correct order automatically.

## Testing on the Hyper-V dev VM

- Target VM: `Ambiente de desenvolvimento do Windows 10` (windev-image, Win10 Enterprise, Gen 2 UEFI, storvsc, 8 vCPU, WDAC enforced mode 2, testsigning ON, HVCI OFF, Secure Boot OFF).
- **Before starting the VM for any arming test**, disable heartbeat + KVP integration services on the host:
  ```powershell
  Disable-VMIntegrationService -VMName 'Ambiente de desenvolvimento do Windows 10' `
      -Name 'Pulsação','Troca do Par Chave-Valor'
  ```
  Otherwise the Hyper-V watchdog resets the guest at ~52-56s post-Winlogon when KVP encounters the modified registry state (Bug 4, closed as H2 host-side reset — see `incident-v405-vm-pipeline-validation.md` header). Names above are Windows PT-BR; EN names are `Heartbeat` and `Key-Value Pair Exchange`.
- Restore config re-enables both services on VM checkpoint restore — always redisable after `Restore-VMCheckpoint`.
- File transfer host → guest: `Copy-VMFile -Name '<vm>' -SourcePath <host> -DestinationPath <guest> -CreateFullPath -FileSource Host -Force`. Requires guest's `vmicguestinterface` service running (Manual startup, resets to Stopped on each reboot — the user starts it manually per session). Copy-VMFile **guest → host does not exist**; use base64-into-chat or SMB share for that direction.
- Working checkpoints on the VM (as of PR #18):
  - `clean-v505-phase0-armed` (2026-09-01) — **driver v5.0.5 installed + EnableRegCallback=1 + Phase 0 instrumentation validated (SCSI end-to-end, ring buffer + per-path counters + NonRubi counter all persist). Ideal base para iteracao Phase 1 (BTH + STORAGE\Volume + descriptor-table refactor) e Phase 2 (RegNtPostQueryValueKey handler).** State: shutdown limpo pos-sanity test. Ver [`scripts/phase0-sanity-test.ps1`](scripts/phase0-sanity-test.ps1) pro test harness.
  - `clean-v504-armed-track-d-tested` (2026-09-01) — driver v5.0.4 installed + EnableRegCallback=1 + probed once (HitCount=1). Superseded pelo v5.0.5 checkpoint acima; mantido para regressao contra v5.0.4 se necessario.
  - `clean-v501-armed-track-d` (2026-09-01) — driver v5.0.1 armed, superseded pelo v5.0.4 checkpoint acima.
  - `clean-v409-installed` — driver v4.0.9 signed installed, no arming. Base historica.
  - `clean-no-driver` — no `RstFlt` registered anywhere. Base for install-from-scratch tests; parent de todos os `clean-v50X-*` checkpoints.
  - `pre-v406-test` — the last v4.0.4 checkpoint kept around for the historical binary if needed.

## Gotchas

- **PowerShell `sc` is not `sc.exe`.** In PS 5.1, bare `sc` is an alias for `Set-Content`. When invoking the Service Control Manager from PS, always use `sc.exe` explicitly. From within `.bat` files, `sc` resolves to `sc.exe` correctly.
- **PowerShell script files must be ASCII** (or UTF-8 with BOM). PS 5.1 default reads BOM-less UTF-8 as Windows-1252 and multi-byte chars (em-dash, accents) break the parser. Scripts in this repo are ASCII-only on purpose (see the comment header in `check-consistency.ps1`). If you edit, keep ASCII.
- **PE `TimeDateStamp` + Authenticode signature timestamp make SHA256 change every relink** — do not use SHA to validate driver identity. Use `check-consistency.ps1 Read-DriverVersionMarker` (regex-matches the embedded `RstFlt-v<version>-BUILD-MARKER` string kept by `#pragma comment(linker, "/INCLUDE:RstFltVersion")` in `rstflt.c`) or `signtool verify /pa /v rstflt.sys`.
- **`mssmbios.sys` is `Start=1` (SYSTEM_START) on stock Windows**, loading AFTER our BOOT_START `RstFlt` — `ZwOpenKey` on `\Registry\Machine\SYSTEM\CurrentControlSet\Services\mssmbios\Data` at DriverEntry time returns `STATUS_OBJECT_NAME_NOT_FOUND`. The driver's `WriteLastReplayStatus` breadcrumb records tag `0x04 MSSMBIOS-OPEN-FAIL` in `LastReplayStatus` when this fires — that is the expected steady state on this Hyper-V VM, not a bug.
- **WMI (Win32_ComputerSystemProduct, Win32_BaseBoard, Win32_SystemEnclosure) serves from mssmbios's in-kernel firmware cache**, not from `HKLM\...\mssmbios\Data\SMBiosData`. Registry writes into that key have no effect on WMI queries — confirmed empirically 2026-08-31. Real spoof requires IRP-level interception on `\Driver\mssmbios` or a UMDF WMI provider shadow, both scheduled in [`docs/roadmap-v41-wmi-intercept.md`](docs/roadmap-v41-wmi-intercept.md). Do NOT re-attempt the registry-write strategy without reading Bug 3 in `incident-v406-bug-triage.md`.
- **On a `03-instalar-driver.bat` failure with `CreateService FAILED 1072`** (service marked for deletion): a prior `sc delete` did not fully commit. Reboot once, run `03-instalar-driver.bat` again — it succeeds cleanly on a fresh SCM state.
- **Track D `RstRegistryCallback` MUST NOT call `Zw*` registry APIs from inside its body** — MSDN explicitly warns of deadlock under the CM-internal lock. Any breadcrumb persistence goes through `WriteLastCallbackStatus` → `TrackDFlushWorker` which runs on `DelayedWorkQueue` OUTSIDE the callback stack. Same rule for the `PsSetCreateProcessNotifyRoutineEx` callback (safer, but keep the contract uniform). Config (seed, enable gate, override PID) is read once at DriverEntry into file-scope globals and mutated only by the callback's own `RegNtPreSetValueKey` tap on our own Parameters key — no external Zw calls.
- **Track D uses altitude `321000` for `CmRegisterCallbackEx`** — this is a TEST-ONLY altitude never allocated by Microsoft. Fine for dev boxes; if this ever ships beyond the maintainer's own systems, requisition an official allocation via MSDN ALTITUDE registry before wider distribution.

## Documentation map

- `README.md` — the main user-facing changelog and setup guide, Portuguese, ~55KB. Everything user-facing goes there.
- `docs/postmortem-v4-phase5/` — incident writeups by version. Read the latest (`incident-v407-driver-boot-regression.md`) first for the current stable-driver context; the `incident-v405-vm-pipeline-validation.md` header shows the closure status of every open bug.
- `docs/roadmap-v41-wmi-intercept.md` — the next architectural pivot for real WMI-visible spoofing. Explicit PatchGuard warnings against the naive `DriverObject` dispatch swap. UMDF WMI provider shadow to test first.
- `docs/emac-recon-v2.md`, `docs/fase2-kickoff.md`, `docs/fase2-track-a-windows-test-kickoff.md` — anti-cheat threat model + phase planning.

## Style

- Every driver change requires a corresponding changelog block at the top of `driver/rstflt.c` (`v4.0.x - ...`) — do not merge without.
- Every non-trivial toolkit-behavior discovery gets a new `docs/postmortem-v4-phase5/incident-v40X-*.md`. Reference the file from `README.md` and from the corresponding `v4.0.x` changelog block in the driver.
- Commit messages end with `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` when the assistant did substantial work.
- PR bodies end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- Squash-merge is the convention (`gh pr merge <n> --squash --delete-branch`).
