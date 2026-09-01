/*
 * RstFlt - Minimal SMBIOS + Gated CPU Registry Replay Filter Driver (v4.0.10)
 *
 * SYSTEM_START upper filter of the DiskDrive class. Its jobs are to
 * replay a userspace-cached SMBIOS blob into mssmbios\Data during
 * DriverEntry (ahead of winmgmt / anti-cheat), and to replay cached
 * per-core CPU identity strings (ProcessorNameString / Identifier /
 * VendorIdentifier) into every subkey under
 *   \Registry\Machine\HARDWARE\DESCRIPTION\System\CentralProcessor
 * so per-thread readers (WMI Win32_Processor, GetSystemInfo, cpuinfo
 * scrapers, EMAC-style AC probes) return the spoofed identity on every
 * logical processor. CPU replay runs on a system worker thread so
 * DriverEntry returns immediately (no boot slowdown). All IRPs are
 * strict pass-through - the driver does no filtering of storage I/O.
 *
 * Changelog
 * ---------
 * v1  Initial proof-of-concept (IOCTL_STORAGE_QUERY_PROPERTY only).
 * v2  Fixed PnP/Power handling, added IO_REMOVE_LOCK, validated
 *     IoStatus.Information sizes, added DbgPrint tracing.
 * v3  - Deterministic serial generation using registry seed + device
 *       location (stable across reboots, immune to ASLR).
 *     - Intercepts IOCTL_SMART_RCV_DRIVE_DATA (IDENTIFY DEVICE)
 *       and IOCTL_ATA_PASS_THROUGH in addition to STORAGE_QUERY_PROPERTY.
 *     - Configurable serial prefix and length via registry.
 *     - Realistic serial format matching OEM conventions.
 *     - Renamed debug prefix to "[RstFlt]".
 * v3.1 - Fixed BSOD risk: DispatchPassthrough and DispatchPower now
 *       acquire IO_REMOVE_LOCK, preventing device deletion while
 *       READ/WRITE/CREATE/CLOSE/Power IRPs are in flight.
 * v3.2 - Fixed integer-overflow BSOD in SpoofAtaPassCompletion
 *       (untrusted DataBufferOffset + 512 could wrap).
 *     - Fixed over-zero of STORAGE_DEVICE_DESCRIPTOR: only the serial
 *       field is cleared, no longer corrupts vendor/product strings
 *       that may follow it on non-standard stor miniports.
 *     - Added IOCTL_STORAGE_PROTOCOL_COMMAND interception for the
 *       NVMe IDENTIFY CONTROLLER path (Serial Number at bytes 4-23).
 *       Closes the main NVMe leak; previous versions only covered
 *       STORAGE_QUERY_PROPERTY on NVMe.
 * v3.3 - Added IOCTL_ATA_PASS_THROUGH_DIRECT interception. This
 *       IOCTL uses METHOD_OUT_DIRECT and carries a user-mode
 *       DataBuffer pointer; we probe+lock it as an MDL at dispatch
 *       time (PASSIVE) so the completion routine can safely write
 *       via the system VA at any IRQL, then defer MmUnlockPages to
 *       a work item.
 *     - SMBIOS blob replay in DriverEntry: if the userspace tool
 *       has cached the modified SMBIOS in Parameters\SmbiosBlob,
 *       the driver copies it into mssmbios\Data\SMBiosData while
 *       the machine is still booting, before winmgmt/anti-cheat
 *       start. Kills the race the old scheduled task had.
 * v3.4 - Post-BSOD hardening.
 *     - SMBIOS blob replay is now OPT-IN via
 *       Parameters\EnableSmbiosReplay (REG_DWORD, default 0).
 *       Old behavior (any cached SmbiosBlob applied unconditionally)
 *       could brick boot when the userspace tool wrote a malformed
 *       blob or when downstream WMI/mssmbios consumers choked on the
 *       replayed structures. Userspace tool now sets EnableSmbiosReplay
 *       only after it has verified the blob round-trips through
 *       Win32_ComputerSystemProduct successfully.
 *     - ValidateSmbiosBlob() now sanity-checks the cached blob before
 *       overwrite: size cap 65535, walkable structure table, Type 127
 *       (End-of-Table) present, string tables terminated. Bad blob is
 *       ignored instead of being propagated to mssmbios\Data.
 *     - Backup of the pre-replay SMBiosData is written to
 *       Parameters\OrigSmbiosData on first apply so 09-recuperar-boot
 *       can restore genuine firmware SMBIOS from offline registry.
 *     - Companion INF drops StartType from 0 (BOOT_START) to 1
 *       (SYSTEM_START) so any future crash in DriverEntry/AddDevice
 *       no longer makes the machine unbootable.
 *     - Fixed MDL/worker race in SpoofAtaPassDirectCompletion: the
 *       deferred cleanup work item is now tracked by a second
 *       RemoveLock reference so IRP_MN_REMOVE_DEVICE cannot delete
 *       the device object (and thus the work-item's owner) while a
 *       cleanup worker is still queued.
 * v3.5 - Fixed serial truncation in SpoofStorageCompletion.
 *       When the disk's real serial is shorter than the spoofed
 *       one (e.g. a 6-char OEM serial vs a 15-char spoof), the
 *       lower driver sized the response to `actual = original + 1`
 *       and we could only overwrite `original - 1` chars — the
 *       spoofed serial came out truncated and inconsistent with
 *       what SMART/IDENTIFY/NVMe paths reported.
 *       Fix: capture OutputBufferLength at dispatch (new
 *       RSTFLT_STORAGE_CTX), and in the completion:
 *         (a) if SerialNumber is the LAST field in the descriptor
 *             (Windows storport default), extend the response up
 *             to OutputBufferLength and update IoStatus.Information
 *             so the caller reads the full spoofed serial;
 *         (b) if a vendor miniport packs another field AFTER the
 *             serial (rare — some Intel RST / LSI stacks do this),
 *             truncate before that next field so we don't corrupt
 *             VendorId/ProductId/Firmware that follow it.
 *       Falls back to v3.4 behavior (truncate at `actual`) if the
 *       context allocation fails.
 * v3.6 - Stripped storage IOCTL intercept paths entirely.
 *     - EMAC recon confirmed anti-cheat does not query disk serial
 *       via DeviceIoControl. Storage IOCTL paths were carrying six
 *       historical BSOD sources (see v3.1-v3.5 entries above) for
 *       no EMAC-relevant benefit. Kept for other-AC portability in
 *       earlier versions; removed here after user BSOD on v3.5.
 *     - Driver is now a minimal SYSTEM_START upper filter whose
 *       sole job is SMBIOS blob replay in DriverEntry. All IRPs
 *       are pass-through. AddDevice remains so the service loads
 *       reliably (upper filter of DiskDrive class ensures load
 *       ordering that beats winmgmt/anti-cheat to SMBIOS access).
 *     - Removed: DispatchDeviceControl entirely, GenerateSerial,
 *       ReadRegistryConfig, Spoof* completions, MDL cleanup path,
 *       SerialSeed/SerialPrefix/SerialLength registry parameters.
 *     - Kept: SMBIOS replay opt-in gate (EnableSmbiosReplay=1),
 *       ValidateSmbiosBlob, OrigSmbiosData backup, IO_REMOVE_LOCK
 *       discipline on remaining PnP/Power/passthrough dispatch.
 *     - Post-review hardening:
 *         (a) ApplySmbiosBlobIfCached guards NULL/empty RegPath so
 *             Driver Verifier fault injection cannot bootloop us.
 *         (b) ValidateSmbiosBlob header/fit bounds use <= not <, so
 *             legitimate slim blobs are no longer silently refused.
 *         (c) IRP_MN_REMOVE_DEVICE now forward-and-wait: attach a
 *             completion routine that signals a KEVENT, wait, then
 *             IoDetachDevice + IoDeleteDevice, then complete the IRP.
 *             Previous shape (release-lock-and-wait immediately after
 *             IoCallDriver) races async lower-driver REMOVE completion
 *             on stacks like iaStorAC.
 *         (d) DriverUnload registration dropped — a DiskDrive upper
 *             filter always has attachments, so unload never actually
 *             runs, and advertising it lets sc-stop→replace→sc-start
 *             race the stale mapped image.
 * v4.0 - CPU registry replay added (Track A of Fase 2).
 *     - New ReplayCpuRegistry queued as a system-thread work item
 *       from DriverEntry; runs at PASSIVE off the boot-driver thread
 *       so DriverEntry returns immediately (no boot slowdown) and
 *       the CPU-population race with HAL is drained with a 10s
 *       budget instead of blocking DriverEntry for 500ms.
 *     - Opt-in via Parameters\EnableCpuReplay (REG_DWORD, default 0)
 *       mirroring EnableSmbiosReplay. Cached CpuStrings absent OR
 *       gate zero -> replay is a no-op.
 *     - Parameters\OrigCpuStrings backup written on first apply so
 *       09-recuperar-boot can restore genuine CPU strings offline.
 *     - HAL race hardening: wait for CentralProcessor subkey count
 *       to reach KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)
 *       before enumerating; each per-value write is preceded by a
 *       ZwQueryValueKey probe so we only overwrite values HAL has
 *       already populated (avoids the last-writer-wins loss).
 *     - Cached blob is validated before use: reject odd DataLength,
 *       enforce per-string caps (128 wchar name / 64 wchar identifier
 *       / 16 wchar vendor) so a corrupted or oversized cache cannot
 *       propagate a 32k string into registry consumers.
 *     - subBuf sized 256 WCHARs; STATUS_BUFFER_OVERFLOW /
 *       STATUS_BUFFER_TOO_SMALL on ZwEnumerateKey is treated as
 *       "skip this entry, continue" instead of aborting the enum.
 *     - Ordering: ReplayCpuRegistry is queued BEFORE
 *       ApplySmbiosBlobIfCached in DriverEntry so the race-sensitive
 *       op does not sit behind an on-disk hive I/O in the queue.
 *       (ApplySmbiosBlobIfCached itself stays inline in DriverEntry —
 *       its target hive is on-disk and mssmbios has already booted
 *       BOOT_START before us, so the timing pressure is on future
 *       readers/reloads, not this-boot mssmbios.)
 * v5.0.4 - Simplify PID matching to per-callback image-name check
 *       (Kickoff sec 3.3 Option A). Remove PsSetCreateProcessNotifyRoutineEx
 *       + g_TrackDTrackedPids[] + KSPIN_LOCK + g_TrackDOverridePid +
 *       Parameters\RubinOtPid tap. v5.0.0-v5.0.3 shipped Option B (PID
 *       array populated by Ps notify) against the kickoff's own MVP
 *       recommendation. Post-v5.0.3 audit + third bare-metal ban proved
 *       four independent failure modes could keep the PID array empty
 *       when rubinot* was actually running:
 *         (a) driver armed AFTER rubinot* already spawned - Ps notify
 *             only fires on create, so the pre-existing PID is invisible.
 *         (b) launcher/updater chain spawns the game via an intermediate
 *             shim whose ImageFileName is NOT rubi-prefixed - Ps notify
 *             rejected the shim and by the time the eventual
 *             rubinot_dx.exe fired its create, its own HW enum had
 *             already happened in-process during image load.
 *         (c) Ps-notify-vs-first-callback race: on fast SSDs the first
 *             RegNtPostEnumerateKey from rubinot_dx.exe can land before
 *             Ps notify has finished adding the PID (both fire at
 *             PASSIVE from the same create path). Delta HitCount = 0
 *             for the launch, HitCount jumps by 1 on the SECOND enum.
 *         (d) PS_CREATE_NOTIFY_INFO->ImageFileName is documented as
 *             OPTIONAL - some NtCreateUserProcess paths deliver NULL.
 *             Our handler bailed silently, missing that spawn.
 *     - Fix: RstRegistryCallback now calls
 *         PsGetProcessImageFileName(PsGetCurrentProcess())
 *       and _strnicmp("rubinot", 7) against the returned 15-byte
 *       EPROCESS ImageFileName. Next-byte guard rejects anything
 *       whose char after the prefix is neither '\0' nor '.' nor '_',
 *       so `rubinotify.exe` cannot slip through. Match runs per-fire,
 *       imune to (a)-(d) by construction: no PID-enrollment step to
 *       miss, no ordering constraint, no spawn-time NULL to bail on.
 *     - Deletions (~70 LOC): RstProcessNotifyCallback + its register/
 *       unreg calls, g_TrackDTrackedPids[]/g_TrackDTrackedPidCount/
 *       g_TrackDPidsLock/g_TrackDOverridePid globals, TrackDAdd/Remove/
 *       MatchesTrackedPid + TrackDImageNameMatchesRubi + TrackDCurrent-
 *       CallerIsTarget helpers, Parameters\RubinOtPid load in
 *       LoadTrackDConfig, isPid branch of TrackDHandlePreSetValue,
 *       KeInitializeSpinLock at arm time.
 *     - New instrumentation (closes v5.0.3-documented gap "callback
 *       silent when gate rejects"):
 *         g_TrackDInvokeCount    LONG - incremented at top of
 *             RstRegistryCallback after the enable-gate, before the
 *             name gate. Answers "did the callback fire at all this
 *             boot" without depending on rewrite success.
 *         g_TrackDNameMissCount  LONG - incremented when the image-name
 *             gate rejects the caller (any non-rubinot process).
 *         g_TrackDLastMissName   CHAR[16] - first 15 bytes of the most
 *             recent rejected image name, NUL-terminated. Diagnostic
 *             hint: which process dominates the miss traffic.
 *       All three persisted by the existing TrackDFlushWorker as
 *       REG_DWORD / REG_DWORD / REG_SZ under Services\RstFlt\Parameters
 *       (CallbackInvokeCount / CallbackNameMissCount / LastMissImageName).
 *       Drift-recheck loop extended to cover all five now-published
 *       values so on-disk breadcrumbs never permanently lag hot-path.
 *     - Tag 0x01 redefined in place: TRACKD_TAG_NO_PID -> TRACKD_TAG_
 *       NAME_MISS. Same slot value (0x01) so pre-v5.0.4 decoders that
 *       ingested breadcrumbs from older builds still decode without
 *       collision; the label just changes meaning. Tag 0x02 (was
 *       PID_STALE) reserved as TRACKD_TAG_STALE_UNUSED so no future
 *       redefine silently reuses it.
 *     - Split LastArmStatus from LastCallbackStatus (P0.4 in the
 *       audit): new WriteLastArmStatus helper writes to
 *       Parameters\LastArmStatus at ArmTrackD success AND at the
 *       arm-failure path. LastCallbackStatus is written ONLY from the
 *       hot-path callback body after v5.0.4. Fixes the v5.0.3-flagged
 *       ambiguity ("`tag=0x00 OK` from -Diagnose could mean 'callback
 *       fired cleanly' OR 'callback merely armed cleanly'").
 *     - Companion userland changes:
 *         scripts/track-d-arm.ps1 -SetPid removed (no PID plumbing to
 *             set); -Diagnose prints CallbackInvokeCount /
 *             CallbackNameMissCount / LastMissImageName / LastArmStatus
 *             plus decoded tag table with 0x01 = NAME-MISS.
 *         scripts/check-consistency.ps1 Track D block extended to
 *             surface the same values; NAME-MISS treated as diagnostic
 *             (Yellow), not benign.
 *     - Companion audit: adversarial workflow run 2026-09-01 against
 *       v5.0.2 tree - 44 findings, 41 CONFIRMED, 1 REFUTED, 2
 *       PLAUSIBLE. Findings that directly drove this refactor:
 *         no-invocation-counter (critical), pid-gate-silent-exit
 *         (critical), lastcallbackstatus-arm-time-only-when-clean
 *         (high), v503-changelog-anticipates-this-gap (high),
 *         pid-filter-uses-unicode-imagefilename-with-proper-sync
 *         (info; REFUTES original ANSI/UNICODE-bug hypothesis).
 *     - Version marker bumped v5.0.3 -> v5.0.4.
 *     - Postmortem: docs/postmortem-v5-track-d/incident-v504-pid-
 *       matching-simplification.md.
 *     - Backward compat: RubinOtPid REG_DWORD under Parameters is now
 *       ignored (safe to leave from previous arms; -Enable no longer
 *       writes it). Tag 0x02 slot reserved for compat with older
 *       decoders. EnableRegCallback / RegCallbackSeed /
 *       CallbackHitCount / LastCallbackStatus shapes unchanged.
 *     - Reentrancy contract preserved: no Zw* inside callback body;
 *       LastArmStatus write is safe (ArmTrackD runs at PASSIVE,
 *       DriverEntry context, outside any Cm callback frame).
 *
 * v5.0.3 - HOTFIX: add /INTEGRITYCHECK linker flag (required by
 *       PsSetCreateProcessNotifyRoutineEx).
 *     - Empirical discovery, bare-metal test 2026-09-01: v5.0.2's
 *       Ps notify auto-detect silently failed. Cm callback path OK
 *       (proven via manual SetPid: 4 rewrites landed, HitCount 0->4)
 *       but no rubinot* process was ever added to
 *       g_TrackDTrackedPids array (delta HitCount = 0 across launcher
 *       start + a rubi-prefixed powershell probe test).
 *     - Root cause: MSDN mandates `/INTEGRITYCHECK` linker flag for
 *       ANY driver registering PsSetCreateProcessNotifyRoutineEx:
 *         "Any driver that registers process notify routines via
 *          PsSetCreateProcessNotifyRoutineEx or ..NotifyRoutineEx2
 *          must be linked with the /INTEGRITYCHECK linker option."
 *       Without the flag, the register call returns
 *       STATUS_ACCESS_DENIED. ArmTrackD ignores this silently
 *       (non-fatal per design — override PID still works), so from
 *       userland it looks like the callback armed OK
 *       (`LastCallbackStatus tag=0x00 OK` — but that's just the Cm
 *       callback's init breadcrumb; Ps notify has no separate
 *       breadcrumb). Testsigning does NOT bypass the requirement
 *       — confirmed empirically on this bare-metal box.
 *     - Fix: add `/INTEGRITYCHECK` to `LFLAGS_COMMON` in
 *       `driver/makefile.mak`. Rebuild → PE header carries
 *       IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY → kernel accepts the
 *       Ps notify registration on next load. No C source change
 *       needed.
 *     - Marker bumped `v5.0.2` -> `v5.0.3` to distinguish the build.
 *     - Follow-up: consider adding a per-subsystem breadcrumb tag
 *       (e.g. `LastPsNotifyStatus`) so future arm-time failures are
 *       visible from `check-consistency.ps1` without spelunking DBG
 *       output. Deferred to v5.0.4 if needed.
 * v5.0.2 - Multi-PID array + substring image match for Ps notify.
 *     - Empirical finding (bare-metal test 2026-09-01): RubinOT ships
 *       as TWO cooperating processes -
 *         `RubinOT.exe`      - launcher/client shell; does the initial
 *                              EMAC registration + HW enumeration
 *                              (creates ~\emac-uuid, POSTs fingerprint)
 *                              in sub-1s from process create.
 *         `rubinot_dx.exe`   - game client; spawned when user picks a
 *                              server and clicks Play; does its own
 *                              periodic HW probes during gameplay.
 *       Both must be intercepted in parallel: the launcher registers
 *       the machine identity on server, the game client feeds session
 *       telemetry. If either goes uncaptured, the server sees a
 *       mismatched (real-launcher, spoofed-game) pair - inherently
 *       suspicious.
 *     - v5.0.1's `TRACKD_RUBINOT_IMAGE_STR` suffix-matched only
 *       `\rubinot_dx.exe` and cached the detected PID in a SINGLE
 *       slot (`g_TrackDAutoPid`). Two independent failures:
 *         (a) `RubinOT.exe` launcher never matched -> its HW enum
 *             (sub-1s) was never intercepted.
 *         (b) Even if we listed both image names, when the game client
 *             fired later, `InterlockedExchangePointer` on the single
 *             slot would OVERWRITE the launcher's PID - the launcher
 *             would lose interception mid-session.
 *     - v5.0.2 fixes both. New file-scope globals replace the single
 *       slot:
 *           KSPIN_LOCK g_TrackDPidsLock;
 *           HANDLE     g_TrackDTrackedPids[TRACKD_MAX_TRACKED_PIDS];
 *           ULONG      g_TrackDTrackedPidCount;
 *       With TRACKD_MAX_TRACKED_PIDS=8 (comfortable headroom for a
 *       launcher family plus updaters). Add/Remove helpers use the
 *       spinlock; the hot-path reader in `TrackDCurrentCallerIsTarget`
 *       takes the lock too - contention is negligible because Ps
 *       notify updates are rare (process create/exit only).
 *     - Image-name match promoted from suffix-exact to
 *       case-insensitive substring on the LAST PATH COMPONENT ONLY
 *       (chars after final `\`). Match is: first 4 wchars of that
 *       component compare equal to `rubi` (case-insensitive). Covers:
 *         `RubinOT.exe`, `rubinot_dx.exe`, `RubinOTUpdater.exe`,
 *         any hypothetical rename that starts the leaf with `rubi`
 *         (Rubinix, RubinOT_v3, etc.). Rejects false positives from
 *         random paths that CONTAIN rubi but not as a leaf prefix.
 *     - PsSetCreateProcessNotifyRoutineEx exit branch now calls
 *       `TrackDRemoveTrackedPid(ProcessId)` unconditionally - safe
 *       (no-op if PID not tracked), keeps the array from bloating
 *       across long uptime.
 *     - `TrackDCurrentCallerIsTarget` now:
 *         override != 0  ->  return current == override  (unchanged;
 *                            manual test override still wins)
 *         override == 0  ->  scan g_TrackDTrackedPids for match
 *     - `g_TrackDRubinotImage` UNICODE_STRING + `TRACKD_RUBINOT_IMAGE
 *       _STR` #define both removed - no consumers left after substring
 *       match.
 *     - No config surface change - `EnableRegCallback`, `RubinOtPid`,
 *       `RegCallbackSeed`, `LastCallbackStatus`, `CallbackHitCount`
 *       stay the same shape. `track-d-arm.ps1` needs no update.
 *     - Version marker bumped `v5.0.1` -> `v5.0.2`.
 *     - Reentrancy contract preserved: spinlock is at PASSIVE (Ps
 *       notify) and PASSIVE (Cm callback) - both allow it. Zero Zw*
 *       inside the callback body. No new external API surface.
 * v5.0.1 - Track D expansion + `-Disable` hot-toggle fix.
 *     - `TrackDHandlePreSetValue` now dispatches by ValueName: still
 *       taps `RubinOtPid` (v5.0.0), and ADDITIONALLY taps
 *       `EnableRegCallback`. Userland `track-d-arm.ps1 -Disable` now
 *       takes effect immediately (previous behavior required reboot
 *       because `g_TrackDEnabled` was only read at DriverEntry). Same
 *       tap works for `-Enable` — flipping the DWORD on the fly
 *       toggles the hot-path gate. Closes the v5.0.0 known limitation
 *       documented in docs/postmortem-v5-track-d/incident-v500-mvp-
 *       integration.md sec 0.1.
 *     - Expanded read intercepts beyond MVP scope. New per-path
 *       synthesizers, all preserving structural markers and same
 *       wchar count so caller's NameLength stays valid:
 *         * `\Enum\PCI\VEN_*&DEV_*&SUBSYS_*&REV_*` -
 *           rewrites SUBSYS+REV tokens, preserves VEN+DEV+CC (never
 *           touches VEN or DEV — driver binding is keyed on those).
 *         * `\Enum\USB\VID_*&PID_*\<serial>` -
 *           rewrites the leaf serial subkey name, preserves the
 *           `VID_*&PID_*` parent (driver binding stays intact).
 *           Parent classification: parent path ends with
 *           `\Enum\USB\VID_XXXX&PID_XXXX` (case-insensitive; last
 *           component matches `VID_` + 4 hex + `&PID_` + 4 hex).
 *         * `\Enum\HID\VID_*&PID_*\<serial>` -
 *           same shape as USB. Kickoff had this as POST-MVP with
 *           input-safety caveat; kernel intercept only rewrites the
 *           returned subkey NAME, does NOT rename actual PnP path or
 *           change driver binding, so keyboard/mouse keep working.
 *           Serial-name change only affects readers doing RegEnumKey
 *           enumeration under the VID_&PID_ parent.
 *         * `\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\
 *           Audio\Render\{GUID}` and `\Capture\{GUID}` -
 *           rewrites the entire endpoint GUID (32 hex chars in
 *           canonical dashed form), preserves the enclosing `{...}`
 *           and dash positions.
 *     - New classifier `TrackDClassifyParent` returns a `TRACKD_PATH_
 *       TYPE` enum (NONE / SCSI / PCI / USB_INSTANCE / HID_INSTANCE
 *       / AUDIO_RENDER / AUDIO_CAPTURE). `TrackDHandlePostEnumerate`
 *       now dispatches by classifier result to the per-type
 *       synthesizer. Reentrancy contract preserved: zero Zw* inside
 *       the callback body; all classification is memory-only on the
 *       parent path returned by `CmCallbackGetKeyObjectID`.
 *     - New file-scope UNICODE_STRING views for the additional path
 *       suffixes (`\Enum\PCI`, `\MMDevices\Audio\Render`, `\MMDevices
 *       \Audio\Capture`) + a shared value-name view for
 *       `EnableRegCallback`. Initialized once in `ArmTrackD` from
 *       string literals in `.rdata`; zero heap.
 *     - Version marker bumped `v5.0.0` → `v5.0.1`.
 *     - Companion userland: `scripts/track-d-arm.ps1 -Disable` now
 *       correctly claims immediate effect; README "Level C+/Track D"
 *       section updated. `-Diagnose` legend unchanged (same tag set,
 *       same breadcrumb encoding).
 *     - PatchGuard posture unchanged: same CmRegisterCallbackEx +
 *       PsSetCreateProcessNotifyRoutineEx registrations, no new
 *       API surface, no structure patches.
 *     - Kickoff sec 4 non-goals broken deliberately: HID intercept
 *       was POST-MVP; included here per user choice for full-coverage
 *       bare-metal test. If EMAC / RubinOT flags HID rewrites (unlikely
 *       given kernel intercept doesn't affect binding), revert HID
 *       via v5.0.2 by masking HID_INSTANCE in the classifier dispatch.
 * v5.0.0 - Track D: kernel registry callback for Enum\SCSI\Disk subkey
 *       name rewrite. Root motivation is three consecutive RubinOT / EMAC
 *       bans (2026-08-31 baseline, 2026-08-31 Level A userland, 2026-09-01
 *       fresh identity with PRs #12/#13/#14/#15 armed) all inside ~1 minute
 *       of login. Investigation confirmed H2 from docs/emac-recon-v3.md:
 *       EMAC reads SUBKEY NAMES via RegEnumKeyEx under
 *         HKLM\SYSTEM\CurrentControlSet\Enum\{SCSI,PCI,USB,HID}
 *       and userland spoofers can only rewrite VALUES *inside* those
 *       subkeys, not the subkey names themselves. User-mode rename in
 *       PR #13 failed against live devices with open-handle contention
 *       (SCSI/USB/HID/audio all blocked). See docs/track-d-kernel-
 *       registry-callback-kickoff.md for the full design rationale.
 *     - New CmRegisterCallbackEx registration at altitude "321000"
 *       (test-only altitude range; if this ever ships beyond the
 *       maintainer's own boxes, requisition an official allocation
 *       via Microsoft ALTITUDE registry).
 *     - Callback (RstRegistryCallback) handles TWO REG_NOTIFY_CLASS
 *       operations. On RegNtPostEnumerateKey it rewrites subkey names
 *       IN PLACE when: (a) EnableRegCallback=1, (b) caller PID matches
 *       the tracked RubinOT PID, (c) parent path ends with the MVP
 *       filter suffix "\Enum\SCSI", (d) subkey name starts with
 *       "Disk&Ven_" — three of those four are strict same-wchar-count
 *       rewrites of the Ven/Prod/Rev tokens using deterministic FNV-1a
 *       hex derived from Parameters\RegCallbackSeed + the real subkey
 *       name. Post-callback rewrite (not pre-callback + STATUS_CALLBACK_
 *       BYPASS) is used deliberately: it lets the CM populate the buffer
 *       normally and we mutate before the caller sees it, with zero
 *       reentrancy risk of calling Zw* under the CM-internal lock. On
 *       RegNtPreSetValueKey the callback taps writes to our OWN
 *       Parameters\RubinOtPid and updates the in-memory override — this
 *       is how the unit-test workflow (write a specific PID, watch it
 *       take effect) works without exposing an ioctl.
 *     - PID discovery uses a companion PsSetCreateProcessNotifyRoutineEx
 *       registration (deviates from kickoff Opt A recommendation toward
 *       Opt B) so RubinOT's PID auto-populates on process create and
 *       auto-clears on exit; robust against restart. Opt A required
 *       either Zw calls inside the registry callback (deadlock under
 *       CM lock) or worker-thread polling (ugly), both worse trade-offs.
 *       Image-name match is a case-insensitive suffix compare against
 *       "\rubinot_dx.exe" on PS_CREATE_NOTIFY_INFO->ImageFileName.
 *       Parameters\RubinOtPid override (non-zero) beats the Ps-detected
 *       PID, so the unit test can point the callback at any process.
 *     - Configuration surface added to Parameters:
 *           EnableRegCallback     REG_DWORD  master gate, 0=off default
 *           RubinOtPid            REG_DWORD  test override (0=use auto)
 *           RegCallbackSeed       REG_SZ     32-hex FNV seed mirror of
 *                                            profile.pci_hardwareid.
 *                                            randomize_seed
 *           LastCallbackStatus    REG_DWORD  breadcrumb, tag<<24|status
 *       Tag values (mirror LastReplayStatus shape):
 *           0x00 OK                (rewrite landed)
 *           0x01 NO-PID            (RubinOtPid=0 AND Ps hasn't seen it)
 *           0x02 PID-STALE         (tracked PID no longer exists)
 *           0x03 PATH-GET-FAIL     (CmCallbackGetKeyObjectID failed)
 *           0x04 BUFFER-BAD        (KEY_BASIC_INFORMATION malformed)
 *           0x05 ALLOC-FAIL        (NonPagedPoolNx alloc failed)
 *           0x06 SEH-FAULT         (__try caught access violation
 *                                   or other exception in name write)
 *     - Scope: MVP intercepts ONLY the "\Enum\SCSI" enumerator and
 *       ONLY subkey names starting with "Disk&Ven_". Expansion to
 *       Enum\USB / PCI / HID / MMDevices Audio is scheduled by
 *       bare-metal test result per kickoff section 4.
 *     - Safety:
 *         (a) __try/__except wraps every write into the caller's
 *             KEY_INFORMATION buffer; on EXCEPTION_EXECUTE_HANDLER
 *             we set LastCallbackStatus tag 0x06 and pass-through
 *             (caller sees the real name, no bypass).
 *         (b) PAGED_CODE on the callback body; explicit
 *             NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL).
 *         (c) Zero Zw* registry I/O from inside the callback.
 *             Config (seed, gate, override PID) is cached in
 *             file-scope globals populated at DriverEntry time
 *             and mutated only by the RegNtPreSetValueKey tap.
 *         (d) Same-wchar-count rewrite guarantees the caller's
 *             NameLength field stays valid without touching it.
 *     - PatchGuard: CmRegisterCallbackEx and PsSetCreateProcessNotify-
 *       RoutineEx are BOTH documented Microsoft-supported extensibility
 *       APIs. Neither is a hook, dispatch swap, or structure patch —
 *       PatchGuard does NOT flag either. Distinct from the rejected
 *       "DriverObject->MajorFunction[X] swap" route in docs/roadmap-
 *       v41-wmi-intercept.md Option C (which PG WOULD flag).
 *     - DriverUnload intentionally still not registered (same v3.6
 *       reasoning as before: a DiskDrive UpperFilter always has
 *       attachments, so unload never fires and CmUnRegisterCallback
 *       is implicitly released on reboot).
 *     - Companion userland: scripts/track-d-arm.ps1 (new) writes
 *       EnableRegCallback + RegCallbackSeed to Parameters, exposes
 *       -Enable/-Disable/-Diagnose/-SetPid switches.
 *     - Kickoff and MVP acceptance criteria: docs/track-d-kernel-
 *       registry-callback-kickoff.md. First postmortem scaffold:
 *       docs/postmortem-v5-track-d/incident-v500-mvp-integration.md
 *       (fill after bare-metal RubinOT gameplay test).
 * v4.0.10 - HOTFIX: ValidateSmbiosBlob scan-window bug that produced
 *       spurious 0x03 VALIDATION-FAIL breadcrumbs on Hyper-V (and on
 *       ANY host whose mssmbios wrapper had DmiRevision in {0,1,2,3},
 *       which covers most modern Windows). Root cause: the initial
 *       Type-0/1/2/3 header scan (rstflt.c:432 loop) started at offset
 *       0, so it walked INTO the fixed 8-byte mssmbios wrapper. On
 *       Hyper-V Gen2 the wrapper looks like
 *           [03 03 00 00 XX XX XX XX]
 *       (Used21CallingMethod, MajVer=3, MinVer=0, DmiRev=0, then a
 *       ULONG-LE raw-table size). At i=3 the pair (Blob[3]=DmiRev=0,
 *       Blob[4]=size_lo>=4) satisfies (t in {0,1,2,3}, L>=4, i+L<=Len),
 *       so tableStart pinned to 3 instead of 8. The subsequent walk
 *       ran misaligned inside the wrapper, blew past the real Type 127
 *       End-of-Table, and returned FALSE with sawEnd=FALSE, producing
 *       breadcrumb 0x0300003E. The scan was intentionally loose (see
 *       comment at ValidateSmbiosBlob) but the looseness collided with
 *       the wrapper. Fix: start the scan at i=8, past the documented
 *       fixed-size mssmbios wrapper. Also tightened the fallback at
 *       rstflt.c:442 from `tableStart == 0 && Blob[0] > 127` to
 *       `tableStart == 0` because with i>=8 the only way tableStart
 *       stays 0 is "no plausible header found anywhere in the scan
 *       window", which is genuinely malformed input.
 *       Root cause identified via multi-agent workflow investigation
 *       (three independent readers + local host repro with synthetic
 *       Hyper-V-shaped blob + two adversarial verifiers, one CONFIRMED
 *       one PARTIAL-with-fix-agreement) — findings in
 *       docs/postmortem-v4-phase5/incident-v410-smbios-validator-scan-
 *       window.md.
 *       Companion script hardening: scripts/spoof-smbios.ps1
 *       Build-SmbiosBlob now recomputes the mssmbios wrapper's raw-
 *       size DWORD (bytes 4-7) after rebuild, so downstream mssmbios
 *       consumers see a wrapper that matches the actual raw-table byte
 *       count (previously it was left stale at the firmware's original
 *       value, silently over-declaring the raw size after a spoof
 *       shortened it — a latent bug the workflow surfaced independent
 *       of the primary scan-window cause).
 *       New tool: scripts/test-smbios-blob.ps1 - ports ValidateSmbios-
 *       Blob to PowerShell so a user can offline-check a firmware blob
 *       or the currently-cached SmbiosBlob before rebooting into the
 *       driver replay path. Modes: -Live, -Cached, -File, -Synthetic.
 *       Second latent bug closed in the same ship: pre-v4.0.10
 *       scripts/spoof-smbios.ps1 Step 10c cached CpuStrings but NEVER
 *       set Parameters\EnableCpuReplay=1 in combined mode (no flags).
 *       IsCpuReplayEnabled() therefore returned FALSE in DriverEntry
 *       and the CpuReplay worker was never queued - CPU silently
 *       leaked despite combined arm looking successful. Broken since
 *       v4.0.6 switch introduction; nobody caught it because CPU
 *       validation always went through -CpuOnly (which explicitly
 *       sets the flag). Fix: Step 10c now writes EnableCpuReplay=1
 *       alongside CpuStrings, mirroring the -CpuOnly pattern. The
 *       -DisableKernelReplay cleanup also removes EnableCpuReplay
 *       now (was implicit no-op pre-v4.0.10). No driver changes -
 *       driver-side CpuReplay path itself was correct all along;
 *       verification in Hyper-V VM confirmed all 8 logical processors
 *       spoof to profile CPU AND Win32_Processor.Name reflects the
 *       spoof (unlike SMBIOS Types 1/2/3 which serve WMI from
 *       mssmbios in-kernel cache, Win32_Processor reads directly from
 *       HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\N registry).
 * v4.0.9 - HOTFIX: added Authenticode signing to build pipeline. The
 *       "Automatic Repair loop after v4.0.6 install" family of failures
 *       was NOT caused by any source-code regression — bisection through
 *       v4.0.6/7/8 (removing WriteLastReplayStatus body, removing
 *       RstFltVersion marker, even rebuilding pure v4.0.4 source) all
 *       reproduced identically. Root cause: the toolkit stopped signing
 *       rstflt.sys at some point. WDAC-enforced Win10 winload REJECTS
 *       an unsigned BOOT_START driver during PnP UpperFilters walk,
 *       CM_PROB_FAILED_ADD fires, storage stack cannot come up, boot
 *       manager retries three times then hands off to WinRE Automatic
 *       Repair — no bugcheck screen because no kernel ever finished
 *       booting. Fix: signtool sign step added to driver/makefile.mak
 *       linking rule, using the self-signed HWToolkit Test Cert 2026
 *       (thumbprint 30310EE7644799431FFF099E1194817E813152B9) already
 *       provisioned in Cert:\CurrentUser\My on the host and Cert:\
 *       LocalMachine\Root on the target VM (see v4.0.2 postmortem).
 *       WriteLastReplayStatus body RESTORED to active ZwSetValueKey.
 *       RstFltVersion marker + /INCLUDE pragma RESTORED — the H2/H1
 *       "reverts" of v4.0.7/8 were red herrings.
 *       Documented in docs/postmortem-v4-phase5/incident-v407-driver-
 *       boot-regression.md.
 * v4.0.8 - REJECTED (H1 revert bisection attempt; source discarded).
 * v4.0.7 - REJECTED (H2 revert bisection attempt; source discarded).
 * v4.0.6 - Bug 3 findings originally shipped here (RstFltVersion marker
 *       + WriteLastReplayStatus breadcrumb + corrected DriverEntry
 *       comment about mssmbios boot ordering). All that source is
 *       RESTORED in v4.0.9; only the missing signtool step was the
 *       actual regression. See v4.0.6 changelog block below.
 * v4.0.6-original - was v4.0.6 comment placeholder — replaced by v4.0.9 above.
 * v4.0.9-old-hotfix-note - HOTFIX: v4.0.6 introduced a WriteLastReplayStatus helper
 *       that called ZwSetValueKey on our own Services\RstFlt\
 *       Parameters key from inside DriverEntry at BOOT_START. That
 *       write reproducibly triggered Automatic Repair (STOP 0x7B
 *       family, no visible bugcheck screen) on Win10 Enterprise dev
 *       VM even in the gate-off no-op path (EnableSmbiosReplay=0).
 *       Multi-agent triage confirmed the ZwSetValueKey as the sole
 *       runtime differential vs v4.0.4 on the empirical gate=0 boot
 *       path. Neutered the helper body to UNREFERENCED_PARAMETER
 *       so every call site becomes a no-op without touching the
 *       10 sites in ApplySmbiosBlobIfCached individually. Version
 *       marker + comment blocks + DBG banner all kept from v4.0.6.
 *       See docs/postmortem-v4-phase5/incident-v407-driver-boot-
 *       regression.md. Follow-up (v4.1): defer breadcrumb to a
 *       DelayedWorkQueue work item at PASSIVE post-boot.
 * v4.0.6 - Bug 3 findings (v4.0.5 postmortem, VM validation):
 *     - CORRECTED the false claim under v4.0 that "mssmbios has already
 *       booted BOOT_START before us". Empirically verified 2026-08-30
 *       on Win10 Pro dev host: mssmbios is Start=1 (SYSTEM_START) with
 *       no group ordering, while RstFlt is Start=0 (BOOT_START). RstFlt
 *       therefore runs BEFORE mssmbios, and ApplySmbiosBlobIfCached's
 *       ZwOpenKey on \Registry\Machine\...\mssmbios\Data typically
 *       returns STATUS_OBJECT_NAME_NOT_FOUND at BOOT_START init because
 *       the Data subkey is (re)created by mssmbios itself during its
 *       own SYSTEM_START init (likely REG_OPTION_VOLATILE). This is
 *       exactly why Parameters\OrigSmbiosData stayed 0 bytes in the
 *       v4.0.5 postmortem — we bail at the mssmbios-open step, before
 *       the backup path is reachable.
 *     - Even if the ZwOpenKey succeeded, the whole "write mssmbios\Data
 *       from a driver" strategy is architecturally ineffective: WMI
 *       (Win32_ComputerSystemProduct, Win32_BaseBoard, Win32_System-
 *       Enclosure, MSSmBios_RawSMBiosTables) queries route through the
 *       kernel WMI infrastructure (WmipQueryRawSMBiosTables → Wmip-
 *       GetRawSMBiosTableData) which reads SMBIOS DIRECTLY FROM FIRMWARE
 *       (physical memory scan for legacy or ACPI RSMB entry-point for
 *       UEFI). The registry value is a write-back artifact for external
 *       readers, not the source-of-truth mssmbios itself consults.
 *       Real WMI-visible SMBIOS spoofing requires IRP_MJ_SYSTEM_CONTROL
 *       dispatch interception on \Driver\mssmbios; that pivot is
 *       scheduled for v4.1 (see docs/roadmap-v41-wmi-intercept.md).
 *     - ApplySmbiosBlobIfCached is RETAINED as a best-effort no-op with
 *       diagnostic breadcrumb. New helper WriteLastReplayStatus records
 *       the exit tag+NTSTATUS at every bail path into
 *       Parameters\LastReplayStatus (REG_DWORD, encoding (tag<<24)|
 *       (status&0x00FFFFFF)), so future postmortems have evidence-in-
 *       hive without WinDbg attach. Tags:
 *           0x00 SUCCESS               0x01 GATE-OFF
 *           0x02 NO-BLOB               0x03 VALIDATION-FAIL
 *           0x04 MSSMBIOS-OPEN-FAIL    0x05 MSSMBIOS-WRITE-FAIL
 *       scripts/check-consistency.ps1 decodes and prints this.
 *     - Kept for the physical-hardware case where SMBIOS registry
 *       behavior may differ from Hyper-V; on Hyper-V, expect
 *       LastReplayStatus tag=0x04 (MSSMBIOS-OPEN-FAIL) every boot.
 * v4.0.1 - HOTFIX: v4.0 froze physical hardware at boot even with
 *       EnableCpuReplay=0 (no BSOD, no dump, no bugcheck 1001,
 *       Verifier /standard armed and clean). Root cause: DriverEntry
 *       unconditionally allocated the CPU_REPLAY_CTX and queued the
 *       worker via ExQueueWorkItem; only the worker itself checked
 *       the EnableCpuReplay gate. The mere act of queueing +
 *       scheduling the worker during SYSTEM_START driver init
 *       interacted badly with the boot sequence.
 *     - Fix: new static helper IsCpuReplayEnabled runs BEFORE any
 *       allocation or queue. If EnableCpuReplay is absent, zero, or
 *       unreadable, DriverEntry skips the entire CPU-replay path,
 *       leaving the driver functionally equivalent to v3.6
 *       (SMBIOS-only) — a configuration proven stable in production.
 *     - Fix (compile): three FIELD_OFFSET(..., Data) comparisons
 *       against ULONG needSize/curNeed now cast to (ULONG) at the
 *       FIELD_OFFSET site to silence C4018 signed/unsigned mismatch.
 *       Prior versions required CL=/wd4018 to build under MSVC
 *       14.44 + WDK 10.0.22621 (both raise C4018 where older
 *       toolchains did not); with the cast the driver builds
 *       cleanly under /W4 /WX without any warning suppression.
 *
 * WARNING: Kernel drivers can BSOD your machine if buggy.
 * Test signing mode required to load unsigned drivers.
 */

#include <ntddk.h>

/* v5.0.4: PsGetProcessImageFileName is a semi-documented kernel export
 * (present in ntoskrnl.exe on every supported Windows version since XP
 * but not declared in wdm.h/ntddk.h). Prototype mirrors the ntoskrnl
 * symbol. Returns a pointer to the 15-byte fixed-length ImageFileName
 * field inside EPROCESS (ANSI, NUL-padded, may be un-terminated when
 * the leaf reaches 15 chars) - callers must bound their compare. Used
 * by the per-callback image-name filter that replaced the v5.0.0-v5.0.3
 * PID-array gate. */
NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

/* ================================================================
 *  Constants
 * ================================================================ */
#define POOL_TAG    'tRsF'

/* v4.0.9: version marker RESTORED. The v4.0.8 removal-as-bisection was
 * a red herring — Authenticode signing being missing was the real cause
 * of the boot regression, not this const array. The /INCLUDE linker
 * directive forces link.exe to keep the symbol under aggressive dead-
 * code elimination so `scripts/check-consistency.ps1 Read-DriverVersion-
 * Marker` can validate the installed driver came from v4.0.9+ source
 * without depending on the PE TimeDateStamp (which changes on relink). */
#pragma comment(linker, "/INCLUDE:RstFltVersion")
const char RstFltVersion[] = "RstFlt-v5.0.4-BUILD-MARKER";


/* v4.0: per-string caps for the cached CpuStrings REG_MULTI_SZ.
 * Downstream WMI / session-mgr consumers commonly use fixed 260-char
 * buffers; caps well under that protect them from a corrupted cache
 * that would otherwise propagate a 32k string. */
#define CPU_NAME_MAX_WCHARS    128
#define CPU_IDENT_MAX_WCHARS   64
#define CPU_VENDOR_MAX_WCHARS  16

/* v4.0: HAL/subkey-population wait budget. Each pass sleeps 100ms;
 * 100 passes = 10s. Runs on a worker thread so this does not block
 * DriverEntry or downstream SYSTEM_START drivers. */
#define CPU_REPLAY_MAX_PASSES  100
#define CPU_REPLAY_DELAY_MS    100

/* ================================================================
 *  v5.0.0 Track D constants - Cm registry callback tunables.
 *
 *  MVP scope per docs/track-d-kernel-registry-callback-kickoff.md
 *  section 4: intercept ONLY \Enum\SCSI enumerations, ONLY when the
 *  child subkey name starts with L"Disk&Ven_". Everything else falls
 *  through untouched. Expansion (Enum\USB, Enum\PCI, MMDevices\Audio)
 *  is bare-metal-test gated.
 * ================================================================ */

/* Altitude for CmRegisterCallbackEx. 321000 is a TEST-ONLY altitude
 * (Microsoft never allocated it). Fits in the "FSFilter Anti-Virus"
 * band. If Track D ships beyond the maintainer's own dev boxes,
 * request an official allocation via Microsoft's ALTITUDE registry. */
#define TRACKD_ALTITUDE_STR     L"321000"

/* Parent-path suffixes and required child-name prefixes for each
 * intercepted enumerator. All comparisons case-insensitive via
 * Rtl*UnicodeString or the local StartsWithI helper.
 *
 * Kernel-side names reported by CmCallbackGetKeyObjectID are of the form
 *   \REGISTRY\MACHINE\SYSTEM\ControlSet001\Enum\SCSI
 * (numeric ControlSet may vary; suffix match is control-set agnostic)
 * or for MMDevices
 *   \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\
 *   MMDevices\Audio\Render
 */
#define TRACKD_ENUM_SUFFIX_STR    L"\\Enum\\SCSI"           /* SCSI parent */
#define TRACKD_SUBKEY_PREFIX_STR  L"Disk&Ven_"              /* SCSI child */

#define TRACKD_PCI_SUFFIX_STR         L"\\Enum\\PCI"        /* PCI parent */
#define TRACKD_PCI_CHILD_PREFIX_STR   L"VEN_"               /* PCI child */

#define TRACKD_MMDEV_RENDER_STR    L"\\MMDevices\\Audio\\Render"
#define TRACKD_MMDEV_CAPTURE_STR   L"\\MMDevices\\Audio\\Capture"

/* USB/HID: parent path must MATCH the pattern
 *   \...\Enum\USB\VID_XXXX&PID_XXXX     (case-insensitive; X = hex digit)
 * or same with \Enum\HID\. We check case-insensitively via
 * TrackDMatchUsbHidInstanceParent (see below) — the last path
 * component after `\` starts with VID_ and matches the 17-wchar
 * `VID_XXXX&PID_XXXX` shape. */
#define TRACKD_ENUM_USB_MARKER_STR  L"\\Enum\\USB\\"
#define TRACKD_ENUM_HID_MARKER_STR  L"\\Enum\\HID\\"

/* Suffix on our OWN Parameters key path for the write-tap that lets
 * userland toggle RubinOtPid + EnableRegCallback without a rebooted
 * driver having to re-read Parameters (which would deadlock under the
 * CM callback lock). Compared case-insensitively. */
#define TRACKD_PARAMS_SUFFIX_STR  L"\\Services\\RstFlt\\Parameters"
#define TRACKD_ENABLE_VAL_STR     L"EnableRegCallback"     /* v5.0.1 tap */

/* v5.0.4: per-callback ANSI image-name filter. PsGetProcessImageFileName
 * returns the fixed 15-byte EPROCESS ImageFileName field (may be un-
 * terminated when the leaf reaches 15 chars); we compare via _strnicmp
 * on the first N bytes. Length 7 ("rubinot") is strict enough to reject
 * unrelated processes yet still match every observed RubinOT leaf
 * ("RubinOT.exe", "rubinot_dx.exe", "RubinOTUpdater.exe"). The filter
 * body also inspects the byte at offset TRACKD_IMAGE_MATCH_LEN and
 * requires it to be one of {'\0', '.', '_'} so a hypothetical
 * "rubinotimposter.exe" cannot slip through. Replaces the pre-v5.0.4
 * TRACKD_IMAGE_LEAF_PREFIX_STR wide-string prefix used by the removed
 * Ps notify path. */
#define TRACKD_IMAGE_MATCH_PREFIX  "rubinot"
#define TRACKD_IMAGE_MATCH_LEN     7

/* Upper bound for the subkey name we will rewrite in place. Real
 * SCSI subkey names cap around ~90 wchars; 256 wchars is generous.
 * Larger names pass through unchanged (defensive: refuse to touch
 * anything outside the expected shape). */
#define TRACKD_MAX_NAME_WCHARS  256

/* FNV-1a-64 constants. Match scripts/spoof-pci-hardwareid.ps1
 * Get-Fnv1a64Hash for the MIXING PRIMITIVE ONLY. The full input
 * construction (domain-tag inventory, seed encoding, real-field
 * bytes as raw UTF-16LE, per-round digit byte) differs from what
 * Get-Fnv1a64Hash on a joined UTF-8 string produces — see
 * TrackDFillTokenFnv doc comment for the exact recipe, and
 * docs/track-d-name-recipe.md for the userland-facing spec that a
 * porter must follow to reproduce this kernel's output byte-for-byte. */
#define TRACKD_FNV_OFFSET_BASIS  0xCBF29CE484222325ULL
#define TRACKD_FNV_PRIME         0x00000100000001B3ULL

/* Breadcrumb tags for LastCallbackStatus, encoded (tag<<24)|status.
 * Shape mirrors LastReplayStatus so scripts/check-consistency.ps1
 * can share the decoder. */
#define TRACKD_TAG_OK             0x00u  /* rewrite landed             */
#define TRACKD_TAG_NAME_MISS      0x01u  /* v5.0.4: image-name gate    */
                                         /* did not match TRACKD_IMAGE */
                                         /* _MATCH_PREFIX (replaces    */
                                         /* pre-v5.0.4 NO_PID; same    */
                                         /* slot preserved so old      */
                                         /* decoders decode without    */
                                         /* value-collision surprise). */
#define TRACKD_TAG_STALE_UNUSED   0x02u  /* reserved (was PID_STALE    */
                                         /* pre-v5.0.4; no longer      */
                                         /* emitted after Ps notify    */
                                         /* removal - slot kept so no  */
                                         /* future add silently reuses */
                                         /* the value)                 */
#define TRACKD_TAG_PATH_GET_FAIL  0x03u  /* CmCallbackGetKeyObjectID   */
#define TRACKD_TAG_BUFFER_BAD     0x04u  /* KEY_INFORMATION malformed  */
#define TRACKD_TAG_ALLOC_FAIL     0x05u  /* NonPagedPoolNx alloc fail  */
#define TRACKD_TAG_SEH_FAULT      0x06u  /* __except caught fault      */

/* v5.0.1 - path type classifier result for the intercepted parent
 * enumeration key. Returned by TrackDClassifyParent; used by
 * TrackDHandlePostEnumerate to dispatch to the right synthesizer. */
typedef enum _TRACKD_PATH_TYPE {
    TRACKD_PATH_NONE           = 0,
    TRACKD_PATH_SCSI           = 1,
    TRACKD_PATH_PCI            = 2,
    TRACKD_PATH_USB_INSTANCE   = 3,
    TRACKD_PATH_HID_INSTANCE   = 4,
    TRACKD_PATH_AUDIO_RENDER   = 5,
    TRACKD_PATH_AUDIO_CAPTURE  = 6
} TRACKD_PATH_TYPE;

/* ================================================================
 *  v5.0.0 Track D globals (BSS-resident; retained for driver's
 *  lifetime). Hot path only reads them; the RegNtPreSetValueKey tap
 *  on our own Parameters and the PsSetCreateProcessNotifyRoutineEx
 *  callback are the only writers. All accesses to volatile fields
 *  use InterlockedExchangePointer / plain volatile read as noted.
 * ================================================================ */

static LARGE_INTEGER   g_TrackDCookie;
static BOOLEAN         g_TrackDRegistered   = FALSE;
static BOOLEAN         g_TrackDEnabled      = FALSE;

/* Seed bytes as they appear in Parameters\RegCallbackSeed
 * (32-char ASCII hex string, stored raw to feed the FNV mixer
 * verbatim). Length in bytes (0..64). Written once at DriverEntry
 * inside LoadTrackDConfig; never modified afterwards. */
static UCHAR           g_TrackDSeed[64];
static ULONG           g_TrackDSeedLen      = 0;

/* Callback-observable breadcrumb. volatile LONG so
 * InterlockedExchange can update without racing overlapping
 * callback invocations. */
static volatile LONG   g_TrackDLastStatus   = 0;

/* v5.0.4 instrumentation counters. Written on every callback invocation
 * (Invoke, post enable-gate, before name gate) or every image-name-miss
 * exit (NameMiss); persisted lazily by TrackDFlushWorker as REG_DWORDs
 * `CallbackInvokeCount` and `CallbackNameMissCount`. LastMissName is a
 * 16-byte buffer storing the most-recent image name that failed the
 * filter (raw first 15 bytes of EPROCESS ImageFileName, NUL-terminated).
 * Persisted as REG_SZ `LastMissImageName`. Purpose: with the Ps notify
 * path removed the filter runs blind against every process's registry
 * access; these three values let userland diagnose "why did zero
 * rewrites happen this boot" (invoke=0 vs. name_miss=all vs. invoke>0
 * + hit>0 as expected). Race on LastMissName buffer is acceptable for
 * a diagnostic - see TrackDRecordNameMiss comment. */
static volatile LONG   g_TrackDInvokeCount   = 0;
static volatile LONG   g_TrackDNameMissCount = 0;
static CHAR            g_TrackDLastMissName[16] = {0};

/* Cached UNICODE_STRING views over the string literals above,
 * initialized once in ArmTrackD via RtlInitUnicodeString. */
static UNICODE_STRING  g_TrackDAltitude;
static UNICODE_STRING  g_TrackDEnumSuffix;         /* \Enum\SCSI */
static UNICODE_STRING  g_TrackDSubkeyPrefix;       /* Disk&Ven_ */
static UNICODE_STRING  g_TrackDParamsSuffix;
/* v5.0.4: g_TrackDPidValueName removed - the Parameters\RubinOtPid tap
 * disappeared with the Ps notify + PID array subsystem. See v5.0.4
 * changelog block for the empirical driver for this refactor. */
/* v5.0.1 - additional path/value views */
static UNICODE_STRING  g_TrackDPciSuffix;          /* \Enum\PCI */
static UNICODE_STRING  g_TrackDPciChildPrefix;     /* VEN_ */
static UNICODE_STRING  g_TrackDMMDevRender;        /* \MMDevices\Audio\Render */
static UNICODE_STRING  g_TrackDMMDevCapture;       /* \MMDevices\Audio\Capture */
static UNICODE_STRING  g_TrackDEnableValueName;    /* EnableRegCallback */

/* Rewrite counter (incremented once per successful in-place mutation)
 * plus flush infrastructure. The Cm callback never opens registry
 * directly (would deadlock under CM-internal lock); instead it
 * updates g_TrackDLastStatus/g_TrackDHitCount atomically and (if not
 * already pending) queues g_TrackDFlushWorkItem to a delayed system
 * worker thread that runs at PASSIVE, outside the callback's context,
 * and safely persists both DWORDs to Parameters. */
static volatile LONG   g_TrackDHitCount    = 0;
static WORK_QUEUE_ITEM g_TrackDFlushWorkItem;
static volatile LONG   g_TrackDFlushQueued = 0;

/* Full NT path to our Parameters key, cached at DriverEntry for the
 * flusher's ZwOpenKey. g_TrackDParamsBuf backs the UNICODE_STRING. */
static UNICODE_STRING  g_TrackDParamsFullPath;
static WCHAR           g_TrackDParamsBuf[512];

/* ================================================================
 *  Device extension - attached to each filtered disk device.
 *  v3.6: no per-device state beyond what PnP correctness requires.
 *  v4.0.4: paging-path bookkeeping added — see DispatchPnp
 *  IRP_MN_DEVICE_USAGE_NOTIFICATION handler and AddDevice's
 *  DO_POWER_PAGABLE propagation for the rationale.
 * ================================================================ */
typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT  LowerDevice;
    PDEVICE_OBJECT  PhysicalDevice;
    IO_REMOVE_LOCK  RemoveLock;
    BOOLEAN         Started;
    BOOLEAN         Removed;
    /* v4.0.4: PagingPathCount counts the number of paging-type usages
     * currently active on this filter DO (paging, hibernation, dump
     * files). DO_POWER_PAGABLE on our DO is CLEARED while >0 and
     * RESTORED when it returns to 0. Guarded by PagingPathMutex to
     * serialize concurrent DEVICE_USAGE_NOTIFICATION IRPs. */
    LONG            PagingPathCount;
    FAST_MUTEX      PagingPathMutex;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

/* ================================================================
 *  CPU replay worker context - allocated in nonpaged pool by
 *  DriverEntry, freed by the worker itself after replay finishes.
 *  Owns a private copy of RegPath's buffer (IO manager's UNICODE_STRING
 *  is stack-scoped on the caller and must not outlive DriverEntry).
 * ================================================================ */
typedef struct _CPU_REPLAY_CTX {
    WORK_QUEUE_ITEM  WorkItem;
    UNICODE_STRING   RegPath;
    WCHAR            RegPathBuffer[1];  /* trailing flexible buffer  */
} CPU_REPLAY_CTX, *PCPU_REPLAY_CTX;

/* ================================================================
 *  Forward declarations
 * ================================================================ */
DRIVER_ADD_DEVICE AddDevice;

DRIVER_DISPATCH DispatchPassthrough;
DRIVER_DISPATCH DispatchPnp;
DRIVER_DISPATCH DispatchPower;

static IO_COMPLETION_ROUTINE PnpStartCompletion;
static IO_COMPLETION_ROUTINE PnpRemoveCompletion;

static VOID    ApplySmbiosBlobIfCached(PUNICODE_STRING RegPath);
static BOOLEAN ValidateSmbiosBlob(const UCHAR *Blob, ULONG Length);
static VOID    ReplayCpuRegistry(PUNICODE_STRING RegPath);
static VOID    CpuReplayWorker(PVOID Context);
static BOOLEAN IsCpuReplayEnabled(PUNICODE_STRING RegPath);
static VOID    WriteLastReplayStatus(HANDLE hParams, UCHAR tag, NTSTATUS st);

/* v5.0.0 Track D forward declarations */
static NTSTATUS ArmTrackD(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath);
static NTSTATUS LoadTrackDConfig(PUNICODE_STRING RegPath);
static VOID     WriteLastCallbackStatus(UCHAR tag, NTSTATUS st);
static VOID     TrackDFlushWorker(PVOID unused);
static ULONGLONG TrackDFnvHash64(const UCHAR *data, ULONG len);
static VOID     TrackDFillTokenFnv(WCHAR *outName, ULONG cursor, ULONG fieldLen,
                                   const WCHAR *realName, ULONG realStart,
                                   ULONG realFieldLen,
                                   const UCHAR *domain, ULONG domainLen);
static VOID     TrackDBuildSyntheticName(const WCHAR *realName, ULONG realWchars,
                                         WCHAR *outName);
/* v5.0.1 additional synthesizers + classifier + helpers */
static VOID     TrackDBuildSyntheticPciName(const WCHAR *realName, ULONG realWchars,
                                            WCHAR *outName);
static VOID     TrackDBuildSyntheticUsbHidInstance(const WCHAR *realName, ULONG realWchars,
                                                   WCHAR *outName);
static VOID     TrackDBuildSyntheticAudioGuid(const WCHAR *realName, ULONG realWchars,
                                              WCHAR *outName);
static BOOLEAN  TrackDStartsWithI(const WCHAR *text, ULONG textLen,
                                  const WCHAR *prefix, ULONG prefixLen);
static BOOLEAN  TrackDIsHexWchar(WCHAR c);
static BOOLEAN  TrackDMatchUsbHidInstanceParent(PCUNICODE_STRING parent,
                                                BOOLEAN wantUsb);
static TRACKD_PATH_TYPE TrackDClassifyParent(PCUNICODE_STRING parent);
/* v5.0.4: image-name filter + miss recorder + arm-status writer.
 * Replaces the v5.0.2 PID-array + Ps notify helpers (all removed). */
static BOOLEAN  TrackDCurrentCallerNameMatches(VOID);
static VOID     TrackDRecordNameMiss(VOID);
static VOID     WriteLastArmStatus(UCHAR tag, NTSTATUS st);
static NTSTATUS TrackDHandlePostEnumerate(PVOID Argument2);
static VOID     TrackDHandlePreSetValue(PVOID Argument2);
static NTSTATUS RstRegistryCallback(PVOID CallbackContext,
                                    PVOID Argument1,
                                    PVOID Argument2);

/* ================================================================
 *  WriteLastReplayStatus - v4.0.6 diagnostic breadcrumb.
 *
 *  Records the exit tag and NTSTATUS from ApplySmbiosBlobIfCached
 *  into <RegPath>\Parameters\LastReplayStatus (REG_DWORD, encoding
 *      code = (tag << 24) | (status & 0x00FFFFFF)
 *  ) so scripts/check-consistency.ps1 can decode and print WHERE
 *  the replay bailed on the previous boot — without a WinDbg attach.
 *
 *  Tag values (see v4.0.6 changelog):
 *      0x00 SUCCESS
 *      0x01 GATE-OFF               (EnableSmbiosReplay=0 or absent)
 *      0x02 NO-BLOB                (Parameters\SmbiosBlob missing/tiny)
 *      0x03 VALIDATION-FAIL        (ValidateSmbiosBlob rejected cached blob)
 *      0x04 MSSMBIOS-OPEN-FAIL     (ZwOpenKey on mssmbios\Data failed —
 *                                   expected on stock Windows because
 *                                   mssmbios is SYSTEM_START; see v4.0.6
 *                                   comment block)
 *      0x05 MSSMBIOS-WRITE-FAIL    (ZwSetValueKey on SMBiosData failed)
 *
 *  Best-effort: failure of the status write is ignored. Called ONLY
 *  when hParams is non-NULL (guarded at call sites) so we always have
 *  a KEY_SET_VALUE handle to the Parameters key.
 * ================================================================ */
static VOID WriteLastReplayStatus(HANDLE hParams, UCHAR tag, NTSTATUS st)
{
    /* v4.0.9: body RESTORED. Previous "revert" hypothesis (v4.0.7)
       thought BOOT_START ZwSetValueKey was the boot-breaker; bisection
       proved that wrong — the actual regression was the missing
       Authenticode signature. With signtool re-added to the build,
       this write is safe. See v4.0.9 changelog block above. */
    UNICODE_STRING valName;
    ULONG code;

    if (hParams == NULL) return;

    code = ((ULONG)tag << 24) | ((ULONG)st & 0x00FFFFFFUL);
    RtlInitUnicodeString(&valName, L"LastReplayStatus");
    (void)ZwSetValueKey(hParams, &valName, 0, REG_DWORD,
                        &code, sizeof(code));
}

/* ================================================================
 *  ValidateSmbiosBlob - sanity-check a cached SMBIOS blob before
 *  we splat it into mssmbios\Data\SMBiosData.
 *
 *  v3.4 addition. Before v3.4 the driver trusted whatever bytes
 *  userland had cached, and a corrupted / truncated blob could
 *  crash mssmbios or WMI providers on the next boot — with
 *  BOOT_START ordering that meant an unbootable box before any
 *  STOP screen could render (exactly the failure mode we hit).
 *
 *  Rules (loose but enough to catch real corruption):
 *    - Overall length between the raw-SMBIOS header (32 bytes) and
 *      64 KiB (mssmbios wraps its RSMB header around the raw table,
 *      so we're really validating what mssmbios stores, not the
 *      firmware EPS).
 *    - Walkable structure table starting at a small offset: each
 *      entry has Type/Length header, formatted section fits, string
 *      table ends with a lone null within bounds.
 *    - Type 127 (End-of-Table) reached before we run off the end.
 *
 *  Returns TRUE only when every structure parses cleanly.
 * ================================================================ */
static BOOLEAN ValidateSmbiosBlob(const UCHAR *Blob, ULONG Length)
{
    /* mssmbios prepends an 8-byte header describing the raw table
       size and version; the raw SMBIOS structure table follows. We
       search for the first plausible structure header instead of
       hard-coding the offset — the layout has drifted between
       Windows versions. */
    ULONG i;
    ULONG tableStart = 0;
    ULONG p;
    BOOLEAN sawEnd = FALSE;

    if (Blob == NULL) return FALSE;
    if (Length < 32) return FALSE;         /* too small to be real   */
    if (Length > 65536) return FALSE;      /* too big — reject       */

    /* Find first byte that looks like a Type 0/1/2/3 header with a
       reasonable Length (>=4, fits within Length). Scan the fixed
       64-byte window AFTER the 8-byte mssmbios wrapper. Uses `<=` on
       the fit test so a blob whose only header sits at exact end is
       still accepted.

       v4.0.10: scan now STARTS at i=8, not i=0. The mssmbios REG_BINARY
       layout begins with an 8-byte wrapper
           [Used21CallingMethod, MajVer, MinVer, DmiRev, RawSize DWORD LE]
       whose byte values collide with the "plausible Type 0/1/2/3
       header" heuristic. On Hyper-V (and typical modern Windows) the
       wrapper is 03 03 00 00 XX XX XX XX with DmiRev in {0,1,2,3},
       and Blob[4] = size_lo is always >= 4 for a non-empty raw table,
       so pre-v4.0.10 the scan false-matched at i=3, pinned tableStart
       into the wrapper, and the subsequent walk desynchronized before
       reaching Type 127 - producing spurious 0x0300003E VALIDATION-FAIL
       breadcrumbs on every arm of scripts/spoof-smbios.ps1. Starting
       at i=8 makes the scan land on the first real SMBIOS struct
       header (typically Type 0 BIOS Info) exactly where the raw table
       begins per the documented mssmbios layout. If Windows ever
       reshapes this wrapper, revisit here. */
    for (i = 8; i + 2 <= Length && i < 64; i++) {
        UCHAR t = Blob[i];
        UCHAR L = Blob[i + 1];
        if ((t == 0 || t == 1 || t == 2 || t == 3) &&
            L >= 4 && (ULONG)i + L <= Length)
        {
            tableStart = i;
            break;
        }
    }
    /* v4.0.10: with i starting at 8, tableStart==0 uniquely means the
       scan window [8,63] never matched any plausible SMBIOS struct
       header - genuinely malformed input, reject. The pre-v4.0.10
       "Blob[0]>127" side condition made sense only when the scan
       started at 0 (permissive fallback for weird pre-wrapper layouts)
       and is now nonsensical since tableStart is never 0 on a valid
       accept path. */
    if (tableStart == 0) return FALSE;

    /* Walk structures. Each iteration advances past the formatted
       area, then over the string table (sequence of NUL-terminated
       ASCII, ended by an empty string i.e. two NULs). */
    p = tableStart;
    while (p + 2 <= Length) {
        UCHAR type = Blob[p];
        UCHAR len  = Blob[p + 1];
        ULONG q;

        if (len < 4)                return FALSE;
        if ((ULONG)p + len > Length) return FALSE;

        q = p + len;   /* start of string table */

        /* End-of-table structure has no meaningful string table but
           still terminates with the double-NUL sentinel. */
        if (q >= Length) return FALSE;

        if (Blob[q] == 0) {
            /* Empty string table: just the double-NUL. */
            if (q + 1 >= Length) return FALSE;
            if (Blob[q + 1] != 0) return FALSE;
            p = q + 2;
        } else {
            /* Non-empty: scan for terminating empty string. */
            ULONG pos = q;
            BOOLEAN terminated = FALSE;
            while (pos < Length) {
                ULONG strEnd = pos;
                while (strEnd < Length && Blob[strEnd] != 0)
                    strEnd++;
                if (strEnd >= Length) return FALSE;
                if (strEnd == pos) {
                    /* empty string → end of table */
                    terminated = TRUE;
                    p = pos + 1;
                    break;
                }
                pos = strEnd + 1;
            }
            if (!terminated) return FALSE;
        }

        if (type == 127) {   /* End-of-Table */
            sawEnd = TRUE;
            break;
        }

        /* Bound structure count to avoid a pathological loop on a
           blob that keeps declaring more structures than actually
           fit — 512 is far above any realistic firmware. */
        if (p >= Length) return FALSE;
    }

    return sawEnd;
}

/* ================================================================
 *  ApplySmbiosBlobIfCached - replay a pre-computed SMBIOS blob
 *
 *  v3.4 semantics (breaking change vs v3.3):
 *    - Replay is OPT-IN. Userspace must set
 *        Parameters\EnableSmbiosReplay = 1  (REG_DWORD)
 *      after it has verified the blob round-trips through WMI on
 *      a live boot. Missing / zero = replay disabled, we return
 *      immediately. This closes the "cached blob from previous
 *      buggy run kills next boot" failure mode.
 *    - Cached blob is validated with ValidateSmbiosBlob() before
 *      we touch mssmbios\Data. Bad blob = ignored, no BSOD.
 *    - On first successful apply we snapshot the pre-replay
 *      SMBiosData into Parameters\OrigSmbiosData so
 *      09-recuperar-boot can restore genuine firmware SMBIOS from
 *      offline registry if we ever brick the box.
 *
 *  Failures never propagate. The driver's only remaining job (this
 *  function) failing simply leaves the firmware SMBIOS untouched;
 *  the driver still loads and its pass-through dispatch keeps disks
 *  working normally.
 * ================================================================ */
static VOID ApplySmbiosBlobIfCached(PUNICODE_STRING RegPath)
{
    NTSTATUS st;
    HANDLE   hParams   = NULL;
    HANDLE   hMssmbios = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING paramsPath, tail, valName, mssmbiosPath;
    WCHAR   paramsBuf[512];
    ULONG   needSize = 0;
    ULONG   allocSize;
    PKEY_VALUE_PARTIAL_INFORMATION info    = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION origInfo = NULL;
    UCHAR   flagBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION flagInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)flagBuf;
    ULONG   flagVal = 0;

    /* Defensive: IO manager should never pass a NULL/empty RegPath,
       but Driver Verifier fault injection and third-party service-
       manager wrappers can. SYSTEM_START + fault here = bootloop. */
    if (RegPath == NULL || RegPath->Buffer == NULL || RegPath->Length == 0)
        return;

    /* Build "<RegPath>\Parameters" */
    paramsPath.Buffer        = paramsBuf;
    paramsPath.Length        = 0;
    paramsPath.MaximumLength = sizeof(paramsBuf);

    st = RtlAppendUnicodeStringToString(&paramsPath, RegPath);
    if (!NT_SUCCESS(st)) return;

    RtlInitUnicodeString(&tail, L"\\Parameters");
    st = RtlAppendUnicodeStringToString(&paramsPath, &tail);
    if (!NT_SUCCESS(st)) return;

    InitializeObjectAttributes(&oa, &paramsPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    st = ZwOpenKey(&hParams, KEY_READ | KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(st)) return;

    /* --- Opt-in gate: EnableSmbiosReplay = 1 --- */
    RtlInitUnicodeString(&valName, L"EnableSmbiosReplay");
    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         flagInfo, sizeof(flagBuf), &needSize);
    if (!NT_SUCCESS(st) ||
        flagInfo->Type != REG_DWORD ||
        flagInfo->DataLength < sizeof(ULONG))
    {
#if DBG
        DbgPrint("[RstFlt] SMBIOS replay: opt-in flag absent, skipping\n");
#endif
        WriteLastReplayStatus(hParams, 0x01, st);   /* GATE-OFF (absent) */
        goto out;
    }
    RtlCopyMemory(&flagVal, flagInfo->Data, sizeof(ULONG));
    if (flagVal == 0) {
#if DBG
        DbgPrint("[RstFlt] SMBIOS replay: opt-in flag = 0, skipping\n");
#endif
        WriteLastReplayStatus(hParams, 0x01, STATUS_SUCCESS);  /* GATE-OFF (=0) */
        goto out;
    }

    /* Two-phase query: first learn size, then allocate + read. */
    RtlInitUnicodeString(&valName, L"SmbiosBlob");
    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         NULL, 0, &needSize);
    if (st != STATUS_BUFFER_TOO_SMALL &&
        st != STATUS_BUFFER_OVERFLOW) {
        WriteLastReplayStatus(hParams, 0x02, st);   /* NO-BLOB */
        goto out;                        /* no cached blob → nothing to do */
    }
    if (needSize < (ULONG)(FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + 32)) {
        WriteLastReplayStatus(hParams, 0x02, STATUS_BUFFER_TOO_SMALL);
        goto out;                        /* smaller than any real SMBIOS */
    }

    allocSize = needSize;
    info = (PKEY_VALUE_PARTIAL_INFORMATION)
           ExAllocatePoolWithTag(NonPagedPool, allocSize, POOL_TAG);
    if (info == NULL) {
        WriteLastReplayStatus(hParams, 0x02, STATUS_INSUFFICIENT_RESOURCES);
        goto out;
    }

    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         info, allocSize, &needSize);
    if (!NT_SUCCESS(st))          { WriteLastReplayStatus(hParams, 0x02, st); goto out; }
    if (info->Type != REG_BINARY) { WriteLastReplayStatus(hParams, 0x02, STATUS_OBJECT_TYPE_MISMATCH); goto out; }

    /* v3.4: validate before ever touching mssmbios */
    if (!ValidateSmbiosBlob(info->Data, info->DataLength)) {
#if DBG
        DbgPrint("[RstFlt] SMBIOS replay: cached blob failed validation "
                 "(%lu bytes) — ignored\n", info->DataLength);
#endif
        WriteLastReplayStatus(hParams, 0x03, STATUS_DATA_ERROR);  /* VALIDATION-FAIL */
        goto out;
    }

    /* Open mssmbios\Data. Kernel handle bypasses ACL — the userland
       equivalent has to do a whole take-ownership dance. */
    RtlInitUnicodeString(&mssmbiosPath,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data");
    InitializeObjectAttributes(&oa, &mssmbiosPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    st = ZwOpenKey(&hMssmbios, KEY_QUERY_VALUE | KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(st)) {
#if DBG
        DbgPrint("[RstFlt] SMBIOS replay: open mssmbios failed 0x%08X\n", st);
#endif
        /* v4.0.6: EXPECTED on stock Windows — mssmbios is SYSTEM_START,
           loads AFTER us; Data subkey doesn't exist yet. See v4.0.6
           changelog comment block. */
        WriteLastReplayStatus(hParams, 0x04, st);   /* MSSMBIOS-OPEN-FAIL */
        goto out;
    }

    /* --- v3.4: snapshot the current SMBiosData to OrigSmbiosData
       (only on first apply, so we don't overwrite the genuine
       firmware copy with a previously-replayed one). --- */
    {
        UNICODE_STRING origName;
        ULONG origNeed = 0;

        RtlInitUnicodeString(&origName, L"OrigSmbiosData");
        st = ZwQueryValueKey(hParams, &origName, KeyValuePartialInformation,
                             NULL, 0, &origNeed);
        if (st == STATUS_OBJECT_NAME_NOT_FOUND) {
            /* No backup yet — read current mssmbios data and store. */
            UNICODE_STRING curName;
            ULONG curNeed = 0;

            RtlInitUnicodeString(&curName, L"SMBiosData");
            st = ZwQueryValueKey(hMssmbios, &curName,
                                 KeyValuePartialInformation,
                                 NULL, 0, &curNeed);
            if ((st == STATUS_BUFFER_TOO_SMALL ||
                 st == STATUS_BUFFER_OVERFLOW) &&
                curNeed > (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data))
            {
                origInfo = (PKEY_VALUE_PARTIAL_INFORMATION)
                    ExAllocatePoolWithTag(NonPagedPool, curNeed, POOL_TAG);
                if (origInfo) {
                    st = ZwQueryValueKey(hMssmbios, &curName,
                                         KeyValuePartialInformation,
                                         origInfo, curNeed, &curNeed);
                    if (NT_SUCCESS(st) &&
                        origInfo->Type == REG_BINARY &&
                        origInfo->DataLength > 0)
                    {
                        ZwSetValueKey(hParams, &origName, 0, REG_BINARY,
                                      origInfo->Data,
                                      origInfo->DataLength);
#if DBG
                        DbgPrint("[RstFlt] SMBIOS replay: backed up %lu "
                                 "bytes to OrigSmbiosData\n",
                                 origInfo->DataLength);
#endif
                    }
                }
            }
        }
    }

    RtlInitUnicodeString(&valName, L"SMBiosData");
    st = ZwSetValueKey(hMssmbios, &valName, 0, REG_BINARY,
                       info->Data, info->DataLength);
#if DBG
    DbgPrint("[RstFlt] SMBIOS replay: wrote %lu bytes, status=0x%08X\n",
             info->DataLength, st);
#endif
    /* v4.0.6: breadcrumb — 0x00 SUCCESS if write landed, 0x05 otherwise.
       Reminder: per Bug 3 postmortem, "SUCCESS" here means only that
       the registry write went through, NOT that WMI sees the spoof —
       WMI serves from mssmbios's in-kernel firmware cache which we
       cannot reach from this driver. Real WMI spoof lives in v4.1. */
    if (NT_SUCCESS(st))
        WriteLastReplayStatus(hParams, 0x00, STATUS_SUCCESS);   /* SUCCESS */
    else
        WriteLastReplayStatus(hParams, 0x05, st);               /* MSSMBIOS-WRITE-FAIL */

out:
    if (info)      ExFreePoolWithTag(info, POOL_TAG);
    if (origInfo)  ExFreePoolWithTag(origInfo, POOL_TAG);
    if (hMssmbios) ZwClose(hMssmbios);
    if (hParams)   ZwClose(hParams);
}

/* ================================================================
 *  ReplayCpuRegistry - Track A / v4.0 core routine.
 *
 *  Rewrites three per-core REG_SZ values under
 *      \Registry\Machine\HARDWARE\DESCRIPTION\System\CentralProcessor\<N>
 *  on every logical processor, from a REG_MULTI_SZ cached by userspace
 *  at
 *      <RegPath>\Parameters\CpuStrings
 *  Layout — three consecutive NUL-terminated wide strings then a
 *  final double-NUL sentinel, order fixed:
 *      [0] ProcessorNameString  (cap CPU_NAME_MAX_WCHARS wchars)
 *      [1] Identifier           (cap CPU_IDENT_MAX_WCHARS wchars)
 *      [2] VendorIdentifier     (cap CPU_VENDOR_MAX_WCHARS wchars)
 *
 *  Opt-in gate: Parameters\EnableCpuReplay (REG_DWORD, default 0),
 *  identical shape to EnableSmbiosReplay. Missing or zero -> return.
 *
 *  Backup: on first successful open of CentralProcessor\0, if
 *  Parameters\OrigCpuStrings does not exist, snapshot the current
 *  ProcessorNameString/Identifier/VendorIdentifier there as a
 *  REG_MULTI_SZ so 09-recuperar-boot can restore genuine values.
 *
 *  Race with HAL: HARDWARE\DESCRIPTION\System is a volatile hive
 *  rebuilt every boot. HAL creates the CentralProcessor root very
 *  early but populates each per-CPU subkey and each value inside
 *  those subkeys asynchronously as APs come online. We
 *    (a) wait until ZwQueryKey(hCpuRoot).SubKeys reaches the value
 *        reported by KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS),
 *    (b) before every ZwSetValueKey, probe the target value with
 *        ZwQueryValueKey: if it is not yet present (STATUS_OBJECT_
 *        NAME_NOT_FOUND) we skip that core this pass, mark it, and
 *        try again on the next 100ms tick. Once the value exists we
 *        overwrite it — we are the last writer, so HAL cannot clobber
 *        us afterwards.
 *  Overall budget CPU_REPLAY_MAX_PASSES * CPU_REPLAY_DELAY_MS ms.
 *
 *  Runs on a system worker thread (via CpuReplayWorker) so this whole
 *  loop never blocks DriverEntry or downstream SYSTEM_START drivers.
 *  All failures are silent; never bugchecks.
 * ================================================================ */
static VOID ReplayCpuRegistry(PUNICODE_STRING RegPath)
{
    NTSTATUS st;
    HANDLE   hParams   = NULL;
    HANDLE   hCpuRoot  = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING paramsPath, tail, valName, cpuRootPath;
    WCHAR    paramsBuf[512];
    ULONG    needSize = 0;
    ULONG    allocSize;
    PKEY_VALUE_PARTIAL_INFORMATION info      = NULL;
    UCHAR    flagBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION flagInfo  =
        (PKEY_VALUE_PARTIAL_INFORMATION)flagBuf;
    ULONG    flagVal   = 0;
    PWCHAR   strs[3];
    ULONG    strLens[3];
    ULONG    walkIdx;
    ULONG    foundCount;
    PWCHAR   cursor;
    PWCHAR   limit;
    ULONG    expected;
    ULONG    pass;
    ULONG    keyInfoNeed = 0;
    UCHAR    keyInfoBuf[sizeof(KEY_FULL_INFORMATION) + 64];
    PKEY_FULL_INFORMATION keyInfo = (PKEY_FULL_INFORMATION)keyInfoBuf;
    LARGE_INTEGER delay;
    ULONG    subIndex;
    UCHAR    subBuf[sizeof(KEY_BASIC_INFORMATION) + 256 * sizeof(WCHAR)];
    PKEY_BASIC_INFORMATION subInfo = (PKEY_BASIC_INFORMATION)subBuf;
    ULONG    coresDone;
    ULONG    coresPending;
    BOOLEAN  backupChecked = FALSE;

    /* Same NULL/empty guard as ApplySmbiosBlobIfCached — the two
       functions share the RegPath supplied by IO manager (copied
       into the worker context). */
    if (RegPath == NULL || RegPath->Buffer == NULL || RegPath->Length == 0)
        return;

    /* Build "<RegPath>\Parameters" */
    paramsPath.Buffer        = paramsBuf;
    paramsPath.Length        = 0;
    paramsPath.MaximumLength = sizeof(paramsBuf);

    st = RtlAppendUnicodeStringToString(&paramsPath, RegPath);
    if (!NT_SUCCESS(st)) return;

    RtlInitUnicodeString(&tail, L"\\Parameters");
    st = RtlAppendUnicodeStringToString(&paramsPath, &tail);
    if (!NT_SUCCESS(st)) return;

    InitializeObjectAttributes(&oa, &paramsPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    st = ZwOpenKey(&hParams, KEY_READ | KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(st)) return;

    /* --- Opt-in gate: EnableCpuReplay = 1 --- */
    RtlInitUnicodeString(&valName, L"EnableCpuReplay");
    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         flagInfo, sizeof(flagBuf), &needSize);
    if (!NT_SUCCESS(st) ||
        flagInfo->Type != REG_DWORD ||
        flagInfo->DataLength < sizeof(ULONG))
    {
#if DBG
        DbgPrint("[RstFlt] CPU replay: opt-in flag absent, skipping\n");
#endif
        goto out;
    }
    RtlCopyMemory(&flagVal, flagInfo->Data, sizeof(ULONG));
    if (flagVal == 0) {
#if DBG
        DbgPrint("[RstFlt] CPU replay: opt-in flag = 0, skipping\n");
#endif
        goto out;
    }

    /* Two-phase query for CpuStrings. */
    RtlInitUnicodeString(&valName, L"CpuStrings");
    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         NULL, 0, &needSize);
    if (st != STATUS_BUFFER_TOO_SMALL &&
        st != STATUS_BUFFER_OVERFLOW)
    {
#if DBG
        DbgPrint("[RstFlt] CPU replay: CpuStrings absent, skipping\n");
#endif
        goto out;
    }
    if (needSize < (ULONG)(FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) +
                           3 * sizeof(WCHAR)))
        goto out;

    allocSize = needSize;
    info = (PKEY_VALUE_PARTIAL_INFORMATION)
           ExAllocatePoolWithTag(NonPagedPool, allocSize, POOL_TAG);
    if (info == NULL) goto out;

    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         info, allocSize, &needSize);
    if (!NT_SUCCESS(st))              goto out;
    if (info->Type != REG_MULTI_SZ)   goto out;
    if (info->DataLength < 3 * sizeof(WCHAR)) goto out;

    /* Reject odd byte length up front — WCHAR-alignment invariant. */
    if (info->DataLength & 1) {
#if DBG
        DbgPrint("[RstFlt] CPU replay: CpuStrings odd DataLength, ignored\n");
#endif
        goto out;
    }

    /* Walk the MULTI_SZ, capture pointers/lengths for the first three
       non-empty strings. Bounds use a wchar-typed limit so odd-length
       cases (rejected above but belt-and-braces) cannot step past the
       nominal allocation. */
    for (walkIdx = 0; walkIdx < 3; walkIdx++) {
        strs[walkIdx]    = NULL;
        strLens[walkIdx] = 0;
    }
    foundCount = 0;
    cursor = (PWCHAR)info->Data;
    limit  = (PWCHAR)info->Data + (info->DataLength / sizeof(WCHAR));

    while (cursor < limit && foundCount < 3) {
        PWCHAR scan = cursor;
        ULONG  wideLen = 0;

        while (scan < limit && *scan != L'\0') {
            scan++;
            wideLen++;
        }
        if (scan >= limit) break;     /* no terminator inside bounds  */
        if (wideLen == 0) break;      /* empty string — end of table  */

        strs[foundCount]    = cursor;
        strLens[foundCount] = wideLen;
        foundCount++;
        cursor = scan + 1;            /* skip past NUL                */
    }

    if (foundCount < 3) {
#if DBG
        DbgPrint("[RstFlt] CPU replay: CpuStrings has %lu strings, "
                 "need 3 — skipping\n", foundCount);
#endif
        goto out;
    }

    /* Per-string caps: reject the whole blob if any string overruns
       the realistic upper bound (128/64/16 wchars respectively).
       Downstream WMI/session-mgr readers commonly assume 260-char
       buffers, and a 32k ProcessorNameString on every core is a
       reliable way to crash them at SYSTEM_START. */
    if (strLens[0] > CPU_NAME_MAX_WCHARS   ||
        strLens[1] > CPU_IDENT_MAX_WCHARS  ||
        strLens[2] > CPU_VENDOR_MAX_WCHARS)
    {
#if DBG
        DbgPrint("[RstFlt] CPU replay: CpuStrings too long "
                 "(%lu/%lu/%lu wchars) — skipping\n",
                 strLens[0], strLens[1], strLens[2]);
#endif
        goto out;
    }

    /* CentralProcessor root path — volatile hive, no on-disk I/O. */
    RtlInitUnicodeString(&cpuRootPath,
        L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor");

    /* Expected logical-CPU count from the kernel scheduler. Zero
       return would be pathological; treat it as "give up". */
    expected = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (expected == 0) {
#if DBG
        DbgPrint("[RstFlt] CPU replay: KeQueryActiveProcessorCountEx=0, "
                 "skipping\n");
#endif
        goto out;
    }

    /* Track which cores still need at least one value written. We
       don't know the max subkey index until we enumerate, so we
       count coresDone against `expected` and re-enter the pass loop
       until every core is done or the budget expires. */
    coresDone = 0;

    for (pass = 0; pass < CPU_REPLAY_MAX_PASSES; pass++) {

        /* Reset per-pass root handle up front — defensive against
           Verifier fault-injection paths that don't clear the OUT
           handle on failure. */
        hCpuRoot = NULL;

        InitializeObjectAttributes(&oa, &cpuRootPath,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL, NULL);
        st = ZwOpenKey(&hCpuRoot,
                       KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                       &oa);
        if (!NT_SUCCESS(st)) {
            if (st == STATUS_OBJECT_NAME_NOT_FOUND) {
                /* HAL has not published the root yet — wait and retry. */
                delay.QuadPart =
                    -(LONGLONG)(CPU_REPLAY_DELAY_MS * 10 * 1000);
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
                continue;
            }
#if DBG
            DbgPrint("[RstFlt] CPU replay: open CentralProcessor "
                     "failed 0x%08X\n", st);
#endif
            goto out;
        }

        /* Wait for HAL to publish every per-CPU subkey. */
        st = ZwQueryKey(hCpuRoot, KeyFullInformation,
                        keyInfo, sizeof(keyInfoBuf), &keyInfoNeed);
        if (!NT_SUCCESS(st)) {
#if DBG
            DbgPrint("[RstFlt] CPU replay: ZwQueryKey failed 0x%08X\n", st);
#endif
            ZwClose(hCpuRoot);
            hCpuRoot = NULL;
            goto out;
        }

        if (keyInfo->SubKeys < expected) {
            /* Not all APs have come online yet. Close and retry. */
            ZwClose(hCpuRoot);
            hCpuRoot = NULL;
            delay.QuadPart =
                -(LONGLONG)(CPU_REPLAY_DELAY_MS * 10 * 1000);
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            continue;
        }

        /* Enumerate every subkey. For each one, per-value pre-check
           against HAL race: only overwrite values HAL has already
           populated. Count cores fully written this pass; if any
           remain pending, retry after a delay. */
        coresDone    = 0;
        coresPending = 0;
        subIndex     = 0;

        for (;;) {
            HANDLE hCpu = NULL;
            UNICODE_STRING subName;
            OBJECT_ATTRIBUTES subOa;
            UNICODE_STRING vProcName, vIdent, vVendor;
            ULONG resultLen  = 0;
            ULONG probeNeed  = 0;
            NTSTATUS probeSt;
            BOOLEAN valuesReady = TRUE;

            st = ZwEnumerateKey(hCpuRoot, subIndex, KeyBasicInformation,
                                subInfo, sizeof(subBuf), &resultLen);
            if (st == STATUS_NO_MORE_ENTRIES) break;
            if (st == STATUS_BUFFER_OVERFLOW ||
                st == STATUS_BUFFER_TOO_SMALL)
            {
                /* Oversized subkey name — skip past it, keep going. */
#if DBG
                DbgPrint("[RstFlt] CPU replay: enum idx=%lu oversized, "
                         "skipping\n", subIndex);
#endif
                subIndex++;
                continue;
            }
            if (!NT_SUCCESS(st)) {
#if DBG
                DbgPrint("[RstFlt] CPU replay: enum idx=%lu failed 0x%08X\n",
                         subIndex, st);
#endif
                break;
            }

            subName.Buffer        = subInfo->Name;
            subName.Length        = (USHORT)subInfo->NameLength;
            subName.MaximumLength = (USHORT)subInfo->NameLength;

            InitializeObjectAttributes(&subOa, &subName,
                                       OBJ_CASE_INSENSITIVE |
                                       OBJ_KERNEL_HANDLE,
                                       hCpuRoot, NULL);
            st = ZwOpenKey(&hCpu, KEY_QUERY_VALUE | KEY_SET_VALUE, &subOa);
            if (!NT_SUCCESS(st)) {
#if DBG
                DbgPrint("[RstFlt] CPU replay: open subkey idx=%lu "
                         "failed 0x%08X\n", subIndex, st);
#endif
                subIndex++;
                continue;
            }

            /* One-shot backup on the FIRST subkey we can open with
               all three values present. Only cores past the HAL race
               are legitimate sources of "genuine" values.
               Post-verify fix (N1): backupChecked is set AFTER the
               successful ZwSetValueKey below, not on entry — so a
               core still mid-population on this pass does not consume
               the one-shot; the next pass / next subkey retries. */
            if (!backupChecked) {
                UNICODE_STRING origName;
                ULONG origNeed = 0;

                RtlInitUnicodeString(&origName, L"OrigCpuStrings");
                probeSt = ZwQueryValueKey(hParams, &origName,
                                          KeyValuePartialInformation,
                                          NULL, 0, &origNeed);
                if (probeSt == STATUS_OBJECT_NAME_NOT_FOUND) {
                    /* Read current name/ident/vendor from THIS core.
                       Skip backup if any value is not yet present —
                       we'll try again next pass on the next subkey. */
                    UNICODE_STRING nName, iName, vName2;
                    PKEY_VALUE_PARTIAL_INFORMATION nInfo = NULL;
                    PKEY_VALUE_PARTIAL_INFORMATION iInfo = NULL;
                    PKEY_VALUE_PARTIAL_INFORMATION vInfo = NULL;
                    ULONG nNeed = 0, iNeed = 0, vNeed = 0;
                    NTSTATUS nSt, iSt, vSt;

                    RtlInitUnicodeString(&nName, L"ProcessorNameString");
                    RtlInitUnicodeString(&iName, L"Identifier");
                    RtlInitUnicodeString(&vName2, L"VendorIdentifier");

                    nSt = ZwQueryValueKey(hCpu, &nName,
                                          KeyValuePartialInformation,
                                          NULL, 0, &nNeed);
                    iSt = ZwQueryValueKey(hCpu, &iName,
                                          KeyValuePartialInformation,
                                          NULL, 0, &iNeed);
                    vSt = ZwQueryValueKey(hCpu, &vName2,
                                          KeyValuePartialInformation,
                                          NULL, 0, &vNeed);

                    if ((nSt == STATUS_BUFFER_TOO_SMALL ||
                         nSt == STATUS_BUFFER_OVERFLOW) &&
                        (iSt == STATUS_BUFFER_TOO_SMALL ||
                         iSt == STATUS_BUFFER_OVERFLOW) &&
                        (vSt == STATUS_BUFFER_TOO_SMALL ||
                         vSt == STATUS_BUFFER_OVERFLOW))
                    {
                        nInfo = (PKEY_VALUE_PARTIAL_INFORMATION)
                            ExAllocatePoolWithTag(NonPagedPool,
                                                  nNeed, POOL_TAG);
                        iInfo = (PKEY_VALUE_PARTIAL_INFORMATION)
                            ExAllocatePoolWithTag(NonPagedPool,
                                                  iNeed, POOL_TAG);
                        vInfo = (PKEY_VALUE_PARTIAL_INFORMATION)
                            ExAllocatePoolWithTag(NonPagedPool,
                                                  vNeed, POOL_TAG);

                        if (nInfo && iInfo && vInfo) {
                            nSt = ZwQueryValueKey(hCpu, &nName,
                                    KeyValuePartialInformation,
                                    nInfo, nNeed, &nNeed);
                            iSt = ZwQueryValueKey(hCpu, &iName,
                                    KeyValuePartialInformation,
                                    iInfo, iNeed, &iNeed);
                            vSt = ZwQueryValueKey(hCpu, &vName2,
                                    KeyValuePartialInformation,
                                    vInfo, vNeed, &vNeed);

                            if (NT_SUCCESS(nSt) && NT_SUCCESS(iSt) &&
                                NT_SUCCESS(vSt) &&
                                nInfo->Type == REG_SZ &&
                                iInfo->Type == REG_SZ &&
                                vInfo->Type == REG_SZ)
                            {
                                /* Assemble a MULTI_SZ:
                                   name\0ident\0vendor\0\0
                                   We assume the source values are
                                   NUL-terminated as REG_SZ from HAL. */
                                ULONG nBytes = nInfo->DataLength;
                                ULONG iBytes = iInfo->DataLength;
                                ULONG vBytes = vInfo->DataLength;
                                ULONG totalBytes;
                                PUCHAR blob;

                                /* Ensure each has its own terminator;
                                   if not, pad. */
                                if (nBytes < sizeof(WCHAR)) nBytes = 0;
                                if (iBytes < sizeof(WCHAR)) iBytes = 0;
                                if (vBytes < sizeof(WCHAR)) vBytes = 0;

                                totalBytes = nBytes + iBytes + vBytes +
                                             sizeof(WCHAR); /* final NUL */

                                blob = (PUCHAR)ExAllocatePoolWithTag(
                                        NonPagedPool, totalBytes,
                                        POOL_TAG);
                                if (blob) {
                                    ULONG off = 0;
                                    if (nBytes) {
                                        RtlCopyMemory(blob + off,
                                                      nInfo->Data,
                                                      nBytes);
                                        off += nBytes;
                                    }
                                    if (iBytes) {
                                        RtlCopyMemory(blob + off,
                                                      iInfo->Data,
                                                      iBytes);
                                        off += iBytes;
                                    }
                                    if (vBytes) {
                                        RtlCopyMemory(blob + off,
                                                      vInfo->Data,
                                                      vBytes);
                                        off += vBytes;
                                    }
                                    /* trailing double-NUL sentinel:
                                       previous string's NUL + one more */
                                    blob[off]     = 0;
                                    blob[off + 1] = 0;

                                    {
                                        NTSTATUS bkSt;
                                        bkSt = ZwSetValueKey(hParams,
                                                    &origName, 0,
                                                    REG_MULTI_SZ,
                                                    blob,
                                                    (ULONG)totalBytes);
                                        if (NT_SUCCESS(bkSt)) {
                                            backupChecked = TRUE;
#if DBG
                                            DbgPrint("[RstFlt] CPU "
                                                "replay: backed up %lu "
                                                "bytes to "
                                                "OrigCpuStrings\n",
                                                totalBytes);
#endif
                                        }
                                    }
                                    ExFreePoolWithTag(blob, POOL_TAG);
                                }
                            }
                        }

                        if (nInfo) ExFreePoolWithTag(nInfo, POOL_TAG);
                        if (iInfo) ExFreePoolWithTag(iInfo, POOL_TAG);
                        if (vInfo) ExFreePoolWithTag(vInfo, POOL_TAG);
                    }
                }
            }

            /* Per-value pre-check: only overwrite what HAL has
               already published on this core. If any of the three
               is absent, treat this core as not-ready for this pass. */
            RtlInitUnicodeString(&vProcName, L"ProcessorNameString");
            RtlInitUnicodeString(&vIdent,    L"Identifier");
            RtlInitUnicodeString(&vVendor,   L"VendorIdentifier");

            probeSt = ZwQueryValueKey(hCpu, &vProcName,
                                      KeyValuePartialInformation,
                                      NULL, 0, &probeNeed);
            if (probeSt == STATUS_OBJECT_NAME_NOT_FOUND)
                valuesReady = FALSE;

            if (valuesReady) {
                probeSt = ZwQueryValueKey(hCpu, &vIdent,
                                          KeyValuePartialInformation,
                                          NULL, 0, &probeNeed);
                if (probeSt == STATUS_OBJECT_NAME_NOT_FOUND)
                    valuesReady = FALSE;
            }
            if (valuesReady) {
                probeSt = ZwQueryValueKey(hCpu, &vVendor,
                                          KeyValuePartialInformation,
                                          NULL, 0, &probeNeed);
                if (probeSt == STATUS_OBJECT_NAME_NOT_FOUND)
                    valuesReady = FALSE;
            }

            if (!valuesReady) {
                coresPending++;
                ZwClose(hCpu);
                subIndex++;
                continue;
            }

            /* HAL has published all three values on this core.
               Overwrite them — we are the last writer for each.
               DataSize argument cast to ULONG explicitly to keep
               WDK /W4 /WX quiet on x64. */
            ZwSetValueKey(hCpu, &vProcName, 0, REG_SZ,
                          (PVOID)strs[0],
                          (ULONG)((strLens[0] + 1) * sizeof(WCHAR)));

            ZwSetValueKey(hCpu, &vIdent, 0, REG_SZ,
                          (PVOID)strs[1],
                          (ULONG)((strLens[1] + 1) * sizeof(WCHAR)));

            ZwSetValueKey(hCpu, &vVendor, 0, REG_SZ,
                          (PVOID)strs[2],
                          (ULONG)((strLens[2] + 1) * sizeof(WCHAR)));

#if DBG
            DbgPrint("[RstFlt] CPU replay: rewrote CentralProcessor\\%wZ\n",
                     &subName);
#endif
            coresDone++;
            ZwClose(hCpu);
            subIndex++;
        }

        ZwClose(hCpuRoot);
        hCpuRoot = NULL;

        if (coresPending == 0) {
            /* Every enumerable core is done. */
#if DBG
            DbgPrint("[RstFlt] CPU replay: pass %lu, %lu core(s) done, "
                     "no pending\n", pass, coresDone);
#endif
            break;
        }

#if DBG
        DbgPrint("[RstFlt] CPU replay: pass %lu, %lu done, %lu pending, "
                 "waiting %ums\n",
                 pass, coresDone, coresPending, CPU_REPLAY_DELAY_MS);
#endif
        delay.QuadPart = -(LONGLONG)(CPU_REPLAY_DELAY_MS * 10 * 1000);
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

#if DBG
    DbgPrint("[RstFlt] CPU replay: finished, %lu core(s) written\n",
             coresDone);
#endif

out:
    if (info)     ExFreePoolWithTag(info, POOL_TAG);
    if (hCpuRoot) ZwClose(hCpuRoot);
    if (hParams)  ZwClose(hParams);
}

/* ================================================================
 *  IsCpuReplayEnabled - early opt-in gate check for DriverEntry.
 *
 *  v4.0.1 hotfix: previously the worker queue was unconditional in
 *  DriverEntry and only ReplayCpuRegistry (inside the worker) read
 *  EnableCpuReplay. That configuration froze boot on physical
 *  hardware even with the gate = 0, because the worker's very act
 *  of being scheduled + starting to run at SYSTEM_START interacted
 *  badly with the boot sequence (no BSOD, no dump, just hang —
 *  ruling out pool/IRQL/deadlock via Verifier /standard).
 *
 *  Fix: read the gate HERE, before we allocate the ctx or queue the
 *  work item. If the flag is absent or zero, DriverEntry does not
 *  touch the worker path at all — the driver becomes functionally
 *  equivalent to v3.6 (SMBIOS-only) on this boot, matching a proven
 *  stable configuration.
 *
 *  Any failure to open Parameters or read the value is treated as
 *  "gate off" — conservative. Returns TRUE only when we successfully
 *  read a REG_DWORD value equal to 1.
 * ================================================================ */
static BOOLEAN IsCpuReplayEnabled(PUNICODE_STRING RegPath)
{
    NTSTATUS st;
    HANDLE   hParams = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING paramsPath, tail, valName;
    WCHAR    paramsBuf[512];
    ULONG    needSize = 0;
    UCHAR    flagBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION flagInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)flagBuf;
    ULONG    flagVal = 0;
    BOOLEAN  enabled = FALSE;

    if (RegPath == NULL || RegPath->Buffer == NULL || RegPath->Length == 0)
        return FALSE;

    /* Build "<RegPath>\Parameters" */
    paramsPath.Buffer        = paramsBuf;
    paramsPath.Length        = 0;
    paramsPath.MaximumLength = sizeof(paramsBuf);

    st = RtlAppendUnicodeStringToString(&paramsPath, RegPath);
    if (!NT_SUCCESS(st)) return FALSE;

    RtlInitUnicodeString(&tail, L"\\Parameters");
    st = RtlAppendUnicodeStringToString(&paramsPath, &tail);
    if (!NT_SUCCESS(st)) return FALSE;

    InitializeObjectAttributes(&oa, &paramsPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    st = ZwOpenKey(&hParams, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) return FALSE;

    RtlInitUnicodeString(&valName, L"EnableCpuReplay");
    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         flagInfo, sizeof(flagBuf), &needSize);
    if (NT_SUCCESS(st) &&
        flagInfo->Type == REG_DWORD &&
        flagInfo->DataLength >= sizeof(ULONG))
    {
        RtlCopyMemory(&flagVal, flagInfo->Data, sizeof(ULONG));
        if (flagVal == 1) {
            enabled = TRUE;
        }
    }

    ZwClose(hParams);
    return enabled;
}

/* ================================================================
 *  CpuReplayWorker - system worker thread entry point.
 *
 *  Runs at PASSIVE_LEVEL, off DriverEntry's thread. Consumes the
 *  CPU_REPLAY_CTX allocated by DriverEntry (owning RegPath copy),
 *  invokes ReplayCpuRegistry, then frees itself.
 *
 *  Must never touch the DRIVER_OBJECT or the IO manager's original
 *  RegPath — both may be out of scope by the time we run. Our
 *  UNICODE_STRING inside the context is self-contained.
 * ================================================================ */
static VOID CpuReplayWorker(PVOID Context)
{
    PCPU_REPLAY_CTX ctx = (PCPU_REPLAY_CTX)Context;

    if (ctx == NULL) return;

    ReplayCpuRegistry(&ctx->RegPath);

    ExFreePoolWithTag(ctx, POOL_TAG);
}

/* ================================================================
 *  v5.0.0 Track D - implementation
 *
 *  Layered so each helper has a single responsibility:
 *    TrackDFnvHash64            - deterministic 64-bit hash primitive
 *    TrackDFillTokenFnv         - fill a WCHAR field with FNV-derived
 *                                 hex; called for Ven/Prod/Rev tokens
 *    TrackDBuildSyntheticName   - rewrite Disk&Ven_/Prod_/Rev_ tokens
 *                                 in place, same wchar count
 *    TrackDCurrentCallerNameMatches - v5.0.4: does
 *                                 PsGetProcessImageFileName(current)
 *                                 begin with "rubinot"? Replaces the
 *                                 removed PID-array gate.
 *    TrackDRecordNameMiss       - v5.0.4: snapshot rejected image
 *                                 name into g_TrackDLastMissName and
 *                                 bump miss counter (diagnostic).
 *    TrackDHandlePostEnumerate  - RegNtPostEnumerateKey body: match
 *                                 parent path suffix + child prefix,
 *                                 SEH-wrap the buffer mutate
 *    TrackDHandlePreSetValue    - RegNtPreSetValueKey tap on our own
 *                                 Parameters\EnableRegCallback
 *    RstRegistryCallback        - Cm dispatch by REG_NOTIFY_CLASS
 *    TrackDFlushWorker          - one-shot worker that flushes the
 *                                 in-memory breadcrumb to Parameters
 *    WriteLastCallbackStatus    - callback-safe wrapper: interlocked
 *                                 update + guarded work item queue
 *    LoadTrackDConfig           - one-time Parameters read at
 *                                 DriverEntry (safe context)
 *    ArmTrackD                  - register Cm + Ps callbacks; called
 *                                 from DriverEntry after existing
 *                                 SMBIOS/CPU wiring
 *
 *  Reentrancy contract:
 *    - Callback body (RstRegistryCallback and children) NEVER calls
 *      any Zw* registry primitive. All persisted state either lives
 *      in file-scope globals updated by the Parameters tap, or is
 *      deferred to TrackDFlushWorker (which runs OUTSIDE the CM
 *      callback stack via the delayed system worker queue).
 *    - PatchGuard: CmRegisterCallbackEx is a Microsoft-supported
 *      extensibility API, distinct from the rejected
 *      DriverObject->MajorFunction[] swap (see
 *      docs/roadmap-v41-wmi-intercept.md Option C).
 * ================================================================ */

/* FNV-1a-64 mixing primitive. Same algorithm and constants as
 * scripts/spoof-pci-hardwareid.ps1 Get-Fnv1a64Hash — any userland
 * port can reproduce this kernel's synthetic names byte-for-byte
 * given the same seed and input.
 *
 * C89 unsigned long long naturally wraps at 2^64, matching the
 * PS BigInteger `-band $mask` explicit mask. */
static ULONGLONG TrackDFnvHash64(const UCHAR *data, ULONG len)
{
    ULONGLONG h = TRACKD_FNV_OFFSET_BASIS;
    ULONG i;
    for (i = 0; i < len; i++) {
        h ^= (ULONGLONG)data[i];
        h = h * TRACKD_FNV_PRIME;
    }
    return h;
}

/* Fill a WCHAR field of `fieldLen` wchars starting at outName[cursor]
 * with hex characters derived from FNV over
 *     <domain> + <seedBytes> + '|' + <realFieldBytes> + '|' + '<round>'
 * repeated with round=0,1,2,... until we have emitted enough hex to
 * cover fieldLen wchars. `realFieldBytes` are the raw WCHAR bytes of
 * the real name at positions [realStart, realStart+realFieldLen); we
 * feed the raw UTF-16LE bytes to keep the mixer input canonical.
 *
 * The output is always ASCII-safe uppercase hex, so the field parses
 * as a valid PnP token component (letters + digits, no `&` or `\`). */
static VOID TrackDFillTokenFnv(WCHAR *outName, ULONG cursor, ULONG fieldLen,
                               const WCHAR *realName, ULONG realStart,
                               ULONG realFieldLen,
                               const UCHAR *domain, ULONG domainLen)
{
    static const WCHAR HEX_UPPER[16] =
        { L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7',
          L'8', L'9', L'A', L'B', L'C', L'D', L'E', L'F' };
    ULONG round = 0;
    ULONG produced = 0;
    UCHAR buf[192];
    ULONG bufLen;
    ULONG realBytes;
    ULONGLONG h;
    ULONG i;

    if (fieldLen == 0) return;

    while (produced < fieldLen) {
        bufLen = 0;

        if (bufLen + domainLen > sizeof(buf)) break;
        RtlCopyMemory(buf + bufLen, domain, domainLen);
        bufLen += domainLen;

        if (g_TrackDSeedLen > 0) {
            if (bufLen + g_TrackDSeedLen > sizeof(buf)) break;
            RtlCopyMemory(buf + bufLen, g_TrackDSeed, g_TrackDSeedLen);
            bufLen += g_TrackDSeedLen;
        }

        if (bufLen + 1 > sizeof(buf)) break;
        buf[bufLen++] = (UCHAR)'|';

        realBytes = realFieldLen * sizeof(WCHAR);
        if (bufLen + realBytes > sizeof(buf)) realBytes = sizeof(buf) - bufLen;
        if (realBytes > 0) {
            RtlCopyMemory(buf + bufLen, (const UCHAR *)(realName + realStart),
                          realBytes);
            bufLen += realBytes;
        }

        if (bufLen + 1 > sizeof(buf)) break;
        buf[bufLen++] = (UCHAR)'|';

        /* Round marker: one ASCII byte per hash iteration. `('0' +
         * (round & 0xF))` emits '0'..'9' for rounds 0..9 then
         * ':',';','<','=','>','?' for rounds 10..15, then wraps back
         * to '0' at round 16 (mod-16 mask). This is INTENTIONAL — the
         * mixer only needs a monotonically-varying byte per round;
         * ASCII digits vs punctuation is irrelevant. Any userland
         * reproducer MUST mirror this exactly rather than assuming
         * decimal digits. SCSI Ven/Prod/Rev tokens today cap at ~20
         * wchars = round 1, so the wrap never triggers in production;
         * documented for future maintainer expanding TrackD to wider
         * fields. See docs/track-d-name-recipe.md. */
        if (bufLen + 1 > sizeof(buf)) break;
        buf[bufLen++] = (UCHAR)('0' + (round & 0xF));

        h = TrackDFnvHash64(buf, bufLen);

        for (i = 0; i < 16 && produced < fieldLen; i++) {
            outName[cursor + produced] =
                HEX_UPPER[(ULONG)((h >> (60 - i * 4)) & 0xFULL)];
            produced++;
        }
        round++;
    }
}

/* Rewrite a Disk&Ven_XXX&Prod_YYY[&Rev_ZZ] subkey name in place,
 * preserving structural markers (positions of `Disk&Ven_`, `&Prod_`,
 * `&Rev_`, and any trailing `&` separators inside them). Same wchar
 * count throughout, so the caller's NameLength stays valid without
 * mutation.
 *
 * Best-effort by design: if the real name has an unexpected shape
 * (missing &Prod_, weird casing, extra tokens), we only rewrite the
 * fields we recognize and leave the rest as-is. Worst case: nothing
 * gets rewritten and outName == realName (a strict pass-through). */
static VOID TrackDBuildSyntheticName(const WCHAR *realName, ULONG realWchars,
                                     WCHAR *outName)
{
    static const UCHAR DOMAIN_VEN[]  = "SCSI_VEN|";
    static const UCHAR DOMAIN_PROD[] = "SCSI_PROD|";
    static const UCHAR DOMAIN_REV[]  = "SCSI_REV|";
    static const ULONG DOMAIN_VEN_LEN  = sizeof(DOMAIN_VEN) - 1;
    static const ULONG DOMAIN_PROD_LEN = sizeof(DOMAIN_PROD) - 1;
    static const ULONG DOMAIN_REV_LEN  = sizeof(DOMAIN_REV) - 1;

    /* MVP filter guaranteed the prefix, so realWchars >= 9. */
    ULONG venStart, venEnd;
    ULONG prodStart = 0, prodEnd = 0;
    ULONG revStart  = 0, revEnd  = 0;
    BOOLEAN hasProd = FALSE, hasRev = FALSE;
    ULONG i;

    /* Copy real to out as the baseline; we overwrite specific token
     * ranges below. Structural chars (Disk&Ven_, &Prod_, &Rev_) stay
     * literal in both input and output. */
    RtlCopyMemory(outName, realName, realWchars * sizeof(WCHAR));

    if (realWchars < 9) return;    /* not "Disk&Ven_..." shape */

    /* Ven token = chars right after L"Disk&Ven_" up to next `&`. */
    venStart = 9;
    venEnd = venStart;
    while (venEnd < realWchars && realName[venEnd] != L'&') venEnd++;

    /* Locate &Prod_ marker after venEnd. Case-insensitive by folding
     * ASCII 'P'/'p', 'r'/'R', etc. */
    for (i = venEnd; i + 6 <= realWchars; i++) {
        if (realName[i]     == L'&' &&
            (realName[i+1] == L'P' || realName[i+1] == L'p') &&
            (realName[i+2] == L'r' || realName[i+2] == L'R') &&
            (realName[i+3] == L'o' || realName[i+3] == L'O') &&
            (realName[i+4] == L'd' || realName[i+4] == L'D') &&
            realName[i+5]  == L'_')
        {
            prodStart = i + 6;
            hasProd = TRUE;
            break;
        }
    }
    if (hasProd) {
        prodEnd = prodStart;
        while (prodEnd < realWchars && realName[prodEnd] != L'&') prodEnd++;

        /* Locate &Rev_ marker after prodEnd. */
        for (i = prodEnd; i + 5 <= realWchars; i++) {
            if (realName[i]     == L'&' &&
                (realName[i+1] == L'R' || realName[i+1] == L'r') &&
                (realName[i+2] == L'e' || realName[i+2] == L'E') &&
                (realName[i+3] == L'v' || realName[i+3] == L'V') &&
                realName[i+4]  == L'_')
            {
                revStart = i + 5;
                hasRev = TRUE;
                break;
            }
        }
        if (hasRev) {
            revEnd = revStart;
            while (revEnd < realWchars && realName[revEnd] != L'&') revEnd++;
        }
    }

    if (venEnd > venStart) {
        TrackDFillTokenFnv(outName, venStart, venEnd - venStart,
                           realName, venStart, venEnd - venStart,
                           DOMAIN_VEN, DOMAIN_VEN_LEN);
    }
    if (hasProd && prodEnd > prodStart) {
        TrackDFillTokenFnv(outName, prodStart, prodEnd - prodStart,
                           realName, prodStart, prodEnd - prodStart,
                           DOMAIN_PROD, DOMAIN_PROD_LEN);
    }
    if (hasRev && revEnd > revStart) {
        TrackDFillTokenFnv(outName, revStart, revEnd - revStart,
                           realName, revStart, revEnd - revStart,
                           DOMAIN_REV, DOMAIN_REV_LEN);
    }
}

/* ================================================================
 *  v5.0.1 Track D - additional synthesizers, path classifier,
 *  and helpers for USB/HID/PCI/Audio intercept coverage.
 *
 *  Same reentrancy contract as v5.0.0: no Zw* or Nt* registry calls,
 *  everything memory-only on the parent path returned by
 *  CmCallbackGetKeyObjectID. Same-wchar-count rewrites throughout so
 *  KEY_INFORMATION.NameLength stays valid without mutation.
 * ================================================================ */

/* ASCII case-insensitive prefix check on raw WCHAR arrays. Folds
 * lowercase a..z to A..Z in both text and prefix; other codepoints
 * compare literally. Sufficient for the ASCII-only path patterns
 * we match (Enum\SCSI, VID_, VEN_, etc.). */
static BOOLEAN TrackDStartsWithI(const WCHAR *text, ULONG textLen,
                                 const WCHAR *prefix, ULONG prefixLen)
{
    ULONG i;
    if (prefix == NULL || text == NULL) return FALSE;
    if (prefixLen > textLen) return FALSE;
    for (i = 0; i < prefixLen; i++) {
        WCHAR a = text[i];
        WCHAR b = prefix[i];
        if (a >= L'a' && a <= L'z') a = (WCHAR)(a - L'a' + L'A');
        if (b >= L'a' && b <= L'z') b = (WCHAR)(b - L'a' + L'A');
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* TRUE iff the given wchar is a valid hex digit [0-9A-Fa-f]. */
static BOOLEAN TrackDIsHexWchar(WCHAR c)
{
    return (c >= L'0' && c <= L'9') ||
           (c >= L'A' && c <= L'F') ||
           (c >= L'a' && c <= L'f');
}

/* Test whether `parent` looks like `\...\Enum\{USB|HID}\VID_XXXX&PID_XXXX`
 * (case-insensitive; last path component is 17 wchars matching the
 * `VID_` + 4 hex + `&PID_` + 4 hex shape). wantUsb=TRUE checks USB
 * marker; wantUsb=FALSE checks HID. */
static BOOLEAN TrackDMatchUsbHidInstanceParent(PCUNICODE_STRING parent,
                                               BOOLEAN wantUsb)
{
    static const WCHAR USB_MARKER[] = L"\\Enum\\USB\\";
    static const WCHAR HID_MARKER[] = L"\\Enum\\HID\\";
    const WCHAR *marker;
    ULONG markerLen;
    ULONG pathWchars;
    LONG i;
    ULONG lastSep;
    ULONG compStart;
    ULONG compLen;
    ULONG segStart;
    const WCHAR *p;

    if (parent == NULL || parent->Buffer == NULL || parent->Length < 34) {
        /* 34 bytes = 17 wchars min for VID_XXXX&PID_XXXX itself */
        return FALSE;
    }
    p = parent->Buffer;
    pathWchars = parent->Length / sizeof(WCHAR);

    marker = wantUsb ? USB_MARKER : HID_MARKER;
    markerLen = wantUsb ? (ULONG)((sizeof(USB_MARKER) - sizeof(WCHAR)) / sizeof(WCHAR))
                        : (ULONG)((sizeof(HID_MARKER) - sizeof(WCHAR)) / sizeof(WCHAR));
    /* markerLen counts the `\Enum\{USB|HID}\` including trailing `\`. */

    /* Find the LAST `\` — everything after it is the last component. */
    lastSep = 0;
    for (i = (LONG)pathWchars - 1; i >= 0; i--) {
        if (p[i] == L'\\') { lastSep = (ULONG)i; break; }
    }
    if (lastSep == 0) return FALSE;

    compStart = lastSep + 1;
    if (compStart >= pathWchars) return FALSE;
    compLen = pathWchars - compStart;

    /* VID_XXXX&PID_XXXX is exactly 17 wchars. */
    if (compLen != 17) return FALSE;
    if (!TrackDStartsWithI(p + compStart, compLen, L"VID_", 4)) return FALSE;
    if (!TrackDIsHexWchar(p[compStart + 4])) return FALSE;
    if (!TrackDIsHexWchar(p[compStart + 5])) return FALSE;
    if (!TrackDIsHexWchar(p[compStart + 6])) return FALSE;
    if (!TrackDIsHexWchar(p[compStart + 7])) return FALSE;
    if (p[compStart + 8] != L'&') return FALSE;
    if (!TrackDStartsWithI(p + compStart + 9, 4, L"PID_", 4)) return FALSE;
    if (!TrackDIsHexWchar(p[compStart + 13])) return FALSE;
    if (!TrackDIsHexWchar(p[compStart + 14])) return FALSE;
    if (!TrackDIsHexWchar(p[compStart + 15])) return FALSE;
    if (!TrackDIsHexWchar(p[compStart + 16])) return FALSE;

    /* Enclosing segment before `lastSep` must end with the `\Enum\{USB|HID}\`
     * marker (with trailing slash lining up on lastSep). */
    if (lastSep + 1 < markerLen) return FALSE;
    segStart = lastSep + 1 - markerLen;
    if (!TrackDStartsWithI(p + segStart, markerLen, marker, markerLen)) return FALSE;

    return TRUE;
}

/* Classify the parent path for intercept dispatch. Returns
 * TRACKD_PATH_NONE if no filter matches (fall through to pass-through). */
static TRACKD_PATH_TYPE TrackDClassifyParent(PCUNICODE_STRING parent)
{
    if (parent == NULL || parent->Buffer == NULL || parent->Length == 0) {
        return TRACKD_PATH_NONE;
    }
    if (RtlSuffixUnicodeString(&g_TrackDEnumSuffix,   parent, TRUE)) return TRACKD_PATH_SCSI;
    if (RtlSuffixUnicodeString(&g_TrackDPciSuffix,    parent, TRUE)) return TRACKD_PATH_PCI;
    if (RtlSuffixUnicodeString(&g_TrackDMMDevRender,  parent, TRUE)) return TRACKD_PATH_AUDIO_RENDER;
    if (RtlSuffixUnicodeString(&g_TrackDMMDevCapture, parent, TRUE)) return TRACKD_PATH_AUDIO_CAPTURE;
    if (TrackDMatchUsbHidInstanceParent(parent, TRUE))  return TRACKD_PATH_USB_INSTANCE;
    if (TrackDMatchUsbHidInstanceParent(parent, FALSE)) return TRACKD_PATH_HID_INSTANCE;
    return TRACKD_PATH_NONE;
}

/* PCI subkey rewriter. Input shape (any subset):
 *   VEN_XXXX&DEV_XXXX&SUBSYS_XXXXXXXX&REV_XX
 * Rewrites SUBSYS and REV tokens using FNV(seed + realTokenBytes).
 * PRESERVES VEN and DEV (driver binding is keyed on those; changing
 * them breaks PnP). CC_ (class code) also preserved literally when
 * present. Same-wchar-count for all rewritten fields.
 *
 * Non-matching or malformed shapes fall through as pure pass-through
 * (outName == realName). */
static VOID TrackDBuildSyntheticPciName(const WCHAR *realName, ULONG realWchars,
                                        WCHAR *outName)
{
    static const UCHAR DOMAIN_SUBSYS[] = "PCI_SUBSYS|";
    static const UCHAR DOMAIN_REV[]    = "PCI_REV|";
    static const ULONG DOMAIN_SUBSYS_LEN = sizeof(DOMAIN_SUBSYS) - 1;
    static const ULONG DOMAIN_REV_LEN    = sizeof(DOMAIN_REV) - 1;

    ULONG i;
    ULONG subStart = 0, subEnd = 0;
    ULONG revStart = 0, revEnd = 0;
    BOOLEAN hasSubsys = FALSE, hasRev = FALSE;

    RtlCopyMemory(outName, realName, realWchars * sizeof(WCHAR));

    /* Locate &SUBSYS_ marker (8 wchars). */
    for (i = 0; i + 8 <= realWchars; i++) {
        if (realName[i]     == L'&' &&
            (realName[i+1] == L'S' || realName[i+1] == L's') &&
            (realName[i+2] == L'U' || realName[i+2] == L'u') &&
            (realName[i+3] == L'B' || realName[i+3] == L'b') &&
            (realName[i+4] == L'S' || realName[i+4] == L's') &&
            (realName[i+5] == L'Y' || realName[i+5] == L'y') &&
            (realName[i+6] == L'S' || realName[i+6] == L's') &&
            realName[i+7]  == L'_')
        {
            subStart = i + 8;
            hasSubsys = TRUE;
            break;
        }
    }
    if (hasSubsys) {
        subEnd = subStart;
        while (subEnd < realWchars && realName[subEnd] != L'&') subEnd++;
    }

    /* Locate &REV_ marker (5 wchars). */
    for (i = 0; i + 5 <= realWchars; i++) {
        if (realName[i]     == L'&' &&
            (realName[i+1] == L'R' || realName[i+1] == L'r') &&
            (realName[i+2] == L'E' || realName[i+2] == L'e') &&
            (realName[i+3] == L'V' || realName[i+3] == L'v') &&
            realName[i+4]  == L'_')
        {
            revStart = i + 5;
            hasRev = TRUE;
            break;
        }
    }
    if (hasRev) {
        revEnd = revStart;
        while (revEnd < realWchars && realName[revEnd] != L'&') revEnd++;
    }

    if (hasSubsys && subEnd > subStart) {
        TrackDFillTokenFnv(outName, subStart, subEnd - subStart,
                           realName, subStart, subEnd - subStart,
                           DOMAIN_SUBSYS, DOMAIN_SUBSYS_LEN);
    }
    if (hasRev && revEnd > revStart) {
        TrackDFillTokenFnv(outName, revStart, revEnd - revStart,
                           realName, revStart, revEnd - revStart,
                           DOMAIN_REV, DOMAIN_REV_LEN);
    }
}

/* USB/HID instance-serial rewriter. Input is the leaf subkey name
 * under `\Enum\{USB|HID}\VID_XXXX&PID_XXXX\`, typically shapes like:
 *   "4&2af66358&0&0001"   (PnP-synthesized: N&hex&N&decimal)
 *   "AABBCCDD1234"        (iSerialNumber from descriptor)
 *   "5&2b47d091&0&010000" (composite)
 *
 * We regenerate the entire name with FNV hex derived from
 *   USB_INST|<seed>|<realNameUTF16LE>|<round>
 * preserving:
 *   - `&` separator positions
 *   - Purely-decimal short components (<= 4 digits — port/hub/interface
 *     indexes that Windows PnP re-checks and would refuse to bind if
 *     changed).
 *   - Same wchar count.
 *
 * This mirrors the userland spoof-usb-ids.ps1 New-SyntheticInstance
 * philosophy (see PR #12 spoof-usb-ids.ps1 lines 179-204). */
static VOID TrackDBuildSyntheticUsbHidInstance(const WCHAR *realName, ULONG realWchars,
                                               WCHAR *outName)
{
    static const UCHAR DOMAIN_INST[] = "USB_INST|";
    static const ULONG DOMAIN_INST_LEN = sizeof(DOMAIN_INST) - 1;

    ULONG i;
    ULONG segStart;
    BOOLEAN allDecimalShort;

    if (realWchars == 0) return;

    RtlCopyMemory(outName, realName, realWchars * sizeof(WCHAR));

    /* Walk components separated by `&`. Each component is either:
     *  - preserved (short pure-decimal, <= 4 digits)
     *  - rewritten with FNV hex of same wchar count */
    segStart = 0;
    for (i = 0; i <= realWchars; i++) {
        if (i == realWchars || realName[i] == L'&') {
            ULONG segLen = i - segStart;
            if (segLen > 0) {
                allDecimalShort = FALSE;
                if (segLen <= 4) {
                    ULONG k;
                    allDecimalShort = TRUE;
                    for (k = 0; k < segLen; k++) {
                        WCHAR c = realName[segStart + k];
                        if (c < L'0' || c > L'9') { allDecimalShort = FALSE; break; }
                    }
                }
                if (!allDecimalShort) {
                    /* Rewrite this component with FNV hex. */
                    TrackDFillTokenFnv(outName, segStart, segLen,
                                       realName, segStart, segLen,
                                       DOMAIN_INST, DOMAIN_INST_LEN);
                }
            }
            segStart = i + 1;
        }
    }
}

/* MMDevices Audio endpoint GUID rewriter. Input is the leaf subkey
 * name shape `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (38 wchars,
 * including braces). Rewrites the 32 hex nibbles preserving the
 * enclosing `{`, `}`, and 4 dashes at fixed offsets.
 *
 * If input doesn't match the exact GUID shape, pass-through unchanged. */
static VOID TrackDBuildSyntheticAudioGuid(const WCHAR *realName, ULONG realWchars,
                                          WCHAR *outName)
{
    static const UCHAR DOMAIN_AUDIO[] = "AUDIO_GUID|";
    static const ULONG DOMAIN_AUDIO_LEN = sizeof(DOMAIN_AUDIO) - 1;
    static const WCHAR HEX_UPPER[16] =
        { L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7',
          L'8', L'9', L'A', L'B', L'C', L'D', L'E', L'F' };
    /* Structural positions (0-indexed) in a 38-wchar canonical GUID
     * `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` : dashes at 9, 14, 19,
     * 24; braces at 0, 37. */
    UCHAR buf[192];
    ULONG bufLen;
    ULONGLONG h1;
    ULONG round = 0;
    ULONG produced = 0;
    ULONG cursor;
    ULONG i;

    if (realWchars != 38) return;    /* not a canonical GUID */
    if (realName[0]  != L'{') return;
    if (realName[37] != L'}') return;
    if (realName[9]  != L'-' || realName[14] != L'-' ||
        realName[19] != L'-' || realName[24] != L'-') return;

    RtlCopyMemory(outName, realName, realWchars * sizeof(WCHAR));

    /* Produce 32 hex chars from FNV rounds, skipping dash positions. */
    cursor = 1;    /* first hex slot inside `{` */
    while (produced < 32) {
        bufLen = 0;
        if (bufLen + DOMAIN_AUDIO_LEN > sizeof(buf)) break;
        RtlCopyMemory(buf + bufLen, DOMAIN_AUDIO, DOMAIN_AUDIO_LEN);
        bufLen += DOMAIN_AUDIO_LEN;
        if (g_TrackDSeedLen > 0) {
            if (bufLen + g_TrackDSeedLen > sizeof(buf)) break;
            RtlCopyMemory(buf + bufLen, g_TrackDSeed, g_TrackDSeedLen);
            bufLen += g_TrackDSeedLen;
        }
        if (bufLen + 1 > sizeof(buf)) break;
        buf[bufLen++] = (UCHAR)'|';
        {
            ULONG realBytes = realWchars * sizeof(WCHAR);
            if (bufLen + realBytes > sizeof(buf)) realBytes = sizeof(buf) - bufLen;
            if (realBytes > 0) {
                RtlCopyMemory(buf + bufLen, (const UCHAR *)realName, realBytes);
                bufLen += realBytes;
            }
        }
        if (bufLen + 1 > sizeof(buf)) break;
        buf[bufLen++] = (UCHAR)'|';
        if (bufLen + 1 > sizeof(buf)) break;
        buf[bufLen++] = (UCHAR)('0' + (round & 0xF));

        h1 = TrackDFnvHash64(buf, bufLen);
        /* Emit up to 16 hex chars from this round, skipping dashes. */
        for (i = 0; i < 16 && produced < 32; i++) {
            /* Skip dash positions when advancing cursor. */
            while (cursor == 9 || cursor == 14 || cursor == 19 || cursor == 24) cursor++;
            if (cursor >= 37) break;   /* would land on `}` */
            outName[cursor] = HEX_UPPER[(ULONG)((h1 >> (60 - i * 4)) & 0xFULL)];
            cursor++;
            produced++;
        }
        round++;
    }
}

/* v5.0.4: in-band image-name filter. Called synchronously from the Cm
 * callback body (PASSIVE_LEVEL - same context as the RegNtPostEnumerate
 * dispatcher below). PsGetProcessImageFileName returns the 15-byte
 * EPROCESS ImageFileName field; we _strnicmp-compare its first 7 bytes
 * against "rubinot" and reject anything with a non-delimiter next byte
 * so "rubinotimposter.exe" cannot slip through. PsGetCurrentProcess
 * returning NULL is a defensive check - inside a Cm callback dispatched
 * by user-mode NtEnumerateKey there is always an attached process, but
 * keep the check to survive future dispatch paths. */
static BOOLEAN TrackDCurrentCallerNameMatches(VOID)
{
    PEPROCESS proc;
    PCHAR name;
    CHAR next;

    proc = PsGetCurrentProcess();
    if (proc == NULL) return FALSE;
    name = PsGetProcessImageFileName(proc);
    if (name == NULL) return FALSE;
    if (_strnicmp(name, TRACKD_IMAGE_MATCH_PREFIX, TRACKD_IMAGE_MATCH_LEN) != 0)
        return FALSE;
    /* Delimiter guard: accept 'rubinot' only when the next byte terminates
     * the leaf (NUL / dot / underscore). Rejects "rubinotimposter.exe". */
    next = name[TRACKD_IMAGE_MATCH_LEN];
    if (next != '\0' && next != '.' && next != '_') return FALSE;
    return TRUE;
}

/* v5.0.4: record the leaf that failed the filter into g_TrackDLastMissName
 * and bump the miss counter. Safe at PASSIVE (called only from the
 * TrackDHandlePostEnumerate name-miss branch, dispatched by
 * RstRegistryCallback under PAGED_CODE()). The name copy is best-effort:
 * concurrent callback invocations on different CPUs may interleave the
 * 16-byte write - the ImageFileName the flusher publishes is guaranteed
 * to be A recent miss but not necessarily THE last one. Acceptable for a
 * diagnostic breadcrumb; the callback body path is intentionally free of
 * spinlocks (v5.0.4 removed the v5.0.2 KSPIN_LOCK on the PID array; we
 * do not reintroduce one for a diagnostic value). */
static VOID TrackDRecordNameMiss(VOID)
{
    PEPROCESS proc;
    PCHAR name;
    CHAR local[16];
    ULONG i;

    InterlockedIncrement(&g_TrackDNameMissCount);

    proc = PsGetCurrentProcess();
    if (proc == NULL) return;
    name = PsGetProcessImageFileName(proc);
    if (name == NULL) return;

    /* Copy at most 15 bytes, force NUL-termination. */
    for (i = 0; i < 15; i++) {
        CHAR c = name[i];
        local[i] = c;
        if (c == '\0') break;
    }
    for (; i < 15; i++) local[i] = '\0';
    local[15] = '\0';

    /* Publish. RtlCopyMemory here is a best-effort snapshot; racing
     * TrackDFlushWorker readers see either the pre- or the post-write
     * bytes (or a torn mixture - acceptable for a diagnostic). */
    RtlCopyMemory(g_TrackDLastMissName, local, sizeof(g_TrackDLastMissName));
}

/* RegNtPostEnumerateKey body: classify parent path, dispatch to the
 * matching child-name gate + synthesizer, rewrite the enumerated
 * subkey name in place. Same wchar count guaranteed by all
 * synthesizers; caller's NameLength never touched.
 *
 * v5.0.1: classifier-driven multi-path dispatch (SCSI, PCI, USB, HID,
 * Audio Render/Capture). Non-classified parents pass-through silently. */
static NTSTATUS TrackDHandlePostEnumerate(PVOID Argument2)
{
    PREG_POST_OPERATION_INFORMATION post;
    PREG_ENUMERATE_KEY_INFORMATION pre;
    NTSTATUS keyIdSt;
    PCUNICODE_STRING keyName = NULL;
    ULONG_PTR keyId = 0;
    ULONG nameLenBytes = 0;
    ULONG nameOffset = 0;
    PWCHAR namePtr = NULL;
    WCHAR real[TRACKD_MAX_NAME_WCHARS];
    WCHAR synth[TRACKD_MAX_NAME_WCHARS];
    ULONG realWchars;
    UNICODE_STRING realUs;
    TRACKD_PATH_TYPE pathType;
    BOOLEAN childOk = FALSE;

    post = (PREG_POST_OPERATION_INFORMATION)Argument2;
    if (post == NULL) return STATUS_SUCCESS;
    if (!NT_SUCCESS(post->Status)) return STATUS_SUCCESS;
    if (post->PreInformation == NULL) return STATUS_SUCCESS;

    /* v5.0.4: image-name gate BEFORE the more expensive Cm callback-
     * get-key-object-id call. Rejected callers bump the name-miss
     * counter and stash their leaf into g_TrackDLastMissName for
     * userland diagnostics - see TrackDRecordNameMiss. */
    if (!TrackDCurrentCallerNameMatches()) {
        TrackDRecordNameMiss();
        return STATUS_SUCCESS;
    }

    pre = (PREG_ENUMERATE_KEY_INFORMATION)post->PreInformation;
    if (pre->KeyInformation == NULL || pre->Length == 0) return STATUS_SUCCESS;

    /* Parent-path classification. */
    keyIdSt = CmCallbackGetKeyObjectID(&g_TrackDCookie, pre->Object,
                                       &keyId, &keyName);
    if (!NT_SUCCESS(keyIdSt) || keyName == NULL) {
        WriteLastCallbackStatus(TRACKD_TAG_PATH_GET_FAIL, keyIdSt);
        return STATUS_SUCCESS;
    }
    pathType = TrackDClassifyParent(keyName);
    if (pathType == TRACKD_PATH_NONE) return STATUS_SUCCESS;

    /* Extract subkey name from caller's buffer per KeyInformationClass. */
    switch (pre->KeyInformationClass) {
    case KeyBasicInformation:
        if (pre->Length < (ULONG)FIELD_OFFSET(KEY_BASIC_INFORMATION, Name)) {
            WriteLastCallbackStatus(TRACKD_TAG_BUFFER_BAD, STATUS_BUFFER_TOO_SMALL);
            return STATUS_SUCCESS;
        }
        {
            PKEY_BASIC_INFORMATION bi =
                (PKEY_BASIC_INFORMATION)pre->KeyInformation;
            nameLenBytes = bi->NameLength;
            nameOffset = (ULONG)FIELD_OFFSET(KEY_BASIC_INFORMATION, Name);
            namePtr = bi->Name;
        }
        break;
    case KeyNodeInformation:
        if (pre->Length < (ULONG)FIELD_OFFSET(KEY_NODE_INFORMATION, Name)) {
            WriteLastCallbackStatus(TRACKD_TAG_BUFFER_BAD, STATUS_BUFFER_TOO_SMALL);
            return STATUS_SUCCESS;
        }
        {
            PKEY_NODE_INFORMATION ni =
                (PKEY_NODE_INFORMATION)pre->KeyInformation;
            nameLenBytes = ni->NameLength;
            nameOffset = (ULONG)FIELD_OFFSET(KEY_NODE_INFORMATION, Name);
            namePtr = ni->Name;
        }
        break;
    default:
        /* KeyFullInformation, KeyNameInformation, etc. — pass-through. */
        return STATUS_SUCCESS;
    }

    if (nameLenBytes == 0 || (nameLenBytes % sizeof(WCHAR)) != 0)
        return STATUS_SUCCESS;
    realWchars = nameLenBytes / sizeof(WCHAR);
    if (realWchars > TRACKD_MAX_NAME_WCHARS) return STATUS_SUCCESS;
    if (nameOffset + nameLenBytes > pre->Length) {
        WriteLastCallbackStatus(TRACKD_TAG_BUFFER_BAD, STATUS_BUFFER_OVERFLOW);
        return STATUS_SUCCESS;
    }

    /* Snapshot real name into stack-local (SEH — caller's buffer
     * origin unknown; probe would need to be done by CM already,
     * but defense is cheap). */
    __try {
        RtlCopyMemory(real, namePtr, nameLenBytes);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteLastCallbackStatus(TRACKD_TAG_SEH_FAULT, GetExceptionCode());
        return STATUS_SUCCESS;
    }

    realUs.Buffer = real;
    realUs.Length = (USHORT)nameLenBytes;
    realUs.MaximumLength = (USHORT)nameLenBytes;

    /* Per-type child-name prefix gate + synthesizer dispatch. */
    switch (pathType) {
    case TRACKD_PATH_SCSI:
        if (RtlPrefixUnicodeString(&g_TrackDSubkeyPrefix, &realUs, TRUE)) {
            TrackDBuildSyntheticName(real, realWchars, synth);
            childOk = TRUE;
        }
        break;
    case TRACKD_PATH_PCI:
        if (RtlPrefixUnicodeString(&g_TrackDPciChildPrefix, &realUs, TRUE)) {
            TrackDBuildSyntheticPciName(real, realWchars, synth);
            childOk = TRUE;
        }
        break;
    case TRACKD_PATH_USB_INSTANCE:
    case TRACKD_PATH_HID_INSTANCE:
        /* No child-name prefix gate: enumerating under a validated
         * VID_&PID_ parent means every child is an instance-serial
         * candidate. Empty or malformed names are handled by the
         * synthesizer itself (no-op copy). */
        TrackDBuildSyntheticUsbHidInstance(real, realWchars, synth);
        childOk = TRUE;
        break;
    case TRACKD_PATH_AUDIO_RENDER:
    case TRACKD_PATH_AUDIO_CAPTURE:
        /* GUID synthesizer bails internally if shape !=
         * `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`. */
        if (realWchars == 38 && real[0] == L'{' && real[37] == L'}') {
            TrackDBuildSyntheticAudioGuid(real, realWchars, synth);
            childOk = TRUE;
        }
        break;
    default:
        break;
    }

    if (!childOk) return STATUS_SUCCESS;

    /* Write back. Same wchar count -> NameLength unchanged. */
    __try {
        RtlCopyMemory(namePtr, synth, nameLenBytes);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteLastCallbackStatus(TRACKD_TAG_SEH_FAULT, GetExceptionCode());
        return STATUS_SUCCESS;
    }

    InterlockedIncrement(&g_TrackDHitCount);
    WriteLastCallbackStatus(TRACKD_TAG_OK, STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/* RegNtPreSetValueKey tap on our OWN Parameters key.
 *
 * v5.0.4: dispatches only on `EnableRegCallback` writes -> update
 * g_TrackDEnabled directly, giving track-d-arm.ps1 -Enable/-Disable
 * hot-toggle without reboot. The pre-v5.0.4 `RubinOtPid` arm went
 * away with the Ps notify + PID array subsystem (v5.0.4 changelog).
 *
 * Any other ValueName in our Parameters key (LastCallbackStatus,
 * LastArmStatus, CallbackHitCount, CallbackInvokeCount,
 * CallbackNameMissCount, LastMissImageName, EnableSmbiosReplay,
 * EnableCpuReplay, etc.) is IGNORED silently. Our own TrackDFlushWorker
 * writes those and its writes fire this tap - the value-name filter
 * here prevents any recursion or unintended side effects. */
static VOID TrackDHandlePreSetValue(PVOID Argument2)
{
    PREG_SET_VALUE_KEY_INFORMATION info;
    NTSTATUS keyIdSt;
    ULONG_PTR keyId = 0;
    PCUNICODE_STRING keyName = NULL;
    ULONG newValue = 0;

    info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
    if (info == NULL || info->ValueName == NULL) return;
    if (info->Type != REG_DWORD || info->DataSize < sizeof(ULONG)) return;
    if (info->Data == NULL) return;

    /* v5.0.4: only EnableRegCallback survives as a hot-toggle tap. The
     * pre-v5.0.4 RubinOtPid arm went away with the Ps notify + PID
     * array subsystem (name-based gate needs no PID plumbing). */
    if (!RtlEqualUnicodeString(&g_TrackDEnableValueName,
                               info->ValueName, TRUE)) {
        return;
    }

    /* Verify parent path is our OWN Parameters key. */
    keyIdSt = CmCallbackGetKeyObjectID(&g_TrackDCookie, info->Object,
                                       &keyId, &keyName);
    if (!NT_SUCCESS(keyIdSt) || keyName == NULL) return;
    if (!RtlSuffixUnicodeString(&g_TrackDParamsSuffix,
                                (PCUNICODE_STRING)keyName, TRUE)) return;

    __try {
        RtlCopyMemory(&newValue, info->Data, sizeof(ULONG));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    /* Toggle the hot-path gate. Plain BOOLEAN write; the hot path
     * reads g_TrackDEnabled without a lock (single-byte MOV is
     * inherently atomic on x86-64). Value semantics: 1 = enabled,
     * anything else = disabled (mirrors LoadTrackDConfig). */
    g_TrackDEnabled = (newValue == 1) ? TRUE : FALSE;
#if DBG
    DbgPrint("[RstFlt/TrackD] EnableRegCallback toggled to %u via Parameters tap (g_TrackDEnabled=%d)\n",
             newValue, g_TrackDEnabled);
#endif
}

/* Cm dispatch. Runs at PASSIVE_LEVEL per MSDN contract. */
static NTSTATUS RstRegistryCallback(PVOID CallbackContext,
                                    PVOID Argument1,
                                    PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;

    UNREFERENCED_PARAMETER(CallbackContext);
    /* PAGED_CODE (matches changelog claim + TrackDFlushWorker style).
     * NT_ASSERT below is stricter on the IRQL axis (PAGED_CODE allows
     * up to APC_LEVEL; we assert exactly PASSIVE_LEVEL per Cm contract). */
    PAGED_CODE();

    if (!g_TrackDEnabled || Argument2 == NULL) return STATUS_SUCCESS;

    /* v5.0.4: instrument every post-gate invocation. Placed BEFORE the
     * IRQL assert so an accidental non-PASSIVE dispatch also bumps the
     * counter and is visible in the breadcrumb. Counter answers
     * "did the callback fire at all this boot" without depending on
     * rewrite success (g_TrackDHitCount stays a rewrite-landed counter). */
    InterlockedIncrement(&g_TrackDInvokeCount);

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    switch (notifyClass) {
    case RegNtPostEnumerateKey:
        (void)TrackDHandlePostEnumerate(Argument2);
        break;
    case RegNtPreSetValueKey:
        TrackDHandlePreSetValue(Argument2);
        break;
    default:
        break;
    }
    return STATUS_SUCCESS;
}

/* Flush the in-memory breadcrumb to Parameters\LastCallbackStatus
 * and Parameters\CallbackHitCount. Runs at PASSIVE outside any
 * Cm callback stack — safe to Zw*.
 *
 * v5.0.0 post-review fix (adversarial workflow finding #1 CONFIRMED,
 * MED severity): the original body persisted the snapshot then cleared
 * g_TrackDFlushQueued unconditionally. Any WriteLastCallbackStatus that
 * fired between snapshot and guard-clear would InterlockedExchange the
 * new value into g_TrackDLastStatus, then find the guard still set,
 * fail its CAS, and skip re-queue — the on-disk breadcrumb would
 * permanently lag the in-memory volatile until another callback fired.
 * Fix: after clearing the guard, re-read the volatiles; if either has
 * drifted from the snapshot we just persisted, re-queue the work item
 * so the next iteration flushes the drift. This closes the window
 * without introducing concurrent-worker complexity. */
static VOID TrackDFlushWorker(PVOID unused)
{
    NTSTATUS st;
    HANDLE hParams = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING valName;
    /* Initialized here so the drift check after `out:` sees defined
     * values even if we took the early goto (Length==0 path). */
    ULONG statusValue = 0, hitValue = 0;
    ULONG invokeValue = 0, nameMissValue = 0;
    ULONG postStatus, postHit, postInvoke, postNameMiss;
    CHAR  missSnap[16];
    CHAR  postMissSnap[16];
    WCHAR missWide[16];
    ULONG i, wlen;

    UNREFERENCED_PARAMETER(unused);
    PAGED_CODE();

    if (g_TrackDParamsFullPath.Length == 0) goto out;

    /* Snapshot all five hot-path publishers before opening the key.
     * Order matters only for the drift-recheck symmetry below. */
    statusValue   = (ULONG)InterlockedCompareExchange(&g_TrackDLastStatus,     0, 0);
    hitValue      = (ULONG)InterlockedCompareExchange(&g_TrackDHitCount,       0, 0);
    invokeValue   = (ULONG)InterlockedCompareExchange(&g_TrackDInvokeCount,    0, 0);
    nameMissValue = (ULONG)InterlockedCompareExchange(&g_TrackDNameMissCount,  0, 0);
    RtlCopyMemory(missSnap, g_TrackDLastMissName, sizeof(missSnap));
    missSnap[15] = '\0'; /* defensive re-termination */

    InitializeObjectAttributes(&oa, &g_TrackDParamsFullPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    st = ZwOpenKey(&hParams, KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(st)) goto out;

    RtlInitUnicodeString(&valName, L"LastCallbackStatus");
    (void)ZwSetValueKey(hParams, &valName, 0, REG_DWORD,
                        &statusValue, sizeof(statusValue));

    RtlInitUnicodeString(&valName, L"CallbackHitCount");
    (void)ZwSetValueKey(hParams, &valName, 0, REG_DWORD,
                        &hitValue, sizeof(hitValue));

    /* v5.0.4 additions */
    RtlInitUnicodeString(&valName, L"CallbackInvokeCount");
    (void)ZwSetValueKey(hParams, &valName, 0, REG_DWORD,
                        &invokeValue, sizeof(invokeValue));

    RtlInitUnicodeString(&valName, L"CallbackNameMissCount");
    (void)ZwSetValueKey(hParams, &valName, 0, REG_DWORD,
                        &nameMissValue, sizeof(nameMissValue));

    /* LastMissImageName: promote ANSI snapshot to UTF-16LE for REG_SZ.
     * Empty string is still written so the value always exists once
     * armed (userland can distinguish "never ran" from "ran, no miss").
     * Data size includes the trailing L'\0'. */
    wlen = 0;
    for (i = 0; i < 15 && missSnap[i] != '\0'; i++) {
        missWide[i] = (WCHAR)(UCHAR)missSnap[i];
        wlen++;
    }
    missWide[wlen] = L'\0';
    RtlInitUnicodeString(&valName, L"LastMissImageName");
    (void)ZwSetValueKey(hParams, &valName, 0, REG_SZ,
                        missWide, (wlen + 1) * sizeof(WCHAR));

out:
    if (hParams) ZwClose(hParams);
    /* Release the guard so a concurrent update can re-queue. */
    InterlockedExchange(&g_TrackDFlushQueued, 0);
    /* Drift check (see banner comment). If any hot-path publish fired
     * inside the persist window, its value never reached the registry -
     * re-queue ourselves to flush it. Reads are cheap Interlocked reads;
     * guarded re-queue prevents thrash. LastMissImageName drift is
     * detected byte-wise; matches the snapshot semantics. */
    postStatus   = (ULONG)InterlockedCompareExchange(&g_TrackDLastStatus,     0, 0);
    postHit      = (ULONG)InterlockedCompareExchange(&g_TrackDHitCount,       0, 0);
    postInvoke   = (ULONG)InterlockedCompareExchange(&g_TrackDInvokeCount,    0, 0);
    postNameMiss = (ULONG)InterlockedCompareExchange(&g_TrackDNameMissCount,  0, 0);
    RtlCopyMemory(postMissSnap, g_TrackDLastMissName, sizeof(postMissSnap));
    if (postStatus   != statusValue   ||
        postHit      != hitValue      ||
        postInvoke   != invokeValue   ||
        postNameMiss != nameMissValue ||
        RtlCompareMemory(postMissSnap, missSnap, sizeof(missSnap)) != sizeof(missSnap))
    {
        if (InterlockedCompareExchange(&g_TrackDFlushQueued, 1, 0) == 0) {
            ExQueueWorkItem(&g_TrackDFlushWorkItem, DelayedWorkQueue);
        }
    }
}

/* Callback-safe breadcrumb setter. Updates the in-memory volatile
 * atomically and — if a flush isn't already pending — queues one. */
static VOID WriteLastCallbackStatus(UCHAR tag, NTSTATUS st)
{
    ULONG code = ((ULONG)tag << 24) | ((ULONG)st & 0x00FFFFFFUL);
    InterlockedExchange(&g_TrackDLastStatus, (LONG)code);
    if (InterlockedCompareExchange(&g_TrackDFlushQueued, 1, 0) == 0) {
        /* Item pre-initialized in ArmTrackD; safe to Queue while flag
         * held. */
        ExQueueWorkItem(&g_TrackDFlushWorkItem, DelayedWorkQueue);
    }
}

/* v5.0.4: arm-time breadcrumb setter. Written into a SEPARATE registry
 * value (Parameters\LastArmStatus) so a boot-time arm failure can no
 * longer be masked by a subsequent hot-path callback that overwrites
 * LastCallbackStatus. Called EXCLUSIVELY from ArmTrackD (PASSIVE,
 * driver-init context, OUTSIDE any Cm callback stack) - direct Zw is
 * safe: no CM-internal lock is held. Uses g_TrackDParamsFullPath cached
 * by LoadTrackDConfig; a NULL path is silently skipped (same failure-
 * tolerance policy as the existing WriteLastReplayStatus /
 * WriteLastCallbackStatus). */
static VOID WriteLastArmStatus(UCHAR tag, NTSTATUS st)
{
    HANDLE hParams = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING valName;
    ULONG code;

    if (g_TrackDParamsFullPath.Length == 0) return;

    code = ((ULONG)tag << 24) | ((ULONG)st & 0x00FFFFFFUL);
    InitializeObjectAttributes(&oa, &g_TrackDParamsFullPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&hParams, KEY_SET_VALUE, &oa))) return;
    RtlInitUnicodeString(&valName, L"LastArmStatus");
    (void)ZwSetValueKey(hParams, &valName, 0, REG_DWORD, &code, sizeof(code));
    ZwClose(hParams);
}

/* Read Parameters into globals + cache the full Parameters NT path
 * for the flusher. Runs at PASSIVE from DriverEntry (safe context;
 * Cm callback is not yet armed so no risk of recursion). */
static NTSTATUS LoadTrackDConfig(PUNICODE_STRING RegPath)
{
    NTSTATUS st;
    HANDLE hParams = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING paramsPath, tail, valName;
    WCHAR paramsBuf[512];
    UCHAR flagBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION flagInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)flagBuf;
    UCHAR seedBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 132];
    PKEY_VALUE_PARTIAL_INFORMATION seedInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)seedBuf;
    ULONG need = 0;
    ULONG flagVal = 0;

    if (RegPath == NULL || RegPath->Buffer == NULL || RegPath->Length == 0)
        return STATUS_INVALID_PARAMETER;

    paramsPath.Buffer = paramsBuf;
    paramsPath.Length = 0;
    paramsPath.MaximumLength = sizeof(paramsBuf);
    st = RtlAppendUnicodeStringToString(&paramsPath, RegPath);
    if (!NT_SUCCESS(st)) return st;
    RtlInitUnicodeString(&tail, L"\\Parameters");
    st = RtlAppendUnicodeStringToString(&paramsPath, &tail);
    if (!NT_SUCCESS(st)) return st;

    InitializeObjectAttributes(&oa, &paramsPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    st = ZwOpenKey(&hParams, KEY_READ | KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(st)) return st;

    /* Cache full Parameters path for the flusher's later ZwOpenKey. */
    if ((ULONG)paramsPath.Length + sizeof(WCHAR) <= sizeof(g_TrackDParamsBuf)) {
        RtlCopyMemory(g_TrackDParamsBuf, paramsPath.Buffer, paramsPath.Length);
        g_TrackDParamsBuf[paramsPath.Length / sizeof(WCHAR)] = L'\0';
        g_TrackDParamsFullPath.Buffer = g_TrackDParamsBuf;
        g_TrackDParamsFullPath.Length = paramsPath.Length;
        g_TrackDParamsFullPath.MaximumLength = (USHORT)sizeof(g_TrackDParamsBuf);
    }

    /* EnableRegCallback (REG_DWORD, default 0). */
    RtlInitUnicodeString(&valName, L"EnableRegCallback");
    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         flagInfo, sizeof(flagBuf), &need);
    if (NT_SUCCESS(st) &&
        flagInfo->Type == REG_DWORD &&
        flagInfo->DataLength >= sizeof(ULONG))
    {
        RtlCopyMemory(&flagVal, flagInfo->Data, sizeof(ULONG));
        if (flagVal == 1) g_TrackDEnabled = TRUE;
    }

    /* RegCallbackSeed (REG_SZ, up to 64 hex chars). Stored raw as
     * lower bytes of each WCHAR (ASCII-safe assumption; a non-ASCII
     * seed would still hash deterministically, just with fewer bits
     * of effective entropy). */
    RtlInitUnicodeString(&valName, L"RegCallbackSeed");
    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         seedInfo, sizeof(seedBuf), &need);
    if (NT_SUCCESS(st) &&
        seedInfo->Type == REG_SZ &&
        seedInfo->DataLength >= sizeof(WCHAR))
    {
        ULONG wcount = seedInfo->DataLength / sizeof(WCHAR);
        ULONG i;
        PWCHAR wsrc = (PWCHAR)seedInfo->Data;
        if (wcount > 0 && wsrc[wcount - 1] == L'\0') wcount--;
        if (wcount > sizeof(g_TrackDSeed)) wcount = sizeof(g_TrackDSeed);
        for (i = 0; i < wcount; i++) {
            g_TrackDSeed[i] = (UCHAR)(wsrc[i] & 0xFF);
        }
        g_TrackDSeedLen = wcount;
    }

    /* v5.0.4: pre-v5.0.4 loaded Parameters\RubinOtPid into
     * g_TrackDOverridePid here. Removed with the entire PID-array +
     * override subsystem; the name-based gate replaces it and needs no
     * config surface. Any stale RubinOtPid value left in Parameters
     * from an older install is now ignored. */

    ZwClose(hParams);
    return STATUS_SUCCESS;
}

/* Register CmRegisterCallbackEx. Any failure is silent from
 * DriverEntry's perspective - driver still loads, other paths
 * unaffected. v5.0.4: PsSetCreateProcessNotifyRoutineEx registration
 * removed; per-callback image-name gate replaces the PID array. */
static NTSTATUS ArmTrackD(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
    NTSTATUS st;

    /* Initialize UNICODE_STRING views over the string literals. Safe
     * to call before we know if we'll register — they're just
     * headers pointing at .rdata. */
    RtlInitUnicodeString(&g_TrackDAltitude,        TRACKD_ALTITUDE_STR);
    RtlInitUnicodeString(&g_TrackDEnumSuffix,      TRACKD_ENUM_SUFFIX_STR);
    RtlInitUnicodeString(&g_TrackDSubkeyPrefix,    TRACKD_SUBKEY_PREFIX_STR);
    RtlInitUnicodeString(&g_TrackDParamsSuffix,    TRACKD_PARAMS_SUFFIX_STR);
    /* v5.0.4: g_TrackDPidValueName init removed - Parameters\RubinOtPid
     * tap disappeared with the Ps notify + PID array subsystem. */
    /* v5.0.4: KeInitializeSpinLock(&g_TrackDPidsLock) removed - array
     * gone; the per-callback name gate needs no synchronization. */
    /* v5.0.1 additional views */
    RtlInitUnicodeString(&g_TrackDPciSuffix,       TRACKD_PCI_SUFFIX_STR);
    RtlInitUnicodeString(&g_TrackDPciChildPrefix,  TRACKD_PCI_CHILD_PREFIX_STR);
    RtlInitUnicodeString(&g_TrackDMMDevRender,     TRACKD_MMDEV_RENDER_STR);
    RtlInitUnicodeString(&g_TrackDMMDevCapture,    TRACKD_MMDEV_CAPTURE_STR);
    RtlInitUnicodeString(&g_TrackDEnableValueName, TRACKD_ENABLE_VAL_STR);

    ExInitializeWorkItem(&g_TrackDFlushWorkItem, TrackDFlushWorker, NULL);

    /* Load config (also caches Parameters path for later flusher). */
    st = LoadTrackDConfig(RegPath);
    if (!NT_SUCCESS(st)) {
#if DBG
        DbgPrint("[RstFlt/TrackD] LoadTrackDConfig 0x%08X; Track D not armed\n",
                 st);
#endif
        return st;
    }

    if (!g_TrackDEnabled) {
#if DBG
        DbgPrint("[RstFlt/TrackD] EnableRegCallback=0; callback not armed\n");
#endif
        return STATUS_SUCCESS;
    }

    /* v5.0.4: PsSetCreateProcessNotifyRoutineEx registration removed -
     * per-callback name gate makes it unnecessary. Only CmRegister-
     * CallbackEx remains. */

    st = CmRegisterCallbackEx(RstRegistryCallback,
                              &g_TrackDAltitude,
                              DrvObj,
                              NULL,
                              &g_TrackDCookie,
                              NULL);
    if (!NT_SUCCESS(st)) {
#if DBG
        DbgPrint("[RstFlt/TrackD] CmRegisterCallbackEx 0x%08X\n", st);
#endif
        /* v5.0.4: arm-failure breadcrumb goes to LastArmStatus (separate
         * value from LastCallbackStatus) so a subsequent hot-path event
         * cannot mask the arm failure userland is trying to diagnose. */
        WriteLastArmStatus(TRACKD_TAG_ALLOC_FAIL, st);
        return st;
    }
    g_TrackDRegistered = TRUE;

#if DBG
    DbgPrint("[RstFlt/TrackD] armed. cookie=0x%llx seedLen=%u\n",
             g_TrackDCookie.QuadPart, g_TrackDSeedLen);
#endif

    /* v5.0.4: arm-success breadcrumb goes to LastArmStatus. LastCallback-
     * Status is reserved for hot-path callback events after the split. */
    WriteLastArmStatus(TRACKD_TAG_OK, STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/* ================================================================
 *  PnpStartCompletion - signals event when IRP_MN_START completes
 * ================================================================ */
static NTSTATUS PnpStartCompletion(
    PDEVICE_OBJECT DevObj,
    PIRP Irp,
    PVOID Ctx)
{
    UNREFERENCED_PARAMETER(DevObj);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent((PKEVENT)Ctx, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* ================================================================
 *  PnpRemoveCompletion - signals event when IRP_MN_REMOVE completes.
 *  Same shape as PnpStartCompletion. We use this so that our
 *  IoDetachDevice/IoDeleteDevice run AFTER the lower stack has
 *  finished tearing down its REMOVE-time work. Some lower filters
 *  (e.g. iaStorAC on OEM builds) defer part of REMOVE; without this
 *  synchronization, our detach/delete can race a lower driver that
 *  still touches our attachment (use-after-free / pool corruption).
 * ================================================================ */
static NTSTATUS PnpRemoveCompletion(
    PDEVICE_OBJECT DevObj,
    PIRP Irp,
    PVOID Ctx)
{
    UNREFERENCED_PARAMETER(DevObj);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent((PKEVENT)Ctx, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* ================================================================
 *  DispatchPnp - Plug and Play IRP handler
 *
 *  Handles START (forward-and-wait), REMOVE (detach + delete),
 *  SURPRISE_REMOVAL, STOP, and forwards everything else.
 * ================================================================ */
NTSTATUS DispatchPnp(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    PDEVICE_EXTENSION  dx = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS st;
    KEVENT   evt;

    st = IoAcquireRemoveLock(&dx->RemoveLock, Irp);
    if (!NT_SUCCESS(st)) {
        Irp->IoStatus.Status = st;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return st;
    }

    switch (sp->MinorFunction) {

    /* ---- START: must forward to lower driver FIRST, then act ---- */
    case IRP_MN_START_DEVICE:
        KeInitializeEvent(&evt, NotificationEvent, FALSE);
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, PnpStartCompletion, &evt,
                               TRUE, TRUE, TRUE);

        st = IoCallDriver(dx->LowerDevice, Irp);
        if (st == STATUS_PENDING) {
            KeWaitForSingleObject(&evt, Executive,
                                  KernelMode, FALSE, NULL);
            st = Irp->IoStatus.Status;
        }

        if (NT_SUCCESS(st)) {
            dx->Started = TRUE;
#if DBG
            DbgPrint("[RstFlt] Device %p started\n", DevObj);
#endif
        }

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&dx->RemoveLock, Irp);
        return st;

    /* ---- REMOVE: forward-and-wait, drain, detach, delete, complete ---
       Post-review change (v3.6): the earlier shape used IoSkip +
       IoCallDriver and immediately IoReleaseRemoveLockAndWait, which
       drains only OUR tracked IRPs — not any lower-driver work that
       runs asynchronously off the REMOVE IRP. If IoDetachDevice ran
       while the lower stack still touched our attachment we could
       get a use-after-free (0xE6/0xC2). Forward-and-wait ensures the
       whole lower stack has processed REMOVE before we detach. */
    case IRP_MN_REMOVE_DEVICE:
        dx->Started = FALSE;
        dx->Removed = TRUE;

        KeInitializeEvent(&evt, NotificationEvent, FALSE);
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, PnpRemoveCompletion, &evt,
                               TRUE, TRUE, TRUE);

        st = IoCallDriver(dx->LowerDevice, Irp);
        if (st == STATUS_PENDING) {
            KeWaitForSingleObject(&evt, Executive,
                                  KernelMode, FALSE, NULL);
            st = Irp->IoStatus.Status;
        }

        /* Now wait for any of OUR tracked IRPs to drain, then detach
           + delete, then complete the REMOVE. */
        IoReleaseRemoveLockAndWait(&dx->RemoveLock, Irp);
        IoDetachDevice(dx->LowerDevice);
        IoDeleteDevice(DevObj);

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
#if DBG
        DbgPrint("[RstFlt] Device %p removed\n", DevObj);
#endif
        return STATUS_SUCCESS;

    /* ---- SURPRISE REMOVAL ---- */
    case IRP_MN_SURPRISE_REMOVAL:
        dx->Started = FALSE;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        st = IoCallDriver(dx->LowerDevice, Irp);
        IoReleaseRemoveLock(&dx->RemoveLock, Irp);
        return st;

    /* ---- STOP ---- */
    case IRP_MN_STOP_DEVICE:
        dx->Started = FALSE;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        st = IoCallDriver(dx->LowerDevice, Irp);
        IoReleaseRemoveLock(&dx->RemoveLock, Irp);
        return st;

    /* ---- DEVICE_USAGE_NOTIFICATION (v4.0.4 — paging path bookkeeping) --
     * Kernel sends this when a device joins/leaves the paging (or
     * hibernation or dump) I/O path. For a class UpperFilter above
     * the boot disk, we MUST toggle DO_POWER_PAGABLE on our filter
     * DO in sync with the lower device's flag, or paging IRPs (which
     * can arrive at DISPATCH_LEVEL) fault against our pageable code
     * path. Boot volume == paging volume so this fires during early
     * boot and its mishandling produces a post-loader, pre-Winlogon
     * hang on Gen 2 UEFI + storvsc. Modeled on the diskperf WDK
     * sample. */
    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        {
            BOOLEAN setPagableIo = FALSE;
            BOOLEAN inPath = sp->Parameters.UsageNotification.InPath;

            ExAcquireFastMutex(&dx->PagingPathMutex);
            if (inPath && dx->PagingPathCount == 0) {
                /* First paging joiner: clear DO_POWER_PAGABLE BEFORE
                 * forwarding, so the flag is correct by the time
                 * lower drivers see the notification propagate. */
                if (DevObj->Flags & DO_POWER_PAGABLE) {
                    DevObj->Flags &= ~DO_POWER_PAGABLE;
                    setPagableIo = TRUE;
                }
            }
            ExReleaseFastMutex(&dx->PagingPathMutex);

            /* Forward and wait for completion so we can update our
             * counter based on the lower stack's success/failure. */
            KeInitializeEvent(&evt, NotificationEvent, FALSE);
            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, PnpStartCompletion, &evt,
                                   TRUE, TRUE, TRUE);
            st = IoCallDriver(dx->LowerDevice, Irp);
            if (st == STATUS_PENDING) {
                KeWaitForSingleObject(&evt, Executive,
                                      KernelMode, FALSE, NULL);
                st = Irp->IoStatus.Status;
            }

            ExAcquireFastMutex(&dx->PagingPathMutex);
            if (NT_SUCCESS(st)) {
                if (inPath) {
                    dx->PagingPathCount++;
                } else {
                    if (--dx->PagingPathCount == 0) {
                        /* Last paging leaver: restore pageable so we
                         * go back to normal power management. */
                        DevObj->Flags |= DO_POWER_PAGABLE;
                    }
                }
            } else if (setPagableIo) {
                /* Lower stack rejected the notification; roll back
                 * the flag change so state stays consistent. */
                DevObj->Flags |= DO_POWER_PAGABLE;
            }
            ExReleaseFastMutex(&dx->PagingPathMutex);

            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            IoReleaseRemoveLock(&dx->RemoveLock, Irp);
            return st;
        }

    /* ---- Everything else: just forward ---- */
    default:
        IoSkipCurrentIrpStackLocation(Irp);
        st = IoCallDriver(dx->LowerDevice, Irp);
        IoReleaseRemoveLock(&dx->RemoveLock, Irp);
        return st;
    }
}

/* ================================================================
 *  DispatchPower - Power IRP handler
 *
 *  WDM requires PoCallDriver + PoStartNextPowerIrp.
 *  Acquires remove lock to prevent device deletion while
 *  the IRP is in flight.
 * ================================================================ */
NTSTATUS DispatchPower(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    PDEVICE_EXTENSION dx = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    NTSTATUS st;

    st = IoAcquireRemoveLock(&dx->RemoveLock, Irp);
    if (!NT_SUCCESS(st)) {
        /* Device being removed — complete with error */
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = st;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return st;
    }

    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    st = PoCallDriver(dx->LowerDevice, Irp);
    IoReleaseRemoveLock(&dx->RemoveLock, Irp);
    return st;
}

/* ================================================================
 *  DispatchPassthrough - generic forwarding for all other IRPs
 *  (including IRP_MJ_DEVICE_CONTROL and IRP_MJ_INTERNAL_DEVICE_CONTROL
 *  in v3.6 — no interception).
 *
 *  Acquires the remove lock to ensure the device extension and
 *  LowerDevice pointer stay valid while the IRP is forwarded.
 *  Without this, a concurrent IRP_MN_REMOVE_DEVICE could free
 *  the device object while IRPs (READ/WRITE/CREATE/CLOSE) are
 *  still in flight, causing BSOD.
 * ================================================================ */
NTSTATUS DispatchPassthrough(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    PDEVICE_EXTENSION dx = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    NTSTATUS st;

    st = IoAcquireRemoveLock(&dx->RemoveLock, Irp);
    if (!NT_SUCCESS(st)) {
        Irp->IoStatus.Status = st;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return st;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    st = IoCallDriver(dx->LowerDevice, Irp);
    IoReleaseRemoveLock(&dx->RemoveLock, Irp);
    return st;
}

/* ================================================================
 *  AddDevice - attach filter to each disk in the PnP stack.
 *
 *  v3.6: no per-device configuration is needed anymore. We still
 *  attach so the service loads reliably at SYSTEM_START (upper
 *  filter of DiskDrive class ensures we load early enough for
 *  DriverEntry's SMBIOS replay to precede winmgmt/anti-cheat),
 *  but the filter is transparent — every IRP that reaches us
 *  is forwarded unchanged.
 * ================================================================ */
NTSTATUS AddDevice(PDRIVER_OBJECT DrvObj, PDEVICE_OBJECT Pdo)
{
    NTSTATUS        st;
    PDEVICE_OBJECT  flt = NULL;
    PDEVICE_EXTENSION dx;

    st = IoCreateDevice(
        DrvObj,
        sizeof(DEVICE_EXTENSION),
        NULL,
        FILE_DEVICE_DISK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &flt);

    if (!NT_SUCCESS(st)) {
#if DBG
        DbgPrint("[RstFlt] IoCreateDevice failed: 0x%08X\n", st);
#endif
        return st;
    }

    dx = (PDEVICE_EXTENSION)flt->DeviceExtension;
    RtlZeroMemory(dx, sizeof(DEVICE_EXTENSION));

    /* Initialize remove lock for safe IRP tracking */
    IoInitializeRemoveLock(&dx->RemoveLock, POOL_TAG, 0, 0);

    dx->PhysicalDevice = Pdo;
    dx->Started        = FALSE;
    dx->Removed        = FALSE;

    /* Attach to the device stack */
    dx->LowerDevice = IoAttachDeviceToDeviceStack(flt, Pdo);
    if (dx->LowerDevice == NULL) {
#if DBG
        DbgPrint("[RstFlt] Attach failed for PDO %p\n", Pdo);
#endif
        IoDeleteDevice(flt);
        return STATUS_NO_SUCH_DEVICE;
    }

    /* Copy I/O method flags from lower device. Bitwise OR preserves
     * anything IoCreateDevice may have set by default. */
    flt->Flags |= dx->LowerDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO);

    /* v4.0.4: DO_POWER_PAGABLE must match the lower device EXACTLY at
     * AddDevice time. IoCreateDevice defaults DO_POWER_PAGABLE=1 on
     * our filter DO. Using bitwise OR to propagate (prior v4.0.x code)
     * kept our filter pageable even when lower disk.sys FDO had the
     * flag cleared for the paging path — which happens whenever the
     * disk participates in paging, i.e. always on the boot volume.
     * A pageable filter above a non-pageable stack violates the paging
     * IRP IRQL contract and causes an intermittent post-loader, pre-
     * Winlogon boot hang on Gen 2 UEFI + storvsc. We must explicitly
     * assign here at AddDevice and then dynamically flip via
     * IRP_MN_DEVICE_USAGE_NOTIFICATION as the paging path is joined
     * or left. Modeled on the diskperf WDK sample. */
    if (dx->LowerDevice->Flags & DO_POWER_PAGABLE) {
        flt->Flags |= DO_POWER_PAGABLE;
    } else {
        flt->Flags &= ~DO_POWER_PAGABLE;
    }

    flt->DeviceType           = dx->LowerDevice->DeviceType;
    flt->Characteristics      = dx->LowerDevice->Characteristics;
    /* v4.0.2 hotfix: propagate AlignmentRequirement from lower.
     * Redundant post-v4.0.4 investigation (IoAttachDeviceToDeviceStack
     * already inherits this field) but harmless — kept as documented
     * hygiene per WDK "Initializing a Device Object". */
    flt->AlignmentRequirement = dx->LowerDevice->AlignmentRequirement;

    /* v4.0.4: initialize the paging-path serializer BEFORE clearing
     * DO_DEVICE_INITIALIZING (once cleared, IRPs may arrive). */
    ExInitializeFastMutex(&dx->PagingPathMutex);
    dx->PagingPathCount = 0;

    flt->Flags               &= ~DO_DEVICE_INITIALIZING;

#if DBG
    DbgPrint("[RstFlt] Attached to PDO %p (lower=%p)\n",
             Pdo, dx->LowerDevice);
#endif
    return STATUS_SUCCESS;
}

/* ================================================================
 *  (DriverUnload intentionally NOT provided.)
 *
 *  A DiskDrive upper-filter always has attachments — REMOVE IRPs
 *  are the only way this driver leaves the system, and they run
 *  through DispatchPnp above. Advertising DriverUnload would let
 *  `sc stop RstFlt` return success synchronously, letting a
 *  hot-replace path (sc stop → replace .sys → sc start) race the
 *  still-mapped image. Omitting it means service-stop reports
 *  "cannot stop — driver cannot accept requests" and forces a
 *  reboot for reinstall, which is the correct behavior.
 * ================================================================ */

/* ================================================================
 *  DriverEntry - queue CPU-registry replay worker, run SMBIOS blob
 *  best-effort no-op, register dispatch routines.
 *
 *  v4.0 ordering: CPU replay is race-sensitive against HAL's per-core
 *  value population and needs a long tick budget, so it goes off-
 *  thread via ExQueueWorkItem FIRST — no boot slowdown, and it starts
 *  scheduling before we sit on any hive I/O.
 *
 *  v4.0.6 correction (previous comment here was factually wrong):
 *  ApplySmbiosBlobIfCached is CURRENTLY a best-effort no-op on stock
 *  Windows. mssmbios.sys is SYSTEM_START (Start=1, verified 2026-08-30
 *  on Win10 Pro dev host) and loads AFTER RstFlt (BOOT_START, Start=0).
 *  ZwOpenKey on \\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services
 *  \\mssmbios\\Data typically returns STATUS_OBJECT_NAME_NOT_FOUND at
 *  BOOT_START init because the Data subkey is (re)created by mssmbios
 *  itself during its own SYSTEM_START init (likely REG_OPTION_VOLATILE).
 *  Even if we somehow raced and won, WMI (Win32_ComputerSystemProduct
 *  etc.) still returns firmware values because mssmbios reads them
 *  directly from ACPI RSMB / firmware physical memory via WmipGetRaw-
 *  SMBiosTableData, not from the registry mirror. Real WMI-visible
 *  spoof requires IRP_MJ_SYSTEM_CONTROL interception on \\Driver\\
 *  mssmbios — deferred to v4.1 (see docs/roadmap-v41-wmi-intercept.md).
 *  Function retained ONLY to (a) leave a Parameters\\LastReplayStatus
 *  breadcrumb for postmortem visibility (WriteLastReplayStatus) and
 *  (b) preserve the code path for the physical-hardware case where
 *  registry behavior may differ.
 *
 *  Both replays are best-effort and never propagate failure.
 * ================================================================ */
NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
    ULONG i;
    PCPU_REPLAY_CTX ctx = NULL;
    ULONG           ctxSize;
    USHORT          copyLen;


    /* v4.0.1 hotfix — EARLY GATE CHECK before allocating ctx or
       queuing any worker. Prior versions queued the worker
       unconditionally and let the worker itself read the
       EnableCpuReplay gate; that produced a reproducible boot
       freeze on physical hardware even with the gate = 0 (no
       BSOD, no dump, no bugcheck event — hang during driver
       init). Isolating the CPU-replay code path behind an
       explicit gate check here makes the driver functionally
       equivalent to v3.6 (SMBIOS-only) whenever the gate is
       absent or zero, which matches a proven stable config.

       Gate check itself uses only ZwOpenKey/ZwQueryValueKey on
       Parameters — the same primitives DriverEntry has always
       used for the SMBIOS opt-in and are known safe here. */
    if (IsCpuReplayEnabled(RegPath)) {
        /* Copy RegPath into a nonpaged allocation the worker owns.
           The IO manager's RegPath UNICODE_STRING is stack-scoped
           on our caller. Ctx alloc failure is silently non-fatal:
           the driver still loads, dispatch is set up, SMBIOS
           replay still runs, only CPU registry stays genuine for
           this boot. */
        copyLen = RegPath->Length;                          /* bytes    */
        ctxSize = (ULONG)(FIELD_OFFSET(CPU_REPLAY_CTX, RegPathBuffer) +
                          copyLen + sizeof(WCHAR));         /* + NUL    */

        ctx = (PCPU_REPLAY_CTX)
              ExAllocatePoolWithTag(NonPagedPool, ctxSize, POOL_TAG);
        if (ctx != NULL) {
            RtlZeroMemory(ctx, ctxSize);
            RtlCopyMemory(ctx->RegPathBuffer, RegPath->Buffer, copyLen);
            ctx->RegPath.Buffer        = ctx->RegPathBuffer;
            ctx->RegPath.Length        = copyLen;
            ctx->RegPath.MaximumLength = (USHORT)(copyLen + sizeof(WCHAR));

            ExInitializeWorkItem(&ctx->WorkItem,
                                 CpuReplayWorker,
                                 ctx);
            ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);
#if DBG
            DbgPrint("[RstFlt] CPU replay: gate ON, worker queued\n");
#endif
        }
#if DBG
        else {
            DbgPrint("[RstFlt] CPU replay: ctx alloc failed, skipping\n");
        }
#endif
    }
#if DBG
    else {
        DbgPrint("[RstFlt] CPU replay: gate OFF, worker not queued\n");
    }
#endif

    /* Replay cached SMBIOS blob (if the userspace tool has ever run
       AND EnableSmbiosReplay=1) into mssmbios\Data\SMBiosData.
       Doing this here — inside a SYSTEM_START driver's DriverEntry —
       beats winmgmt and any user-mode anti-cheat to the punch,
       killing the race that made the old scheduled-task approach
       unreliable. Failure is silently non-fatal: the driver still
       loads and disks still work; only the firmware SMBIOS values
       remain unchanged for that boot. */
    ApplySmbiosBlobIfCached(RegPath);

    /* v5.0.0 Track D: register the Cm registry callback for Enum\SCSI
       subkey name rewrite (MVP scope per docs/track-d-kernel-registry-
       callback-kickoff.md section 4). No-op unless
       Parameters\EnableRegCallback=1. Any failure is silent — driver
       still loads, other paths unaffected. See changelog above and
       ArmTrackD implementation for the safety contract. */
    (void)ArmTrackD(DrvObj, RegPath);

    /* Default: all IRPs pass through (v3.6: DEVICE_CONTROL included) */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DrvObj->MajorFunction[i] = DispatchPassthrough;

    /* Override PnP + Power with WDM-correct handlers */
    DrvObj->MajorFunction[IRP_MJ_PNP]   = DispatchPnp;
    DrvObj->MajorFunction[IRP_MJ_POWER] = DispatchPower;

    DrvObj->DriverExtension->AddDevice = AddDevice;
    /* Intentionally no DriverUnload — see note above. */

#if DBG
    DbgPrint("[RstFlt] DriverEntry OK (v5.0.3, SMBIOS no-op+breadcrumb + gated CPU replay + paging-path handler + Track D {SCSI,PCI,USB,HID,Audio} + multi-PID rubi-substring Ps notify (/INTEGRITYCHECK-signed) + Authenticode signed)\n");
#endif
    return STATUS_SUCCESS;
}
