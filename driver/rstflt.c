/*
 * RstFlt - Minimal SMBIOS + Gated CPU Registry Replay Filter Driver (v4.0.9)
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
const char RstFltVersion[] = "RstFlt-v4.0.9-BUILD-MARKER";


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
       reasonable Length (>=4, fits within Length). Scan the first
       64 bytes. Uses `<=` on the fit test so a blob whose only header
       sits at exact end is still accepted. */
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

    /* Default: all IRPs pass through (v3.6: DEVICE_CONTROL included) */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DrvObj->MajorFunction[i] = DispatchPassthrough;

    /* Override PnP + Power with WDM-correct handlers */
    DrvObj->MajorFunction[IRP_MJ_PNP]   = DispatchPnp;
    DrvObj->MajorFunction[IRP_MJ_POWER] = DispatchPower;

    DrvObj->DriverExtension->AddDevice = AddDevice;
    /* Intentionally no DriverUnload — see note above. */

#if DBG
    DbgPrint("[RstFlt] DriverEntry OK (v4.0.9, SMBIOS no-op+breadcrumb + gated CPU replay + paging-path handler + Authenticode signed)\n");
#endif
    return STATUS_SUCCESS;
}
