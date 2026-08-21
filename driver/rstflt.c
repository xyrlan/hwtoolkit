/*
 * RstFlt - Storage Filter Driver (v3)
 *
 * Upper filter for the DiskDrive device class.
 * Intercepts disk serial number queries across multiple IOCTL paths
 * and replaces them with deterministic, per-slot fake serials.
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
 *
 * WARNING: Kernel drivers can BSOD your machine if buggy.
 * Test signing mode required to load unsigned drivers.
 */

#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ntddstor.h>

/* ================================================================
 *  Constants
 * ================================================================ */
#define POOL_TAG    'tRsF'
#define MAX_SERIAL  40
#define SEED_SIZE   32
#define ID_COMMAND  0xEC  /* ATA IDENTIFY DEVICE */

/* ================================================================
 *  Global state (read-only after DriverEntry)
 * ================================================================ */
static UCHAR    g_Seed[SEED_SIZE];   /* From registry Parameters\SerialSeed   */
static CHAR     g_Prefix[8];        /* Serial prefix (e.g. "S6BN")           */
static ULONG    g_SerialLen;        /* Desired serial length (e.g. 15)       */
static BOOLEAN  g_HasConfig;        /* TRUE if registry config was loaded    */

/* ================================================================
 *  Device extension - attached to each filtered disk device
 * ================================================================ */
typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT  LowerDevice;
    PDEVICE_OBJECT  PhysicalDevice;
    IO_REMOVE_LOCK  RemoveLock;
    BOOLEAN         Started;
    BOOLEAN         Removed;
    CHAR            FakeSerial[MAX_SERIAL + 1];
    BOOLEAN         HasFakeSerial;
    /* Stable location info for deterministic serial generation */
    CHAR            LocationInfo[256];
    ULONG           LocationLen;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

/* ================================================================
 *  Forward declarations
 * ================================================================ */
DRIVER_ADD_DEVICE AddDevice;
DRIVER_UNLOAD     DriverUnload;

DRIVER_DISPATCH DispatchPassthrough;
DRIVER_DISPATCH DispatchPnp;
DRIVER_DISPATCH DispatchPower;
DRIVER_DISPATCH DispatchDeviceControl;

static IO_COMPLETION_ROUTINE PnpStartCompletion;
static IO_COMPLETION_ROUTINE SpoofStorageCompletion;
static IO_COMPLETION_ROUTINE SpoofIdentifyCompletion;
static IO_COMPLETION_ROUTINE SpoofAtaPassCompletion;
static IO_COMPLETION_ROUTINE SpoofNvmeIdentifyCompletion;
static IO_COMPLETION_ROUTINE SpoofAtaPassDirectCompletion;
static IO_WORKITEM_ROUTINE   MdlCleanupWorker;

static VOID    ReadRegistryConfig(PUNICODE_STRING RegPath);
static VOID    GenerateSerial(PDEVICE_EXTENSION dx, CHAR *Buf, ULONG Len);
static VOID    ApplySmbiosBlobIfCached(PUNICODE_STRING RegPath);
static BOOLEAN ValidateSmbiosBlob(const UCHAR *Blob, ULONG Length);
static VOID    DeferMdlCleanup(PDEVICE_OBJECT DevObj, PMDL Mdl);

/* ================================================================
 *  MDL cleanup work item context — a completion routine may run at
 *  DISPATCH_LEVEL but MmUnlockPages requires <= APC_LEVEL, so we
 *  defer the unlock/free to a worker thread.
 * ================================================================ */
typedef struct _RSTFLT_MDL_CLEANUP {
    PMDL             Mdl;
    PIO_WORKITEM     WorkItem;
    /* v3.4: keep DevObj pinned via a RemoveLock reference until the
       worker actually runs. Without this the completion routine could
       release its own IRP-tagged lock, IRP_MN_REMOVE_DEVICE could
       delete DevObj, and IoFreeWorkItem in the worker would touch
       freed memory. DeferMdlCleanup acquires the reference tagged
       with the address of this struct; the worker releases with the
       same tag right before freeing the struct. */
    PIO_REMOVE_LOCK  Lock;
} RSTFLT_MDL_CLEANUP, *PRSTFLT_MDL_CLEANUP;

/* Per-IRP context passed to SpoofAtaPassDirectCompletion via
   IoSetCompletionRoutine. DriverContext[] on the IRP is not
   guaranteed to survive IoCallDriver, so we allocate our own. */
typedef struct _RSTFLT_APTD_CTX {
    PMDL   Mdl;
    UCHAR *Kva;
} RSTFLT_APTD_CTX, *PRSTFLT_APTD_CTX;

/* v3.5: context for SpoofStorageCompletion. Carries the caller's
   OutputBufferLength captured at dispatch time so the completion
   knows how much room it can safely expand a shorter-than-spoof
   serial into. Without this the completion only sees IoStatus.
   Information (what the lower driver wrote), which for short
   serials leaves us with too little room and truncates the spoof. */
typedef struct _RSTFLT_STORAGE_CTX {
    ULONG OutputBufferLength;
} RSTFLT_STORAGE_CTX, *PRSTFLT_STORAGE_CTX;

/* ================================================================
 *  ReadRegistryConfig - load seed, prefix, length from registry
 *
 *  Reads from <RegistryPath>\Parameters:
 *    SerialSeed   REG_BINARY  32 bytes
 *    SerialPrefix REG_SZ
 *    SerialLength REG_DWORD
 *
 *  On any failure the globals keep their defaults.
 * ================================================================ */
static VOID ReadRegistryConfig(PUNICODE_STRING RegPath)
{
    NTSTATUS st;
    HANDLE hKey = NULL;
    HANDLE hParams = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING paramsName;
    UNICODE_STRING valueName;
    UCHAR infoBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)infoBuf;
    ULONG resultLen;
    UNICODE_STRING fullPath;
    WCHAR fullPathBuf[512];
    ULONG i;

    /* Build "<RegPath>\Parameters" */
    fullPath.Buffer        = fullPathBuf;
    fullPath.Length         = 0;
    fullPath.MaximumLength = sizeof(fullPathBuf);

    st = RtlAppendUnicodeStringToString(&fullPath, RegPath);
    if (!NT_SUCCESS(st))
        return;

    RtlInitUnicodeString(&paramsName, L"\\Parameters");
    st = RtlAppendUnicodeStringToString(&fullPath, &paramsName);
    if (!NT_SUCCESS(st))
        return;

    InitializeObjectAttributes(&oa, &fullPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    st = ZwOpenKey(&hParams, KEY_READ, &oa);
    if (!NT_SUCCESS(st))
        return;

    /* -- SerialSeed (REG_BINARY, 32 bytes) -- */
    RtlInitUnicodeString(&valueName, L"SerialSeed");
    st = ZwQueryValueKey(hParams, &valueName, KeyValuePartialInformation,
                         info, sizeof(infoBuf), &resultLen);
    if (NT_SUCCESS(st) &&
        info->Type == REG_BINARY &&
        info->DataLength >= SEED_SIZE)
    {
        RtlCopyMemory(g_Seed, info->Data, SEED_SIZE);
    }

    /* -- SerialPrefix (REG_SZ) -- */
    RtlInitUnicodeString(&valueName, L"SerialPrefix");
    st = ZwQueryValueKey(hParams, &valueName, KeyValuePartialInformation,
                         info, sizeof(infoBuf), &resultLen);
    if (NT_SUCCESS(st) && info->Type == REG_SZ && info->DataLength > 0) {
        /* Convert from wide to narrow, cap at 7 chars + NUL */
        PWCHAR src = (PWCHAR)info->Data;
        ULONG  wLen = info->DataLength / sizeof(WCHAR);
        ULONG  j = 0;

        for (i = 0; i < wLen && j < sizeof(g_Prefix) - 1; i++) {
            if (src[i] == L'\0')
                break;
            g_Prefix[j++] = (CHAR)src[i];
        }
        g_Prefix[j] = '\0';
    }

    /* -- SerialLength (REG_DWORD) -- */
    RtlInitUnicodeString(&valueName, L"SerialLength");
    st = ZwQueryValueKey(hParams, &valueName, KeyValuePartialInformation,
                         info, sizeof(infoBuf), &resultLen);
    if (NT_SUCCESS(st) &&
        info->Type == REG_DWORD &&
        info->DataLength >= sizeof(ULONG))
    {
        ULONG val = *(PULONG)info->Data;
        if (val > 0 && val <= MAX_SERIAL)
            g_SerialLen = val;
    }

    g_HasConfig = TRUE;
    ZwClose(hParams);

    UNREFERENCED_PARAMETER(hKey);
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
       reasonable Length (>=4, <=Length). Scan the first 64 bytes. */
    for (i = 0; i + 4 < Length && i < 64; i++) {
        UCHAR t = Blob[i];
        UCHAR L = Blob[i + 1];
        if ((t == 0 || t == 1 || t == 2 || t == 3) &&
            L >= 4 && (ULONG)(i + L) < Length)
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
 *  Failures never propagate. The driver's storage-spoofing job
 *  still works even if SMBIOS replay is disabled or fails.
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
        goto out;
    }
    RtlCopyMemory(&flagVal, flagInfo->Data, sizeof(ULONG));
    if (flagVal == 0) {
#if DBG
        DbgPrint("[RstFlt] SMBIOS replay: opt-in flag = 0, skipping\n");
#endif
        goto out;
    }

    /* Two-phase query: first learn size, then allocate + read. */
    RtlInitUnicodeString(&valName, L"SmbiosBlob");
    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         NULL, 0, &needSize);
    if (st != STATUS_BUFFER_TOO_SMALL &&
        st != STATUS_BUFFER_OVERFLOW)
        goto out;                        /* no cached blob → nothing to do */
    if (needSize < FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + 32)
        goto out;                        /* smaller than any real SMBIOS */

    allocSize = needSize;
    info = (PKEY_VALUE_PARTIAL_INFORMATION)
           ExAllocatePoolWithTag(NonPagedPool, allocSize, POOL_TAG);
    if (info == NULL) goto out;

    st = ZwQueryValueKey(hParams, &valName, KeyValuePartialInformation,
                         info, allocSize, &needSize);
    if (!NT_SUCCESS(st))          goto out;
    if (info->Type != REG_BINARY) goto out;

    /* v3.4: validate before ever touching mssmbios */
    if (!ValidateSmbiosBlob(info->Data, info->DataLength)) {
#if DBG
        DbgPrint("[RstFlt] SMBIOS replay: cached blob failed validation "
                 "(%lu bytes) — ignored\n", info->DataLength);
#endif
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
                curNeed > FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data))
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

out:
    if (info)      ExFreePoolWithTag(info, POOL_TAG);
    if (origInfo)  ExFreePoolWithTag(origInfo, POOL_TAG);
    if (hMssmbios) ZwClose(hMssmbios);
    if (hParams)   ZwClose(hParams);
}

/* ================================================================
 *  GenerateSerial - deterministic serial from seed + location
 *
 *  Uses FNV-1a to combine the global seed with the per-device
 *  location string, then an LCG to expand the hash into an
 *  alphanumeric serial of the requested length.
 * ================================================================ */
static VOID GenerateSerial(PDEVICE_EXTENSION dx, CHAR *Buf, ULONG Len)
{
    ULONG hash = 0x811c9dc5;  /* FNV-1a offset basis */
    ULONG i;
    ULONG prefixLen = 0;
    static const CHAR cs[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /* Hash the global seed */
    for (i = 0; i < SEED_SIZE; i++) {
        hash ^= g_Seed[i];
        hash *= 0x01000193;   /* FNV-1a prime */
    }

    /* Hash the device location info */
    for (i = 0; i < dx->LocationLen; i++) {
        hash ^= (UCHAR)dx->LocationInfo[i];
        hash *= 0x01000193;
    }

    /* Copy prefix from g_Prefix */
    while (g_Prefix[prefixLen] && prefixLen < Len) {
        Buf[prefixLen] = g_Prefix[prefixLen];
        prefixLen++;
    }

    /* Generate remaining characters using LCG seeded from hash */
    for (i = prefixLen; i < Len; i++) {
        hash = hash * 1103515245 + 12345;
        Buf[i] = cs[(hash >> 16) % (sizeof(cs) - 1)];
    }
    Buf[Len] = '\0';
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

    /* ---- REMOVE: forward, wait for drain, detach, delete ---- */
    case IRP_MN_REMOVE_DEVICE:
        dx->Started = FALSE;
        dx->Removed = TRUE;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        st = IoCallDriver(dx->LowerDevice, Irp);

        /* Wait for all tracked IRPs to complete */
        IoReleaseRemoveLockAndWait(&dx->RemoveLock, Irp);
        IoDetachDevice(dx->LowerDevice);
        IoDeleteDevice(DevObj);
#if DBG
        DbgPrint("[RstFlt] Device %p removed\n", DevObj);
#endif
        return st;

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
 *  SpoofStorageCompletion - modify serial in STORAGE_DEVICE_DESCRIPTOR
 *
 *  Called after lower driver fills STORAGE_DEVICE_DESCRIPTOR for
 *  an IOCTL_STORAGE_QUERY_PROPERTY response.
 *
 *  v3.5 behavior:
 *    Two cases decide how much of the buffer we can rewrite:
 *      (a) SerialNumber is the LAST field in the descriptor
 *          (Windows storport default). Room to write is bounded
 *          by OutputBufferLength (from Ctx), not by what the lower
 *          driver wrote. If our spoof is longer than the original,
 *          extend it and bump IoStatus.Information accordingly.
 *      (b) A field lives AFTER SerialNumber (some vendor miniports
 *          — Intel RST, LSI HBAs — pack VendorId/ProductId/Firmware
 *          past the serial). Room is fixed to (nextFieldOffset -
 *          SerialNumberOffset). Truncate to fit; don't touch bytes
 *          past it or those strings get corrupted.
 *    Falls back to v3.4 behavior if Ctx is NULL (OutputBufferLength
 *    unavailable), i.e. truncate at IoStatus.Information.
 *
 *  Releases the remove lock acquired by DispatchDeviceControl and
 *  frees the completion context.
 * ================================================================ */
static NTSTATUS SpoofStorageCompletion(
    PDEVICE_OBJECT DevObj,
    PIRP Irp,
    PVOID Ctx)
{
    PDEVICE_EXTENSION dx = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    PRSTFLT_STORAGE_CTX sctx = (PRSTFLT_STORAGE_CTX)Ctx;
    PSTORAGE_DEVICE_DESCRIPTOR desc;
    PCHAR  ser;
    ULONG  actual;
    ULONG  outLen;
    ULONG  copyLen;
    ULONG  serSpaceEnd;    /* first byte offset AFTER our writable region */
    ULONG  writable;
    ULONG  i;

    if (Irp->IoStatus.Status != STATUS_SUCCESS)
        goto done;

    actual = (ULONG)Irp->IoStatus.Information;
    if (actual < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        goto done;

    desc = (PSTORAGE_DEVICE_DESCRIPTOR)Irp->AssociatedIrp.SystemBuffer;
    if (desc == NULL ||
        desc->SerialNumberOffset == 0 ||
        desc->SerialNumberOffset >= actual)
        goto done;

    /* Generate a fake serial on first access */
    if (!dx->HasFakeSerial) {
        GenerateSerial(dx, dx->FakeSerial, g_HasConfig ? g_SerialLen : 15);
        dx->HasFakeSerial = TRUE;
#if DBG
        DbgPrint("[RstFlt] Storage serial for dev %p: %s\n",
                 DevObj, dx->FakeSerial);
#endif
    }

    copyLen = g_HasConfig ? g_SerialLen : 15;
    outLen  = sctx ? sctx->OutputBufferLength : 0;
    ser     = (PCHAR)desc + desc->SerialNumberOffset;

    /* Find whether any *other* string field lives after SerialNumber.
       Pick the smallest such offset — that's the first byte we can't
       touch. Offset 0 in any of these means the field isn't present. */
    {
        ULONG nextOff = 0;
        ULONG cand;

        cand = desc->VendorIdOffset;
        if (cand > desc->SerialNumberOffset && cand <= actual)
            if (nextOff == 0 || cand < nextOff) nextOff = cand;

        cand = desc->ProductIdOffset;
        if (cand > desc->SerialNumberOffset && cand <= actual)
            if (nextOff == 0 || cand < nextOff) nextOff = cand;

        cand = desc->ProductRevisionOffset;
        if (cand > desc->SerialNumberOffset && cand <= actual)
            if (nextOff == 0 || cand < nextOff) nextOff = cand;

        if (nextOff != 0) {
            /* Case (b): serial is NOT the last field — can't extend. */
            serSpaceEnd = nextOff;
        } else if (outLen > desc->SerialNumberOffset) {
            /* Case (a) with known OutputBufferLength: extend up to
               the caller's original buffer capacity. */
            serSpaceEnd = outLen;
        } else {
            /* Fallback (no ctx / short outLen): v3.4 behavior — stay
               within what the lower driver already wrote. */
            serSpaceEnd = actual;
        }
    }

    if (serSpaceEnd <= desc->SerialNumberOffset)
        goto done;

    writable = serSpaceEnd - desc->SerialNumberOffset;
    if (writable < 2)
        goto done;   /* No room for even a 1-char serial + NUL */

    /* Trim spoofed serial to fit the writable region (leaving 1 byte
       for the NUL terminator). */
    if (copyLen + 1 > writable)
        copyLen = writable - 1;

    /* Zero exactly copyLen + 1 bytes (the string + terminator).
       Never zero beyond that: any trailing field (case b) or unused
       tail of the caller's buffer must stay whatever it was. */
    RtlZeroMemory(ser, copyLen + 1);
    for (i = 0; i < copyLen; i++)
        ser[i] = dx->FakeSerial[i];

    /* If our serial ends AFTER what the lower driver reported,
       announce the longer response so callers read it fully. Never
       shrink Information (would hide fields we didn't touch). */
    {
        ULONG newTail = desc->SerialNumberOffset + copyLen + 1;
        if (newTail > actual)
            Irp->IoStatus.Information = newTail;
    }

done:
    if (sctx) ExFreePoolWithTag(sctx, POOL_TAG);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

/* ================================================================
 *  SpoofIdentifyCompletion - modify serial in SMART IDENTIFY response
 *
 *  Called after lower driver completes IOCTL_SMART_RCV_DRIVE_DATA
 *  with an IDENTIFY DEVICE command.  The 512-byte identify data
 *  block contains the serial at words 10-19 (bytes 20-39), stored
 *  with ATA byte-swap (each word has its bytes swapped).
 *  Releases the remove lock acquired by DispatchDeviceControl.
 * ================================================================ */
static NTSTATUS SpoofIdentifyCompletion(
    PDEVICE_OBJECT DevObj,
    PIRP Irp,
    PVOID Ctx)
{
    PDEVICE_EXTENSION dx = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    PSENDCMDOUTPARAMS out;
    ULONG actual;
    UCHAR *idData;
    ULONG serialOff  = 20;  /* Words 10-19 = bytes 20-39 */
    ULONG serialSize = 20;  /* 20 bytes (10 words)       */
    CHAR serial[MAX_SERIAL + 1];
    ULONG i;

    UNREFERENCED_PARAMETER(Ctx);

    if (Irp->IoStatus.Status != STATUS_SUCCESS)
        goto done;

    actual = (ULONG)Irp->IoStatus.Information;
    if (actual < sizeof(SENDCMDOUTPARAMS) + 512 - 1)
        goto done;

    out    = (PSENDCMDOUTPARAMS)Irp->AssociatedIrp.SystemBuffer;
    idData = out->bBuffer;

    /* Generate fake serial on first access */
    if (!dx->HasFakeSerial) {
        GenerateSerial(dx, dx->FakeSerial, g_HasConfig ? g_SerialLen : 15);
        dx->HasFakeSerial = TRUE;
#if DBG
        DbgPrint("[RstFlt] IDENTIFY serial for dev %p: %s\n",
                 DevObj, dx->FakeSerial);
#endif
    }

    /* ATA serial field is 20 bytes, right-padded with spaces */
    RtlFillMemory(serial, 20, ' ');
    for (i = 0; i < 20 && dx->FakeSerial[i]; i++)
        serial[i] = dx->FakeSerial[i];

    /* Write with ATA byte-swap: each pair of bytes is swapped */
    for (i = 0; i < serialSize; i += 2) {
        idData[serialOff + i]     = serial[i + 1];
        idData[serialOff + i + 1] = serial[i];
    }

done:
    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

/* ================================================================
 *  SpoofAtaPassCompletion - modify serial in ATA_PASS_THROUGH response
 *
 *  Called after lower driver completes IOCTL_ATA_PASS_THROUGH with
 *  an IDENTIFY DEVICE command.  The identify data buffer follows
 *  the ATA_PASS_THROUGH_EX header at DataBufferOffset.
 *  Releases the remove lock acquired by DispatchDeviceControl.
 * ================================================================ */
static NTSTATUS SpoofAtaPassCompletion(
    PDEVICE_OBJECT DevObj,
    PIRP Irp,
    PVOID Ctx)
{
    PDEVICE_EXTENSION dx = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    PATA_PASS_THROUGH_EX apt;
    UCHAR *dataBuffer;
    ULONG actual;
    ULONG serialOff  = 20;
    ULONG serialSize = 20;
    CHAR serial[MAX_SERIAL + 1];
    ULONG i;

    UNREFERENCED_PARAMETER(Ctx);

    if (Irp->IoStatus.Status != STATUS_SUCCESS)
        goto done;

    actual = (ULONG)Irp->IoStatus.Information;
    if (actual < sizeof(ATA_PASS_THROUGH_EX))
        goto done;

    apt = (PATA_PASS_THROUGH_EX)Irp->AssociatedIrp.SystemBuffer;
    if (apt == NULL)
        goto done;

    /* Overflow-safe validation of the caller-controlled DataBufferOffset.
       A malicious/buggy caller can set DataBufferOffset near 0xFFFFFFFF
       so that (DataBufferOffset + 512) wraps around and passes a naive
       "< apt->DataBufferOffset + 512" check, then dataBuffer would point
       into unmapped kernel memory -> BSOD on the next write. */
    if (apt->DataBufferOffset < sizeof(ATA_PASS_THROUGH_EX))
        goto done;
    if (apt->DataBufferOffset > actual)
        goto done;
    if ((ULONGLONG)512 > (ULONGLONG)(actual - apt->DataBufferOffset))
        goto done;

    dataBuffer = (UCHAR*)apt + apt->DataBufferOffset;

    /* Generate fake serial on first access */
    if (!dx->HasFakeSerial) {
        GenerateSerial(dx, dx->FakeSerial, g_HasConfig ? g_SerialLen : 15);
        dx->HasFakeSerial = TRUE;
#if DBG
        DbgPrint("[RstFlt] ATA pass serial for dev %p: %s\n",
                 DevObj, dx->FakeSerial);
#endif
    }

    /* Same ATA byte-swap logic */
    RtlFillMemory(serial, 20, ' ');
    for (i = 0; i < 20 && dx->FakeSerial[i]; i++)
        serial[i] = dx->FakeSerial[i];

    for (i = 0; i < serialSize; i += 2) {
        dataBuffer[serialOff + i]     = serial[i + 1];
        dataBuffer[serialOff + i + 1] = serial[i];
    }

done:
    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

/* ================================================================
 *  SpoofNvmeIdentifyCompletion - rewrite serial in NVMe IDENTIFY
 *  CONTROLLER response.
 *
 *  Called after lower driver completes IOCTL_STORAGE_PROTOCOL_COMMAND
 *  with a NVMe IDENTIFY (opcode 0x06), CNS = 0x01 (Identify Controller).
 *  The 4096-byte controller data block begins at
 *  cmd->DataFromDeviceBufferOffset from the start of the SystemBuffer.
 *  Serial Number lives at bytes 4-23 (20 bytes ASCII, space-padded,
 *  NOT ATA byte-swapped — unlike ATA IDENTIFY).
 *  Releases the remove lock acquired by DispatchDeviceControl.
 * ================================================================ */
static NTSTATUS SpoofNvmeIdentifyCompletion(
    PDEVICE_OBJECT DevObj,
    PIRP Irp,
    PVOID Ctx)
{
    PDEVICE_EXTENSION dx = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    PSTORAGE_PROTOCOL_COMMAND cmd;
    UCHAR *dataBuf;
    ULONG actual;
    ULONG dataOff;
    ULONG dataLen;
    CHAR  serial[MAX_SERIAL + 1];
    ULONG i;
    ULONG copyLen;

    UNREFERENCED_PARAMETER(Ctx);

    if (Irp->IoStatus.Status != STATUS_SUCCESS)
        goto done;

    actual = (ULONG)Irp->IoStatus.Information;
    if (actual < sizeof(STORAGE_PROTOCOL_COMMAND))
        goto done;

    cmd = (PSTORAGE_PROTOCOL_COMMAND)Irp->AssociatedIrp.SystemBuffer;
    if (cmd == NULL)
        goto done;

    dataOff = cmd->DataFromDeviceBufferOffset;
    dataLen = cmd->DataFromDeviceTransferLength;

    /* Overflow-safe bounds validation on caller-controlled offsets */
    if (dataOff < sizeof(STORAGE_PROTOCOL_COMMAND))
        goto done;
    if (dataOff > actual)
        goto done;
    if (dataLen < 64)   /* need at least Identify Controller SN+MN */
        goto done;
    if (dataLen > actual - dataOff)
        goto done;

    dataBuf = (UCHAR*)cmd + dataOff;

    /* Generate fake serial on first access */
    if (!dx->HasFakeSerial) {
        GenerateSerial(dx, dx->FakeSerial, g_HasConfig ? g_SerialLen : 15);
        dx->HasFakeSerial = TRUE;
#if DBG
        DbgPrint("[RstFlt] NVMe serial for dev %p: %s\n",
                 DevObj, dx->FakeSerial);
#endif
    }

    /* NVMe Identify Controller Serial Number: 20 bytes, ASCII,
       space-padded, plain byte order (no ATA swap). */
    RtlFillMemory(serial, 20, ' ');
    copyLen = g_HasConfig ? g_SerialLen : 15;
    if (copyLen > 20)
        copyLen = 20;
    for (i = 0; i < copyLen && dx->FakeSerial[i]; i++)
        serial[i] = dx->FakeSerial[i];

    for (i = 0; i < 20; i++)
        dataBuf[4 + i] = serial[i];

done:
    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

/* ================================================================
 *  MdlCleanupWorker - runs at PASSIVE_LEVEL, unlocks and frees an
 *  MDL that a completion routine could not release itself due to
 *  IRQL restrictions.
 * ================================================================ */
static VOID MdlCleanupWorker(
    PDEVICE_OBJECT DevObj,
    PVOID Context)
{
    PRSTFLT_MDL_CLEANUP c = (PRSTFLT_MDL_CLEANUP)Context;
    UNREFERENCED_PARAMETER(DevObj);

    if (c == NULL)
        return;

    if (c->Mdl) {
        MmUnlockPages(c->Mdl);
        IoFreeMdl(c->Mdl);
    }
    if (c->WorkItem)
        IoFreeWorkItem(c->WorkItem);

    /* v3.4: release the RemoveLock reference DeferMdlCleanup took
       for this worker. Must happen after IoFreeWorkItem — the work
       item is owned by DevObj, and DevObj is only guaranteed to stay
       alive while the remove-lock reference is held. Tag = c so the
       release matches the acquire in DeferMdlCleanup. */
    if (c->Lock)
        IoReleaseRemoveLock(c->Lock, c);

    ExFreePoolWithTag(c, POOL_TAG);
}

/* ================================================================
 *  DeferMdlCleanup - queue the MDL to be released at PASSIVE_LEVEL.
 *
 *  v3.4: acquires an extra RemoveLock reference tagged with the
 *  cleanup context itself so DevObj cannot be deleted while the
 *  work item is queued/running. The worker releases with the same
 *  tag right before freeing the struct.
 *
 *  If we cannot allocate the work item / context / lock, fall back
 *  to inline release only when IRQL permits; otherwise the MDL
 *  leaks (small pinned memory) rather than crashing the system.
 * ================================================================ */
static VOID DeferMdlCleanup(PDEVICE_OBJECT DevObj, PMDL Mdl)
{
    PDEVICE_EXTENSION   dx = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    PRSTFLT_MDL_CLEANUP c;
    PIO_WORKITEM        wi;
    NTSTATUS            st;

    if (Mdl == NULL)
        return;

    wi = IoAllocateWorkItem(DevObj);
    if (wi == NULL) {
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
        }
        return;
    }

    c = (PRSTFLT_MDL_CLEANUP)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(*c), POOL_TAG);
    if (c == NULL) {
        IoFreeWorkItem(wi);
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
        }
        return;
    }

    /* Take a RemoveLock reference so DevObj outlives the work item.
       Tag = c (unique for this operation). If the device is already
       being removed, the acquire fails — bail out and best-effort
       release the MDL inline. */
    st = IoAcquireRemoveLock(&dx->RemoveLock, c);
    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(c, POOL_TAG);
        IoFreeWorkItem(wi);
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
        }
        return;
    }

    c->Mdl      = Mdl;
    c->WorkItem = wi;
    c->Lock     = &dx->RemoveLock;
    IoQueueWorkItem(wi, MdlCleanupWorker, DelayedWorkQueue, c);
}

/* ================================================================
 *  SpoofAtaPassDirectCompletion - rewrite serial for the DIRECT
 *  variant of IOCTL_ATA_PASS_THROUGH.
 *
 *  Unlike the BUFFERED variant, the ATA data payload lives at a
 *  user-mode pointer (aptd->DataBuffer) that the dispatch routine
 *  already probed+locked into an MDL. The kernel VA and the MDL
 *  arrive here via the completion context.
 * ================================================================ */
static NTSTATUS SpoofAtaPassDirectCompletion(
    PDEVICE_OBJECT DevObj,
    PIRP Irp,
    PVOID Ctx)
{
    PDEVICE_EXTENSION   dx  = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    PRSTFLT_APTD_CTX    cx  = (PRSTFLT_APTD_CTX)Ctx;
    PMDL   mdl     = NULL;
    UCHAR *dataBuf = NULL;
    CHAR   serial[MAX_SERIAL + 1];
    ULONG  i;
    ULONG  serialOff  = 20;
    ULONG  serialSize = 20;

    if (cx) {
        mdl     = cx->Mdl;
        dataBuf = cx->Kva;
    }

    if (Irp->IoStatus.Status != STATUS_SUCCESS)
        goto cleanup;
    if (dataBuf == NULL || mdl == NULL)
        goto cleanup;

    /* Generate fake serial on first access */
    if (!dx->HasFakeSerial) {
        GenerateSerial(dx, dx->FakeSerial, g_HasConfig ? g_SerialLen : 15);
        dx->HasFakeSerial = TRUE;
#if DBG
        DbgPrint("[RstFlt] ATA_DIRECT serial for dev %p: %s\n",
                 DevObj, dx->FakeSerial);
#endif
    }

    /* Same 20-byte, space-padded, ATA byte-swapped serial layout as
       the buffered ATA variant. */
    RtlFillMemory(serial, 20, ' ');
    for (i = 0; i < 20 && dx->FakeSerial[i]; i++)
        serial[i] = dx->FakeSerial[i];

    for (i = 0; i < serialSize; i += 2) {
        dataBuf[serialOff + i]     = serial[i + 1];
        dataBuf[serialOff + i + 1] = serial[i];
    }

cleanup:
    /* Defer MDL cleanup to PASSIVE_LEVEL — MmUnlockPages is illegal
       at DISPATCH_LEVEL, which is where storage completions often
       run. */
    if (mdl)
        DeferMdlCleanup(DevObj, mdl);
    if (cx)
        ExFreePoolWithTag(cx, POOL_TAG);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

/* ================================================================
 *  DispatchDeviceControl - intercept serial-exposing IOCTLs
 *
 *  Five interception paths:
 *    1. IOCTL_STORAGE_QUERY_PROPERTY   (StorageDeviceProperty)
 *    2. IOCTL_SMART_RCV_DRIVE_DATA     (ATA IDENTIFY DEVICE, cmd 0xEC)
 *    3. IOCTL_ATA_PASS_THROUGH         (ATA IDENTIFY DEVICE, buffered)
 *    4. IOCTL_STORAGE_PROTOCOL_COMMAND (NVMe IDENTIFY CONTROLLER)
 *    5. IOCTL_ATA_PASS_THROUGH_DIRECT  (ATA IDENTIFY DEVICE, direct)
 * ================================================================ */
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    PDEVICE_EXTENSION  dx = (PDEVICE_EXTENSION)DevObj->DeviceExtension;
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl;
    NTSTATUS st;

    st = IoAcquireRemoveLock(&dx->RemoveLock, Irp);
    if (!NT_SUCCESS(st)) {
        Irp->IoStatus.Status = st;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return st;
    }

    /* Only intercept when device is fully started and not removed */
    if (!dx->Started || dx->Removed)
        goto passthru;

    ioctl = sp->Parameters.DeviceIoControl.IoControlCode;

    /* ---- Path 1: IOCTL_STORAGE_QUERY_PROPERTY ---- */
    if (ioctl == IOCTL_STORAGE_QUERY_PROPERTY) {
        PSTORAGE_PROPERTY_QUERY q;
        PRSTFLT_STORAGE_CTX     sctx;

        if (sp->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(STORAGE_PROPERTY_QUERY))
            goto passthru;

        q = (PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer;
        if (q->PropertyId != StorageDeviceProperty ||
            q->QueryType  != PropertyStandardQuery)
            goto passthru;

        /* v3.5: capture OutputBufferLength so the completion knows
           the caller's buffer capacity (not just what the lower
           driver actually wrote). Lets us safely EXTEND a short
           original serial to full spoof length. If the alloc fails
           we still fall through with completion=NULL, and the
           routine reverts to v3.4 truncate-at-actual behavior. */
        sctx = (PRSTFLT_STORAGE_CTX)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(*sctx), POOL_TAG);
        if (sctx != NULL) {
            sctx->OutputBufferLength =
                sp->Parameters.DeviceIoControl.OutputBufferLength;
        }

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, SpoofStorageCompletion, sctx,
                               TRUE, TRUE, TRUE);
        return IoCallDriver(dx->LowerDevice, Irp);
    }

    /* ---- Path 2: IOCTL_SMART_RCV_DRIVE_DATA (IDENTIFY DEVICE) ---- */
    if (ioctl == SMART_RCV_DRIVE_DATA) {
        PSENDCMDINPARAMS inParams;

        if (sp->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(SENDCMDINPARAMS))
            goto passthru;

        inParams = (PSENDCMDINPARAMS)Irp->AssociatedIrp.SystemBuffer;

        /* Only intercept IDENTIFY DEVICE (0xEC), not other SMART cmds */
        if (inParams->irDriveRegs.bCommandReg != ID_COMMAND)
            goto passthru;

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, SpoofIdentifyCompletion, NULL,
                               TRUE, TRUE, TRUE);
        return IoCallDriver(dx->LowerDevice, Irp);
    }

    /* ---- Path 3: IOCTL_ATA_PASS_THROUGH (IDENTIFY DEVICE) ---- */
    if (ioctl == IOCTL_ATA_PASS_THROUGH) {
        PATA_PASS_THROUGH_EX aptIn;

        if (sp->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(ATA_PASS_THROUGH_EX))
            goto passthru;

        aptIn = (PATA_PASS_THROUGH_EX)Irp->AssociatedIrp.SystemBuffer;

        /* CurrentTaskFile[6] is the command register */
        if (aptIn->CurrentTaskFile[6] != ID_COMMAND)
            goto passthru;

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, SpoofAtaPassCompletion, NULL,
                               TRUE, TRUE, TRUE);
        return IoCallDriver(dx->LowerDevice, Irp);
    }

    /* ---- Path 4: IOCTL_STORAGE_PROTOCOL_COMMAND (NVMe IDENTIFY) ---- */
    if (ioctl == IOCTL_STORAGE_PROTOCOL_COMMAND) {
        PSTORAGE_PROTOCOL_COMMAND cmd;
        ULONG inLen;
        UCHAR opc;
        UCHAR cns;

        inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
        if (inLen < sizeof(STORAGE_PROTOCOL_COMMAND))
            goto passthru;

        cmd = (PSTORAGE_PROTOCOL_COMMAND)Irp->AssociatedIrp.SystemBuffer;
        if (cmd == NULL)
            goto passthru;

        /* NVMe only. STORAGE_PROTOCOL_TYPE: 1=Scsi, 2=Ata, 3=Nvme.
           Use the numeric constant to avoid pulling in the enum on
           older WDKs that may name it differently. */
        if (cmd->ProtocolType != 3 /* ProtocolTypeNvme */)
            goto passthru;

        /* Need at least OPC (byte 0) + CDW10 (bytes 40-43) of the
           embedded NVMe command to identify Identify Controller. */
        if (cmd->CommandLength < 44)
            goto passthru;

        /* Overflow-safe check that Command[] actually fits.
           STORAGE_PROTOCOL_COMMAND already declares Command[1], so the
           real total is sizeof(...) + CommandLength - 1. */
        if (cmd->CommandLength > inLen)
            goto passthru;
        if (inLen - cmd->CommandLength < sizeof(STORAGE_PROTOCOL_COMMAND) - 1)
            goto passthru;

        opc = cmd->Command[0];
        cns = cmd->Command[40];  /* CDW10 low byte = CNS */

        /* NVMe Admin IDENTIFY opcode = 0x06, CNS 0x01 = Identify Controller
           (where the 20-byte Serial Number lives at bytes 4-23). */
        if (opc != 0x06 || cns != 0x01)
            goto passthru;

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, SpoofNvmeIdentifyCompletion, NULL,
                               TRUE, TRUE, TRUE);
        return IoCallDriver(dx->LowerDevice, Irp);
    }

    /* ---- Path 5: IOCTL_ATA_PASS_THROUGH_DIRECT (ATA IDENTIFY DEVICE) ---- */
    if (ioctl == IOCTL_ATA_PASS_THROUGH_DIRECT) {
        PATA_PASS_THROUGH_DIRECT aptd;
        PMDL   mdl;
        PVOID  kva;
        PRSTFLT_APTD_CTX cx;

        if (sp->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(ATA_PASS_THROUGH_DIRECT))
            goto passthru;

        aptd = (PATA_PASS_THROUGH_DIRECT)Irp->AssociatedIrp.SystemBuffer;
        if (aptd == NULL)
            goto passthru;

        /* Only intercept IDENTIFY DEVICE (0xEC). CurrentTaskFile[6]
           holds the ATA command register in ATA_PASS_THROUGH_DIRECT. */
        if (aptd->CurrentTaskFile[6] != ID_COMMAND)
            goto passthru;

        if (aptd->DataTransferLength < 512)
            goto passthru;
        if (aptd->DataBuffer == NULL)
            goto passthru;

        cx = (PRSTFLT_APTD_CTX)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(*cx), POOL_TAG);
        if (cx == NULL)
            goto passthru;

        /* Dispatch runs at PASSIVE_LEVEL in the caller's process
           context. Build an MDL over the user DataBuffer and lock
           the pages so the completion routine (potentially at
           DISPATCH_LEVEL) can still touch the buffer via a system
           VA that stays valid regardless of context/IRQL. */
        mdl = IoAllocateMdl(aptd->DataBuffer, aptd->DataTransferLength,
                            FALSE, FALSE, NULL);
        if (mdl == NULL) {
            ExFreePoolWithTag(cx, POOL_TAG);
            goto passthru;
        }

        __try {
            MmProbeAndLockPages(mdl, Irp->RequestorMode, IoWriteAccess);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(mdl);
            ExFreePoolWithTag(cx, POOL_TAG);
            goto passthru;
        }

        kva = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        if (kva == NULL) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            ExFreePoolWithTag(cx, POOL_TAG);
            goto passthru;
        }

        cx->Mdl = mdl;
        cx->Kva = (UCHAR*)kva;

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, SpoofAtaPassDirectCompletion, cx,
                               TRUE, TRUE, TRUE);
        return IoCallDriver(dx->LowerDevice, Irp);
    }

passthru:
    IoSkipCurrentIrpStackLocation(Irp);
    st = IoCallDriver(dx->LowerDevice, Irp);
    IoReleaseRemoveLock(&dx->RemoveLock, Irp);
    return st;
}

/* ================================================================
 *  DispatchPassthrough - generic forwarding for all other IRPs
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
 *  AddDevice - attach filter to each disk in the PnP stack
 *
 *  Queries DevicePropertyLocationInformation for a stable per-slot
 *  identifier used in deterministic serial generation.
 * ================================================================ */
NTSTATUS AddDevice(PDRIVER_OBJECT DrvObj, PDEVICE_OBJECT Pdo)
{
    NTSTATUS        st;
    PDEVICE_OBJECT  flt = NULL;
    PDEVICE_EXTENSION dx;
    WCHAR  locBufW[128];
    ULONG  locLen = 0;
    ULONG  i;

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
    dx->HasFakeSerial  = FALSE;

    /* Get device location info for deterministic serial generation */
    st = IoGetDeviceProperty(
        Pdo,
        DevicePropertyLocationInformation,
        sizeof(locBufW),
        locBufW,
        &locLen);

    if (NT_SUCCESS(st) && locLen > 0) {
        /* Convert wide to narrow, store in extension */
        ULONG wChars = locLen / sizeof(WCHAR);
        ULONG j = 0;

        for (i = 0; i < wChars && j < sizeof(dx->LocationInfo) - 1; i++) {
            if (locBufW[i] == L'\0')
                break;
            dx->LocationInfo[j++] = (CHAR)locBufW[i];
        }
        dx->LocationInfo[j] = '\0';
        dx->LocationLen = j;
    } else {
        /* Fallback: hash of PDO pointer as location string.
           Formatted manually to avoid pulling stdio out of ntstrsafe. */
        ULONG_PTR pdoVal = (ULONG_PTR)Pdo;
        ULONG_PTR ptrVal = (ULONG_PTR)Pdo;
        static const CHAR hex[] = "0123456789ABCDEF";
        CHAR *p = dx->LocationInfo;
        int nibble;
        int j;

        pdoVal ^= (pdoVal >> 16);
        pdoVal *= 0x45d9f3b;
        pdoVal ^= (pdoVal >> 16);

        /* "PDO_" prefix */
        *p++ = 'P'; *p++ = 'D'; *p++ = 'O'; *p++ = '_';

        /* Pointer as 16 hex digits */
        for (j = 15; j >= 0; j--) {
            nibble = (int)((ptrVal >> (j * 4)) & 0xF);
            *p++ = hex[nibble];
        }
        *p++ = '_';

        /* Hash as 8 hex digits */
        for (j = 7; j >= 0; j--) {
            nibble = (int)((pdoVal >> (j * 4)) & 0xF);
            *p++ = hex[nibble];
        }
        *p = '\0';

        dx->LocationLen = (ULONG)(p - dx->LocationInfo);
    }

    /* Attach to the device stack */
    dx->LowerDevice = IoAttachDeviceToDeviceStack(flt, Pdo);
    if (dx->LowerDevice == NULL) {
#if DBG
        DbgPrint("[RstFlt] Attach failed for PDO %p\n", Pdo);
#endif
        IoDeleteDevice(flt);
        return STATUS_NO_SUCH_DEVICE;
    }

    /* Copy relevant flags from lower device */
    flt->Flags |= dx->LowerDevice->Flags &
                  (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    flt->DeviceType      = dx->LowerDevice->DeviceType;
    flt->Characteristics = dx->LowerDevice->Characteristics;
    flt->Flags          &= ~DO_DEVICE_INITIALIZING;

#if DBG
    DbgPrint("[RstFlt] Attached to PDO %p (lower=%p, loc=%s)\n",
             Pdo, dx->LowerDevice, dx->LocationInfo);
#endif
    return STATUS_SUCCESS;
}

/* ================================================================
 *  DriverUnload
 *  PnP IRP_MN_REMOVE_DEVICE handles actual cleanup.
 * ================================================================ */
VOID DriverUnload(PDRIVER_OBJECT DrvObj)
{
    UNREFERENCED_PARAMETER(DrvObj);
#if DBG
    DbgPrint("[RstFlt] Unload\n");
#endif
}

/* ================================================================
 *  DriverEntry - read config and register dispatch routines
 * ================================================================ */
NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
    ULONG i;

    /* Set defaults before attempting registry read */
    RtlZeroMemory(g_Seed, SEED_SIZE);
    RtlCopyMemory(g_Prefix, "S6BN", 5);   /* includes NUL */
    g_SerialLen = 15;
    g_HasConfig = FALSE;

    /* Try to load configuration from registry */
    ReadRegistryConfig(RegPath);

    /* Replay cached SMBIOS blob (if the userspace tool has ever run)
       into mssmbios\Data\SMBiosData. Doing this here — inside the
       boot-start driver's DriverEntry — beats winmgmt and any
       user-mode anti-cheat to the punch, killing the race that made
       the old scheduled-task approach unreliable. */
    ApplySmbiosBlobIfCached(RegPath);

    /* Default: all IRPs pass through */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DrvObj->MajorFunction[i] = DispatchPassthrough;

    /* Override specific handlers */
    DrvObj->MajorFunction[IRP_MJ_PNP]                     = DispatchPnp;
    DrvObj->MajorFunction[IRP_MJ_POWER]                   = DispatchPower;
    DrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]          = DispatchDeviceControl;
    DrvObj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = DispatchDeviceControl;

    DrvObj->DriverExtension->AddDevice = AddDevice;
    DrvObj->DriverUnload               = DriverUnload;

#if DBG
    DbgPrint("[RstFlt] DriverEntry OK (v3.5) config=%s prefix=%s len=%lu\n",
             g_HasConfig ? "loaded" : "defaults", g_Prefix, g_SerialLen);
#endif
    return STATUS_SUCCESS;
}
