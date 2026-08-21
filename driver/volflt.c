/*
 * VolFlt - Volume Serial Number spoofing minifilter (v1.0)
 *
 * Companion to rstflt. Rewrites the ULONG VolumeSerialNumber that
 * NTFS/FAT/exFAT return in FileFsVolumeInformation queries — the
 * value virtually every anti-cheat / telemetry collector reads via
 * GetVolumeInformationW(L"C:\\", ..., &vsn, ...).
 *
 * Why a MINIFILTER and not a volume upper filter:
 *   FileFsVolumeInformation is served from the FS driver (NTFS/FAT)
 *   directly out of the mounted-volume's cached BPB. The query does
 *   NOT descend to the volume device object, so a legacy upper
 *   filter on the Volume setup class never sees it. Only something
 *   riding above the FS — i.e. a minifilter — can intercept.
 *
 * Design:
 *   - Post-callback on IRP_MJ_QUERY_VOLUME_INFORMATION with
 *     FsInformationClass == FileFsVolumeInformation.
 *   - Pre-callback returns SUCCESS_NO_CALLBACK for all other info
 *     classes so we don't pay IRP-tracking cost on every FS query.
 *   - Fake VSN = FNV-1a( SerialSeed (from registry, shared with
 *     rstflt) + volume device name from FltGetVolumeName ). Stable
 *     across reboots for the same volume; changes across profiles.
 *   - InstanceSetup only attaches to disk FS (NTFS/FAT/exFAT).
 *     Network / CD / RAM / unknown are skipped — spoofing UNC or
 *     ISO VSNs breaks nothing but exposes us to more surface.
 *   - StartType = SYSTEM_START (never BOOT_START). If DriverEntry
 *     ever fails, the machine boots without VSN spoofing rather
 *     than requiring WinRE recovery.
 *
 * WARNING: kernel drivers can BSOD your machine if buggy. This one
 * only overwrites a fixed 4-byte field at a checked offset, so the
 * blast radius is small — but Verifier is still recommended during
 * development.
 */

#include <fltKernel.h>

#define POOL_TAG        'tFlV'
#define SEED_SIZE       32
#define VOLNAME_MAX     512

/* Global (read-only after DriverEntry) */
static UCHAR    g_Seed[SEED_SIZE];
static BOOLEAN  g_HasSeed = FALSE;

PFLT_FILTER     g_Filter = NULL;

/* Forward */
static VOID  ReadRegistrySeed(PUNICODE_STRING RegPath);
static ULONG ComputeFakeVsn(PCFLT_RELATED_OBJECTS FltObjects);

/* ================================================================
 *  Pre-callback: filter to just the info class we care about.
 * ================================================================ */
FLT_PREOP_CALLBACK_STATUS
PreQueryVolume(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->Parameters.QueryVolumeInformation.FsInformationClass
        != FileFsVolumeInformation)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/* ================================================================
 *  Post-callback: overwrite VolumeSerialNumber in the response.
 *
 *  FILE_FS_VOLUME_INFORMATION layout:
 *    +0  LARGE_INTEGER VolumeCreationTime
 *    +8  ULONG         VolumeSerialNumber   <-- target
 *   +12  ULONG         VolumeLabelLength
 *   +16  BOOLEAN       SupportsObjects
 *   +17  WCHAR         VolumeLabel[]
 *
 *  We accept both STATUS_SUCCESS and STATUS_BUFFER_OVERFLOW: some
 *  callers query with a short buffer just for the VSN and take
 *  overflow as normal; the fixed part is still filled.
 * ================================================================ */
FLT_POSTOP_CALLBACK_STATUS
PostQueryVolume(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags)
{
    PFILE_FS_VOLUME_INFORMATION info;
    ULONG length;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* Instance is being torn down while this IRP was in flight —
       leave the buffer alone. */
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(Data->IoStatus.Status) &&
        Data->IoStatus.Status != STATUS_BUFFER_OVERFLOW)
        return FLT_POSTOP_FINISHED_PROCESSING;

    length = Data->Iopb->Parameters.QueryVolumeInformation.Length;
    info   = (PFILE_FS_VOLUME_INFORMATION)
             Data->Iopb->Parameters.QueryVolumeInformation.VolumeBuffer;

    /* Need at least VolumeCreationTime (8) + VolumeSerialNumber (4). */
    if (info == NULL ||
        length < FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabelLength))
        return FLT_POSTOP_FINISHED_PROCESSING;

    info->VolumeSerialNumber = ComputeFakeVsn(FltObjects);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ================================================================
 *  InstanceSetup: decide whether to attach to a given volume.
 *  Only real disk FS's — NTFS, FAT, exFAT.
 * ================================================================ */
NTSTATUS
InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM)
        return STATUS_FLT_DO_NOT_ATTACH;
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS  &&
        VolumeFilesystemType != FLT_FSTYPE_FAT   &&
        VolumeFilesystemType != FLT_FSTYPE_EXFAT)
        return STATUS_FLT_DO_NOT_ATTACH;

    return STATUS_SUCCESS;
}

NTSTATUS
InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    /* Always allow teardown — we hold no per-instance state. */
    return STATUS_SUCCESS;
}

NTSTATUS
FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (g_Filter) {
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
    }
    return STATUS_SUCCESS;
}

/* ================================================================
 *  Registration tables
 * ================================================================ */
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      PreQueryVolume,
      PostQueryVolume },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),       /* Size            */
    FLT_REGISTRATION_VERSION,       /* Version         */
    0,                              /* Flags           */
    NULL,                           /* Context         */
    Callbacks,                      /* OperationRegs   */
    FilterUnload,                   /* FilterUnload    */
    InstanceSetup,                  /* InstanceSetup   */
    InstanceQueryTeardown,          /* InstanceQueryTd */
    NULL,                           /* InstanceTeardownStart */
    NULL,                           /* InstanceTeardownComplete */
    NULL,                           /* GenerateFileName */
    NULL,                           /* NormalizeNameComponent */
    NULL,                           /* NormalizeContextCleanup */
    NULL,                           /* TransactionNotificationCallback */
    NULL                            /* NormalizeNameComponentEx */
};

/* ================================================================
 *  ReadRegistrySeed - load SerialSeed (shared convention with rstflt)
 * ================================================================ */
static VOID ReadRegistrySeed(PUNICODE_STRING RegPath)
{
    NTSTATUS st;
    HANDLE hParams = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING full, tail, name;
    WCHAR buf[512];
    UCHAR infoBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + SEED_SIZE + 8];
    PKEY_VALUE_PARTIAL_INFORMATION pi =
        (PKEY_VALUE_PARTIAL_INFORMATION)infoBuf;
    ULONG got;

    full.Buffer        = buf;
    full.Length        = 0;
    full.MaximumLength = sizeof(buf);

    if (!NT_SUCCESS(RtlAppendUnicodeStringToString(&full, RegPath)))
        return;
    RtlInitUnicodeString(&tail, L"\\Parameters");
    if (!NT_SUCCESS(RtlAppendUnicodeStringToString(&full, &tail)))
        return;

    InitializeObjectAttributes(&oa, &full,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&hParams, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) return;

    RtlInitUnicodeString(&name, L"SerialSeed");
    st = ZwQueryValueKey(hParams, &name, KeyValuePartialInformation,
                         pi, sizeof(infoBuf), &got);
    if (NT_SUCCESS(st) &&
        pi->Type == REG_BINARY &&
        pi->DataLength >= SEED_SIZE)
    {
        RtlCopyMemory(g_Seed, pi->Data, SEED_SIZE);
        g_HasSeed = TRUE;
    }
    ZwClose(hParams);
}

/* ================================================================
 *  ComputeFakeVsn - deterministic per-volume, per-profile.
 *  FNV-1a( g_Seed || FltGetVolumeName(FltObjects->Volume) )
 * ================================================================ */
static ULONG ComputeFakeVsn(PCFLT_RELATED_OBJECTS FltObjects)
{
    NTSTATUS st;
    ULONG needed = 0;
    UNICODE_STRING volName;
    PWCHAR nameBuf = NULL;
    ULONG hash = 0x811c9dc5;    /* FNV-1a offset basis */
    ULONG i;

    /* Mix in the seed. */
    for (i = 0; i < SEED_SIZE; i++) {
        hash ^= g_Seed[i];
        hash *= 0x01000193;      /* FNV-1a prime */
    }

    /* Get the volume's device name for a deterministic per-volume VSN.
       Two-phase: first learn required size, then allocate. */
    st = FltGetVolumeName(FltObjects->Volume, NULL, &needed);
    if (st == STATUS_BUFFER_TOO_SMALL &&
        needed > 0 && needed < VOLNAME_MAX)
    {
        nameBuf = (PWCHAR)ExAllocatePoolWithTag(
            PagedPool, needed + sizeof(WCHAR), POOL_TAG);
        if (nameBuf) {
            volName.Buffer        = nameBuf;
            volName.Length        = 0;
            volName.MaximumLength = (USHORT)needed;
            st = FltGetVolumeName(FltObjects->Volume, &volName, NULL);
            if (NT_SUCCESS(st)) {
                for (i = 0; i < volName.Length; i++)
                    hash = (hash ^ ((UCHAR*)volName.Buffer)[i]) * 0x01000193;
            }
            ExFreePoolWithTag(nameBuf, POOL_TAG);
        }
    }

    /* Some tools treat VSN==0 as "not initialized" — force non-zero. */
    if (hash == 0) hash = 0xDEADBEEF;
    return hash;
}

/* ================================================================
 *  DriverEntry
 * ================================================================ */
NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
    NTSTATUS st;

    RtlZeroMemory(g_Seed, SEED_SIZE);
    ReadRegistrySeed(RegPath);

    st = FltRegisterFilter(DrvObj, &FilterRegistration, &g_Filter);
    if (!NT_SUCCESS(st)) {
#if DBG
        DbgPrint("[VolFlt] FltRegisterFilter failed 0x%08X\n", st);
#endif
        return st;
    }

    st = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(st)) {
#if DBG
        DbgPrint("[VolFlt] FltStartFiltering failed 0x%08X\n", st);
#endif
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
        return st;
    }

#if DBG
    DbgPrint("[VolFlt] DriverEntry OK (v1.0) seed=%s\n",
             g_HasSeed ? "loaded" : "defaults");
#endif
    return STATUS_SUCCESS;
}
