/*++

Module Name:

    trackd_inventory.h

Abstract:

    Track D v5.0.6 Phase 1 - per-class inventory pools for the OEM
    string synthesizer.

    Curated enterprise-plausible, LATAM-uncommon, anti-collision
    synthetic vendor / product / description strings.  The Phase 2
    value-read handler will select ONE row per device using ONLY
    className + parentPathHash (see contract block below) and then
    dispatch to columns on that row by valueName.  Applied to
    RegQueryValueEx reads against Enum\SCSI\Disk, Enum\PCI, Enum\USB,
    Enum\HID, Enum\BTH and Enum\STORAGE\Volume subkeys, when the caller
    passes the EnableValueSynth gate (arm flag landed in Phase 0).

    Motivation: v5.0.5 Phase 2 (bare-metal ban, 2026-09-02) shipped a
    byte-exact SUBSTRING-based value-read handler that rewrote
    HardwareID / CompatibleIDs correctly but LEAKED cleartext OEM
    strings through DeviceDesc / FriendlyName / Mfg
    ("NVIDIA GeForce RTX 3070", "KINGSTON SA400S37480G",
    "(ASMedia,3.20,1.10)"), because those INF-sourced strings share no
    substring with parent-path tokens (VEN_ / DEV_ / Prod hex).  Phase 2
    replaces that failure mode with an independent per-class
    synthesizer that draws from the pools declared here.

    Scope: Phase 1 lands DATA + STRUCT CONTRACTS ONLY.  No accessor
    functions are declared here.  Phase 2 wires the descriptor-table
    synthesizer callbacks and consumes these tables under EnableValueSynth.

    Phase 1 PCI classHint sourcing (per kickoff Q2 decision
    A_HASHMAP_WORKITEM): a DriverEntry-scheduled IoAllocateWorkItem
    walks Enum\PCI subkeys OUTSIDE the Cm callback lock, reads each
    child's ClassGUID, and populates a private 256-slot
    FNV1a(VEN|DEV|SUBSYS|REV) hash map with the resolved
    TRACKD_PCI_CLASSHINT_* tag.  The Cm callback consults that map
    O(1) per parent path.  Cold-start window (a few hundred ms before
    the worker completes) falls through safely to the class-generic
    pool.

    References:
      docs/track-d-v506-oem-string-synthesizer-kickoff.md
      docs/postmortem-v5-track-d/incident-v506-phase0-implementation.md
      docs/postmortem-v5-track-d/incident-v505-phase2-ban-cleartext-oem-strings.md

    Style: C89-compatible, WDK nmake /W4 /WX.  Only <ntddk.h> types
    used (WCHAR, UCHAR, ULONG) plus the two class enums declared below.
    All string literals are L"..." ASCII inside UCS-2; no accents, no
    smart quotes, no U+2013/U+2014, no U+2122.  All data lives behind
    TRACKD_INVENTORY_IMPL so a single translation unit instantiates the
    pools.

    Phase 1 review pass (2026-09-02) applied 30 findings across four
    review lenses.  Notable changes:
      - Dropped all @rstsyn*.inf INF-reference syntax from SCSI Mfg;
        Windows RegQueryValueEx returns the raw string (";fallback" is
        not a runtime split) and the "@rstsyn" prefix leaked driver
        identity + the "v506" suffix leaked driver version.
      - Fixed CRITICAL contract bug: subSeed no longer XORs valueName,
        guaranteeing that DeviceDesc / FriendlyName / Mfg / and (for
        SCSI) reconstructed HardwareID all resolve to the SAME row for
        a given device.  Previously the three columns diverged, which
        would have produced multi-vendor fake identities per PDO.
      - Renamed PCI GPU row from "NVIDIA Quadro RTX A4000"
        (anachronistic brand mashup) to "NVIDIA RTX A4000" and moved
        DevHex to the real 24B7.  Applied Policy B (real product name
        + real DevHex) uniformly across all PCI rows.
      - Dropped BTH "Bluetooth Wireless Controller" (wrong namespace -
        radio-side, not Enum\BTH\Dev_* paired PDO).
      - Dropped PCI Focusrite row (vendor-vs-VID mismatch: 1D02 is
        Tekram, not Focusrite).
      - Dropped USB Root Hub row (Root Hubs enumerate under
        Enum\USB\ROOT_HUB30 without VID/PID pair).
      - Dropped USB Chicony webcam (LATAM-common on Brazilian consumer
        laptops - violates LATAM-uncommon bias).
      - Fixed NVMe token position in five SCSI rows (real Windows
        surfaces NVMe drives as "NVMe <VENDOR> <MODEL>", not
        "<VENDOR> <MODEL> NVMe SCSI Disk Device").
      - Fixed SCSI Rev fields to plausible trailing-firmware chars.
      - Fixed USB Mass Storage Mfg to canonical plural
        "Compatible USB storage devices" (real usbstor.inf token).
      - Aligned Broadcom MegaRAID brand across DeviceDesc/FriendlyName.
      - Bumped pool sizes to primes (SCSI 19, PCI 13, USB 13, HID 13,
        BTH 13, STORAGE 7) - reduces FNV % rowCount modulo bias.
      - Changed TRACKD_PCI_ROW.ClassHint / TRACKD_USB_ROW.DeviceClass
        to their enum types (was UCHAR + comment) so MSVC /W4 catches
        cross-class typos; dropped all (UCHAR) casts.
      - Added TRACKD_SYNTH_VALUENAME enum so Phase 2 resolves the
        valueName string ONCE at the callback front-end; downstream
        dispatch becomes a switch, not a chain of _wcsicmp.
      - Added FriendlyName field to TRACKD_HID_ROW set to NULL for
        every row (contract symmetry with the other five row types;
        Phase 2 treats NULL as "pass through real value").
      - Added TRACKD_INVENTORY_IMPL_INSTANTIATED ODR guard.
      - Wrapped six count initializers in (ULONG)(...) cast against
        possible future WDK toolchain drift.

--*/

#ifndef TRACKD_INVENTORY_H_
#define TRACKD_INVENTORY_H_

#include <ntddk.h>


/* ==================================================================
 * Phase 2 selection / mapping contract (documented; wired in rstflt.c
 * Phase 2, NOT in this header).
 * ==================================================================
 *
 * Given a fingerprint value read by a gated caller
 * (EnableValueSynth == 1 && image-name gate matched):
 *
 *     className   in { L"SCSI", L"PCI", L"USB", L"HID", L"BTH",
 *                     L"STORAGE" } - inferred from the parent's
 *                     first Enum\<X> path segment.
 *     valueName   in { L"DeviceDesc", L"FriendlyName", L"Mfg",
 *                     L"HardwareID", L"CompatibleIDs" } - the
 *                     RegQueryValueEx target.  Resolved once at the
 *                     callback front-end via TRACKD_SYNTH_VALUENAME.
 *     parentPathHash = FNV1a64 over the fully-qualified registry parent
 *                     path.  This is the SAME hash the name-side uses,
 *                     so the same device deterministically resolves to
 *                     the same row across name-side and value-side.
 *
 * Selection formula (v5.0.6 Phase 1 REVISED - subSeed does NOT depend
 * on valueName; the row is fixed per (className, parent), and
 * valueName only selects which column of that row is returned):
 *
 *     subSeed  = FNV1a64(g_TrackDSeed, className);
 *     rowIndex = (ULONG)((FNV1a64(subSeed, parentPathHash) >> 32) % rowCount);
 *
 * Why the >>32 shift: FNV1a64's low bits are known-weaker than the
 * high bits (that is why golden-ratio hashing multiplies before the
 * mod).  Combined with the prime rowCount per pool, the shift removes
 * the residual low-bit bias that would otherwise leak into % rowCount.
 *
 * Worked example (same PCI parent, three value reads):
 *
 *     className     = L"PCI"                  (fixed per callback path)
 *     parentPathHash = <hash of the PCI parent>  (fixed per device)
 *     subSeed       = FNV1a64(g_TrackDSeed, L"PCI")   (fixed per class)
 *     rowIndex      = (ULONG)((FNV1a64(subSeed, parentPathHash) >> 32) % 13)
 *
 *     RegQueryValueEx(L"DeviceDesc")     -> synthRow[rowIndex].DeviceDesc
 *     RegQueryValueEx(L"FriendlyName")   -> synthRow[rowIndex].FriendlyName
 *     RegQueryValueEx(L"Mfg")            -> synthRow[rowIndex].Mfg
 *
 * All three come off the SAME row, guaranteeing brand coherence and
 * cross-value consistency for a given device.
 *
 * Field mapping per class:
 *
 *   SCSI     row -> DeviceDesc, FriendlyName, Mfg columns land verbatim.
 *            VendorPadded / Product / Rev feed the substring
 *            rewriter's inquiry-triple reconstruction so the byte-exact
 *            HardwareID surface stays consistent with the synthesized
 *            display strings.  Because rowIndex is stable per device,
 *            HardwareID synthesis and DeviceDesc/FriendlyName/Mfg
 *            synthesis all agree.
 *
 *   PCI      row -> DeviceDesc, FriendlyName, Mfg columns land verbatim.
 *            VenHex / DevHex are advisory only for name-side
 *            cross-check; the callback does NOT overwrite the parent's
 *            real VEN_ / DEV_ tokens with these (name-side owns that
 *            surface via its own synthesis).  Rows are filtered by
 *            ClassHint against the PCI classmap before the modulo
 *            selection; on empty filtered subset, Phase 2 falls back
 *            to the whole pool.
 *
 *   USB      row -> DeviceDesc, FriendlyName, Mfg columns land verbatim.
 *            Rows are filtered by DeviceClass against the parent's
 *            inferred USB class before the modulo selection.
 *
 *   HID      row -> DeviceDesc column lands verbatim; Mfg column lands
 *            verbatim.  FriendlyName column is NULL for every row and
 *            Phase 2 MUST treat NULL as "pass through real value":
 *            Windows input.inf does not set FriendlyName for HID
 *            collections, so synthesizing one is itself a red flag.
 *
 *   BTH      row -> DeviceDesc, FriendlyName, Mfg columns land verbatim.
 *
 *   STORAGE  row -> DeviceDesc, FriendlyName, Mfg columns land verbatim
 *            (defensive - Phase 0 measure showed ValHit_Storage = 0
 *            across 269M callback invocations; pool exists so Phase 2
 *            can flip on synthesis if future EMAC telemetry ever
 *            starts reading these values).
 *
 * ================================================================== */


/* ------------------------------------------------------------------
 * PCI class hint enum.  Populated by the DriverEntry-scheduled work
 * item that walks Enum\PCI and reads each subkey's ClassGUID +
 * Class-Code registry values.  Consumed by the Cm callback for pool
 * sub-selection.  Reserved slots 6-8 exist for Phase 1.5 sub-splits
 * (HDA-only audio, NVMe-only storage, SATA-RAID-only storage) without
 * a header-schema break.
 * ------------------------------------------------------------------ */

typedef enum _TRACKD_PCI_CLASSHINT {
    TRACKD_PCI_CLASSHINT_UNKNOWN       = 0,
    TRACKD_PCI_CLASSHINT_GPU           = 1,
    TRACKD_PCI_CLASSHINT_NIC           = 2,
    TRACKD_PCI_CLASSHINT_STORAGE_CTRL  = 3,
    TRACKD_PCI_CLASSHINT_AUDIO         = 4,
    TRACKD_PCI_CLASSHINT_USB_CTRL      = 5,
    TRACKD_PCI_CLASSHINT_HDA_AUDIO     = 6,  /* reserved - Phase 1.5 */
    TRACKD_PCI_CLASSHINT_NVME          = 7,  /* reserved - Phase 1.5 */
    TRACKD_PCI_CLASSHINT_RAID_SATA     = 8   /* reserved - Phase 1.5 */
} TRACKD_PCI_CLASSHINT;


/* ------------------------------------------------------------------
 * USB device class enum.  Inferred by the Cm callback from the USB
 * child's bInterfaceClass / bDeviceClass + parent path shape, used to
 * filter the USB pool before selection.
 * ------------------------------------------------------------------ */

typedef enum _TRACKD_USB_DEVICECLASS {
    TRACKD_USB_DEVICECLASS_UNKNOWN         = 0,
    TRACKD_USB_DEVICECLASS_COMPOSITE       = 1,
    TRACKD_USB_DEVICECLASS_HID_COMPOSITE   = 2,
    TRACKD_USB_DEVICECLASS_HUB             = 3,
    TRACKD_USB_DEVICECLASS_MASS_STORAGE    = 4,
    TRACKD_USB_DEVICECLASS_PRINT           = 5,
    TRACKD_USB_DEVICECLASS_AUDIO           = 6,
    TRACKD_USB_DEVICECLASS_WEBCAM          = 7,
    TRACKD_USB_DEVICECLASS_GENERIC         = 8,
    TRACKD_USB_DEVICECLASS_HID_KEYBOARD    = 9,
    TRACKD_USB_DEVICECLASS_HID_MOUSE       = 10,
    TRACKD_USB_DEVICECLASS_BLUETOOTH_HOST  = 11,
    TRACKD_USB_DEVICECLASS_CDC_ETHER       = 12
} TRACKD_USB_DEVICECLASS;


/* ------------------------------------------------------------------
 * Synth value-name enum.  Phase 2's callback front-end resolves the
 * incoming wide-string valueName to one of these ONCE; the row-column
 * dispatcher is then a switch.  A single lookup point plus enum-typed
 * dispatch means a typo in the resolver can't silently fall through
 * to a passthrough (the exact leak class v5.0.6 prevents).
 * The enum also becomes the natural key for the SynthHit_* counters
 * to be wired in Phase 2.
 * ------------------------------------------------------------------ */

typedef enum _TRACKD_SYNTH_VALUENAME {
    TRACKD_SVN_UNKNOWN       = 0,
    TRACKD_SVN_DEVICEDESC    = 1,
    TRACKD_SVN_FRIENDLYNAME  = 2,
    TRACKD_SVN_MFG           = 3,
    TRACKD_SVN_HARDWAREID    = 4,
    TRACKD_SVN_COMPATIBLEIDS = 5
} TRACKD_SYNTH_VALUENAME;


/* ------------------------------------------------------------------
 * Row structs.  All fields are read-only WCHAR pointers into .rdata
 * literals sized at compile time.  No allocation, no runtime init.
 *
 * Enum-typed classifier fields (TRACKD_PCI_ROW.ClassHint,
 * TRACKD_USB_ROW.DeviceClass) are declared with their enum type so
 * MSVC /W4 flags cross-class assignment; costs a few bytes of trailing
 * pad per row on x64, worth it against the class of authoring typo.
 * ------------------------------------------------------------------ */

typedef struct _TRACKD_SCSI_ROW {
    const WCHAR *VendorPadded;   /* EXACTLY 8 wide chars, space-padded (T10) */
    const WCHAR *Product;        /* <= 16 wide chars                        */
    const WCHAR *Rev;            /* EXACTLY 4 wide chars                    */
    const WCHAR *DeviceDesc;
    const WCHAR *FriendlyName;
    const WCHAR *Mfg;
} TRACKD_SCSI_ROW;

typedef struct _TRACKD_PCI_ROW {
    TRACKD_PCI_CLASSHINT ClassHint;
    const WCHAR *VenHex;         /* 4 uppercase hex, e.g. L"10DE" */
    const WCHAR *DevHex;         /* 4 uppercase hex, e.g. L"24B7" */
    const WCHAR *DeviceDesc;
    const WCHAR *FriendlyName;
    const WCHAR *Mfg;
} TRACKD_PCI_ROW;

typedef struct _TRACKD_USB_ROW {
    TRACKD_USB_DEVICECLASS DeviceClass;
    const WCHAR *VidHex;         /* 4 uppercase hex, e.g. L"0424" */
    const WCHAR *PidHex;         /* 4 uppercase hex, e.g. L"A012" */
    const WCHAR *DeviceDesc;
    const WCHAR *FriendlyName;
    const WCHAR *Mfg;
} TRACKD_USB_ROW;

typedef struct _TRACKD_HID_ROW {
    const WCHAR *DeviceDesc;
    const WCHAR *FriendlyName;   /* ALWAYS NULL - Phase 2 must pass through real */
    const WCHAR *Mfg;
} TRACKD_HID_ROW;

typedef struct _TRACKD_BTH_ROW {
    const WCHAR *DeviceDesc;
    const WCHAR *FriendlyName;
    const WCHAR *Mfg;
} TRACKD_BTH_ROW;

typedef struct _TRACKD_STORAGE_ROW {
    const WCHAR *DeviceDesc;
    const WCHAR *FriendlyName;
    const WCHAR *Mfg;
} TRACKD_STORAGE_ROW;


/* ==================================================================
 * Pool data.  Instantiated only when TRACKD_INVENTORY_IMPL is defined
 * (rstflt.c defines it before #include "trackd_inventory.h").  Every
 * other translation unit sees the type + enum declarations above but
 * no storage.  A companion ODR sentinel below catches accidental
 * multi-TU instantiation at compile time.
 * ================================================================== */

#ifdef TRACKD_INVENTORY_IMPL

#ifdef TRACKD_INVENTORY_IMPL_INSTANTIATED
#error "trackd_inventory.h: TRACKD_INVENTORY_IMPL was already defined in another translation unit; instantiate the pools exactly once."
#endif
#define TRACKD_INVENTORY_IMPL_INSTANTIATED


/* ------------------------------------------------------------------
 * SCSI pool - 19 rows (prime, was 18).
 *
 * Composition:  4 Micron enterprise SSD lines (5300/5400/7400/9300),
 * 3 Samsung PM datacenter drives, 2 Intel D3/D-series, 1 Solidigm QLC,
 * 2 Kioxia enterprise NVMe/SAS, 4 enterprise nearline HDDs (WD Ultrastar,
 * Seagate Exos, Toshiba MG09, HGST He10), 1 Toshiba MG10 (added for
 * prime count), 2 RAID-controller virtual volume presentations (HP
 * Smart Array, DELL PERC H755).
 *
 * VendorPadded is EXACTLY 8 wide chars, space-padded per T10 inquiry
 * convention.  Product is <= 16 wide chars.  Rev is EXACTLY 4 wide
 * chars and derived from the trailing 4 chars of a known real firmware
 * revision for that SKU (Micron D3MU002 -> "M002" etc).
 *
 * DeviceDesc/FriendlyName follow the Windows convention
 * "VENDOR PART SCSI Disk Device" for SAS/SATA disks; NVMe drives use
 * "NVMe VENDOR PART" (no "SCSI Disk Device" tail) matching stornvme.sys
 * enumeration behaviour on real Windows 10/11.
 *
 * All Mfg fields carry plain plaintext manufacturer strings; the
 * @rstsyn*.inf,%token%;fallback INF-reference wrapper used in the
 * initial draft was dropped after the Phase 1 review: RegQueryValueEx
 * returns the raw string (';fallback' is not a runtime split), the
 * "rstsyn" prefix leaked driver identity, and one row carried the
 * literal version "v506" - a categorically synthetic marker.
 * ------------------------------------------------------------------ */

static const TRACKD_SCSI_ROW g_TrackDSynthScsiRows[] = {
    /*  0 */ { L"MICRON  ", L"5300 MAX",        L"M002",
               L"MICRON 5300 MAX SCSI Disk Device",
               L"MICRON 5300 MAX SCSI Disk Device",
               L"Micron Technology, Inc." },

    /*  1 */ { L"MICRON  ", L"5400 PRO",        L"M042",
               L"MICRON 5400 PRO SCSI Disk Device",
               L"MICRON 5400 PRO SCSI Disk Device",
               L"Micron Technology, Inc." },

    /*  2 */ { L"MICRON  ", L"7400 PRO",        L"U200",
               L"NVMe MICRON 7400 PRO",
               L"NVMe MICRON 7400 PRO",
               L"Micron Technology, Inc." },

    /*  3 */ { L"MICRON  ", L"9300 MAX",        L"E301",
               L"NVMe MICRON 9300 MAX",
               L"NVMe MICRON 9300 MAX",
               L"Micron Technology, Inc." },

    /*  4 */ { L"SAMSUNG ", L"MZ7L3960HCJR",    L"4104",
               L"SAMSUNG MZ7L3960HCJR SCSI Disk Device",
               L"SAMSUNG MZ7L3960HCJR SCSI Disk Device",
               L"Samsung Electronics Co., Ltd." },

    /*  5 */ { L"SAMSUNG ", L"MZQL21T9HCJR",    L"GDC7",
               L"NVMe SAMSUNG MZQL21T9HCJR",
               L"NVMe SAMSUNG MZQL21T9HCJR",
               L"Samsung Electronics Co., Ltd." },

    /*  6 */ { L"SAMSUNG ", L"MZWLJ3T8HBLS",    L"EPA7",
               L"NVMe SAMSUNG MZWLJ3T8HBLS",
               L"NVMe SAMSUNG MZWLJ3T8HBLS",
               L"Samsung Electronics Co., Ltd." },

    /*  7 */ { L"INTEL   ", L"SSDSC2KG960G8",   L"010B",
               L"INTEL SSDSC2KG960G8 SCSI Disk Device",
               L"INTEL SSDSC2KG960G8 SCSI Disk Device",
               L"Intel Corporation" },

    /*  8 */ { L"INTEL   ", L"SSDPE2KE016T8",   L"VDV1",
               L"NVMe INTEL SSDPE2KE016T8",
               L"NVMe INTEL SSDPE2KE016T8",
               L"Intel Corporation" },

    /*  9 */ { L"SOLIDIGM", L"SSDPF2KX076T1",   L"9CV1",
               L"NVMe SOLIDIGM SSDPF2KX076T1",
               L"NVMe SOLIDIGM SSDPF2KX076T1",
               L"Solidigm" },

    /* 10 */ { L"KIOXIA  ", L"KCD6XVUL3T84",    L"0104",
               L"NVMe KIOXIA KCD6XVUL3T84",
               L"NVMe KIOXIA KCD6XVUL3T84",
               L"Kioxia Corporation" },

    /* 11 */ { L"KIOXIA  ", L"KPM6VVUG1T60",    L"3P04",
               L"KIOXIA KPM6VVUG1T60 SAS SCSI Disk Device",
               L"KIOXIA KPM6VVUG1T60 SAS SCSI Disk Device",
               L"Kioxia Corporation" },

    /* 12 */ { L"WDC     ", L"WUH721818ALE6L4", L"RE00",
               L"WDC WUH721818ALE6L4 SCSI Disk Device",
               L"WDC WUH721818ALE6L4 SCSI Disk Device",
               L"Western Digital Corporation" },

    /* 13 */ { L"SEAGATE ", L"ST18000NM000J",   L"SN02",
               L"SEAGATE ST18000NM000J SCSI Disk Device",
               L"SEAGATE ST18000NM000J SCSI Disk Device",
               L"Seagate Technology LLC" },

    /* 14 */ { L"TOSHIBA ", L"MG09ACA18TE",     L"0102",
               L"TOSHIBA MG09ACA18TE SCSI Disk Device",
               L"TOSHIBA MG09ACA18TE SCSI Disk Device",
               L"Toshiba Corporation" },

    /* 15 */ { L"HGST    ", L"HUH721010ALE604", L"T2H0",
               L"HGST HUH721010ALE604 SCSI Disk Device",
               L"HGST HUH721010ALE604 SCSI Disk Device",
               L"HGST, a Western Digital Company" },

    /* 16 */ { L"HP      ", L"LOGICAL VOLUME",  L"6.88",
               L"HP LOGICAL VOLUME SCSI Disk Device",
               L"HP LOGICAL VOLUME SCSI Disk Device",
               L"Hewlett Packard Enterprise" },

    /* 17 */ { L"DELL    ", L"PERC H755 Front", L"5.16",
               L"DELL PERC H755 Front SCSI Disk Device",
               L"DELL PERC H755 Front SCSI Disk Device",
               L"Dell Inc." },

    /* 18 */ { L"TOSHIBA ", L"MG10ACA20TE",     L"0104",
               L"TOSHIBA MG10ACA20TE SCSI Disk Device",
               L"TOSHIBA MG10ACA20TE SCSI Disk Device",
               L"Toshiba Corporation" }
};

static const ULONG g_TrackDSynthScsiCount =
    (ULONG)(sizeof(g_TrackDSynthScsiRows) / sizeof(g_TrackDSynthScsiRows[0]));


/* ------------------------------------------------------------------
 * PCI pool - 13 rows (prime, was 14).
 *
 * Composition: 4 GPU (3 workstation Ampere/Radeon PRO/Intel Flex +
 * 1 Tesla T4), 3 NIC (Mellanox ConnectX-6 Dx, Intel X710 SFP+,
 * Broadcom NetXtreme-E BCM57504), 3 STORAGE_CTRL (Broadcom MegaRAID
 * SAS, Marvell 88SE9230 AHCI, Intel VMD/VROC), 1 AUDIO (RME HDSPe AIO
 * Pro), 2 USB_CTRL (Intel MS-inbox xHCI, Renesas uPD720201).
 *
 * Policy B applied uniformly: real product name + real matching
 * DevHex for that SKU.  Trade-off: accepts some collision risk with a
 * real device the user might own, in exchange for surviving any
 * public-PCI-ID DB lookup by an audit lens.  Focusrite RedNet PCIeR
 * row was dropped (VenHex 1D02 is Tekram, not Focusrite; keeping the
 * row with Xilinx 10EE would collide with the RME row's VenHex).
 *
 * LATAM-uncommon bias: server/workstation flavor across the pool, no
 * consumer GeForce / Radeon-RX / Realtek-ALC etc.
 * ------------------------------------------------------------------ */

static const TRACKD_PCI_ROW g_TrackDSynthPciRows[] = {
    /*  0 GPU  */ { TRACKD_PCI_CLASSHINT_GPU,
                    L"10DE", L"24B7",
                    L"NVIDIA RTX A4000",
                    L"NVIDIA RTX A4000",
                    L"NVIDIA" },

    /*  1 GPU  */ { TRACKD_PCI_CLASSHINT_GPU,
                    L"1002", L"73A3",
                    L"AMD Radeon PRO W6800",
                    L"AMD Radeon PRO W6800",
                    L"Advanced Micro Devices, Inc." },

    /*  2 GPU  */ { TRACKD_PCI_CLASSHINT_GPU,
                    L"8086", L"56C0",
                    L"Intel(R) Data Center GPU Flex 170",
                    L"Intel(R) Data Center GPU Flex 170",
                    L"Intel Corporation" },

    /*  3 GPU  */ { TRACKD_PCI_CLASSHINT_GPU,
                    L"10DE", L"1EB8",
                    L"NVIDIA Tesla T4",
                    L"NVIDIA Tesla T4",
                    L"NVIDIA" },

    /*  4 NIC  */ { TRACKD_PCI_CLASSHINT_NIC,
                    L"15B3", L"101D",
                    L"Mellanox ConnectX-6 Dx EN Adapter",
                    L"Mellanox ConnectX-6 Dx EN Adapter",
                    L"Mellanox Technologies" },

    /*  5 NIC  */ { TRACKD_PCI_CLASSHINT_NIC,
                    L"8086", L"1572",
                    L"Intel(R) Ethernet Controller X710 for 10GbE SFP+",
                    L"Intel(R) Ethernet Controller X710 for 10GbE SFP+",
                    L"Intel Corporation" },

    /*  6 NIC  */ { TRACKD_PCI_CLASSHINT_NIC,
                    L"14E4", L"1751",
                    L"Broadcom BCM57504 NetXtreme-E 10Gb/25Gb Ethernet",
                    L"Broadcom NetXtreme-E BCM57504 25GbE Adapter",
                    L"Broadcom Inc." },

    /*  7 STG  */ { TRACKD_PCI_CLASSHINT_STORAGE_CTRL,
                    L"1000", L"10E2",
                    L"Broadcom MegaRAID 9560-16i SAS/SATA/NVMe Controller",
                    L"Broadcom MegaRAID Adapter",
                    L"Broadcom Inc." },

    /*  8 STG  */ { TRACKD_PCI_CLASSHINT_STORAGE_CTRL,
                    L"1B4B", L"9230",
                    L"Marvell 88SE9230 AHCI Controller",
                    L"Marvell 88SE9230 AHCI Controller",
                    L"Marvell Semiconductor, Inc." },

    /*  9 STG  */ { TRACKD_PCI_CLASSHINT_STORAGE_CTRL,
                    L"8086", L"9A0B",
                    L"Intel(R) Volume Management Device NVMe RAID Controller",
                    L"Intel(R) VROC (VMD) Controller",
                    L"Intel Corporation" },

    /* 10 AUD  */ { TRACKD_PCI_CLASSHINT_AUDIO,
                    L"10EE", L"3FC8",
                    L"RME HDSPe AIO Pro Audio Interface",
                    L"RME HDSPe AIO Pro",
                    L"RME Audio" },

    /* 11 USB  */ { TRACKD_PCI_CLASSHINT_USB_CTRL,
                    L"8086", L"A36D",
                    L"Intel(R) USB 3.20 eXtensible Host Controller - 1.20 (Microsoft)",
                    L"Intel(R) USB 3.20 eXtensible Host Controller - 1.20 (Microsoft)",
                    L"Intel Corporation" },

    /* 12 USB  */ { TRACKD_PCI_CLASSHINT_USB_CTRL,
                    L"1912", L"0014",
                    L"Renesas Electronics USB 3.0 Host Controller",
                    L"Renesas Electronics USB 3.0 eXtensible Host Controller - 1.00 (Renesas,1.00,2.03)",
                    L"Renesas Electronics" }
};

static const ULONG g_TrackDSynthPciCount =
    (ULONG)(sizeof(g_TrackDSynthPciRows) / sizeof(g_TrackDSynthPciRows[0]));


/* ------------------------------------------------------------------
 * USB pool - 13 rows (prime, was 15).
 *
 * Composition: 1 composite, 1 HID composite, 1 hub (companion),
 * 1 mass storage, 1 print (Epson enterprise), 1 audio, 1 webcam
 * (generic Microsoft-branded), 1 smart-card reader (OmniKey / HID
 * Global), 1 keyboard, 1 mouse, 1 Bluetooth host, 1 CDC ethernet
 * (ASIX AX88179A, common in Lenovo/Dell enterprise docks - swapped
 * from Realtek USB-Ethernet which is LATAM-common consumer dongle),
 * 1 fingerprint reader (Synaptics WBDI).
 *
 * Dropped rows vs Phase 1 draft:
 *   - Root Hub (root hubs enumerate under Enum\USB\ROOT_HUB30 without
 *     a VID_/PID_ pair; a VID/PID-indexed row can't route to that
 *     shape correctly).
 *   - Chicony Integrated Camera (LATAM-common on Brazilian Dell G-
 *     series / Lenovo Legion / HP Pavilion / Acer Nitro consumer
 *     laptops - violates LATAM-uncommon bias).
 *
 * All VidHex values are REAL USB-IF-assigned vendor IDs.  PidHex
 * values are chosen outside well-known real ranges to reduce collision
 * with a real device the user might own.  DeviceDesc/FriendlyName
 * follow Windows conventions.
 * ------------------------------------------------------------------ */

static const TRACKD_USB_ROW g_TrackDSynthUsbRows[] = {
    /*  0 */ { TRACKD_USB_DEVICECLASS_COMPOSITE,
               L"0424", L"A012",
               L"USB Composite Device",
               L"USB Composite Device",
               L"(Standard system devices)" },

    /*  1 */ { TRACKD_USB_DEVICECLASS_HID_COMPOSITE,
               L"0451", L"2078",
               L"USB Input Device",
               L"USB Input Device",
               L"(Standard system devices)" },

    /*  2 */ { TRACKD_USB_DEVICECLASS_HUB,
               L"8087", L"A034",
               L"Generic USB Hub",
               L"Generic USB Hub",
               L"(Standard USB HUBs)" },

    /*  3 */ { TRACKD_USB_DEVICECLASS_MASS_STORAGE,
               L"0424", L"B308",
               L"USB Mass Storage Device",
               L"USB Mass Storage Device",
               L"Compatible USB storage devices" },

    /*  4 */ { TRACKD_USB_DEVICECLASS_PRINT,
               L"04B8", L"D482",
               L"USB Printing Support",
               L"USB Printing Support",
               L"Microsoft" },

    /*  5 */ { TRACKD_USB_DEVICECLASS_AUDIO,
               L"0424", L"C401",
               L"USB Audio Device",
               L"USB Audio Device",
               L"Microsoft" },

    /*  6 */ { TRACKD_USB_DEVICECLASS_WEBCAM,
               L"04CA", L"7108",
               L"USB Video Device",
               L"USB Video Device",
               L"Microsoft" },

    /*  7 */ { TRACKD_USB_DEVICECLASS_GENERIC,
               L"076B", L"2054",
               L"USB Smart Card Reader",
               L"USB Smart Card Reader",
               L"(Standard system devices)" },

    /*  8 */ { TRACKD_USB_DEVICECLASS_HID_KEYBOARD,
               L"0483", L"5710",
               L"USB Input Device",
               L"USB Input Device",
               L"(Standard system devices)" },

    /*  9 */ { TRACKD_USB_DEVICECLASS_HID_MOUSE,
               L"04F2", L"0428",
               L"USB Input Device",
               L"USB Input Device",
               L"(Standard system devices)" },

    /* 10 */ { TRACKD_USB_DEVICECLASS_BLUETOOTH_HOST,
               L"8087", L"0BB0",
               L"Generic Bluetooth Adapter",
               L"Generic Bluetooth Adapter",
               L"Microsoft" },

    /* 11 */ { TRACKD_USB_DEVICECLASS_CDC_ETHER,
               L"0B95", L"178A",
               L"ASIX AX88179A USB 3.2 Gen 1 to Gigabit Ethernet Adapter",
               L"ASIX AX88179A USB 3.2 Gen 1 to Gigabit Ethernet Adapter",
               L"ASIX Electronics Corp." },

    /* 12 */ { TRACKD_USB_DEVICECLASS_GENERIC,
               L"06CB", L"00DE",
               L"Synaptics WBDI Fingerprint Reader",
               L"Synaptics WBDI Fingerprint Reader",
               L"Synaptics" }
};

static const ULONG g_TrackDSynthUsbCount =
    (ULONG)(sizeof(g_TrackDSynthUsbRows) / sizeof(g_TrackDSynthUsbRows[0]));


/* ------------------------------------------------------------------
 * HID pool - 13 rows (prime, was 12).
 *
 * HID DeviceDesc / Mfg values are Windows-generic by design: input.inf
 * shipped in %WINDIR%\INF sets these regardless of the underlying
 * device vendor, so a Logitech mouse, a Dell touchpad, and a Kioxia
 * authentication token all surface with one of these strings.
 * Anti-collision here is by USAGE ROLE, not by vendor - each row is a
 * HID usage-page/collection kind that Windows ships a canonical
 * descriptor for.  All strings match input.inf verbatim (space in
 * "touch pad" / "touch screen" is intentional).  Mfg is uniform
 * "(Standard system devices)" (parentheses match input.inf verbatim).
 *
 * FriendlyName column is ALWAYS NULL.  input.inf does not set
 * FriendlyName for HID collections and synthesizing one would itself
 * be a red flag; Phase 2 dispatcher MUST treat NULL as "pass through
 * the real value untouched" for TRACKD_SVN_FRIENDLYNAME on HID.
 * The column exists in the struct for contract symmetry with the
 * other five row types (uniform per-value dispatch table).
 *
 * Row 12 "HID-compliant sensor" added for prime-count pool size.
 * ------------------------------------------------------------------ */

static const TRACKD_HID_ROW g_TrackDSynthHidRows[] = {
    /*  0 */ { L"HID-compliant mouse",                  NULL, L"(Standard system devices)" },
    /*  1 */ { L"HID-compliant keyboard",               NULL, L"(Standard system devices)" },
    /*  2 */ { L"HID-compliant vendor-defined device",  NULL, L"(Standard system devices)" },
    /*  3 */ { L"HID-compliant touch pad",              NULL, L"(Standard system devices)" },
    /*  4 */ { L"HID-compliant consumer control device",NULL, L"(Standard system devices)" },
    /*  5 */ { L"HID-compliant system controller",      NULL, L"(Standard system devices)" },
    /*  6 */ { L"HID-compliant game controller",        NULL, L"(Standard system devices)" },
    /*  7 */ { L"HID-compliant device",                 NULL, L"(Standard system devices)" },
    /*  8 */ { L"HID-compliant pen",                    NULL, L"(Standard system devices)" },
    /*  9 */ { L"HID-compliant digitizer",              NULL, L"(Standard system devices)" },
    /* 10 */ { L"HID-compliant touch screen",           NULL, L"(Standard system devices)" },
    /* 11 */ { L"HID-compliant headset",                NULL, L"(Standard system devices)" },
    /* 12 */ { L"HID-compliant sensor",                 NULL, L"(Standard system devices)" }
};

static const ULONG g_TrackDSynthHidCount =
    (ULONG)(sizeof(g_TrackDSynthHidRows) / sizeof(g_TrackDSynthHidRows[0]));


/* ------------------------------------------------------------------
 * BTH pool - 13 rows (prime, was 15).
 *
 * All values are Windows-native bth.inf role descriptions: a real
 * Enum\BTH\Dev_<hex> child on stock Windows 10/11 surfaces with
 * Mfg="Microsoft".  Vendor branding for Bluetooth devices lives under
 * Enum\BTHENUM\{service-guid}\... or Enum\USB for BT-USB dongles, NOT
 * under Enum\BTH\Dev_*, so the OEM-brand suppression rule does not
 * apply here.
 *
 * Dropped rows vs Phase 1 draft:
 *   - "Bluetooth Wireless Controller" (wrong namespace: radio-side,
 *     not a paired-device PDO; Enum\BTH\Dev_* is paired-device only).
 *   - "Bluetooth Hands-free Audio" (redundant hyphenated variant of
 *     the canonical "Bluetooth Handsfree Device"; carrying both
 *     partitions the pool on an editorial choice).
 *
 * Coverage spans generic device, LE variants, audio
 * (generic/handsfree/headset), peripheral, AVRCP media-control, HID
 * (short + long form as both appear across Win10/Win11), serial/SPP,
 * PAN, GATT service.
 * ------------------------------------------------------------------ */

static const TRACKD_BTH_ROW g_TrackDSynthBthRows[] = {
    /*  0 */ { L"Bluetooth Device",
               L"Bluetooth Device",                              L"Microsoft" },
    /*  1 */ { L"Bluetooth LE Peripheral",
               L"Bluetooth LE Peripheral",                       L"Microsoft" },
    /*  2 */ { L"Bluetooth Low Energy Device",
               L"Bluetooth Low Energy Device",                   L"Microsoft" },
    /*  3 */ { L"Bluetooth Audio Device",
               L"Bluetooth Audio Device",                        L"Microsoft" },
    /*  4 */ { L"Bluetooth Handsfree Device",
               L"Bluetooth Handsfree Device",                    L"Microsoft" },
    /*  5 */ { L"Bluetooth Headset",
               L"Bluetooth Headset",                             L"Microsoft" },
    /*  6 */ { L"Bluetooth Peripheral Device",
               L"Bluetooth Peripheral Device",                   L"Microsoft" },
    /*  7 */ { L"Bluetooth AVRCP Device",
               L"Bluetooth AVRCP Transport",                     L"Microsoft" },
    /*  8 */ { L"Bluetooth HID Device",
               L"Bluetooth HID Device",                          L"Microsoft" },
    /*  9 */ { L"Bluetooth Human Interface Device",
               L"Bluetooth Human Interface Device",              L"Microsoft" },
    /* 10 */ { L"Bluetooth Serial Port",
               L"Standard Serial over Bluetooth link",           L"Microsoft" },
    /* 11 */ { L"Bluetooth PAN Network Adapter",
               L"Bluetooth PAN Network Adapter",                 L"Microsoft" },
    /* 12 */ { L"Bluetooth GATT Service",
               L"Bluetooth GATT Service",                        L"Microsoft" }
};

static const ULONG g_TrackDSynthBthCount =
    (ULONG)(sizeof(g_TrackDSynthBthRows) / sizeof(g_TrackDSynthBthRows[0]));


/* ------------------------------------------------------------------
 * STORAGE pool - 7 rows (prime, was 8).
 *
 * DEFENSIVE pool.  STORAGE\Volume PDOs are Windows-created objects
 * (volume.inf), not device-vendor-authored, so the real-world value
 * space is essentially always DeviceDesc="Volume" / Mfg="Microsoft"
 * with FriendlyName either absent or matching.  Phase 0 measure
 * counter ValHit_Storage = 0 across 269M callback invocations - EMAC
 * does not read these value names in current telemetry.  This pool
 * exists so Phase 2 can flip on synthesis if future EMAC telemetry
 * ever starts reading these values; every row preserves the generic
 * "Volume" + "Microsoft" framing to remain indistinguishable from
 * unmodified Windows STORAGE\Volume PDOs.  FriendlyName varies across
 * Windows-natural role prefixes (Generic / Fixed / Storage / System /
 * Data / Removable) that appear organically on real systems.
 * "Basic Volume" row from Phase 1 draft was dropped for prime count.
 * ------------------------------------------------------------------ */

static const TRACKD_STORAGE_ROW g_TrackDSynthStorageRows[] = {
    /*  0 */ { L"Volume",         L"Volume",           L"Microsoft" },
    /*  1 */ { L"Generic Volume", L"Generic Volume",   L"Microsoft" },
    /*  2 */ { L"Volume",         L"Fixed Volume",     L"Microsoft" },
    /*  3 */ { L"Storage Volume", L"Storage Volume",   L"Microsoft" },
    /*  4 */ { L"Volume",         L"System Volume",    L"Microsoft" },
    /*  5 */ { L"Volume",         L"Data Volume",      L"Microsoft" },
    /*  6 */ { L"Volume",         L"Removable Volume", L"Microsoft" }
};

static const ULONG g_TrackDSynthStorageCount =
    (ULONG)(sizeof(g_TrackDSynthStorageRows) / sizeof(g_TrackDSynthStorageRows[0]));


#endif /* TRACKD_INVENTORY_IMPL */


/* ==================================================================
 * POOL SIZES SUMMARY (Track D v5.0.6 Phase 1, post-review)
 * ------------------------------------------------------------------
 *   SCSI     19 rows   (enterprise SSD / NVMe / SAS / nearline HDD /
 *                       RAID-controller logical-volume presentations)
 *   PCI      13 rows   (4 GPU / 3 NIC / 3 STORAGE_CTRL / 1 AUDIO /
 *                       2 USB_CTRL; filtered by ClassHint at Phase 2)
 *   USB      13 rows   (1 composite / 1 HID composite / 1 hub /
 *                       1 mass storage / 1 print / 1 audio / 1 webcam /
 *                       1 smart-card / 1 keyboard / 1 mouse /
 *                       1 Bluetooth host / 1 CDC ether / 1 fingerprint;
 *                       filtered by DeviceClass at Phase 2)
 *   HID      13 rows   (canonical input.inf usage-role descriptors)
 *   BTH      13 rows   (bth.inf role descriptions)
 *   STORAGE   7 rows   (defensive; ValHit_Storage = 0 in Phase 0)
 *
 *   Total    78 rows across 6 classes.  Every pool size is prime;
 *   combined with the >>32 shift on the FNV hash before the modulo
 *   (see contract block above), FNV1a64 % rowCount modulo bias is
 *   under measurement noise for these pool sizes.
 * ================================================================== */


#endif /* TRACKD_INVENTORY_H_ */
