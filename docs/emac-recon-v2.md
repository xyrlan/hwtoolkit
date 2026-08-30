# EMAC Reconnaissance v2 (corrected)

Status: supersedes the earlier internal recon v1 (not versioned in
this repo).
Data source: two cross-verified procmon captures on a live RubinOT / EMAC
session:

- 7 min baseline (steady-state, already registered)
- 18 min re-registration burst (after `emac-uuid` recreated, forcing full
  fingerprint collection)

All claims below are anchored to actual events in those traces. Anything
not observed in both captures is marked explicitly.

---

## Preface

Reconnaissance v1 was built from partial data and static analysis of
`EMACDRVGLTB.sys`. It arrived at a plausible-but-wrong picture of what
EMAC actually queries at runtime, and the toolkit followed those
assumptions into two mistakes:

1. v3.5.1 removed `windows.machine_guid`, `sqm_machine_id` and
   `product_id` from the profile, believing EMAC didn't read any of
   them. That is only true for two of the three.
2. v3.1-3.4 kept expanding a Storage IOCTL intercept in the driver
   under the assumption EMAC hashed ATA/NVMe serials. It doesn't.

v2 undoes the assumption errors and locks the architecture to what the
process monitor actually shows.

---

## Corrections from v1

| # | v1 claim                                                           | v2 reality                                                                                     | Source                                       |
|---|--------------------------------------------------------------------|------------------------------------------------------------------------------------------------|----------------------------------------------|
| 1 | "HWID collection is ~90% kernel-side"                              | 100% user-mode via registry reads from `RubinOT.exe` / EMAC agent                              | Procmon full sweep, `WmiPrvSE.exe` idle      |
| 2 | "Zero MachineGuid reads"                                           | `MachineGuid` IS read (`Buffer Overflow` -> `Success` = classic `RegQueryValueEx` size probe)  | Procmon (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) |
| 3 | "Disk serial only through the kernel driver"                       | Disk model is read from the SCSI enum registry cache; no `DeviceIoControl` at all              | Procmon + `HKLM\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_*` |
| 4 | "Kernel driver `EMACDRVGLTB.sys` collects HWID"                    | Kernel driver is DEFENSE ONLY (`ObRegisterCallbacks`, `PsSetLoadImageNotifyRoutine`)           | `sc qc`, `fltmc filters`, procmon (no IO)    |
| 5 | "Storage IOCTL intercept is useful"                                | Zero `DeviceIoControl` calls of any code during the entire capture window                      | Procmon filtered on `IRP_MJ_DEVICE_CONTROL`  |
| 6 | "WMI is the primary path"                                          | `WmiPrvSE.exe` records zero events during the collection burst                                 | Procmon (`Process Name is WmiPrvSE.exe`)     |
| 7 | "SQM MachineId is part of the hash"                                | Zero reads under `HKLM\SOFTWARE\Microsoft\SQMClient` in either capture                         | Procmon                                      |
| 8 | "Product ID / DigitalProductId are read"                           | Zero reads under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\{ProductId,DigitalProductId}` | Procmon                                    |

---

## Confirmed reads (registry paths, user-mode)

All reads below are performed by `RubinOT.exe` (or its EMAC user-mode
agent, same process) unless noted. Access pattern is `RegOpenKey` ->
`RegQueryValueEx` (frequently with the `Buffer Overflow` -> `Success`
double-call to size the buffer).

### Windows identity

| Vector           | Registry path                                                                                 | Notes                                             |
|------------------|-----------------------------------------------------------------------------------------------|---------------------------------------------------|
| MachineGuid      | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`                                            | Single high-signal value, per-install GUID.       |
| ComputerName     | `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\ComputerName`          | Read alongside TCP hostname; usually the same.    |
| TCP/IP hostname  | `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Hostname`                            | Effectively `== ComputerName` on default installs |
| WMI Restrictions | `HKLM\SOFTWARE\Microsoft\WBEM\CIMOM\...`                                                      | Behavioral fingerprint of WMI security posture    |
| SystemSetupInProgress | `HKLM\SYSTEM\Setup\SystemSetupInProgress`                                                | Anti-sandbox / OOBE check                         |

### Hardware topology (PCI / SCSI enum cache)

| Vector             | Registry path                                                                                          | Notes                                                                                              |
|--------------------|--------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| PCI VEN&DEV enum   | `HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_XXXX&DEV_XXXX\...`                                         | Coarse device inventory (baseline).                                                                |
| PCI granular HWID  | `HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_XXXX&DEV_XXXX\{instance}\HardwareID` (REG_MULTI_SZ)        | Includes `VEN_XXXX&DEV_XXXX&SUBSYS_XXXX&REV_XX&CC_XXXXXX`. 362 reads during re-registration burst. |
| SCSI Disk model    | `HKLM\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_XXX&Prod_YYY\{instance}`                             | Instances observed: `Kingston_SA400S3`, `IM2P33F3_NVMe_AD` (ADATA XPG SX8200), `XPG_GAMMIX_S70_B`. |
| Volume GUIDs       | `HKLM\SYSTEM\CurrentControlSet\Enum\STORAGE\Volume\{GUID}#offset`                                      | 3 volumes read. Observed GUIDs `{21c67967-a16b-11f1-a7a1-806e6f6e6963}`, `{21c67968-...}`.         |
| CPU strings        | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString`                              | Comes from CPUID; NOT covered by SMBIOS Type 4.                                                    |

### Display / audio / network

| Vector                      | Registry path                                                                | Notes                                                     |
|-----------------------------|------------------------------------------------------------------------------|-----------------------------------------------------------|
| Network PnPInstanceId       | `HKLM\SYSTEM\CurrentControlSet\Enum\{PCI,USB,BTH,VMBUS}\...`                 | 4 adapters enumerated per capture.                        |
| EDID blobs                  | `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\<PNP>\<INST>\Device Parameters\EDID` | 3 monitors read (full 128-byte block each).           |
| Audio endpoint GUIDs        | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\{Render,Capture}\{GUID}` | High-signal per-endpoint identifier.                 |
| Video device GUIDs          | Various `Class\{4d36e968-...}\NNNN` and `MediaCategories\{GUID}`             | Ancillary; low individual weight.                         |

### Persistent user-mode cache

| Vector       | Path                                | Notes                                                                                        |
|--------------|-------------------------------------|----------------------------------------------------------------------------------------------|
| `emac-uuid`  | `C:\Users\<user>\emac-uuid`         | 36-byte ASCII UUID v4 (no BOM). Written on first run, used as session key thereafter.        |

---

## Confirmed NOT read

The following surfaces show ZERO events in both captures. They are safe
to leave real, and there is no benefit to spoofing them.

- `HKLM\SOFTWARE\Microsoft\SQMClient\MachineId`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId`
- `HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\*\HwProfileGuid`
- Any `DeviceIoControl` IRP (any IOCTL, any target device)
- WMI `Win32_*` queries (`WmiPrvSE.exe` idle for full capture)
- `\Device\PhysicalMemory`
- `\Device\Harddisk*`, `\Device\PhysicalDrive*`, `\Device\Scsi*`, `\Device\NVMe*`
- `GetVolumeInformationW` API path (no `\??\C:\` volume information IRPs)

Consequence: v3.6's removal of the Storage IOCTL intercept from the
driver was correct. No revert planned.

---

## Kernel driver `EMACDRVGLTB.sys` — corrected role

Static: static analysis originally suggested HWID collection primitives.
Dynamic: procmon proves those primitives never fire in a normal session.
The driver's true role is runtime self-defense of the EMAC user-mode
process.

Facts:

- Start type: `DEMAND_START` (not `SYSTEM_START`). It loads only when
  `RubinOT.exe` launcher starts, and unloads on process close.
- Registration: `FILE_SYSTEM_DRIVER` minifilter (`FltMgr` dependent).
- Altitude: 40000-49999 band (`FSFilter Activity Monitor` group).
- Callbacks: `ObRegisterCallbacks` (blocks handle open against protected
  process), `PsSetLoadImageNotifyRoutine` and
  `PsSetCreateThreadNotifyRoutine` (catches injected DLLs and remote
  threads).
- Zero IRP MJ DeviceControl handlers observed servicing HWID queries.

Consequence: the toolkit does not need to defeat this driver to spoof
HWID; it only needs to defeat it to inject anything into the user-mode
process. Kernel-side DSE-bypass tooling is out of scope for this repo.

---

## Integrity check (bundled vs system drivers)

EMAC computes a hash over three drivers shipped with the game in
`C:\Program Files (x86)\RubinOT 2.0\`:

- `mssmbios.sys`
- `tpm.sys`
- `netbios.sys`

and compares each to the corresponding file in
`C:\Windows\System32\drivers\`.

Impact for `hwtoolkit`: NONE.

We write only to the `mssmbios\Data\SMBiosData` REG_BINARY value under
`HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data`. We never touch
the `mssmbios.sys` binary, nor `tpm.sys`, nor `netbios.sys`. The bundled
vs system hash comparison is unaffected by SMBIOS blob spoofing.

---

## Fingerprint model (revised)

Grouped by category, with per-vector stability notes.

Windows identity
- `MachineGuid` — very stable across reboots; changes only on reinstall
  or explicit rewrite. High weight.
- `ComputerName` / TCP hostname — stable; usually equal.

Hardware topology
- SCSI disk model strings — stable across reboots; changes on drive
  swap. Cached in registry Enum, no IOCTL touched.
- PCI granular `HardwareID` (SUBSYS+REV+CC) — stable across reboots;
  changes only on hardware swap or driver reinstall.
- Volume GUIDs (Enum\STORAGE\Volume) — stable across reboots per-volume;
  changes only on repartition / format. Boot volume GUID is load-bearing
  for `\SystemRoot` resolution.
- CPU `ProcessorNameString` — comes from CPUID, cannot be rewritten in
  user mode; SMBIOS Type 4 does not cover it.

Display
- 3x EDID blob — stable per monitor. Descriptor blocks 0xFC (name) and
  0xFF (serial ASCII) are the high-signal bytes.

Audio
- MMDevices Render/Capture endpoint GUIDs — stable across reboots;
  regenerated only on device removal / driver reset.

Network
- 4x PnPInstanceId (per adapter) — stable across reboots; regenerated
  on adapter uninstall or bus filter re-enum.
- MAC addresses — trivially rewritable at the registry level (already
  covered).

Locale / anti-sandbox
- WMI Restrictions, SystemSetupInProgress — behavioral, low individual
  weight but flip anti-sandbox heuristics if wrong.

Persistent
- `C:\Users\<user>\emac-uuid` — server-side session key; deleting it
  triggers a heavy re-registration burst (32k+ RegOpenKey observed
  plus a POST rain to Vultr/Cloudflare endpoints), which is itself a
  ban signal.

---

## Bypass strategy implications

Given the corrected model:

- No need for a kernel-mode HWID intercept driver. Rewriting the right
  registry values in user mode is sufficient for every collection
  surface EMAC actually reads.
- No need for a Storage IOCTL driver. Confirmed dead code path.
- `MachineGuid` handling must be reinstated in the toolkit (HOTFIX for
  v3.5.1's removal). Fase 1.5 was too aggressive.
- New spoof surface, all registry-only:
  - Disk model strings under `Enum\SCSI\Disk&Ven_*&Prod_*`
  - PCI granular `HardwareID` under `Enum\PCI\VEN_*&DEV_*\{instance}`
  - Volume GUIDs under `Enum\STORAGE\Volume\{GUID}#offset` +
    corresponding `HKLM\SYSTEM\MountedDevices` values
    (never touch the boot volume GUID; will brick boot)
- Kernel-side defense (`ObCallbacks`) blocks user-mode DLL injection
  into `RubinOT.exe`. Kernel-side hooking would be possible in
  combination with an external DSE-bypass, but is out of scope for
  this repo.

---

## Timeline of misassumptions (v1 -> v2)

- v1 (initial recon)
  - Read `EMACDRVGLTB.sys` strings, saw `Nt*` primitives, assumed HWID
    kernel-side collection.
  - Concluded MachineGuid was not read (based on limited procmon window
    with no re-registration event).
  - Concluded Storage IOCTL intercept was needed (guessed from disk
    serial being commonly hashed in similar anti-cheats).
- v3.1-3.4 (driver expansion)
  - 6 BSOD fixes chasing `STORAGE_QUERY`, `SMART_IDENTIFY`,
    `ATA_PASS_THROUGH`, `ATA_PASS_THROUGH_DIRECT`,
    `STORAGE_PROTOCOL_COMMAND` code paths. Cost stayed high, benefit
    stayed zero.
- v3.5.1 (profile trim)
  - Removed `windows.machine_guid`, `sqm_machine_id`, `product_id`
    from profile v6. Two of the three were correct.
- v3.6 (driver minimization)
  - Storage IOCTL intercept dropped. Correct decision, kept in v2.
- v3.7 (post-recon-v2, this repo state)
  - `MachineGuid` restored to profile v8.
  - Fase 1.6 adds `spoof-disk-registry.ps1`, `spoof-pci-hardwareid.ps1`,
    `spoof-volume-guid.ps1`.

---

## Fase 2 revised (kernel-required gaps)

Only two gaps remain that cannot be closed with registry writes alone.

- GAP #1 — Network `PnPInstanceId`
  Registry rewrite alone is undone at the next PnP enumeration. Requires
  an NDIS bus filter to intercept and rewrite at enum time.
- GAP #2 — CPU `ProcessorNameString`
  Value comes from CPUID; the registry mirror only reflects it. Would
  require a kernel-mode CPUID trap / VMX replay, or a hypervisor-level
  shim. Out of scope for a registry+SMBIOS toolkit.

Everything else previously deferred to Fase 2 is now closed by Fase 1.6:

- GAP #7 disk model      -> `spoof-disk-registry.ps1`
- GAP #8 PCI granular ID -> `spoof-pci-hardwareid.ps1`
- GAP #9 Volume GUID     -> `spoof-volume-guid.ps1`

---

## References

- Procmon captures (local, not committed):
  `baseline-7min.PML`, `reregistration-18min.PML`.
- Cross-check queries used:
  - `Process Name is RubinOT.exe` AND `Operation is RegQueryValue`
  - `Process Name is WmiPrvSE.exe` (idle-check)
  - `Operation is DeviceIoControl` (zero-check across all processes)
  - `Path contains \Device\PhysicalDrive` / `\Device\Scsi` / `\Device\NVMe`
- Static analysis of `EMACDRVGLTB.sys`:
  `sc qc EMACDRVGLTB`, `fltmc filters`, PE import table dump.
- v1 reconnaissance: internal notes only (not versioned in this
  repo). All conclusions from v1 that survived cross-check with
  the two procmon captures are reproduced above; the rest were
  wrong and are called out inline as "recon v1 assumed X — v2
  confirms not observed".
