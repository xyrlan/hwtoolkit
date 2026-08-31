# v4.1 Roadmap — real WMI-visible SMBIOS spoofing

**Status:** design draft. Not implemented in v4.0.6.
**Predecessor incident:** `docs/postmortem-v4-phase5/incident-v406-bug-triage.md` (Bug 3 root cause).
**Blocker for start:** need one WinDbg session on the VM to capture the exact WNODE layout `WmipQueryRawSMBiosTables` returns (offset of the actual SMBIOSTableData region inside the `WNODE_ALL_DATA` reply).

## Why v4.0.6 is not enough

The v4.0.6 postmortem confirmed the SMBIOS registry-write strategy inherited from v3.4 cannot work. Two independent defects stack:

1. **`mssmbios.sys` serves WMI queries from an in-kernel firmware cache**, not from `HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data\SMBiosData`. Verified via ReactOS `ntoskrnl/wmi/smbios.c`: `WmipQueryRawSMBiosTables` → `WmipGetRawSMBiosTableData` scans firmware physical memory (0xF0000 legacy or ACPI RSMB pointer) directly. The registry mirror is a **write-back artifact** for the crash-dump path + external tooling only. MSDN explicitly says: *"consumers should continue to use WMI or the GetSystemFirmwareTable() API to retrieve SMBIOS data"* — the registry is not the source of truth.

2. **mssmbios is `Start=1` (SYSTEM_START)**, verified empirically on Windows 10 Pro dev host 2026-08-30:
   ```powershell
   Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\mssmbios |
       Select Start, Type, Group
   # Start:1, Type:1 (Kernel driver), Group:<empty>
   ```
   RstFlt is `Start=0` (BOOT_START), so we run **before** mssmbios. `ZwOpenKey` on `\Registry\Machine\SYSTEM\CurrentControlSet\Services\mssmbios\Data` typically returns `STATUS_OBJECT_NAME_NOT_FOUND` — the `Data` subkey is (re)created by mssmbios during its own SYSTEM_START init, likely `REG_OPTION_VOLATILE`. `Parameters\OrigSmbiosData` staying 0 bytes across v4.0.5 arming runs is the direct signature of this bail path.

Both defects have the same fix: **intercept the WMI query path**, not the registry.

## Preferred path — try the low-risk options first

### Option A: user-mode WMI provider that shadows the Win32_* classes

Windows lets you register a WMI provider via MOF + `mofcomp` that reports data for a specific class. If we register a provider that answers queries for `Win32_ComputerSystemProduct`, `Win32_BaseBoard`, `Win32_SystemEnclosure` (and the underlying `MSSmBios_RawSMBiosTables` in `root\wmi` namespace) with our spoofed values, and it has higher precedence than the built-in `cimwin32.dll` provider that answers the same classes today, it wins.

**Advantages:**
- No kernel work, no PatchGuard risk, no signed driver required beyond what we already ship.
- Runs under WmiPrvSE.exe hosting; failures don't BSOD.
- Configurable per-machine.

**Investigate:**
- Whether WMI actually resolves "higher precedence" the way we want, or whether the built-in provider's `#pragma namespace` claim is exclusive. If exclusive, need to un-register the built-in first — invasive and reverts on WMI repository repair.
- Whether anti-cheats explicitly call `IWbemLocator::ConnectServer` with `WBEM_FLAG_CONNECT_USE_MAX_WAIT` and a specific provider path that skips our shadow. If yes, this option is defeated.
- Whether user-mode `GetSystemFirmwareTable("RSMB", 0, buf, len)` gets our shadow's data (probably not — it goes straight to `NtQuerySystemInformation(SystemFirmwareTableInformation)` via `ntdll`, bypassing WMI entirely). If not, we still need a kernel piece for that path.

**Verdict:** worth prototyping as the first attempt. Small blast radius. Even a partial win reduces the kernel patch surface.

### Option B: minifilter registered against the mssmbios namespace

The filter-manager stack lets an altitude-based minifilter observe/intercept `IRP_MJ_SYSTEM_CONTROL` on named devices. If we can register a minifilter that binds to `\Driver\mssmbios` at a high altitude (i.e., closer to the caller than mssmbios itself), it sees the WMI query IRP before mssmbios completes it and can rewrite the returned WNODE buffer.

**Investigate:**
- Whether the filter manager actually attaches to non-file-system driver objects. The FltMgr documentation is file-system-centric; WMI-IRP interception may not be a supported altitude class.
- Alternative: legacy filter-driver `IoAttachDeviceToDeviceStack` on a device object of `\Driver\mssmbios` (if it creates one — mssmbios typically does not create a device object in the classical sense, since it services WMI via `WmiSystemControl` from the kernel side).

**Verdict:** likely a dead end because mssmbios's WMI plumbing goes through the WMI infrastructure rather than a device object with an IRP dispatch we can filter. Note down as tried, move on.

## Fallback path — kernel dispatch interception (HIGH RISK)

Only if Options A and B fail:

### Option C: PsSetLoadImageNotifyRoutine + IRP_MJ_SYSTEM_CONTROL patch

1. Register `PsSetLoadImageNotifyRoutine` in DriverEntry (safer than a KeSetTimer polling loop — this is the WDK-canonical hook point for "watch for a specific driver to load").
2. When mssmbios.sys load-image notification fires, call `ObReferenceObjectByName(L"\\Driver\\mssmbios", ...)` to get the DriverObject.
3. **Interlocked**-swap `DrvObj->MajorFunction[IRP_MJ_SYSTEM_CONTROL]` with our own dispatcher, saving the original pointer for pass-through.
4. Our dispatcher inspects the incoming `PIRP`'s `Parameters.WMI.DataPath` — if the WMI GUID is `MSSmBios_RawSMBiosTables_GUID {8F680850-A584-11D1-BF38-00A0C9062910}`, we forward with a completion routine.
5. Completion routine scans the returned WNODE buffer, finds our cached `SmbiosBlob` insertion offset, and `memcpy`'s our fake bytes over the real ones before completing to the caller.
6. On our own DriverUnload path, restore the original `MajorFunction[IRP_MJ_SYSTEM_CONTROL]` and `ObDereferenceObject` the reference.

**CRITICAL constraint: PatchGuard.** Modifying a foreign DriverObject's `MajorFunction[]` array is a documented PG target on Windows 10 20H1+. On any system with signature-enforced kernel integrity, PG will bugcheck `0x109 CRITICAL_STRUCTURE_CORRUPTION` within 30-120 seconds of the swap.

- **HVCI off is necessary but NOT sufficient.** PG runs on top of HVCI-off too.
- **testsigning ON does not disable PG.** They're orthogonal.
- **Runtime PG-armed detection is mandatory.** Query BCD hypervisor policy and `ci.dll` KDP status at DriverEntry; if PG is armed, refuse to install the hook and record `LastReplayStatus` tag `0x06 PATCHGUARD-ARMED` (reserve this tag now). Document loudly: **"v4.1 SMBIOS interception requires Test Signing + PatchGuard disabled. Dev/research use only. Do NOT distribute for production use."**

### Option D: hook `WmipGetRawSMBiosTableData` via kernel-mode inline patching

Locate the export/internal address in ntoskrnl.exe, place an INT3 or a JMP to our stub, do the same buffer rewrite there. **Rejected.** Even worse PG exposure than Option C, and the function is not exported so we'd depend on symbol server offsets that change per Windows build. Not viable for a distributable tool.

## Test plan (before code)

1. **WinDbg VM session (one time):**
   - `!drvobj mssmbios 7` — confirm major function table, note if any minifilters already attached.
   - `bp nt!WmipQueryRawSMBiosTables` — break, dump `rax` on return, inspect the WNODE layout to pin the exact offset of `SMBIOSTableData` (or `Data` region) inside the reply. Capture size, alignment, and where the SMBIOS structure table starts inside it. Save this dump for the code to reference.
   - `!wmiquery` on a known consumer (`wmic ComputerSystemProduct get UUID`) to see whether WMI queries land as `IRP_MJ_SYSTEM_CONTROL` on `\Driver\mssmbios` or take a different path entirely.

2. **Option A prototype (user-mode only):**
   - Author a minimal COM WMI provider DLL that answers `Win32_ComputerSystemProduct.UUID` with a hard-coded string.
   - Register via `mofcomp` in a class MOF that claims the class with a higher precedence than the built-in.
   - Query `Get-CimInstance Win32_ComputerSystemProduct` and see whether we win. If yes → the whole v4.1 might not need any kernel work. If no → move to Option B.

3. **Option C gated dev-only prototype (only if A+B fail):**
   - Build a separate `.sys` (not part of the main RstFlt filter) that only does the load-image + dispatch-swap. Test on a Hyper-V guest with `bcdedit /set nointegritychecks on /set testsigning on` and explicit PG-off. Measure BSOD time under a hostile PG-armed kernel to validate the runtime detection guards work.

## Accepted limitations

Even a perfect SMBIOS spoof does NOT hide the VM on Hyper-V. The guest still leaks:

- **VMBus** enumeration (`\Device\VmBus`, `HKLM\SYSTEM\CurrentControlSet\Enum\VMBUS`) — every synthetic device (storvsc, netvsc, hyperv-keyboard) advertises the Microsoft Hyper-V vendor.
- **KVP integration service** publishes IntegrationServicesVersion, PhysicalHostName, PhysicalHostNameFullyQualified to the host — anti-cheats can query `Root\Virtualization\v2` on the host or, if they run as SYSTEM, read the KVP intrinsic exchange values from the guest side (`HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest`).
- **CPUID hypervisor bit** (leaf 1, bit 31 of ECX) — HW-level flag set by Hyper-V; kernel-mode readers see it directly regardless of any WMI spoof.
- **BCD hypervisorlaunchtype** if VM is nested — visible in EMS/BCD reads.

The v4.1 SMBIOS work is meaningful for **bare-metal targets** (which is where the toolkit ultimately runs). On Hyper-V guests, treat the spoof as a dev-loop convenience for iterating downstream code, not a production stealth mechanism.

## Non-goals for v4.1

- Any change to the CPU registry replay path. That works correctly today and its stability is independent of the SMBIOS re-architecture.
- Physical-memory ACPI table modification (patching the firmware SMBIOS bytes in-place). Would require a UEFI DXE driver signed for SecureBoot; out of scope for a Windows-loadable toolkit.
- User-mode DLL injection into anti-cheat processes to hook `GetSystemFirmwareTable`. Considered and rejected — the moment we ship a general-purpose AC injector we cross into malware detection heuristics that would make the toolkit far harder to distribute for legitimate research use.

## Owner + timeline

Unassigned. Prerequisite: the Bug 4 investigation from v4.0.6 must close first (either confirmed host-side reset via VmHeartbeat → no driver change needed, or captured MEMORY.DMP naming a specific consumer service → targeted fix in the driver or user-mode). Only then does v4.1 land on a stable base.
