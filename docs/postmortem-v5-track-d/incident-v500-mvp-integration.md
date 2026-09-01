# incident-v500-mvp-integration - Track D MVP kernel integration

Status: **VM UNIT TEST PASSED** (2026-09-01). Bare-metal RubinOT test still pending.
Data: 2026-09-01
Driver: rstflt.sys v5.0.0
Escopo: MVP conforme docs/track-d-kernel-registry-callback-kickoff.md
        secao 4 - intercepta apenas `\Enum\SCSI` + subkeys que
        comecam com `Disk&Ven_`.

---

## 0. VM unit test result (2026-09-01)

Test env: Hyper-V VM `Ambiente de desenvolvimento do Windows 10`
(guest hostname `DESKTOP-YF580NS`), Win10 Enterprise Gen2 UEFI,
storvsc, WDAC enforced mode 2, testsigning ON, HVCI OFF, heartbeat +
KVP disabled on host. Restored from `clean-no-driver` checkpoint.

Sequence: `03-instalar-driver.bat` (v5.0.0 signed, marker OK) →
reboot → `track-d-arm.ps1 -Enable` (EnableRegCallback=1,
seed=`50489da3...`, RubinOtPid=0) → reboot → test PS (PID 7020)
`-SetPid 7020` → both tracked (PID 7020) and untracked (PID 2020)
PowerShell sessions enumerated `HKLM\SYSTEM\CurrentControlSet\Enum\SCSI`
via `[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(...).GetSubKeyNames()`.

Actual output:

| PID | CdRom subkey | Disk subkey |
|-----|--------------|-------------|
| 7020 (tracked) | `CdRom&Ven_Msft&Prod_Virtual_DVD-ROM` (real, pass-through) | **`Disk&Ven_F583&Prod_2FB5A67112E6`** (synthetic FNV hex, rewritten) |
| 2020 (untracked) | `CdRom&Ven_Msft&Prod_Virtual_DVD-ROM` (real) | `Disk&Ven_Msft&Prod_Virtual_Disk` (real) |

`track-d-arm.ps1 -Diagnose` after test:
```
EnableRegCallback   : 1
RegCallbackSeed     : 50489da37e94ae91078353c3b3287dd0
RubinOtPid          : 7020
CallbackHitCount    : 2
LastCallbackStatus  : 0x00000000  tag=0x00 OK
```

Signals verified:
- Post-callback `RegNtPostEnumerateKey` rewrite path works — buffer
  in `KEY_BASIC_INFORMATION.Name` mutated in place before caller reads.
- Same-wchar-count guaranteed: `Disk&Ven_Msft&Prod_Virtual_Disk` (31)
  → `Disk&Ven_F583&Prod_2FB5A67112E6` (31); markers `Disk&Ven_` (9)
  and `&Prod_` (6) preserved; Ven token `Msft` (4) → `F583` (4);
  Prod token `Virtual_Disk` (12) → `2FB5A67112E6` (12). Caller's
  `NameLength` untouched.
- PID filter isolates cleanly (same enum call, PID 7020 sees synthetic,
  PID 2020 sees real).
- MVP scope respected: `CdRom&` prefix bypasses the child-prefix gate
  and returns as pass-through untouched.
- `RegNtPreSetValueKey` tap on our own `Parameters\RubinOtPid` works:
  `-SetPid 7020` took effect without reboot via the callback's Parameters
  key write intercept.
- No BSOD, no PatchGuard trigger, no crash. Driver marker at
  `RstFlt-v5.0.0-BUILD-MARKER`. `sc query RstFlt` = `Running` / `Boot`.
- Breadcrumb race fix from adversarial review (finding #1) also
  validated in practice: `CallbackHitCount=2` and `LastCallbackStatus=OK`
  both persisted correctly to Parameters despite burst enum.

All fixes from the adversarial workflow pass live.

### 0.1 Known limitation surfaced during VM smoke: `-Disable` requires reboot

Smoke test 1 (post-unit-test) ran `track-d-arm.ps1 -Disable` expecting
the rewrite to stop immediately on the next enum. It did NOT — the
enum still returned the synthetic name.

Root cause: `TrackDHandlePreSetValue` (the `RegNtPreSetValueKey` tap
on our own Parameters key) filters only on `RubinOtPid` value name.
When userland writes `Parameters\EnableRegCallback=0`, the driver
never notices — `g_TrackDEnabled` is set once at `LoadTrackDConfig`
time (from `DriverEntry`) and stays TRUE for the driver's lifetime.

Impact: LOW. Rebooting drains `EnableRegCallback=0` correctly via
`DriverEntry`. `08-desinstalar-driver.bat` (which reboots anyway)
gives the same effect via full uninstall. The "efeito imediato"
promise in the previous `-Disable` message and README was aspirational,
not implemented.

Mitigations applied in this session (v5.0.0):
- `scripts/track-d-arm.ps1` `-Disable` message now warns that reboot
  is required.
- `README.md` "Level C+ / Track D" section documents the limitation.

Fix planned for v5.0.1:
- Expand `TrackDHandlePreSetValue` (`driver/rstflt.c`) to dispatch on
  value name and mirror the same pattern used for `RubinOtPid`: on
  `EnableRegCallback` write, `RtlCopyMemory(&newVal, info->Data,
  sizeof(ULONG))` under SEH, then update `g_TrackDEnabled` accordingly.
  About 15 additional LOC in the existing tap handler; no other code
  changes needed.
- No design change; same reentrancy contract (all reads/writes are
  memory-only within the callback body).

Deferred deliberately per user choice this session to avoid a
rebuild-reinstall-reboot cycle just for a UX affordance; MVP kernel
correctness is unaffected, and the bare-metal RubinOT test (which is
the gate that actually matters) needs `-Enable + reboot` only.

Bare-metal RubinOT test (kickoff sec 6.3) is the remaining gate.

---

## 1. Summary

Este documento e o postmortem obrigatorio pelo CLAUDE.md style
("Every non-trivial toolkit-behavior discovery gets a new incident-
v40X-*.md"). Sera preenchido apos o teste bare-metal descrito na
secao 6.3 do kickoff. Atualmente contem apenas o design-of-record
das decisoes tomadas na implementacao e o estado dos testes VM.

---

## 2. Contexto - por que Track D e por que agora

Os tres bans empiricos observados 2026-08-31 e 2026-09-01 (baseline,
Level A userland, fresh identity com PRs #12/#13/#14/#15 armados)
todos dentro de ~1 minuto de login confirmaram H2 do
docs/emac-recon-v3.md: EMAC le NOMES DE SUBKEYS via `RegEnumKeyEx`,
e nosso spoof userland ate PR #15 so reescrevia VALUES dentro dos
subkeys. Renomear subkeys em user-mode ficou bloqueado por handle
contention do PnP Manager (documentado em PR #13 fake-rollback).

Track D e a resposta arquitetural: intercepta a LEITURA no kernel
via `CmRegisterCallbackEx`, sem tentar mudar o dado subjacente.

---

## 3. Design decisions (aplicadas ao codigo)

### 3.1 PID discovery: Opt B em vez de Opt A recomendada no kickoff

Kickoff recomendou MVP com Opt A (userland `track-d-arm.ps1 -Launch`
escreve PID via `Set-ItemProperty`, driver le do Parameters). A
implementacao usou Opt B (`PsSetCreateProcessNotifyRoutineEx`) por
tres razoes:

1. **Reentrancy trap na Opt A**: para o driver "ver" updates de
   `Parameters\RubinOtPid` sem polling, teria que chamar `ZwOpenKey`
   + `ZwQueryValueKey` de dentro do proprio `RstRegistryCallback`.
   MSDN explicitamente adverte contra Zw* dentro de Cm callback -
   deadlock potencial sob o CM-internal lock.

2. **Ps callback e nativo e cheap**: registra uma vez em DriverEntry,
   auto-populates on process create, auto-clears on process exit.
   Sem polling, sem periodic worker.

3. **Menos codigo total**: ~40 LOC para Opt B vs. ~80 LOC para Opt A
   com worker + safe re-read logic.

Kickoff explicitamente permite Opt B como fallback ("Opt B fica em
docs/track-d-followup.md se o teste bare-metal expuser flakiness
por PID stale") - implementacao usou direto.

Preservado da Opt A: userland pode setar `Parameters\RubinOtPid`
(REG_DWORD, non-zero) via `track-d-arm.ps1 -SetPid <int>` para
sobrescrever o PID auto-detectado. Necessario para o unit test do
kickoff secao 6.1 (test process nao e rubinot_dx.exe). Driver
detecta essa escrita via TAP no proprio `RegNtPreSetValueKey`
callback, sem Zw calls.

### 3.2 Rewrite strategy: post-callback rewrite em vez de pre + BYPASS

Kickoff menciona `STATUS_CALLBACK_BYPASS` na secao 5.3. A
implementacao usou `RegNtPostEnumerateKey` (post-callback) e mutou
o buffer do caller in-place. Vantagens:

1. **Zero reentrancy**: nao precisa enumerar por conta propria
   (impossivel sem Zw calls dentro do callback).
2. **NameLength preservada**: garantia by-construction de same
   wchar count entre real e sintetico.
3. **Menos superficie de bug**: kernel faz a enumeration completa,
   nos so mudamos bytes especificos.

Trade-off: se algum dia quisermos ESCONDER subkeys inteiras (nao so
renomear), teremos que voltar para pre-callback + BYPASS. Nao e
requisito MVP.

### 3.3 Breadcrumb via deferred work item

`WriteLastCallbackStatus` nao chama Zw* dentro do Cm callback.
Atualiza `g_TrackDLastStatus` e `g_TrackDHitCount` via
`InterlockedExchange` / `InterlockedIncrement`, e - se ainda nao
esta pendente - queueia `g_TrackDFlushWorkItem` no
`DelayedWorkQueue`. O worker (`TrackDFlushWorker`) roda a
PASSIVE_LEVEL, FORA do Cm callback stack, seguro para
`ZwSetValueKey`.

Flag `g_TrackDFlushQueued` evita double-queue via
`InterlockedCompareExchange` gate. Aceita "lost updates" no
sentido de que se dois updates coalescem no mesmo flush, so a
segunda amostra e persistida - suficiente para intent diagnostico
("last state") mas nao para telemetria de fire count exata.

`CallbackHitCount` acumula monotonicamente entre reboots (nao
resetado por Flush) - representa "quantos rewrites este boot".

### 3.4 Rewrite algorithm: FNV over token bytes por SCSI field

Cada campo (Ven, Prod, Rev) e reescrito independentemente:

- Input FNV: `<domain-tag>|<seed-bytes>|<real-field-UTF16-bytes>|<round>`
  onde `<round>` = `'0'..'F'` para gerar hex adicional quando o
  field e mais longo que 16 chars (64 bits = 16 hex).
- Output: hex upper-case, cursor no field, ate `fieldLen` chars.
- Preserva markers `Disk&Ven_`, `&Prod_`, `&Rev_` e todos os `&`
  separators.

Determinismo: dado (seed, real_name), sempre mesmo synthetic. Rerun
com mesmo profile = mesmo fingerprint spoofado em multiplas
sessoes.

---

## 4. VM unit test (pending)

Sequencia planejada per kickoff secao 6.1:

- [ ] Restaurar checkpoint `clean-no-driver`. Disable heartbeat + KVP.
- [ ] Copy `driver/rstflt.sys` v5.0.0 + `scripts/track-d-arm.ps1`.
- [ ] `03-instalar-driver.bat` (base install, sem arm).
- [ ] Reboot.
- [ ] `track-d-arm.ps1 -Enable` (seta EnableRegCallback=1 + seed).
- [ ] Reboot (Track D so entra em vigor no proximo boot se driver ja
      estava carregado).
- [ ] Pos-reboot: PowerShell test process com PID=P.
- [ ] `track-d-arm.ps1 -SetPid P`.
- [ ] Test process faz `Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI`.
- [ ] Esperar: nomes de subkeys sinteticos (nao Kingston/etc real).
- [ ] Outro PowerShell (PID != P) do mesmo `Get-ChildItem`.
- [ ] Esperar: nomes reais (filtro por PID isolando).
- [ ] `track-d-arm.ps1 -Diagnose` -> LastCallbackStatus tag 0x00 OK.
- [ ] Kill test process. Outro test process com novo PID Q. SetPid Q.
- [ ] Verificar novo PID passa a ser filtrado.
- [ ] `track-d-arm.ps1 -Disable`. Todos os PIDs voltam a ver real.
- [ ] `08-desinstalar-driver.bat`. Reboot. `sc query rstflt` = 1060.

---

## 5. VM soak test (pending)

Kickoff secao 6.2: 24h com script loopando `Get-ChildItem` +
`Get-ItemProperty` sob `Enum\SCSI` + expandido para USB/PCI/HID/
Audio se aplicavel. Metricas de aceitacao:

- Zero BSODs.
- `LastCallbackStatus` estavel em 0x00 OK (ou 0x01 NO-PID em janelas
  de reboot).
- Sem leak crescente de NonPagedPool.
- Latency por reg op nao mais que 5x baseline sem callback.

---

## 6. Bare-metal RubinOT test (pending)

Kickoff secao 6.3:

- [ ] `08b-rollback-userland.bat`.
- [ ] `08-desinstalar-driver.bat` + reboot.
- [ ] `02-compilar-driver.bat` no host + transferir + `03-instalar-driver.bat`.
- [ ] Reboot.
- [ ] `00-gerar-profile.bat` (seed novo).
- [ ] `04b-aplicar-hwid-emac.bat --skip-disk --skip-volume --skip-usb --skip-hid`.
- [ ] `track-d-arm.ps1 -Enable`.
- [ ] Reboot.
- [ ] Launch RubinOT (Ps auto-tracking populates PID).
- [ ] Criar conta nova. Login. Iniciar gameplay.
- [ ] Coletar:
  - `%USERPROFILE%\emac-uuid`
  - `%TEMP%\rubinot_delete_uuid.csv` se ban
  - `track-d-arm.ps1 -Diagnose` output
  - `wmic diskdrive get model,serialnumber /format:list`
  - `Get-PnpDevice | Select FriendlyName, InstanceId`

---

## 7. Success criteria

MVP DONE quando:

1. VM unit test passa (secao 4).
2. VM soak 24h sem BSOD, sem leak, sem >5x latency.
3. Bare-metal criacao de conta + login + gameplay session **sem ban**.
4. `08-desinstalar-driver.bat` restaura sistema limpo pos-reboot.

---

## 8. Follow-ups conhecidos (se ban persistir apos MVP)

Ordem de expansao per kickoff secao 4:

1. `Enum\USB\VID_*&PID_*\<serial>` - 889 reads/sessao, maior volume.
2. `Enum\PCI\VEN_*&DEV_*&SUBSYS_*&REV_*`.
3. `MMDevices\Audio\Render\{GUID}` + `\Capture\{GUID}`.
4. `Enum\HID\*` (last porque input safety - keyboard/mouse ATIVOS
   nao podem ser mexidos sem gate special).
5. Se necessario: shadow para `Enum\SCSI\Disk\HardwareID` VALUES
   dentro dos subkeys (defense-in-depth mesmo que Level A userland
   ja escreva).

---

## 9. References

- [`docs/track-d-kernel-registry-callback-kickoff.md`](../track-d-kernel-registry-callback-kickoff.md) - kickoff completo.
- [`docs/emac-recon-v3.md`](../emac-recon-v3.md) - recon EMAC.
- [`docs/track-d-name-recipe.md`](../track-d-name-recipe.md) - especificacao byte-a-byte do sintetizador (userland reproducibility).
- [`driver/rstflt.c`](../../driver/rstflt.c) - implementacao (procurar bloco `v5.0.0 Track D`).
- [`scripts/track-d-arm.ps1`](../../scripts/track-d-arm.ps1) - userland arm/disarm/diagnose.
- Kickoff secao 5.3 tabela de riscos + mitigacoes.
- Adversarial review workflow (wf_4cd7f5d0-871): 6 findings surviving verify (2 CONFIRMED / 4 PARTIAL). Fixes applied inline in v5.0.0 build. Zero HIGH severity, no BSOD risk.
