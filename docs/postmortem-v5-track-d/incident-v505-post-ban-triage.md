# incident-v505-post-ban-triage - v5.0.4 bare-metal ban #4 empirical triage + v5.0.5 scoping

Status: **CLOSED as scoping-input** (2026-09-01). Adversarial workflow review consumed; v5.0.5 kickoff derived in [`../track-d-v505-value-handler-kickoff.md`](../track-d-v505-value-handler-kickoff.md).
Data: 2026-09-01
Driver: rstflt.sys v5.0.4 armado (`.\scripts\track-d-arm.ps1 -Enable`), Level A userland aplicado.
Escopo: pos-mortem do quarto ban RubinOT consecutivo, agora com Track D v5.0.4 (image-name gate inline validado em VM unit test) armado end-to-end. Triage empirico dos contadores + adversarial workflow review (11 agents, 880k tokens, refutou 3 de 6 alegacoes iniciais do operador) que redefiniu o escopo do v5.0.5. Complemento tecnico ao [`incident-v504-pid-matching-simplification.md`](incident-v504-pid-matching-simplification.md).

---

## 1. Summary

Sessao RubinOT ~15min pos-login. Ban emitido no timing tipico (~9-10min). Track D v5.0.4 armado (`EnableRegCallback=1`, image-name gate validado em VM antes do bare-metal). Contadores pos-ban:

| Contador | Valor | Interpretacao |
|---|---|---|
| `CallbackInvokeCount` | 258,578,834 | Callback dispatch system-wide funcional |
| `CallbackHitCount` | **2** | So 2 rewrites landaram em TODAS as 6 path types combinadas |
| `CallbackNameMissCount` | 177,928 | 178K enums de processos nao-rubinot rejeitados |
| `LastMissImageName` | `powershell.exe` | Buffer sobrescrito pelo `-Diagnose` posterior; inconclusive |
| `LastCallbackStatus` | 0x00 OK | Hot path executou pelo menos 1x sem erro |
| `LastArmStatus` | 0x00 OK | Callback armed limpo (split de LastCallbackStatus per v5.0.4) |

Probe pos-ban (`Copy-Item reg.exe rubinot_probe.exe; .\rubinot_probe.exe query HKLM\SYSTEM\CurrentControlSet\Enum\SCSI`): +4 HitCount delta (4 discos reais rewriteados byte-exact para synthetic `Ven_/Prod_`). Gate + rewriter mecanicamente 100% OK. emac-uuid regenerado (`1e5848ce-affc-4422-ae96-4e4b77ca0527`, era `f01b87e5`) - EMAC fez POST de re-registration com HW fingerprint durante a sessao.

Zero BSOD apos 258M invocations. MVP kernel-side v5.0.4 estabilidade provada.

---

## 2. Ground-truth do codigo v5.0.4 (adversarial workflow recon)

Auditoria de 3 agentes paralelos + refutacao de 5 claims + sintese produziu o mapa exato da superficie atual, contra o qual o plano do operador foi validado. Achados nao-obvios:

### 2.1 PCI/USB/HID/MMDevices Render/Capture JA SAO INTERCEPTADOS em v5.0.4

Correcao ao entendimento anterior (implicito em varias fontes, incluindo o texto inicial do operador): [`driver/rstflt.c:2385-2397`](../../driver/rstflt.c) - `TrackDClassifyParent` ja despacha 6 path types (SCSI, PCI, USB, HID, AudioR, AudioC) via enum em [`driver/rstflt.c:808-816`](../../driver/rstflt.c). Changelog v5.0.1 documentou essa expansao mas nao ficou destacado em memory nem em CLAUDE.md.

Implicacao: "Phase 1 = expand rewriter" como o operador o formulou (PCI/USB/HID/MMDev/BTH/STORAGE) e ~85% ja shipped. Net-new e apenas **BTH + STORAGE\\Volume** (~5-15% coverage adicional).

### 2.2 `g_TrackDHitCount` e GLOBAL, nao SCSI-only

Grep-verificado em [`driver/rstflt.c:2828`](../../driver/rstflt.c): `InterlockedIncrement(&g_TrackDHitCount)` sitting no fim de `TrackDHandlePostEnumerate`, **apos** o switch que dispatches para os 6 rewriters. HitCount incrementa quando qualquer path type consegue rewrite.

Consequencia direta: HitCount=2 em 15min = **so 2 rewrites totais landaram em TODAS as 6 categorias combinadas** ao longo da sessao.

### 2.3 ZERO value-read notify classes handled

Top-level switch em [`driver/rstflt.c:2916-2925`](../../driver/rstflt.c) handles apenas `RegNtPostEnumerateKey` e `RegNtPreSetValueKey` (o segundo e o tap na nossa propria Parameters). Todas as classes de value-read (`RegNtPreQueryValueKey`, `RegNtPostQueryValueKey`, `RegNtPreGetValueKey`, `RegNtPostGetValueKey`, `RegNtPreQueryMultipleValueKey`) caem em `default: break` e retornam `STATUS_SUCCESS` com buffer real intacto.

---

## 3. Hipoteses concorrentes para HitCount=2 + ban persistente

**RESOLVIDO EMPIRICAMENTE via 2 CSVs procmon (delete_uuid + v502_test) + grep in-tree.** Cinco leituras plausiveis foram cross-checkadas; a resposta correta nao estava na lista original.

| # | Hipotese | Veredicto |
|---|---|---|
| A | Rubinot enumera SCSI/etc apenas no startup | REFUTADA - recon documenta re-register burst; fresh emac-uuid POST prova que ele rodou |
| B | EMAC injeta em host nao-`rubinot*` | **REFUTADA** - Q2 confirma emac-client64.dll loaded EXCLUSIVAMENTE por rubinot_dx.exe (Load Image=1; launcher RubinOT.exe faz Load Image=0, so stat) |
| C | Multi-stage launcher chain com processo nao-`rubinot*` | **REFUTADA** - so 2 processos (`rubinot_dx.exe`, `RubinOT.exe`), ambos com prefix "rubinot" case-insensitive matchado pelo gate |
| D | EMAC co-opta WmiPrvSE/svchost helper | **REFUTADA** - Q4 confirma WmiPrvSE = 0 events em ambos CSVs; svchost activity e baseline PnP housekeeping |
| E | HitCount SCSI-only mascarando PCI/USB/HID fires | REFUTADA - grep [`driver/rstflt.c:2828`](../../driver/rstflt.c) confirma HitCount global |
| **F** | **EMAC usa `RegOpenKey(exact-name) + RegQueryValueEx(HardwareID)` obtendo nomes via SetupDi/CM_* PnP APIs, NAO via `RegEnumKeyEx`. `RegNtPostEnumerateKey` handler nunca dispara para esse padrao.** | **CONFIRMADA** - recon-v3:32 verbatim "100% user-mode via RegQueryValueEx". Handler v5.0.4 escuta so classe errada. |

### 3.1 Consequencia da hipotese F

- Gate `_strnicmp("rubinot", 7)` + delimiter guard esta 100% funcional para ambos os processos alvo. Nao precisa broadenar. Verificado empiricamente:
  - `rubinot_dx.exe` -> primeiros 7 chars = "rubinot" + delimiter `_` -> accepted por [`driver/rstflt.c:2627-2632`](../../driver/rstflt.c)
  - `RubinOT.exe` -> primeiros 7 chars case-insensitive matcham "rubinot" + delimiter `.` -> accepted
- HitCount=2 e a contagem legitima das raras vezes que algo em rubinot_dx.exe ou RubinOT.exe genuinamente chamou `RegEnumKeyEx` num dos nossos parents (provavelmente init do Tauri Rust backend do launcher, ou uma chamada interna de `CM_Get_Child` que resolveu via `RegEnumKeyEx`).
- **Phase 2 (RegNtPostQueryValueKey + RegNtPostGetValueKey handler) fica ainda mais claramente arithmetically dominant como P0 fix** - nao e so "expandir cobertura" mas literalmente "escutar a notify class que EMAC de fato usa".
- Phase 0 instrumentacao deixa de servir para "broadenar o gate" e passa a servir para (a) validar que Phase 2 handler dispara pros processos certos, (b) contar quantos value reads por path type acontecem em sessao real, (c) diagnostic post-mortem se Phase 2 nao flippa ban outcome.

### 3.2 Dual-flow HW enum (Q2 side finding)

- `rubinot_dx.exe` = game client, loada `emac-client64.dll`, faz HWID collection via essa DLL (path documentado em recon).
- `RubinOT.exe` = launcher Tauri, **nao loada emac-client64.dll** - faz seu proprio HW enum via backend Rust do Tauri, codigo INDEPENDENTE do EMAC.
- Ambos posta pro mesmo backend server, ambos precisam ver values synth para o ban parar.
- Gate cobre os dois (§3.1), mas Phase 2 handler precisa cobrir os value reads chamados pelos DOIS - o que ja acontece naturalmente porque o handler filtra por image name, nao por qual DLL fez a chamada.

---

## 4. Vetor ranking adversarial (workflow output)

Peso estimado de contribuicao pro ban se o vetor fosse a UNICA correcao. Ranking bayesiano em cima de recon + refutacoes:

| Rank | Vetor | Ban-weight solo | Cobertura v5.0.4 |
|---|---|---|---|
| 1 | Enum\* leaf VALUES (HardwareID/CompatibleIDs/DeviceDesc/FriendlyName under SCSI/PCI/USB/HID/BTH/STORAGE) | 35-50% (~70% combinado com #2) | none |
| 2 | **Inconsistencia name-vs-value ativa** (parent name synth "F583" + HardwareID value real "Kingston SA400S37240G" sob a mesma chave) | 25-40% | partial - criada por v5.0.4 |
| 3 | EDID (128-byte REG_BINARY, descriptor blocks 0xFC/0xFF) | 15-25% | partial (Level A escreve; persistencia bare-metal pos-GPU-driver-event UNVERIFIED) |
| 4 | STORAGE\Volume\{GUID}#offset enum names + leaf values | 10-20% | none |
| 5 | MMDevices Audio endpoint VALUES (subkey GUID rewritten mas values sob ela nao) | 8-15% | partial |
| 6 | PCI HardwareID VALUE reads (REG_MULTI_SZ com SUBSYS+REV+CC) | 10-20% (overlap com #1) | partial - name rewrite cria inconsistencia |
| 7 | HID value reads | 5-12% | none |
| 8 | BTH enum names + values | 3-8% | none |
| 9 | HARDWARE\DEVICEMAP\VIDEO indirection | 3-8% | none |
| 10 | WMI in-proc reads (Win32_ComputerSystemProduct.UUID, Win32_BaseBoard, Win32_BIOS) | **1-3% (LOW PRIOR)** | none - CATEGORICAMENTE cego mas empiricamente cold para EMAC |
| 11 | cpuid inline em `.emac` VMProtect section | 2-5% (unfalsifiable ceiling) | partial via registry mirror |
| 12 | GetAdaptersAddresses / IP Helper direto | 2-5% | covered (Level A) |
| 13 | MachineGuid/ComputerName/Hostname/CentralProcessor value reads | 1-3% | covered (Level A escreveu, mas EMAC ainda le - reincide se Level A reverteu) |

**Take-away**: name-side rewrite expandido para BTH+STORAGE (~5-15%) e insuficiente. Value-read handler (~93% dos ~16,317 RegQueryValue events/re-register per recon-v3 §3.2) e o fix arithmetically dominant.

---

## 5. Refutacoes centrais do workflow

Todas com evidencia em recon docs + grep no codigo:

1. **"Phase 1 cobre ~60%"**: FALSA. 5-15% real (PCI/USB/HID/MMDev ja shipped; net-new BTH+STORAGE). Ver §2.1.
2. **"HitCount=2 = enum startup-only"**: FALSA. Ver §3 + §2.2. HitCount global mostra que o burst nao chegou ao dispatcher via `rubinot*`.
3. **"Phase 3 (WMI shadow) deve ser P0 pela ceguera categorical de CmRegisterCallback"**: FALSA para ESTE alvo. recon-v2 correction #6 + recon-v3 TL;DR:33 documentam WmiPrvSE idle em 25min combinados; recon-v3:32-34 zera DeviceIoControl, GetSystemFirmwareTable, \Device\PhysicalMemory. Guardar para v5.1+ (target diferente).
4. **"Parallelizar P1+P3 corta tempo pela metade"**: FALSA. Aritmetica errada (P3 e critical path dominante) e P3 e wasted work. P1+P2 compartilham [`driver/rstflt.c`](../../driver/rstflt.c) - sequential-merged e cheaper.
5. **"probe valida phase = done"**: FALSA. Probe testa dispatch + gate; nao testa ban logic. Ultimo teste provou: byte-exact SCSI rewrite + probe pass + **ban mesmo assim**. Probes viram regression gates de rebuild-time.
6. **"Phase plan tem gap em cpuid/GetSystemFirmwareTable/IOCTL SMBIOS"**: FALSA em duas dimensoes. Empiricamente: recon zera todos esses para EMAC. Estruturalmente: cpuid @ CPL=3 nao e interceptavel por driver KMDF nenhum - so hypervisor Type-1 (v6+ Bareflank/EfiGuard pivot).

---

## 6. Recomendacao consolidada v5.0.5

Detalhes completos em [`../track-d-v505-value-handler-kickoff.md`](../track-d-v505-value-handler-kickoff.md).

| Phase | Prio | Dias | Escopo |
|---|---|---|---|
| 0 - Instrumentation preflight | P0 | 0.5 | Per-path-type counters (SCSI/PCI/USB/HID/AudioR/AudioC/BTH/STORAGE) + ring buffer de last-16 (imageName, pathType, parentPath, childName) + segundo counter para invocations onde parent matches AND image nao-`rubinot*`. Exposto via check-consistency.ps1. |
| 1 - Enum-rewriter BTH + STORAGE\Volume | P0 | 2-3 | Duas patterns novas + descriptor-table refactor de `TrackDClassifyParent` para `{matcher, childGate, synthesizer, valueRewriter}` que Phase 2 consome |
| 2 - **Value-read handler** | P0 | 5-7 | `RegNtPostQueryValueKey` + `RegNtPostGetValueKey` dispatcher, table-driven, cobrindo MachineGuid, ComputerName, Hostname, PnPInstanceId x4, EDID (128B + checksum), CentralProcessor N, SCSI/PCI/USB/HID/BTH/STORAGE leaf values, MMDev endpoint values. Post-only design. |
| 3 - WMI provider shadow | **P3 - DROP** | - | Zero EMAC vectors. Guardar para v5.1+ |
| 4 - HARDWARE\DEVICEMAP\VIDEO | P2 - defer | - | Highest BSOD risk (dxgkrnl read at boot + mode switch); LOW ban weight (EDID e o load-bearing GPU discriminator, coberto em Phase 2) |

Total v5.0.5: ~7-10 dev-days, uma branch, um RubinOT test.

---

## 7. Open questions - status pos Q2/Q3/Q4

1. ~~**Q2 - Nome real do processo RubinOT**~~ **RESOLVIDO 2026-09-01** via 2 CSVs procmon. `emac-client64.dll` loaded so por `rubinot_dx.exe`. `RubinOT.exe` (launcher Tauri) nao loada DLL - faz HW enum via Rust backend proprio. Ambos matcham gate substring "rubinot" case-insensitive + delimiter guard. Gate esta OK, nao precisa broadenar. Ver §3.2.
2. **Q3 - EDID bare-metal persistence** cross-GPU-driver-events. **PARCIALMENTE PREDIZIDO, EMPIRICA PENDENTE**. Analise tecnica indica que independente de PnP re-write no hot-plug/sleep, EDID VALUE vaza HOJE porque v5.0.4 nao intercepta RegQueryValueEx. Phase 2 EDID rewriter (com checksum recompute) e a defesa duravel. Teste discriminativo simples fica na checklist pre-Phase-2 EDID work:
   ```powershell
   $edid1 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY\MHH2708\*\Device Parameters' -Name EDID -EA 0).EDID
   # <hot-plug ou sleep+wake do monitor>
   $edid2 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY\MHH2708\*\Device Parameters' -Name EDID -EA 0).EDID
   if ($edid1 -eq $edid2) { 'REGISTRY DURAVEL (userland write persiste)' } else { 'PNP RE-ESCREVEU (kernel intercept obrigatorio)' }
   ```
   Ambos os outcomes chegam na mesma conclusao pratica: Phase 2 EDID value handler e a solucao correta.
3. ~~**Q4 - Fresh procmon capture**~~ **RESOLVIDO 2026-09-01** via mesmos 2 CSVs. WmiPrvSE = 0 events em ambos = out-of-process WMI descartado. svchost activity nas HWID keys e baseline PnP housekeeping (22-45k eventos totais, 22-198 RegOpenKey nas HWID keys em 15min - normal para PlugPlay service polling). Cross-process HW enum via proxy service descartado. Ver §3.1.
4. **Q3-adjacent - In-process wbemprox status**. Recon-v3:32-34 zera DeviceIoControl (incluindo pro \Device\WMIDataDevice), GetSystemFirmwareTable, e \Device\PhysicalMemory. Se `wbemprox.dll` estivesse carregada em rubinot_dx.exe fazendo queries reais (Win32_ComputerSystemProduct.UUID etc), esperariamos IOCTLs para mssmbios - que sao zero. Duas interpretacoes possiveis:
   - **A**: rubinot_dx.exe carrega wbemprox mas nao faz queries que precisem de mssmbios/CIMOM. Wbemprox loaded mas cold.
   - **B**: rubinot_dx.exe faz queries via wbemprox in-proc que se resolvem em provider linkage direto (nao via IOCTL nem CIMOM/WmiPrvSE). Teoricamente possivel mas nao evidenciado pelos CSVs.
   Verificacao definitiva: capturar ETW WMI-Activity trace durante lifecycle rubinot_dx.exe. Se zero events em `Microsoft-Windows-WMI-Activity`, in-process WMI descartado empiricamente e Phase 3 (UMDF WMI shadow) fica formalmente closed. Se events aparecem, elevate Phase 3 para v5.0.6 backlog. Custo: ~5min de setup logman + 15min de RubinOT session.

---

## 8. Follow-ups

- [ ] Executar Q1 (Process Explorer live) na proxima sessao RubinOT
- [ ] Instrumentacao Phase 0 antes de qualquer trabalho de Phase 1/2 (nao serve pra debug post-hoc; serve pra decidir se gate precisa broadenar antes de Phase 2 lock-in)
- [ ] Rerun `docs/emac-recon` procmon capture na target bare-metal (game build pode ter mudado colecao)
- [ ] Verificacao EDID persistence bare-metal (fase 2 escopo depende disso)

---

## 9. Referencias

- [`incident-v504-pid-matching-simplification.md`](incident-v504-pid-matching-simplification.md) - refactor imediatamente anterior (Opcao A image-name gate)
- [`../emac-recon-v3.md`](../emac-recon-v3.md) - fonte primaria do "100% user-mode RegQueryValueEx" + zero-WMI + read counts por categoria
- [`../track-d-kernel-registry-callback-kickoff.md`](../track-d-kernel-registry-callback-kickoff.md) secao 3.2 row 6 - RegNtPreQueryValueKey handler prometido, jamais landeu (P0.2 do audit v5.0.4)
- [`../roadmap-v41-wmi-intercept.md`](../roadmap-v41-wmi-intercept.md) - onde WMI shadow provider fica ate v5.1+
- [`../track-d-v505-value-handler-kickoff.md`](../track-d-v505-value-handler-kickoff.md) - plano de execucao v5.0.5
- Workflow output raw: `C:\Users\xyrlan\AppData\Local\Temp\claude\C--Users-xyrlan-hwtoolkit\bff5208c-050e-40fc-8014-e53a7483a4d9\tasks\w8xx241ix.output` (temp; sessao-scoped)
