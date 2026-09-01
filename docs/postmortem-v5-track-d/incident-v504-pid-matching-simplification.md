# incident-v504-pid-matching-simplification - Track D volta para Opcao A (inline name check)

Status: **REFACTOR LANDED, PENDING VM+BARE-METAL VALIDATION** (2026-09-01). VM unit test do gate name-match + bare-metal RubinOT run com contadores novos ainda nao rodaram.
Data: 2026-09-01
Driver: rstflt.sys v5.0.4
Escopo: troca do mecanismo de identificacao de processo alvo do Track D. Pre-v5.0.4 usava PID array populado por `PsSetCreateProcessNotifyRoutineEx` + `Parameters\RubinOtPid` como override manual. v5.0.4 usa `PsGetProcessImageFileName(PsGetCurrentProcess())` + `_strnicmp("rubinot", 7)` inline dentro de `RstRegistryCallback`, alinhando com Kickoff secao 3.3 "Recomendacao MVP: Opcao A". Adiciona instrumentacao (CallbackInvokeCount, CallbackNameMissCount, LastMissImageName, LastArmStatus) para responder deterministicamente "o callback rodou pra rubinot_dx.exe?".

---

## 1. Summary

Postmortem obrigatorio pelo CLAUDE.md style. Este arquivo documenta o refactor v5.0.4 do subsistema de PID matching do Track D, motivado pelo terceiro ban RubinOT consecutivo com Track D v5.0.2 armado. Adversarial audit workflow (2026-09-01, 44 findings, 41 CONFIRMED, 1 REFUTED, 2 PLAUSIBLE) confirmou dois defeitos empilhados: design escolheu Kickoff secao 3.3 "Opcao B" contra a propria recomendacao MVP, e instrumentacao so contava rewrites bem-sucedidos - impossivel do userland provar se o callback ativou pra rubinot_dx.exe ou nao.

---

## 2. Contexto - por que este refactor e por que agora

Tres bans RubinOT empiricos (baseline, Level A userland puro, Level A + Track D v5.0.2 fresh identity - documentados em [`../emac-recon-v3.md`](../emac-recon-v3.md) H2), todos com timing entre 8-10min post-login. Zero IOCTL de rubinot\* para `\Device\aff*` observadas em captura de 25min - driver nao foi detectado, o ban veio por fingerprint match server-side. Level A + Track D v5.0.2 aparentava armar corretamente: `track-d-arm.ps1 -Diagnose` mostrava `LastCallbackStatus = 0x00 OK` e `CallbackHitCount > 0`. Mas o audit revelou que esses dois sinais nao provavam o que o operador presumia:

- `LastCallbackStatus = 0x00 OK` era o breadcrumb do arm-time (gravado em ArmTrackD success path como seed), nao evidencia de que o callback disparou para o processo alvo.
- `CallbackHitCount > 0` provava que ALGUM rewrite landou, mas nao distinguia "rubinot_dx.exe foi interceptado" de "outro processo foi interceptado". O PID que efetivamente disparou nao ficava registrado em lugar nenhum.
- O tag `TRACKD_TAG_NO_PID` (0x01) estava definido em `driver/rstflt.c` desde v5.0.0 mas nenhum code path escrevia esse valor. Toda early-return por PID miss retornava `STATUS_SUCCESS` silenciosamente.

Alinhamento com kickoff explicito: [`../track-d-kernel-registry-callback-kickoff.md`](../track-d-kernel-registry-callback-kickoff.md) secao 3.3 recomendou "Opcao A" (name check inline por invocacao) como MVP. v5.0.0 shipou "Opcao B" (Ps notify + PID array + override IOCTL-equivalent) contra essa recomendacao, argumentando latency e sync. Post-audit, os dois argumentos nao sustentam: `PsGetProcessImageFileName + _strnicmp` custa nanoseconds e nao precisa de sync (array + KSPIN_LOCK + Interlocked* desnecessarios).

Opcao A e a resposta arquitetural: elimina a classe inteira de falha silenciosa (ordering, spawn chain masking, race, CreateInfo NULL) por construcao.

---

## 3. Design decisions (aplicadas ao codigo)

### 3.1 Gate por image-name inline em vez de PID array populado por Ps notify

**Escolhido: per-callback `PsGetProcessImageFileName(PsGetCurrentProcess()) + _strnicmp("rubinot", 7)` em vez de `PsSetCreateProcessNotifyRoutineEx` + `g_TrackDTrackedPids[]` + `KSPIN_LOCK`.**

Razoes:

1. Elimina 4 modos de falha empiricos que o audit identificou:
   - **Ordering**: driver armado APOS rubinot rodando -> Ps notify nunca fire para PID pre-existente.
   - **Spawn chain masking**: launcher/updater via loader com nome nao-rubi -> Ps notify rejeita loader; game HW enum roda em-processo durante image load antes do Ps notify do rubinot_dx.exe.
   - **Race Ps-notify-vs-first-callback**: em SSDs rapidos primeira `RegNtPostEnumerateKey` de rubinot_dx.exe pode landar antes do `TrackDAddTrackedPid` completar.
   - **`PS_CREATE_NOTIFY_INFO->ImageFileName` NULL**: alguns `NtCreateUserProcess`/`NtCreateProcessEx` paths (v5.0.4 comentario tecnico) entregam CreateInfo com ImageFileName NULL - handler antigo bailava silenciosamente.

2. Elimina ~70 LOC de sync overhead: `KSPIN_LOCK g_TrackDPidsLock`, `TrackDAddTrackedPid`, `TrackDRemoveTrackedPid`, `TrackDMatchesTrackedPid`, `TrackDImageNameMatchesRubi`, `TrackDCurrentCallerIsTarget`, `g_TrackDOverridePid` (single-slot override), `RstProcessNotifyCallback` (Ps notify handler), Parameters\RubinOtPid load em `LoadTrackDConfig`, isPid branch de `TrackDHandlePreSetValue`.

3. `PsGetProcessImageFileName` retorna ponteiro dentro do `EPROCESS.ImageFileName` (fixed 15-byte ANSI, NUL-padded). Compare de 7 bytes na posicao 0 (`"rubinot"`) e trivial computacionalmente e casa todos os leaf observados (`RubinOT.exe`, `rubinot_dx.exe`, `RubinOTUpdater.exe`). Truncamento 15-byte e irrelevante para prefixos ate 15 chars.

4. Next-char guard rejeita `rubinotimposter.exe`: `name[7]` precisa ser `'\0'`, `'.'`, ou `'_'` para o match aceitar. Custa 3 linhas extras e blindada contra false positives obvios.

**Trade-offs aceitos**:

- `PsGetProcessImageFileName` e semi-documentada (nao esta em wdm.h/ntddk.h, mas exportada pelo ntoskrnl desde WinXP; usada por N drivers em producao). Prototype declarado localmente no rstflt.c topo. Se um dia MS quebrar, fallback e `SeLocateProcessImageName` (PASSIVE only, requer deferir para work item).
- Perdemos a capacidade de matchear por parent directory (full NT path). Nao usado hoje.
- Perdemos o escape hatch `-SetPid`. Substituto: qualquer processo com nome comecando `rubinot*` funciona como probe (ex: `Copy-Item rubinot_dx.exe rubinot_probe.exe; .\rubinot_probe.exe`).

### 3.2 Instrumentacao para responder "o callback fires pra rubinot?"

**Adicionados: `g_TrackDInvokeCount` (LONG), `g_TrackDNameMissCount` (LONG), `g_TrackDLastMissName[16]` (CHAR), persistidos como REG_DWORD/REG_DWORD/REG_SZ via TrackDFlushWorker existente.**

Razoes:

1. Audit finding `no-invocation-counter` (critical) confirmou que `g_TrackDHitCount` so incrementa em rewrite bem-sucedido. Todo early return (name gate, path classify, child prefix, buffer bad) devolvia STATUS_SUCCESS sem breadcrumb. `CallbackInvokeCount` fecha esse gap - incrementa em toda entrada no callback body pos-`g_TrackDEnabled` gate.
2. Audit finding `pid-gate-silent-exit` (critical) mostrou que `TRACKD_TAG_NO_PID` estava definido mas dead code. `CallbackNameMissCount` + `LastMissImageName` + tag redefinido `TRACKD_TAG_NAME_MISS` fecham esse gap - operador consegue distinguir "callback nunca fired" de "callback fired mas gate rejeitou N vezes".
3. `LastMissImageName` (15 bytes do rejected image name, NUL-terminated) e diagnostico: se `LastMissImageName == "rubinot_dx"` mas `HitCount == 0`, sabemos que rubinot bateu no gate mas foi rejeitado pelo next-char guard (leaf name real difere do esperado). Sem esse valor, so `DbgPrint` (que nao existe em release build).
4. Race na escrita do buffer 16-byte e aceita: `RtlCopyMemory` sem lock. Concurrent misses em CPUs distintas podem interleave escritas. Valor e diagnostico, nao input de decisao. Nao vale reintroduzir spinlock pra isso (v5.0.4 acabou de tirar um).

**Persistencia**: `TrackDFlushWorker` estendido para snapshot dos 5 publishers (LastStatus, HitCount, InvokeCount, NameMissCount, LastMissName), single-shot ZwSetValueKey, drift-recheck de todos os 5, re-queue guarded se algum drifitou durante persist window. Mesmo padrao do v5.0.0 post-review fix, apenas escalado.

### 3.3 Split `LastArmStatus` de `LastCallbackStatus`

**Escolhido: novo `WriteLastArmStatus` que escreve em `Parameters\LastArmStatus` (valor separado) em vez de compartilhar `LastCallbackStatus` com o hot path.**

Razoes:

1. Audit finding `lastcallbackstatus-arm-time-only-when-clean` (high) confirmou que ArmTrackD escrevia `LastCallbackStatus = 0x00 OK` no success path como seed. Isso colidia com o hot-path `TRACKD_TAG_OK` semanticamente identico - operador via `OK` no `-Diagnose` sem saber se o callback fired ou apenas armou.
2. Split resolve por completo: `LastArmStatus` reflete APENAS o outcome de ArmTrackD (0x00 OK success, ou tag != 0x00 failure). `LastCallbackStatus` reflete APENAS eventos do hot-path callback body.
3. `WriteLastArmStatus` roda em PASSIVE, driver-init context, FORA de qualquer Cm callback stack -> direto Zw* e safe (sem risco de CM-internal lock deadlock que motivou o TrackDFlushWorker deferred pattern).
4. v5.0.3 changelog block ja anteciparia esse split como "considerar splitear LastArmStatus". v5.0.4 executa.

**Trade-off**: quebra decodificadores extremamente rigidos que assumem apenas `LastCallbackStatus`. Nenhum decoder da arvore assume isso (`check-consistency.ps1` e `track-d-arm.ps1` sao os unicos consumidores, ambos atualizados em sync).

### 3.4 Remocao completa do RubinOtPid + IOCTL-equivalent

**Escolhido: sem escape hatch manual. RubinOtPid REG_DWORD e a value tap em `TrackDHandlePreSetValue` removidos. `-SetPid` removido de `track-d-arm.ps1`.**

Razoes:

1. Escape hatch existia para o v5.0.0 unit test (spawn nao-rubinot process, setar override, validar callback path). Com o gate baseado em image name, o probe se torna spawn de qualquer executavel cujo nome comeca com `rubinot` - trivial.
2. Toda superficie stale (RubinOtPid REG_DWORD, isPid branch de TrackDHandlePreSetValue, load em LoadTrackDConfig, `g_TrackDOverridePid`, `g_TrackDPidValueName` UNICODE_STRING) desaparece.
3. Compat backward: um valor RubinOtPid deixado por instalacao antiga em Parameters e silenciosamente ignorado pelo v5.0.4. `-Enable` nao escreve mais esse valor. Nenhum consumidor quebrado.

---

## 4. VM unit test (pending)

- [ ] Restore checkpoint `clean-v409-installed` (ou build v5.0.4 fresh se restore quebrar signing).
- [ ] Copy driver + scripts atualizados pro guest via Copy-VMFile.
- [ ] `.\03-instalar-driver.bat` + reboot.
- [ ] `.\scripts\track-d-arm.ps1 -Enable` + reboot.
- [ ] `.\scripts\track-d-arm.ps1 -Diagnose` - esperar `LastArmStatus = OK`, `CallbackInvokeCount = 0`, `CallbackNameMissCount = 0`, `LastMissImageName` ausente.
- [ ] Spawn probe: `Copy-Item C:\Windows\System32\reg.exe C:\Users\<user>\Downloads\rubinot_probe.exe; C:\Users\<user>\Downloads\rubinot_probe.exe query 'HKLM\SYSTEM\CurrentControlSet\Enum\SCSI'`.
- [ ] `-Diagnose` novamente - esperar `CallbackInvokeCount > 0`, `CallbackHitCount > 0` (rewrite landou para o probe), `CallbackNameMissCount > 0` (Explorer/Discord/etc rejeitados corretamente), `LastMissImageName ~= "explorer.exe"` ou similar.
- [ ] Zero BSOD durante toda a sequencia.

## 5. VM soak test (pending)

- [ ] Manter probe rodando em loop por 5min. Verificar `InvokeCount` cresce, `HitCount` cresce, `NameMissCount` cresce, `LastArmStatus` inalterado.
- [ ] Zero BSOD, zero NonPagedPool leak (verificar via `!poolused` no WinDbg ou baseline vs post do RAM `Get-Counter '\Memory\Pool Nonpaged Bytes'`).
- [ ] Callback rewrite latency <= 100us (probing timing overhead via ETW).

## 6. Bare-metal RubinOT test (gate final per kickoff sec 6.3)

- [ ] Fresh account + fresh spoof cycle: `.\00-gerar-profile.bat` -> `.\04b-aplicar-hwid-emac.bat --skip-disk --skip-volume --skip-usb --skip-hid` -> reboot -> `.\03-instalar-driver.bat` + reboot -> `.\scripts\track-d-arm.ps1 -Enable` + reboot.
- [ ] Login RubinOT, gameplay session ~10min.
- [ ] Post-session: `.\scripts\track-d-arm.ps1 -Diagnose` + `.\scripts\check-consistency.ps1`.
- [ ] Coletar: valores de InvokeCount, NameMissCount, HitCount, LastMissImageName, LastCallbackStatus, LastArmStatus. Screenshot RubinOT session (proof gameplay).
- [ ] Se ban NAO cair E `HitCount > 0` E `LastMissImageName != rubinot*` (indicando gate discrimina corretamente) -> MVP done.
- [ ] Se ban cair mesmo com invocacao confirmada (`InvokeCount > 0, HitCount > 0`) -> proximo passo P0.2 do audit (adicionar `RegNtPostQueryValueKey` handler para intercept de VALUES; ver secao 8).

## 7. Success criteria

1. Build v5.0.4 compila cleanly com `.\02-compilar-driver.bat` (nmake + signtool).
2. VM unit test (secao 4) passa - `InvokeCount > 0`, `HitCount > 0` para probe rubinot_*, `NameMissCount > 0` para nao-rubinot.
3. VM soak test (secao 5) passa - zero BSOD em 5min, contadores crescem monotonicamente.
4. Bare-metal RubinOT test (secao 6) passa - ban NAO cai apos gameplay session com `InvokeCount > 0`.

Se secoes 4-5 passam mas 6 falha (ban persiste), a causa deixa de ser identificacao de processo (`Opcao A` prova que resolveu essa classe) e vira gap de COBERTURA - proximo item e P0.2 do audit.

## 8. Follow-ups conhecidos (se ban persistir apos MVP v5.0.4)

Todos deferidos para PRs separados por serem mudancas arquiteturais independentes que merecem code review isolada.

1. **P0.2 - `RegNtPostQueryValueKey` handler** (audit finding `handler-coverage-post-enumerate-plus-preset-only-no-value-intercept`, medium severity): Track D atual so intercepta subkey NAMES via `RegNtPostEnumerateKey`. `RegQueryValueEx` em `HardwareID` / `CompatibleIDs` / `DeviceDesc` / `FriendlyName` sob parents ja no allow-list passa direto. Kickoff §3.2 row 6 promete defense-in-depth mas nunca aterrissou. Effort ~6h.
2. **P0.3 - expandir allow-list para Cryptography + BTH + PCI parent** (audit finding `path-filter-scope-scsi-pci-usb-hid-mmdevices-only-no-bth-nor-machineguid`): adicionar `\SOFTWARE\Microsoft\Cryptography` (MachineGuid per-PID), `\Enum\BTH`, e reescrita de SUBSYS+REV nos nomes de parent subkeys `\Enum\PCI\VEN_&DEV_&SUBSYS_XXXXXXXX&REV_XX` (preservar VEN+DEV que sao driver binding). Effort ~4h.
3. **Reintroduzir Ps notify como AUXILIAR** (nao como gate): se latency shaving virar relevante (evitar `PsGetProcessImageFileName` em cada callback), Ps notify pode popular um bit "seen-rubinot-recently" como cache. Fica em backlog, nao como MVP.

---

## 9. References

- [`../track-d-kernel-registry-callback-kickoff.md`](../track-d-kernel-registry-callback-kickoff.md) secao 3.3 - "Recomendacao MVP: Opcao A" (base normativa deste refactor).
- [`incident-v500-mvp-integration.md`](incident-v500-mvp-integration.md) - justificativa original (agora superada) para Opcao B.
- [`../emac-recon-v3.md`](../emac-recon-v3.md) - H2 (EMAC le NAMES via `RegEnumKeyEx`) + tres bans empiricos que motivaram Track D + este refactor.
- [`../../driver/rstflt.c`](../../driver/rstflt.c) - procurar bloco `v5.0.4 - Simplify PID matching`.
- [`../../scripts/track-d-arm.ps1`](../../scripts/track-d-arm.ps1) - `-SetPid` removido; `-Diagnose` estendido.
- [`../../scripts/check-consistency.ps1`](../../scripts/check-consistency.ps1) - Read-CallbackStatus estendido para 4 novos values Parameters.
- Adversarial review workflow 2026-09-01 (44 findings, 41 CONFIRMED, 2 PLAUSIBLE, 1 REFUTED) - documentado em CLAUDE.md session log 2026-09-01 e memory `track-d-mvp-implemented`.
